//! Scheduler-side syscall decoding and dispatch.
//!
//! The dispatcher is called after the architecture entry path has saved a
//! [`UserContext`] and yielded to the scheduler. The process address space must
//! still be active while this module copies syscall arguments and results.
//!
//! [`SyscallNumber::WaitMany`] copies its complete request into process-owned
//! kernel memory before blocking. The process scheduler polls that continuation
//! with [`poll_blocked`] and, after activating the process address space, calls
//! [`complete_blocked`] to publish user output and the deferred syscall status.

use alloc::{boxed::Box, string::String, vec, vec::Vec};
use core::mem::size_of;

use ginkgo_filesystem::{
    DirectoryHandle, FsError, NodeKind, NodeMetadata, RedoxFs, RenameMode, MAX_TRAVERSAL_DEPTH,
};
use ginkgo_ipc::{
    handle_transfer_batch_between, HandleOperation, HandleOperationDisposition, HandleTable,
    IpcError, MessageInfo, ObjectType, Rights, Signals, WaitItem, APPLICATION_DATA_MAX_APP_ID_LEN,
};
use ginkgo_sysapi::{
    FilesystemDirectoryEntry, FilesystemOpenFlags, FilesystemRenameFlags, Handle, MapFlags,
    MapProtection, ProcessInfo, SharedMemoryMapArgs, Status, SyscallNumber, SystemPowerAction,
    SystemPowerFlags, SystemPowerInfo, CHANNEL_MAX_BYTES, CHANNEL_MAX_HANDLES, DEADLINE_INFINITE,
    FILESYSTEM_NAME_MAX, FILESYSTEM_READ_MAX_BYTES, PROCESS_MAX_STARTUP_BYTES,
    PROCESS_MAX_STARTUP_HANDLES, RANDOM_MAX_BYTES,
};
use redoxfs::Disk;

use crate::{
    arch::UserContext,
    audio::AudioDevice,
    entropy::EntropyPool,
    memory::UsableFrameAllocator,
    paging::{
        address_space::{AddressSpaceError, UserAccess},
        ActivePageTable, MapError,
    },
    process::{
        DirectStartupBlock, PendingWaitMany, Process, ProcessCreateError, SharedMappingError,
        WaitDeadline, WaitManyCompletion,
    },
};

/// Maximum bytes accepted by one [`SyscallNumber::DebugWrite`] call.
pub const DEBUG_WRITE_MAX_BYTES: usize = 4096;
/// Maximum frame-aligned PCM bytes accepted by one audio write.
pub const AUDIO_WRITE_MAX_BYTES: usize = 16 * 1024;
/// Maximum objects inspected by one bounded wait-many scheduler poll.
pub const WAIT_MANY_MAX_ITEMS: usize = 64;

const WAIT_MANY_ARGS_SIZE: usize = 24;
const WAIT_ITEM_SIZE: usize = 12;
const WAIT_MANY_OUTPUT_SIZE: usize = 8;
const MONOTONIC_TIME_OUTPUT_SIZE: usize = 8;
const HANDLE_OUTPUT_SIZE: usize = 8;
const HANDLE_DISPOSITION_SIZE: usize = 16;
const RECEIVED_HANDLE_SIZE: usize = 16;
const CHANNEL_CREATE_OUTPUT_SIZE: usize = 8;
const CHANNEL_WRITE_ARGS_SIZE: usize = 40;
const CHANNEL_READ_ARGS_SIZE: usize = 48;
const CHANNEL_READ_OUTPUT_SIZE: usize = 8;
const SHARED_MEMORY_SIZE_OUTPUT_SIZE: usize = 8;
const SHARED_MEMORY_MAP_ARGS_SIZE: usize = 32;
const SHARED_MEMORY_MAP_OUTPUT_SIZE: usize = 8;
const FILESYSTEM_OPEN_ARGS_SIZE: usize = 24;
const FILESYSTEM_READ_OUTPUT_SIZE: usize = 8;
const FILESYSTEM_STAT_SIZE: usize = 24;
const FILESYSTEM_DIRECTORY_ENTRY_SIZE: usize = size_of::<FilesystemDirectoryEntry>();
const FILESYSTEM_OPEN_DIRECTORY_ARGS_SIZE: usize = 32;
const FILESYSTEM_CREATE_DIRECTORY_ARGS_SIZE: usize = 24;
const FILESYSTEM_REMOVE_DIRECTORY_ARGS_SIZE: usize = 24;
const FILESYSTEM_RENAME_ARGS_SIZE: usize = 48;
const FILESYSTEM_SYNC_ARGS_SIZE: usize = 8;
const FILESYSTEM_GET_INFO_ARGS_SIZE: usize = 16;
const FILESYSTEM_INFO_SIZE: usize = 64;
const FILESYSTEM_GET_METADATA_ARGS_SIZE: usize = 32;
const FILESYSTEM_METADATA_SIZE: usize = 64;
const FILESYSTEM_READ_DIRECTORY2_ARGS_SIZE: usize = 24;
const FILESYSTEM_DIRECTORY_ENTRY2_SIZE: usize = 288;
const FILESYSTEM_PATH_MAX: usize =
    MAX_TRAVERSAL_DEPTH * FILESYSTEM_NAME_MAX + (MAX_TRAVERSAL_DEPTH - 1);
const PROCESS_CREATE_ARGS_SIZE: usize = 64;
const PROCESS_INFO_SIZE: usize = size_of::<ProcessInfo>();
const SYSTEM_POWER_INFO_SIZE: usize = size_of::<SystemPowerInfo>();
const SYSTEM_POWER_CANCELLATION_NS: u64 = 2_000_000_000;
const APPLICATION_DATA_CREATE_ARGS_SIZE: usize = 32;
const MAX_EXECUTABLE_BYTES: usize = 256 * 1024 * 1024;

/// A bounded destination for early userspace diagnostics.
pub trait DebugSink {
    fn write(&mut self, bytes: &[u8]);
}

/// Scheduler action produced by one syscall dispatch.
pub enum SyscallOutcome {
    /// The syscall completed (successfully or with an error) and the process is
    /// a candidate for a later cooperative scheduling turn.
    Yield,
    /// Syscall completion is deferred until the scheduler wakes the process.
    Blocked,
    /// The process requested termination with this code.
    Exit(i32),
    /// A fully initialized child whose scheduler slot was reserved before dispatch.
    ChildCreated(Box<Process>),
}

enum DispatchResult {
    Complete(Status),
    Blocked,
    ChildCreated(Box<Process>),
}

/// Result of one bounded scheduler poll of a blocked process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockedPoll {
    /// No signal is ready and the deadline has not expired.
    Pending,
    /// Completion is staged in the process and [`complete_blocked`] must be
    /// called with the process address space active.
    Complete,
}

/// Dispatches the syscall saved in `context`.
///
/// Completed outcomes write a sign-extended [`Status`] to RAX. A blocked
/// outcome leaves RAX untouched until [`complete_blocked`] runs. Unknown syscall
/// numbers are decoded without converting an arbitrary integer into a Rust enum.
pub fn dispatch<D: DebugSink + ?Sized, B: Disk>(
    process: &mut Process,
    context: &mut UserContext,
    now_ns: u64,
    kernel_page_table: &ActivePageTable,
    frame_allocator: &mut UsableFrameAllocator<'_>,
    filesystem: &mut RedoxFs<B>,
    audio: &mut Option<AudioDevice>,
    entropy: &mut EntropyPool,
    process_creation_allowed: bool,
    child_slot_reserved: bool,
    debug_sink: &mut D,
) -> SyscallOutcome {
    let Some(number) = decode_syscall_number(context.rax) else {
        set_status(context, Status::UnknownSyscall);
        return SyscallOutcome::Yield;
    };

    if number == SyscallNumber::ProcessExit {
        return match decode_exit_code(context.rdi) {
            Ok(code) => {
                process.mark_exited(code);
                SyscallOutcome::Exit(code)
            }
            Err(status) => {
                set_status(context, status);
                SyscallOutcome::Yield
            }
        };
    }

    // User copies require the process CR3. Checking this before all non-exit
    // operations also prevents a state change followed by an avoidable copy
    // failure when the dispatcher contract is violated by its caller.
    let result = if !process.address_space().is_active() {
        DispatchResult::Complete(Status::InvalidAddress)
    } else {
        dispatch_non_exit(
            number,
            process,
            context,
            now_ns,
            kernel_page_table,
            frame_allocator,
            filesystem,
            audio,
            entropy,
            process_creation_allowed,
            child_slot_reserved,
            debug_sink,
        )
    };
    match result {
        DispatchResult::Complete(status) => {
            set_status(context, status);
            SyscallOutcome::Yield
        }
        DispatchResult::Blocked => SyscallOutcome::Blocked,
        DispatchResult::ChildCreated(child) => {
            set_status(context, Status::Ok);
            SyscallOutcome::ChildCreated(child)
        }
    }
}

fn dispatch_non_exit<D: DebugSink + ?Sized, B: Disk>(
    number: SyscallNumber,
    process: &mut Process,
    context: &UserContext,
    now_ns: u64,
    kernel_page_table: &ActivePageTable,
    frame_allocator: &mut UsableFrameAllocator<'_>,
    filesystem: &mut RedoxFs<B>,
    audio: &mut Option<AudioDevice>,
    entropy: &mut EntropyPool,
    process_creation_allowed: bool,
    child_slot_reserved: bool,
    debug_sink: &mut D,
) -> DispatchResult {
    if number == SyscallNumber::WaitMany {
        return wait_many(process, context.rdi, context.rsi, now_ns);
    }

    let result = match number {
        SyscallNumber::ProcessYield => Ok(()),
        SyscallNumber::ProcessExit => unreachable!("process exit is handled before dispatch"),
        SyscallNumber::HandleClose => handle_close(process, context.rdi),
        SyscallNumber::HandleDuplicate => {
            handle_duplicate(process, context.rdi, context.rsi, context.rdx)
        }
        SyscallNumber::WaitMany => unreachable!("wait-many is handled before ordinary dispatch"),
        SyscallNumber::ChannelCreate => channel_create(process, context.rdi),
        SyscallNumber::ChannelWrite => channel_write(process, context.rdi, context.rsi),
        SyscallNumber::ChannelRead => channel_read(process, context.rdi, context.rsi),
        SyscallNumber::SharedMemoryCreate => {
            shared_memory_create(process, context.rdi, context.rsi)
        }
        SyscallNumber::SharedMemoryGetSize => {
            shared_memory_get_size(process, context.rdi, context.rsi)
        }
        SyscallNumber::SharedMemoryMap => shared_memory_map(
            process,
            context.rdi,
            context.rsi,
            context.rdx,
            kernel_page_table,
            frame_allocator,
        ),
        SyscallNumber::SharedMemoryUnmap => shared_memory_unmap(process, context.rdi, context.rsi),
        SyscallNumber::DebugWrite => debug_write(process, context.rdi, context.rsi, debug_sink),
        SyscallNumber::FilesystemOpen => {
            filesystem_open(process, filesystem, context.rdi, context.rsi, context.rdx)
        }
        SyscallNumber::FilesystemRead => filesystem_read(
            process,
            filesystem,
            context.rdi,
            context.rsi,
            context.rdx,
            context.r10,
            context.r8,
        ),
        SyscallNumber::FilesystemWrite => filesystem_write(
            process,
            filesystem,
            context.rdi,
            context.rsi,
            context.rdx,
            context.r10,
            context.r8,
        ),
        SyscallNumber::FilesystemStat => {
            filesystem_stat(process, filesystem, context.rdi, context.rsi)
        }
        SyscallNumber::FilesystemReadDirectory => {
            filesystem_read_directory(process, filesystem, context.rdi, context.rsi, context.rdx)
        }
        SyscallNumber::FilesystemTruncate => {
            filesystem_truncate(process, filesystem, context.rdi, context.rsi)
        }
        SyscallNumber::FilesystemUnlink => {
            filesystem_unlink(process, filesystem, context.rdi, context.rsi, context.rdx)
        }
        SyscallNumber::AudioWrite => audio_write(process, audio, context.rdi, context.rsi),
        SyscallNumber::ClockGetMonotonic => clock_get_monotonic(process, context.rdi, now_ns),
        SyscallNumber::RandomFill => {
            random_fill(process, entropy, context.rdi, context.rsi, context.rdx)
        }
        SyscallNumber::ProcessCreate if !process_creation_allowed => {
            return DispatchResult::Complete(Status::AccessDenied);
        }
        SyscallNumber::ProcessCreate => {
            return match process_create(
                process,
                filesystem,
                context.rdi,
                kernel_page_table,
                frame_allocator,
                entropy,
                child_slot_reserved,
            ) {
                Ok(child) => DispatchResult::ChildCreated(child),
                Err(status) => DispatchResult::Complete(status),
            };
        }
        SyscallNumber::ProcessGetInfo => process_get_info(process, context.rdi, context.rsi),
        SyscallNumber::ProcessTerminate => process_terminate(process, context.rdi),
        SyscallNumber::ApplicationGetDataDirectory => {
            application_get_data_directory(process, filesystem, context.rdi)
        }
        SyscallNumber::FilesystemOpenDirectory => {
            filesystem_open_directory(process, filesystem, context.rdi)
        }
        SyscallNumber::FilesystemCreateDirectory => {
            filesystem_create_directory(process, filesystem, context.rdi)
        }
        SyscallNumber::FilesystemRemoveDirectory => {
            filesystem_remove_directory(process, filesystem, context.rdi)
        }
        SyscallNumber::FilesystemRename => filesystem_rename(process, filesystem, context.rdi),
        SyscallNumber::FilesystemSync => filesystem_sync(process, filesystem, context.rdi),
        SyscallNumber::FilesystemGetInfo => filesystem_get_info(process, filesystem, context.rdi),
        SyscallNumber::FilesystemGetMetadata => {
            filesystem_get_metadata(process, filesystem, context.rdi)
        }
        SyscallNumber::FilesystemReadDirectory2 => {
            filesystem_read_directory2(process, filesystem, context.rdi)
        }
        SyscallNumber::ApplicationDataCreate => {
            application_data_create(process, filesystem, context.rdi)
        }
        SyscallNumber::SystemPowerRequest => {
            system_power_request(process, context.rdi, context.rsi, context.rdx, now_ns)
        }
        SyscallNumber::SystemPowerCancel => system_power_cancel(process, context.rdi),
        SyscallNumber::SystemPowerGetInfo => {
            system_power_get_info(process, context.rdi, context.rsi)
        }
        SyscallNumber::AnonymousMap => anonymous_map(
            process,
            context.rdi,
            context.rsi,
            context.rdx,
            frame_allocator,
        ),
        SyscallNumber::AnonymousUnmap => {
            anonymous_unmap(process, context.rdi, context.rsi, frame_allocator)
        }
        SyscallNumber::AnonymousProtect => {
            anonymous_protect(process, context.rdi, context.rsi, context.rdx)
        }
    };
    DispatchResult::Complete(match result {
        Ok(()) => Status::Ok,
        Err(status) => status,
    })
}

const fn decode_syscall_number(raw: u64) -> Option<SyscallNumber> {
    Some(match raw {
        0 => SyscallNumber::ProcessYield,
        1 => SyscallNumber::ProcessExit,
        2 => SyscallNumber::HandleClose,
        3 => SyscallNumber::HandleDuplicate,
        4 => SyscallNumber::WaitMany,
        5 => SyscallNumber::ChannelCreate,
        6 => SyscallNumber::ChannelWrite,
        7 => SyscallNumber::ChannelRead,
        8 => SyscallNumber::SharedMemoryCreate,
        9 => SyscallNumber::SharedMemoryGetSize,
        10 => SyscallNumber::SharedMemoryMap,
        11 => SyscallNumber::SharedMemoryUnmap,
        12 => SyscallNumber::DebugWrite,
        13 => SyscallNumber::FilesystemOpen,
        14 => SyscallNumber::FilesystemRead,
        15 => SyscallNumber::FilesystemWrite,
        16 => SyscallNumber::FilesystemStat,
        17 => SyscallNumber::FilesystemReadDirectory,
        18 => SyscallNumber::FilesystemTruncate,
        19 => SyscallNumber::FilesystemUnlink,
        20 => SyscallNumber::AudioWrite,
        21 => SyscallNumber::ClockGetMonotonic,
        22 => SyscallNumber::RandomFill,
        23 => SyscallNumber::ProcessCreate,
        24 => SyscallNumber::ProcessGetInfo,
        25 => SyscallNumber::ProcessTerminate,
        26 => SyscallNumber::ApplicationGetDataDirectory,
        27 => SyscallNumber::FilesystemOpenDirectory,
        28 => SyscallNumber::FilesystemCreateDirectory,
        29 => SyscallNumber::FilesystemRemoveDirectory,
        30 => SyscallNumber::FilesystemRename,
        31 => SyscallNumber::FilesystemSync,
        32 => SyscallNumber::FilesystemGetInfo,
        33 => SyscallNumber::FilesystemGetMetadata,
        34 => SyscallNumber::FilesystemReadDirectory2,
        35 => SyscallNumber::ApplicationDataCreate,
        36 => SyscallNumber::SystemPowerRequest,
        37 => SyscallNumber::SystemPowerCancel,
        38 => SyscallNumber::SystemPowerGetInfo,
        39 => SyscallNumber::AnonymousMap,
        40 => SyscallNumber::AnonymousUnmap,
        41 => SyscallNumber::AnonymousProtect,
        _ => return None,
    })
}

fn set_status(context: &mut UserContext, status: Status) {
    context.set_syscall_return((i64::from(status.raw())) as u64);
}

fn decode_exit_code(raw: u64) -> Result<i32, Status> {
    i32::try_from(raw as i64).map_err(|_| Status::InvalidArgument)
}

fn handle_close(process: &mut Process, raw_handle: u64) -> Result<(), Status> {
    let handle = decode_handle(raw_handle)?;
    process
        .handles_mut()
        .handle_close(handle)
        .map_err(map_ipc_error)
}

fn handle_duplicate(
    process: &mut Process,
    raw_handle: u64,
    raw_rights: u64,
    output_address: u64,
) -> Result<(), Status> {
    let handle = decode_handle(raw_handle)?;
    let rights = decode_rights_u64(raw_rights)?;
    validate_user_output(process, output_address, HANDLE_OUTPUT_SIZE)?;

    let duplicate = process
        .handles_mut()
        .handle_duplicate(handle, rights)
        .map_err(map_ipc_error)?;
    let output = encode_handle_output(duplicate);
    if let Err(status) = copy_to_user(process, output_address, &output) {
        close_handles(process, core::slice::from_ref(&duplicate));
        return Err(status);
    }
    Ok(())
}

fn wait_many(
    process: &mut Process,
    args_address: u64,
    output_address: u64,
    now_ns: u64,
) -> DispatchResult {
    match submit_wait_many(process, args_address, output_address, now_ns) {
        Ok(result) => result,
        Err(status) => DispatchResult::Complete(status),
    }
}

fn submit_wait_many(
    process: &mut Process,
    args_address: u64,
    output_address: u64,
    now_ns: u64,
) -> Result<DispatchResult, Status> {
    let raw_args = copy_block_from_user::<WAIT_MANY_ARGS_SIZE>(process, args_address)?;
    let items_address = read_u64(&raw_args, 0);
    let item_count = read_u64(&raw_args, 8);
    let deadline_ns = read_i64(&raw_args, 16);
    if deadline_ns < 0 {
        return Err(Status::InvalidArgument);
    }
    let deadline = if deadline_ns == DEADLINE_INFINITE {
        WaitDeadline::Infinite
    } else {
        WaitDeadline::At(deadline_ns as u64)
    };

    let items_bytes_len = checked_array_bytes(
        item_count,
        WAIT_ITEM_SIZE,
        WAIT_MANY_MAX_ITEMS as u64,
        Status::OutOfRange,
    )?;
    if item_count == 0 {
        return Err(Status::InvalidArgument);
    }
    validate_user_output(process, items_address, items_bytes_len)?;
    validate_user_output(process, output_address, WAIT_MANY_OUTPUT_SIZE)?;

    let raw_items = copy_vec_from_user(process, items_address, items_bytes_len)?;
    let item_count = usize::try_from(item_count).map_err(|_| Status::OutOfRange)?;
    let mut items = Vec::new();
    items
        .try_reserve_exact(item_count)
        .map_err(|_| Status::OutOfMemory)?;
    for raw in raw_items.chunks_exact(WAIT_ITEM_SIZE) {
        items.push(parse_wait_item(raw)?);
    }
    let mut encoded_items = zeroed_vec(items_bytes_len)?;

    let ready = process
        .handles()
        .poll_wait_many(&mut items)
        .map_err(map_ipc_error)?;
    if let Some(completion) = resolve_wait_completion(ready, deadline, now_ns) {
        encode_wait_items_into(&items, &mut encoded_items);
        copy_to_user(process, items_address, &encoded_items)?;
        return match completion {
            WaitManyCompletion::Ready(ready_index) => {
                let ready_index = u64::try_from(ready_index).map_err(|_| Status::OutOfRange)?;
                copy_to_user(process, output_address, &ready_index.to_le_bytes())?;
                Ok(DispatchResult::Complete(Status::Ok))
            }
            WaitManyCompletion::Failed(status) => Ok(DispatchResult::Complete(status)),
        };
    }

    process.block_wait_many(PendingWaitMany {
        items,
        encoded_items,
        items_address,
        output_address,
        deadline,
        completion: None,
    });
    Ok(DispatchResult::Blocked)
}

fn resolve_wait_completion(
    ready: Option<usize>,
    deadline: WaitDeadline,
    now_ns: u64,
) -> Option<WaitManyCompletion> {
    ready.map(WaitManyCompletion::Ready).or_else(|| {
        deadline
            .is_expired(now_ns)
            .then_some(WaitManyCompletion::Failed(Status::TimedOut))
    })
}

/// Polls one process-owned blocked syscall without activating userspace memory.
///
/// A [`BlockedPoll::Complete`] result leaves the completion staged in `process`.
/// The scheduler must activate that process's address space and immediately call
/// [`complete_blocked`] before scheduling the process again.
pub fn poll_blocked(process: &mut Process, now_ns: u64) -> BlockedPoll {
    let (handles, wait) = process.blocked_wait_many_parts();
    if wait.completion.is_some() {
        return BlockedPoll::Complete;
    }

    let ready = match handles.poll_wait_many(&mut wait.items) {
        Ok(ready) => ready,
        Err(error) => {
            wait.completion = Some(WaitManyCompletion::Failed(map_ipc_error(error)));
            return BlockedPoll::Complete;
        }
    };
    wait.completion = resolve_wait_completion(ready, wait.deadline, now_ns);
    if wait.completion.is_some() {
        BlockedPoll::Complete
    } else {
        BlockedPoll::Pending
    }
}

/// Completes a staged blocked syscall and makes the process runnable.
///
/// The process address space must be active. If it is not, the wait is aborted
/// with [`Status::InvalidAddress`] so the process cannot remain permanently
/// blocked because of a scheduler integration error.
pub fn complete_blocked(process: &mut Process) -> Status {
    let mut wait = process.take_blocked_wait_many();
    let completion = wait
        .completion
        .expect("blocked syscall completion was not staged by poll_blocked");
    let status = if !process.address_space().is_active() {
        Status::InvalidAddress
    } else {
        match completion {
            WaitManyCompletion::Ready(ready_index) => copy_wait_items_to_user(process, &mut wait)
                .and_then(|()| {
                    let ready_index = u64::try_from(ready_index).map_err(|_| Status::OutOfRange)?;
                    copy_to_user(process, wait.output_address, &ready_index.to_le_bytes())
                }),
            WaitManyCompletion::Failed(Status::TimedOut) => {
                copy_wait_items_to_user(process, &mut wait).and(Err(Status::TimedOut))
            }
            WaitManyCompletion::Failed(status) => Err(status),
        }
        .err()
        .unwrap_or(Status::Ok)
    };

    set_status(process.context_mut(), status);
    process.resume_from_block();
    status
}

fn copy_wait_items_to_user(process: &Process, wait: &mut PendingWaitMany) -> Result<(), Status> {
    encode_wait_items_into(&wait.items, &mut wait.encoded_items);
    copy_to_user(process, wait.items_address, &wait.encoded_items)
}

fn random_fill(
    process: &Process,
    entropy: &mut EntropyPool,
    raw_source: u64,
    output_address: u64,
    raw_length: u64,
) -> Result<(), Status> {
    let source = decode_handle(raw_source)?;
    process
        .handles()
        .random_source(source)
        .map_err(map_ipc_error)?;
    let length = checked_array_bytes(raw_length, 1, RANDOM_MAX_BYTES as u64, Status::OutOfRange)?;
    validate_user_output(process, output_address, length)?;
    let mut bytes = zeroed_vec(length)?;
    entropy.fill_bytes(&mut bytes);
    copy_to_user(process, output_address, &bytes)
}

fn clock_get_monotonic(process: &Process, output_address: u64, now_ns: u64) -> Result<(), Status> {
    validate_user_output(process, output_address, MONOTONIC_TIME_OUTPUT_SIZE)?;
    copy_to_user(process, output_address, &now_ns.to_le_bytes())
}

fn channel_create(process: &mut Process, output_address: u64) -> Result<(), Status> {
    validate_user_output(process, output_address, CHANNEL_CREATE_OUTPUT_SIZE)?;
    let (first, second) = process
        .handles_mut()
        .channel_create()
        .map_err(map_ipc_error)?;
    let output = encode_channel_create_output(first, second);
    if let Err(status) = copy_to_user(process, output_address, &output) {
        close_handles(process, &[first, second]);
        return Err(status);
    }
    Ok(())
}

fn channel_write(process: &mut Process, raw_channel: u64, args_address: u64) -> Result<(), Status> {
    let channel = decode_handle(raw_channel)?;
    let raw_args = copy_block_from_user::<CHANNEL_WRITE_ARGS_SIZE>(process, args_address)?;
    let bytes_address = read_u64(&raw_args, 0);
    let byte_count = read_u64(&raw_args, 8);
    let dispositions_address = read_u64(&raw_args, 16);
    let disposition_count = read_u64(&raw_args, 24);
    let flags = read_u32(&raw_args, 32);
    let reserved = read_u32(&raw_args, 36);
    if flags != 0 || reserved != 0 {
        return Err(Status::InvalidArgument);
    }

    let byte_count = checked_array_bytes(
        byte_count,
        1,
        CHANNEL_MAX_BYTES as u64,
        Status::MessageTooLarge,
    )?;
    let disposition_bytes_len = checked_array_bytes(
        disposition_count,
        HANDLE_DISPOSITION_SIZE,
        CHANNEL_MAX_HANDLES as u64,
        Status::MessageTooLarge,
    )?;
    let bytes = copy_vec_from_user(process, bytes_address, byte_count)?;
    let raw_dispositions =
        copy_vec_from_user(process, dispositions_address, disposition_bytes_len)?;

    let disposition_count =
        usize::try_from(disposition_count).map_err(|_| Status::MessageTooLarge)?;
    let mut dispositions = Vec::new();
    dispositions
        .try_reserve_exact(disposition_count)
        .map_err(|_| Status::OutOfMemory)?;
    for raw in raw_dispositions.chunks_exact(HANDLE_DISPOSITION_SIZE) {
        dispositions.push(parse_handle_disposition(raw)?);
    }

    if !process.can_send_channel_bytes(byte_count) {
        return Err(Status::ResourceLimit);
    }
    process
        .handles_mut()
        .channel_write_with_handle_operations(channel, &bytes, &dispositions)
        .map_err(map_ipc_error)?;
    process.record_channel_bytes(byte_count);
    Ok(())
}

fn channel_read(process: &mut Process, raw_channel: u64, args_address: u64) -> Result<(), Status> {
    let channel = decode_handle(raw_channel)?;
    let raw_args = copy_block_from_user::<CHANNEL_READ_ARGS_SIZE>(process, args_address)?;
    let bytes_address = read_u64(&raw_args, 0);
    let byte_capacity = read_u64(&raw_args, 8);
    let handles_address = read_u64(&raw_args, 16);
    let handle_capacity = read_u64(&raw_args, 24);
    let output_address = read_u64(&raw_args, 32);
    let flags = read_u32(&raw_args, 40);
    let reserved = read_u32(&raw_args, 44);
    if flags != 0 || reserved != 0 {
        return Err(Status::InvalidArgument);
    }

    let byte_capacity = checked_array_bytes(
        byte_capacity,
        1,
        CHANNEL_MAX_BYTES as u64,
        Status::OutOfRange,
    )?;
    let handle_bytes_len = checked_array_bytes(
        handle_capacity,
        RECEIVED_HANDLE_SIZE,
        CHANNEL_MAX_HANDLES as u64,
        Status::OutOfRange,
    )?;
    let handle_capacity = usize::try_from(handle_capacity).map_err(|_| Status::OutOfRange)?;

    validate_user_output(process, bytes_address, byte_capacity)?;
    validate_user_output(process, handles_address, handle_bytes_len)?;
    validate_user_output(process, output_address, CHANNEL_READ_OUTPUT_SIZE)?;

    let mut bytes = zeroed_vec(byte_capacity)?;
    let mut handles = Vec::new();
    handles
        .try_reserve_exact(handle_capacity)
        .map_err(|_| Status::OutOfMemory)?;
    handles.resize(handle_capacity, Handle::INVALID);
    // Allocate the complete ABI metadata capacity before channel_read's dequeue
    // commit point. Everything after a successful read is allocation-free.
    let mut metadata = zeroed_vec(handle_bytes_len)?;

    let info = match process
        .handles_mut()
        .channel_read(channel, &mut bytes, &mut handles)
    {
        Ok(info) => info,
        Err(IpcError::BufferTooSmall(info)) => {
            let output = encode_channel_read_output(info);
            copy_to_user(process, output_address, &output)?;
            return Err(Status::BufferTooSmall);
        }
        Err(error) => return Err(map_ipc_error(error)),
    };

    let byte_count = info.byte_count as usize;
    let handle_count = usize::from(info.handle_count);
    if byte_count > bytes.len() || handle_count > handles.len() || info.reserved != 0 {
        close_handles(process, &handles[..handle_count.min(handles.len())]);
        return Err(Status::InvalidMessage);
    }
    let received = &handles[..handle_count];
    let metadata_len = handle_count * RECEIVED_HANDLE_SIZE;
    if fill_received_handle_metadata(process, received, &mut metadata[..metadata_len]).is_err() {
        close_handles(process, received);
        return Err(Status::InvalidMessage);
    }
    let output = encode_channel_read_output(info);

    let copied = copy_to_user(process, bytes_address, &bytes[..byte_count])
        .and_then(|()| copy_to_user(process, handles_address, &metadata[..metadata_len]))
        .and_then(|()| copy_to_user(process, output_address, &output));
    if let Err(status) = copied {
        close_handles(process, received);
        return Err(status);
    }
    Ok(())
}

fn shared_memory_create(
    process: &mut Process,
    raw_size: u64,
    output_address: u64,
) -> Result<(), Status> {
    let size = usize::try_from(raw_size).map_err(|_| Status::OutOfRange)?;
    if !process.can_allocate_shared_memory(size) {
        return Err(Status::ResourceLimit);
    }
    validate_user_output(process, output_address, HANDLE_OUTPUT_SIZE)?;
    let handle = process
        .handles_mut()
        .shared_memory_create(size)
        .map_err(map_ipc_error)?;
    process.record_shared_memory_allocation(size);
    let output = encode_handle_output(handle);
    if let Err(status) = copy_to_user(process, output_address, &output) {
        close_handles(process, core::slice::from_ref(&handle));
        process.release_shared_memory_charge(size);
        return Err(status);
    }
    Ok(())
}

fn shared_memory_get_size(
    process: &mut Process,
    raw_handle: u64,
    output_address: u64,
) -> Result<(), Status> {
    let handle = decode_handle(raw_handle)?;
    validate_user_output(process, output_address, SHARED_MEMORY_SIZE_OUTPUT_SIZE)?;
    let size = process
        .handles()
        .shared_memory_len(handle)
        .map_err(map_ipc_error)?;
    let size = u64::try_from(size).map_err(|_| Status::OutOfRange)?;
    copy_to_user(process, output_address, &size.to_le_bytes())
}

fn shared_memory_map(
    process: &mut Process,
    raw_handle: u64,
    args_address: u64,
    output_address: u64,
    kernel_page_table: &ActivePageTable,
    frame_allocator: &mut UsableFrameAllocator<'_>,
) -> Result<(), Status> {
    let handle = decode_handle(raw_handle)?;
    let raw_args = copy_block_from_user::<SHARED_MEMORY_MAP_ARGS_SIZE>(process, args_address)?;
    let args = parse_shared_memory_map_args(&raw_args)?;
    validate_user_output(process, output_address, SHARED_MEMORY_MAP_OUTPUT_SIZE)?;

    let mapped_address = process
        .map_shared_memory(kernel_page_table, handle, args, frame_allocator)
        .map_err(map_shared_mapping_error)?;
    if let Err(copy_status) = copy_to_user(process, output_address, &mapped_address.to_le_bytes()) {
        return match process.unmap_shared_memory(mapped_address, args.length) {
            Ok(()) => Err(copy_status),
            Err(rollback_error) => Err(map_shared_mapping_error(rollback_error)),
        };
    }
    Ok(())
}

fn shared_memory_unmap(process: &mut Process, address: u64, length: u64) -> Result<(), Status> {
    process
        .unmap_shared_memory(address, length)
        .map_err(map_shared_mapping_error)
}

fn anonymous_map(
    process: &mut Process,
    length: u64,
    raw_protection: u64,
    output_address: u64,
    frame_allocator: &mut UsableFrameAllocator<'_>,
) -> Result<(), Status> {
    let protection_bits = u32::try_from(raw_protection).map_err(|_| Status::InvalidArgument)?;
    let protection = MapProtection::from_bits(protection_bits).ok_or(Status::InvalidArgument)?;
    validate_user_output(process, output_address, SHARED_MEMORY_MAP_OUTPUT_SIZE)?;
    let address = process
        .map_anonymous(length, protection, frame_allocator)
        .map_err(map_shared_mapping_error)?;
    if let Err(status) = copy_to_user(process, output_address, &address.to_le_bytes()) {
        process
            .unmap_anonymous(address, length, frame_allocator)
            .map_err(map_shared_mapping_error)?;
        return Err(status);
    }
    Ok(())
}

fn anonymous_unmap(
    process: &mut Process,
    address: u64,
    length: u64,
    frame_allocator: &mut UsableFrameAllocator<'_>,
) -> Result<(), Status> {
    process
        .unmap_anonymous(address, length, frame_allocator)
        .map_err(map_shared_mapping_error)
}

fn anonymous_protect(
    process: &mut Process,
    address: u64,
    length: u64,
    raw_protection: u64,
) -> Result<(), Status> {
    let bits = u32::try_from(raw_protection).map_err(|_| Status::InvalidArgument)?;
    let protection = MapProtection::from_bits(bits).ok_or(Status::InvalidArgument)?;
    process
        .protect_anonymous(address, length, protection)
        .map_err(map_shared_mapping_error)
}

fn debug_write<D: DebugSink + ?Sized>(
    process: &Process,
    address: u64,
    raw_length: u64,
    debug_sink: &mut D,
) -> Result<(), Status> {
    let length = checked_debug_length(raw_length)?;
    let mut buffer = [0_u8; DEBUG_WRITE_MAX_BYTES];
    process
        .address_space()
        .copy_from_user(&mut buffer[..length], address)
        .map_err(map_address_space_error)?;
    debug_sink.write(&buffer[..length]);
    Ok(())
}

fn filesystem_open<B: Disk>(
    process: &mut Process,
    filesystem: &mut RedoxFs<B>,
    raw_anchor: u64,
    args_address: u64,
    output_address: u64,
) -> Result<(), Status> {
    let anchor_handle = decode_handle(raw_anchor)?;
    let raw = copy_block_from_user::<FILESYSTEM_OPEN_ARGS_SIZE>(process, args_address)?;
    let path_address = read_u64(&raw, 0);
    let path_length = read_u64(&raw, 8);
    let flags =
        FilesystemOpenFlags::from_bits(read_u32(&raw, 16)).ok_or(Status::InvalidArgument)?;
    let execute = flags.contains(FilesystemOpenFlags::EXECUTE);
    if read_u32(&raw, 20) != 0
        || !flags.intersects(FilesystemOpenFlags::READ | FilesystemOpenFlags::WRITE)
        || (flags.intersects(FilesystemOpenFlags::CREATE | FilesystemOpenFlags::TRUNCATE)
            && !flags.contains(FilesystemOpenFlags::WRITE))
        || (execute
            && (!flags.contains(FilesystemOpenFlags::READ)
                || flags.intersects(
                    FilesystemOpenFlags::WRITE
                        | FilesystemOpenFlags::CREATE
                        | FilesystemOpenFlags::TRUNCATE,
                )))
    {
        return Err(Status::InvalidArgument);
    }
    validate_user_output(process, output_address, HANDLE_OUTPUT_SIZE)?;
    let path = copy_filesystem_path(process, path_address, path_length)?;
    let mut required = Rights::READ;
    if execute {
        required |= Rights::EXECUTE;
    }
    if flags.intersects(
        FilesystemOpenFlags::WRITE | FilesystemOpenFlags::CREATE | FilesystemOpenFlags::TRUNCATE,
    ) {
        required |= Rights::WRITE;
    }
    let anchor = resolve_directory_anchor(process, filesystem, anchor_handle, required)?;
    if anchor.is_root && required.contains(Rights::WRITE) && is_protected_system_path(&path) {
        return Err(Status::AccessDenied);
    }

    let mut created = false;
    let file = match filesystem.open_file_at(anchor.directory, &path) {
        Ok(file) => file,
        Err(FsError::NotFound) if flags.contains(FilesystemOpenFlags::CREATE) => {
            created = true;
            filesystem
                .create_file_at(anchor.directory, &path)
                .map_err(map_fs_error)?
        }
        Err(error) => return Err(map_fs_error(error)),
    };
    let mut rights = Rights::empty();
    if flags.contains(FilesystemOpenFlags::READ) {
        rights |= Rights::READ;
    }
    if flags.contains(FilesystemOpenFlags::WRITE) {
        rights |= Rights::WRITE;
    }
    if execute {
        rights |= Rights::EXECUTE | Rights::DUPLICATE | Rights::TRANSFER;
    }
    let handle = match process.handles_mut().filesystem_file_create(file, rights) {
        Ok(handle) => handle,
        Err(error) => {
            if created {
                let _ = remove_file_path(filesystem, anchor.directory, &path);
            }
            return Err(map_ipc_error(error));
        }
    };
    if flags.contains(FilesystemOpenFlags::TRUNCATE) {
        if let Err(error) = filesystem.truncate(file, 0) {
            close_handles(process, core::slice::from_ref(&handle));
            return Err(map_fs_error(error));
        }
    }
    let output = encode_handle_output(handle);
    if let Err(status) = copy_to_user(process, output_address, &output) {
        close_handles(process, core::slice::from_ref(&handle));
        return Err(status);
    }
    Ok(())
}

fn filesystem_read<B: Disk>(
    process: &mut Process,
    filesystem: &mut RedoxFs<B>,
    raw_file: u64,
    offset: u64,
    output_address: u64,
    raw_length: u64,
    count_address: u64,
) -> Result<(), Status> {
    let file = decode_handle(raw_file)?;
    let length = checked_array_bytes(
        raw_length,
        1,
        FILESYSTEM_READ_MAX_BYTES as u64,
        Status::OutOfRange,
    )?;
    validate_user_output(process, output_address, length)?;
    validate_user_output(process, count_address, FILESYSTEM_READ_OUTPUT_SIZE)?;
    let file = process
        .handles()
        .filesystem_file(file, Rights::READ)
        .map_err(map_ipc_error)?;
    let mut bytes = zeroed_vec(length)?;
    let count = filesystem
        .read(file, offset, &mut bytes)
        .map_err(map_fs_error)?;
    copy_to_user(process, output_address, &bytes[..count])?;
    copy_to_user(process, count_address, &(count as u64).to_le_bytes())
}

fn filesystem_write<B: Disk>(
    process: &mut Process,
    filesystem: &mut RedoxFs<B>,
    raw_file: u64,
    offset: u64,
    input_address: u64,
    raw_length: u64,
    count_address: u64,
) -> Result<(), Status> {
    let file = decode_handle(raw_file)?;
    let length = checked_array_bytes(
        raw_length,
        1,
        FILESYSTEM_READ_MAX_BYTES as u64,
        Status::OutOfRange,
    )?;
    validate_user_output(process, count_address, FILESYSTEM_READ_OUTPUT_SIZE)?;
    let file = process
        .handles()
        .filesystem_file(file, Rights::WRITE)
        .map_err(map_ipc_error)?;
    let bytes = copy_vec_from_user(process, input_address, length)?;
    let count = filesystem
        .write(file, offset, &bytes)
        .map_err(map_fs_error)?;
    copy_to_user(process, count_address, &(count as u64).to_le_bytes())
}

fn filesystem_stat<B: Disk>(
    process: &Process,
    filesystem: &mut RedoxFs<B>,
    raw_file: u64,
    output_address: u64,
) -> Result<(), Status> {
    let file = decode_handle(raw_file)?;
    validate_user_output(process, output_address, FILESYSTEM_STAT_SIZE)?;
    let file = process
        .handles()
        .filesystem_file(file, Rights::READ)
        .map_err(map_ipc_error)?;
    let info = filesystem.stat(file).map_err(map_fs_error)?;
    let mut output = [0_u8; FILESYSTEM_STAT_SIZE];
    output[..8].copy_from_slice(&info.len.to_le_bytes());
    copy_to_user(process, output_address, &output)
}

fn filesystem_read_directory<B: Disk>(
    process: &Process,
    filesystem: &mut RedoxFs<B>,
    raw_anchor: u64,
    cookie: u64,
    output_address: u64,
) -> Result<(), Status> {
    let anchor_handle = decode_handle(raw_anchor)?;
    validate_user_output(process, output_address, FILESYSTEM_DIRECTORY_ENTRY_SIZE)?;
    let anchor = resolve_directory_anchor(process, filesystem, anchor_handle, Rights::READ)?;
    let index = usize::try_from(cookie).map_err(|_| Status::OutOfRange)?;
    let entries = filesystem
        .list_directory(anchor.directory)
        .map_err(map_fs_error)?;
    let entry = entries
        .iter()
        .filter(|entry| entry.metadata.kind == NodeKind::File)
        .nth(index)
        .ok_or(Status::EndOfDirectory)?;
    let next_cookie = cookie.checked_add(1).ok_or(Status::OutOfRange)?;
    let mut output = vec![0_u8; FILESYSTEM_DIRECTORY_ENTRY_SIZE];
    put_u64(&mut output, 0, next_cookie);
    put_u64(&mut output, 8, entry.len);
    put_u16(&mut output, 16, entry.name.len() as u16);
    output[24..24 + entry.name.len()].copy_from_slice(entry.name.as_bytes());
    copy_to_user(process, output_address, &output)
}

fn filesystem_truncate<B: Disk>(
    process: &Process,
    filesystem: &mut RedoxFs<B>,
    raw_file: u64,
    length: u64,
) -> Result<(), Status> {
    let file = decode_handle(raw_file)?;
    let file = process
        .handles()
        .filesystem_file(file, Rights::WRITE)
        .map_err(map_ipc_error)?;
    filesystem.truncate(file, length).map_err(map_fs_error)
}

fn filesystem_unlink<B: Disk>(
    process: &Process,
    filesystem: &mut RedoxFs<B>,
    raw_anchor: u64,
    path_address: u64,
    path_length: u64,
) -> Result<(), Status> {
    let anchor_handle = decode_handle(raw_anchor)?;
    let path = copy_filesystem_path(process, path_address, path_length)?;
    let anchor = resolve_directory_anchor(process, filesystem, anchor_handle, Rights::WRITE)?;
    if anchor.is_root && is_protected_system_path(&path) {
        return Err(Status::AccessDenied);
    }
    remove_file_path(filesystem, anchor.directory, &path).map_err(map_fs_error)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DirectoryAnchor {
    directory: DirectoryHandle,
    rights: Rights,
    is_root: bool,
}

fn resolve_directory_anchor<B: Disk>(
    process: &Process,
    filesystem: &mut RedoxFs<B>,
    handle: Handle,
    required_rights: Rights,
) -> Result<DirectoryAnchor, Status> {
    let object_type = process
        .handles()
        .object_type(handle)
        .map_err(map_ipc_error)?;
    let rights = process
        .handles()
        .handle_rights(handle)
        .map_err(map_ipc_error)?;
    match object_type {
        ObjectType::FilesystemRoot => {
            process
                .handles()
                .filesystem_root(handle, required_rights)
                .map_err(map_ipc_error)?;
            Ok(DirectoryAnchor {
                directory: filesystem.root_directory().map_err(map_fs_error)?,
                rights,
                is_root: true,
            })
        }
        ObjectType::Directory => Ok(DirectoryAnchor {
            directory: process
                .handles()
                .filesystem_directory(handle, required_rights)
                .map_err(map_ipc_error)?,
            rights,
            is_root: false,
        }),
        _ => Err(Status::WrongObjectType),
    }
}

fn child_directory_rights(
    anchor_rights: Rights,
    is_root: bool,
    protected_system_path: bool,
) -> Rights {
    let mut namespace_rights = anchor_rights & (Rights::READ | Rights::WRITE);
    if protected_system_path {
        namespace_rights.remove(Rights::WRITE);
    }
    let delegation_rights = if is_root {
        Rights::DUPLICATE | Rights::TRANSFER
    } else {
        anchor_rights & (Rights::DUPLICATE | Rights::TRANSFER)
    };
    namespace_rights | delegation_rights
}

fn filesystem_open_directory<B: Disk>(
    process: &mut Process,
    filesystem: &mut RedoxFs<B>,
    args_address: u64,
) -> Result<(), Status> {
    let raw = copy_block_from_user::<FILESYSTEM_OPEN_DIRECTORY_ARGS_SIZE>(process, args_address)?;
    let (anchor_handle, path_address, path_length) = parse_filesystem_path_args(&raw)?;
    let output_address = read_u64(&raw, 24);
    validate_user_output(process, output_address, HANDLE_OUTPUT_SIZE)?;
    let path = copy_filesystem_path(process, path_address, path_length)?;
    let anchor = resolve_directory_anchor(process, filesystem, anchor_handle, Rights::READ)?;
    let directory = filesystem
        .open_directory_at(anchor.directory, &path)
        .map_err(map_fs_error)?;
    let protected_system_path = anchor.is_root && is_protected_system_path(&path);
    let rights = child_directory_rights(anchor.rights, anchor.is_root, protected_system_path);
    let handle = process
        .handles_mut()
        .filesystem_directory_create(directory, rights)
        .map_err(map_ipc_error)?;
    if let Err(status) = copy_to_user(process, output_address, &encode_handle_output(handle)) {
        close_handles(process, core::slice::from_ref(&handle));
        return Err(status);
    }
    Ok(())
}

fn filesystem_create_directory<B: Disk>(
    process: &Process,
    filesystem: &mut RedoxFs<B>,
    args_address: u64,
) -> Result<(), Status> {
    let raw = copy_block_from_user::<FILESYSTEM_CREATE_DIRECTORY_ARGS_SIZE>(process, args_address)?;
    let (anchor_handle, path_address, path_length) = parse_filesystem_path_args(&raw)?;
    let path = copy_filesystem_path(process, path_address, path_length)?;
    let anchor = resolve_directory_anchor(process, filesystem, anchor_handle, Rights::WRITE)?;
    if anchor.is_root && is_protected_system_path(&path) {
        return Err(Status::AccessDenied);
    }
    filesystem
        .create_directory_at(anchor.directory, &path)
        .map(|_| ())
        .map_err(map_fs_error)
}

fn filesystem_remove_directory<B: Disk>(
    process: &Process,
    filesystem: &mut RedoxFs<B>,
    args_address: u64,
) -> Result<(), Status> {
    let raw = copy_block_from_user::<FILESYSTEM_REMOVE_DIRECTORY_ARGS_SIZE>(process, args_address)?;
    let (anchor_handle, path_address, path_length) = parse_filesystem_path_args(&raw)?;
    let path = copy_filesystem_path(process, path_address, path_length)?;
    let anchor = resolve_directory_anchor(process, filesystem, anchor_handle, Rights::WRITE)?;
    if anchor.is_root && is_protected_system_path(&path) {
        return Err(Status::AccessDenied);
    }
    let (parent, name) = resolve_parent_directory(filesystem, anchor.directory, &path)?;
    filesystem
        .remove_directory_at(parent, name)
        .map_err(map_fs_error)
}

fn filesystem_rename<B: Disk>(
    process: &Process,
    filesystem: &mut RedoxFs<B>,
    args_address: u64,
) -> Result<(), Status> {
    let raw = copy_block_from_user::<FILESYSTEM_RENAME_ARGS_SIZE>(process, args_address)?;
    let args = parse_filesystem_rename_args(&raw)?;
    let source_path = copy_filesystem_path(process, args.source_address, args.source_length)?;
    let destination_path =
        copy_filesystem_path(process, args.destination_address, args.destination_length)?;
    let source = resolve_directory_anchor(process, filesystem, args.source_anchor, Rights::WRITE)?;
    let destination =
        resolve_directory_anchor(process, filesystem, args.destination_anchor, Rights::WRITE)?;
    if (source.is_root && is_protected_system_path(&source_path))
        || (destination.is_root && is_protected_system_path(&destination_path))
    {
        return Err(Status::AccessDenied);
    }
    let mode = if args.flags.contains(FilesystemRenameFlags::REPLACE) {
        RenameMode::Replace
    } else {
        RenameMode::NoReplace
    };
    filesystem
        .rename_at(
            source.directory,
            &source_path,
            destination.directory,
            &destination_path,
            mode,
        )
        .map_err(map_fs_error)
}

fn filesystem_sync<B: Disk>(
    process: &Process,
    filesystem: &mut RedoxFs<B>,
    args_address: u64,
) -> Result<(), Status> {
    let raw = copy_block_from_user::<FILESYSTEM_SYNC_ARGS_SIZE>(process, args_address)?;
    let handle = Handle::from_raw(read_u32(&raw, 0));
    if read_u32(&raw, 4) != 0 {
        return Err(Status::InvalidArgument);
    }
    match process
        .handles()
        .object_type(handle)
        .map_err(map_ipc_error)?
    {
        ObjectType::FilesystemRoot => process
            .handles()
            .filesystem_root(handle, Rights::WRITE)
            .map_err(map_ipc_error)?,
        ObjectType::Directory => {
            process
                .handles()
                .filesystem_directory(handle, Rights::WRITE)
                .map_err(map_ipc_error)?;
        }
        ObjectType::File => {
            process
                .handles()
                .filesystem_file(handle, Rights::WRITE)
                .map_err(map_ipc_error)?;
        }
        _ => return Err(Status::WrongObjectType),
    }
    filesystem.sync().map_err(map_fs_error)
}

fn filesystem_get_info<B: Disk>(
    process: &Process,
    filesystem: &mut RedoxFs<B>,
    args_address: u64,
) -> Result<(), Status> {
    let raw = copy_block_from_user::<FILESYSTEM_GET_INFO_ARGS_SIZE>(process, args_address)?;
    let anchor_handle = Handle::from_raw(read_u32(&raw, 0));
    if read_u32(&raw, 4) != 0 {
        return Err(Status::InvalidArgument);
    }
    let output_address = read_u64(&raw, 8);
    validate_user_output(process, output_address, FILESYSTEM_INFO_SIZE)?;
    resolve_directory_anchor(process, filesystem, anchor_handle, Rights::READ)?;
    let info = filesystem.filesystem_info().map_err(map_fs_error)?;
    let block_size = u32::try_from(info.block_size).map_err(|_| Status::OutOfRange)?;
    let max_name_length = u32::try_from(FILESYSTEM_NAME_MAX).map_err(|_| Status::OutOfRange)?;
    let max_path_depth = u32::try_from(MAX_TRAVERSAL_DEPTH).map_err(|_| Status::OutOfRange)?;
    let free_bytes = info.free_bytes.unwrap_or(0);
    let mut output = [0_u8; FILESYSTEM_INFO_SIZE];
    put_u64(&mut output, 0, info.capacity_bytes);
    put_u64(&mut output, 8, free_bytes);
    put_u64(&mut output, 16, free_bytes);
    put_u32(&mut output, 24, block_size);
    put_u32(&mut output, 28, max_name_length);
    put_u32(&mut output, 32, max_path_depth);
    copy_to_user(process, output_address, &output)
}

fn filesystem_get_metadata<B: Disk>(
    process: &Process,
    filesystem: &mut RedoxFs<B>,
    args_address: u64,
) -> Result<(), Status> {
    let raw = copy_block_from_user::<FILESYSTEM_GET_METADATA_ARGS_SIZE>(process, args_address)?;
    let (anchor_handle, path_address, path_length) = parse_filesystem_path_args(&raw)?;
    let output_address = read_u64(&raw, 24);
    validate_user_output(process, output_address, FILESYSTEM_METADATA_SIZE)?;
    let path = copy_filesystem_path(process, path_address, path_length)?;
    let anchor = resolve_directory_anchor(process, filesystem, anchor_handle, Rights::READ)?;
    let metadata = metadata_at(filesystem, anchor.directory, &path)?;
    let output = encode_filesystem_metadata(metadata)?;
    copy_to_user(process, output_address, &output)
}

fn filesystem_read_directory2<B: Disk>(
    process: &Process,
    filesystem: &mut RedoxFs<B>,
    args_address: u64,
) -> Result<(), Status> {
    let raw = copy_block_from_user::<FILESYSTEM_READ_DIRECTORY2_ARGS_SIZE>(process, args_address)?;
    let directory_handle = Handle::from_raw(read_u32(&raw, 0));
    if read_u32(&raw, 4) != 0 {
        return Err(Status::InvalidArgument);
    }
    let cookie = read_u64(&raw, 8);
    let output_address = read_u64(&raw, 16);
    validate_user_output(process, output_address, FILESYSTEM_DIRECTORY_ENTRY2_SIZE)?;
    let anchor = resolve_directory_anchor(process, filesystem, directory_handle, Rights::READ)?;
    let mut entries = filesystem
        .list_directory(anchor.directory)
        .map_err(map_fs_error)?;
    entries.sort_by_key(|entry| entry.metadata.identity);
    let entry = entries
        .iter()
        .find(|entry| entry.metadata.identity > cookie)
        .ok_or(Status::EndOfDirectory)?;
    let next_cookie = entry.metadata.identity;
    let mut output = [0_u8; FILESYSTEM_DIRECTORY_ENTRY2_SIZE];
    put_u64(&mut output, 0, next_cookie);
    put_u64(&mut output, 8, entry.metadata.size);
    put_u64(&mut output, 16, entry.metadata.identity);
    put_u32(&mut output, 24, filesystem_kind(entry.metadata.kind));
    put_u16(&mut output, 28, entry.name.len() as u16);
    output[36..36 + entry.name.len()].copy_from_slice(entry.name.as_bytes());
    copy_to_user(process, output_address, &output)
}

fn parse_filesystem_path_args(bytes: &[u8]) -> Result<(Handle, u64, u64), Status> {
    if bytes.len() < FILESYSTEM_CREATE_DIRECTORY_ARGS_SIZE || read_u32(bytes, 4) != 0 {
        return Err(Status::InvalidArgument);
    }
    Ok((
        Handle::from_raw(read_u32(bytes, 0)),
        read_u64(bytes, 8),
        read_u64(bytes, 16),
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ParsedFilesystemRenameArgs {
    source_anchor: Handle,
    destination_anchor: Handle,
    source_address: u64,
    source_length: u64,
    destination_address: u64,
    destination_length: u64,
    flags: FilesystemRenameFlags,
}

fn parse_filesystem_rename_args(
    bytes: &[u8; FILESYSTEM_RENAME_ARGS_SIZE],
) -> Result<ParsedFilesystemRenameArgs, Status> {
    let flags =
        FilesystemRenameFlags::from_bits(read_u32(bytes, 40)).ok_or(Status::InvalidArgument)?;
    if read_u32(bytes, 44) != 0 {
        return Err(Status::InvalidArgument);
    }
    Ok(ParsedFilesystemRenameArgs {
        source_anchor: Handle::from_raw(read_u32(bytes, 0)),
        destination_anchor: Handle::from_raw(read_u32(bytes, 4)),
        source_address: read_u64(bytes, 8),
        source_length: read_u64(bytes, 16),
        destination_address: read_u64(bytes, 24),
        destination_length: read_u64(bytes, 32),
        flags,
    })
}

fn copy_filesystem_path(
    process: &Process,
    address: u64,
    raw_length: u64,
) -> Result<String, Status> {
    let length = checked_array_bytes(
        raw_length,
        1,
        FILESYSTEM_PATH_MAX as u64,
        Status::OutOfRange,
    )?;
    if length == 0 {
        return Err(Status::InvalidArgument);
    }
    let bytes = copy_vec_from_user(process, address, length)?;
    let path = core::str::from_utf8(&bytes).map_err(|_| Status::InvalidArgument)?;
    validate_filesystem_path(path)?;
    Ok(String::from(path))
}

fn validate_filesystem_path(path: &str) -> Result<(), Status> {
    if path.is_empty()
        || path.len() > FILESYSTEM_PATH_MAX
        || path.starts_with('/')
        || path.starts_with('\\')
    {
        return Err(Status::InvalidArgument);
    }
    let mut depth = 0;
    for component in path.split('/') {
        if component.is_empty()
            || component == "."
            || component == ".."
            || component.len() > FILESYSTEM_NAME_MAX
            || component.contains(':')
            || component.contains('\\')
            || component.as_bytes().contains(&0)
        {
            return Err(Status::InvalidArgument);
        }
        depth += 1;
        if depth > MAX_TRAVERSAL_DEPTH {
            return Err(Status::OutOfRange);
        }
    }
    Ok(())
}

fn resolve_parent_directory<'a, B: Disk>(
    filesystem: &mut RedoxFs<B>,
    anchor: DirectoryHandle,
    path: &'a str,
) -> Result<(DirectoryHandle, &'a str), Status> {
    match path.rsplit_once('/') {
        Some((parent_path, name)) => Ok((
            filesystem
                .open_directory_at(anchor, parent_path)
                .map_err(map_fs_error)?,
            name,
        )),
        None => Ok((anchor, path)),
    }
}

fn remove_file_path<B: Disk>(
    filesystem: &mut RedoxFs<B>,
    anchor: DirectoryHandle,
    path: &str,
) -> Result<(), FsError> {
    let (parent, name) = match path.rsplit_once('/') {
        Some((parent_path, name)) => (filesystem.open_directory_at(anchor, parent_path)?, name),
        None => (anchor, path),
    };
    filesystem.remove_file_at(parent, name)
}

fn metadata_at<B: Disk>(
    filesystem: &mut RedoxFs<B>,
    anchor: DirectoryHandle,
    path: &str,
) -> Result<NodeMetadata, Status> {
    match filesystem.open_file_at(anchor, path) {
        Ok(file) => filesystem.file_metadata(file).map_err(map_fs_error),
        Err(FsError::IsDirectory) => {
            let directory = filesystem
                .open_directory_at(anchor, path)
                .map_err(map_fs_error)?;
            filesystem
                .directory_metadata(directory)
                .map_err(map_fs_error)
        }
        Err(error) => Err(map_fs_error(error)),
    }
}

fn encode_filesystem_metadata(
    metadata: NodeMetadata,
) -> Result<[u8; FILESYSTEM_METADATA_SIZE], Status> {
    let ctime_ns = timestamp_ns(metadata.ctime.seconds, metadata.ctime.nanoseconds)?;
    let mtime_ns = timestamp_ns(metadata.mtime.seconds, metadata.mtime.nanoseconds)?;
    let mut output = [0_u8; FILESYSTEM_METADATA_SIZE];
    put_u32(&mut output, 0, filesystem_kind(metadata.kind));
    put_u32(&mut output, 4, u32::from(metadata.mode));
    put_u64(&mut output, 8, metadata.size);
    put_u64(&mut output, 16, metadata.identity);
    put_u64(&mut output, 24, ctime_ns);
    put_u64(&mut output, 32, mtime_ns);
    put_u32(&mut output, 40, metadata.uid);
    put_u32(&mut output, 44, metadata.gid);
    put_u32(&mut output, 48, metadata.policy);
    Ok(output)
}

fn timestamp_ns(seconds: u64, nanoseconds: u32) -> Result<u64, Status> {
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(u64::from(nanoseconds)))
        .ok_or(Status::OutOfRange)
}

const fn filesystem_kind(kind: NodeKind) -> u32 {
    match kind {
        NodeKind::File => 1,
        NodeKind::Directory => 2,
    }
}

fn is_protected_system_path(path: &str) -> bool {
    path.split('/').next().is_some_and(is_protected_system_file)
}

fn is_protected_system_file(name: &str) -> bool {
    name == "system"
        || name == "desktop.elf"
        || name == "minimal-client.elf"
        || name == "file-navigator.elf"
        || name == "text-editor.elf"
        || name == "terminal.elf"
        || name == "programs.gkr"
        || name == "system.log"
        || name == "console"
        || name == "input"
}

const fn map_fs_error(error: FsError) -> Status {
    match error {
        FsError::InvalidName => Status::InvalidArgument,
        FsError::TraversalTooDeep => Status::OutOfRange,
        FsError::AlreadyExists => Status::AlreadyExists,
        FsError::NotFound => Status::NotFound,
        FsError::NoSpace => Status::OutOfMemory,
        FsError::InvalidHandle => Status::InvalidHandle,
        FsError::NotDirectory => Status::NotDirectory,
        FsError::IsDirectory => Status::IsDirectory,
        FsError::DirectoryNotEmpty => Status::DirectoryNotEmpty,
        FsError::WouldCycle => Status::InvalidArgument,
        FsError::OffsetOverflow => Status::OutOfRange,
        FsError::Io => Status::Io,
    }
}

fn audio_write(
    process: &Process,
    audio: &mut Option<AudioDevice>,
    address: u64,
    raw_length: u64,
) -> Result<(), Status> {
    let length = checked_array_bytes(
        raw_length,
        1,
        AUDIO_WRITE_MAX_BYTES as u64,
        Status::OutOfRange,
    )?;
    if length == 0 || length % 4 != 0 {
        return Err(Status::InvalidArgument);
    }
    let device = audio.as_mut().ok_or(Status::NotFound)?;
    if device.available_bytes() < length {
        return Err(Status::ShouldWait);
    }
    let bytes = copy_vec_from_user(process, address, length)?;
    match device.write_pcm(&bytes) {
        Ok(accepted) if accepted == length => Ok(()),
        Ok(_) => Err(Status::ShouldWait),
        Err(_) => Err(Status::Io),
    }
}

fn process_create<B: Disk>(
    process: &mut Process,
    filesystem: &mut RedoxFs<B>,
    args_address: u64,
    kernel_page_table: &ActivePageTable,
    frame_allocator: &mut UsableFrameAllocator<'_>,
    entropy: &mut EntropyPool,
    child_slot_reserved: bool,
) -> Result<Box<Process>, Status> {
    if !child_slot_reserved {
        return Err(Status::ResourceLimit);
    }
    let raw = copy_block_from_user::<PROCESS_CREATE_ARGS_SIZE>(process, args_address)?;
    let executable = Handle::from_raw(read_u32(&raw, 0));
    if read_u32(&raw, 4) != 0 {
        return Err(Status::InvalidArgument);
    }
    let args_address = read_u64(&raw, 8);
    let args_length = bounded_startup_length(read_u64(&raw, 16))?;
    let dispositions_address = read_u64(&raw, 24);
    let disposition_count = checked_array_bytes(
        read_u64(&raw, 32),
        1,
        PROCESS_MAX_STARTUP_HANDLES as u64,
        Status::ResourceLimit,
    )?;
    let config_address = read_u64(&raw, 40);
    let config_length = bounded_startup_length(read_u64(&raw, 48))?;
    let output_address = read_u64(&raw, 56);
    if args_length
        .checked_add(config_length)
        .is_none_or(|length| length > PROCESS_MAX_STARTUP_BYTES)
    {
        return Err(Status::ResourceLimit);
    }
    validate_user_output(process, output_address, HANDLE_OUTPUT_SIZE)?;

    let args = copy_vec_from_user(process, args_address, args_length)?;
    let config = copy_vec_from_user(process, config_address, config_length)?;
    let disposition_bytes = checked_array_bytes(
        disposition_count as u64,
        HANDLE_DISPOSITION_SIZE,
        PROCESS_MAX_STARTUP_HANDLES as u64,
        Status::ResourceLimit,
    )?;
    let raw_dispositions = copy_vec_from_user(process, dispositions_address, disposition_bytes)?;
    let mut dispositions = Vec::new();
    dispositions
        .try_reserve_exact(disposition_count)
        .map_err(|_| Status::OutOfMemory)?;
    for raw in raw_dispositions.chunks_exact(HANDLE_DISPOSITION_SIZE) {
        dispositions.push(parse_handle_disposition(raw)?);
    }
    let application_data_index = application_data_disposition_index(&dispositions, |handle| {
        process.handles().object_type(handle)
    })?;
    let mut startup = DirectStartupBlock::new(&args, &config, disposition_count)?;

    let file = process
        .handles()
        .filesystem_file(executable, Rights::EXECUTE)
        .map_err(map_ipc_error)?;
    let executable_length = usize::try_from(filesystem.stat(file).map_err(map_fs_error)?.len)
        .map_err(|_| Status::ResourceLimit)?;
    if executable_length == 0 || executable_length > MAX_EXECUTABLE_BYTES {
        return Err(Status::ResourceLimit);
    }
    let mut image = zeroed_vec(executable_length)?;
    if filesystem.read(file, 0, &mut image).map_err(map_fs_error)? != executable_length {
        return Err(Status::Io);
    }

    let mut child_storage = Box::<Process>::try_new_uninit().map_err(|_| Status::OutOfMemory)?;
    let randomness = [entropy.next_u64(), entropy.next_u64(), entropy.next_u64()];
    unsafe { kernel_page_table.activate() };
    let child =
        Process::from_elf_randomized(&image, kernel_page_table, frame_allocator, randomness);
    unsafe { process.address_space().activate() };
    let child = child.map_err(map_process_create_error)?;
    child_storage.write(child);
    let mut child = unsafe { child_storage.assume_init() };
    let (process_handle, control) = match process.handles_mut().process_create() {
        Ok(created) => created,
        Err(error) => {
            reclaim_unstarted_process(*child, frame_allocator);
            return Err(map_ipc_error(error));
        }
    };
    child.attach_control(control);

    let child_handles = match handle_transfer_batch_between(
        process.handles_mut(),
        child.handles_mut(),
        &dispositions,
    ) {
        Ok(handles) => handles,
        Err(error) => {
            let _ = process.handles_mut().handle_close(process_handle);
            reclaim_unstarted_process(*child, frame_allocator);
            return Err(map_ipc_error(error));
        }
    };
    if let Some(index) = application_data_index {
        child
            .set_application_data(child_handles[index])
            .expect("prevalidated application-data disposition changed type after commit");
    }
    startup.set_handles(&child_handles);

    // All fallible allocation, parsing, range validation, and handle reservation
    // completed before the atomic transfer. These active-address-space copies are
    // therefore invariant checks rather than recoverable post-commit failures.
    unsafe { child.address_space().activate() };
    child
        .install_direct_startup(&startup)
        .expect("validated child stack startup copy failed after handle commit");
    unsafe { process.address_space().activate() };
    copy_to_user(
        process,
        output_address,
        &encode_handle_output(process_handle),
    )
    .expect("validated process-create output failed after handle commit");
    Ok(child)
}

fn application_data_disposition_index<F>(
    dispositions: &[HandleOperationDisposition],
    mut object_type: F,
) -> Result<Option<usize>, Status>
where
    F: FnMut(Handle) -> Result<ObjectType, IpcError>,
{
    let mut application_data = None;
    for (index, disposition) in dispositions.iter().enumerate() {
        if object_type(disposition.handle).map_err(map_ipc_error)? != ObjectType::ApplicationData {
            continue;
        }
        if application_data.is_some() {
            return Err(Status::InvalidArgument);
        }
        let allowed = Rights::READ | Rights::WRITE;
        if !disposition.rights.contains(Rights::READ)
            || !allowed.contains(disposition.rights)
            || disposition.rights.contains(Rights::TRANSFER)
        {
            return Err(Status::InvalidRights);
        }
        application_data = Some(index);
    }
    Ok(application_data)
}

fn process_get_info(
    process: &Process,
    raw_process: u64,
    output_address: u64,
) -> Result<(), Status> {
    let handle = decode_handle(raw_process)?;
    validate_user_output(process, output_address, PROCESS_INFO_SIZE)?;
    let info = process
        .handles()
        .process_info(handle)
        .map_err(map_ipc_error)?;
    let mut output = [0_u8; PROCESS_INFO_SIZE];
    put_u32(&mut output, 0, info.state);
    put_u32(&mut output, 4, info.cause);
    output[8..12].copy_from_slice(&info.exit_code.to_le_bytes());
    put_u32(&mut output, 12, info.fault);
    output[16..24].copy_from_slice(&info.fault_code.to_le_bytes());
    output[24..32].copy_from_slice(&info.fault_address.to_le_bytes());
    copy_to_user(process, output_address, &output)
}

fn process_terminate(process: &Process, raw_process: u64) -> Result<(), Status> {
    let handle = decode_handle(raw_process)?;
    process
        .handles()
        .process_terminate(handle)
        .map_err(map_ipc_error)
}

fn system_power_request(
    process: &Process,
    raw_power: u64,
    raw_action: u64,
    raw_flags: u64,
    now_ns: u64,
) -> Result<(), Status> {
    let power = decode_handle(raw_power)?;
    let action = u32::try_from(raw_action)
        .ok()
        .and_then(SystemPowerAction::from_raw)
        .ok_or(Status::InvalidArgument)?;
    let raw_flags = u32::try_from(raw_flags).map_err(|_| Status::InvalidArgument)?;
    let flags = SystemPowerFlags::from_bits(raw_flags).ok_or(Status::InvalidArgument)?;
    let deadline_ns = now_ns.saturating_add(SYSTEM_POWER_CANCELLATION_NS);
    process
        .handles()
        .system_power_request(power, action, flags, deadline_ns)
        .map_err(map_ipc_error)
}

fn system_power_cancel(process: &Process, raw_power: u64) -> Result<(), Status> {
    let power = decode_handle(raw_power)?;
    process
        .handles()
        .system_power_cancel(power)
        .map_err(map_ipc_error)
}

fn system_power_get_info(
    process: &Process,
    raw_power: u64,
    output_address: u64,
) -> Result<(), Status> {
    let power = decode_handle(raw_power)?;
    validate_user_output(process, output_address, SYSTEM_POWER_INFO_SIZE)?;
    let info = process
        .handles()
        .system_power_info(power)
        .map_err(map_ipc_error)?;
    let mut output = [0_u8; SYSTEM_POWER_INFO_SIZE];
    put_u32(&mut output, 0, info.state);
    put_u32(&mut output, 4, info.action);
    put_u32(&mut output, 8, info.flags);
    output[12..16].copy_from_slice(&info.failure_status.to_le_bytes());
    output[16..24].copy_from_slice(&info.sequence.to_le_bytes());
    output[24..32].copy_from_slice(&info.deadline_ns.to_le_bytes());
    copy_to_user(process, output_address, &output)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ApplicationDataCreateRequest {
    root: Handle,
    app_id_address: u64,
    app_id_length: usize,
    output_address: u64,
}

fn parse_application_data_create_args(
    raw: &[u8; APPLICATION_DATA_CREATE_ARGS_SIZE],
) -> Result<ApplicationDataCreateRequest, Status> {
    if read_u32(raw, 4) != 0 {
        return Err(Status::InvalidArgument);
    }
    Ok(ApplicationDataCreateRequest {
        root: Handle::from_raw(read_u32(raw, 0)),
        app_id_address: read_u64(raw, 8),
        app_id_length: checked_array_bytes(
            read_u64(raw, 16),
            1,
            APPLICATION_DATA_MAX_APP_ID_LEN as u64,
            Status::InvalidArgument,
        )?,
        output_address: read_u64(raw, 24),
    })
}

fn require_application_data_installation_authority(
    handles: &HandleTable,
    root: Handle,
) -> Result<(), Status> {
    handles
        .filesystem_root(root, Rights::WRITE | Rights::EXECUTE)
        .map_err(map_ipc_error)
}

fn application_data_create<B: Disk>(
    process: &mut Process,
    filesystem: &mut RedoxFs<B>,
    args_address: u64,
) -> Result<(), Status> {
    let raw = copy_block_from_user::<APPLICATION_DATA_CREATE_ARGS_SIZE>(process, args_address)?;
    let request = parse_application_data_create_args(&raw)?;
    validate_user_output(process, request.output_address, HANDLE_OUTPUT_SIZE)?;
    require_application_data_installation_authority(process.handles(), request.root)?;
    let app_id_bytes = copy_vec_from_user(process, request.app_id_address, request.app_id_length)?;
    let app_id = core::str::from_utf8(&app_id_bytes).map_err(|_| Status::InvalidArgument)?;

    let handle = process
        .handles_mut()
        .application_data_create(app_id)
        .map_err(map_ipc_error)?;
    let result = (|| {
        let scope = process
            .handles()
            .application_data_scope(handle, Rights::READ)
            .map_err(map_ipc_error)?;
        ensure_application_data_directory(filesystem, scope.app_id())?;
        copy_to_user(
            process,
            request.output_address,
            &encode_handle_output(handle),
        )
    })();
    if let Err(status) = result {
        close_handles(process, core::slice::from_ref(&handle));
        return Err(status);
    }
    Ok(())
}

fn application_get_data_directory<B: Disk>(
    process: &mut Process,
    filesystem: &mut RedoxFs<B>,
    output_address: u64,
) -> Result<(), Status> {
    let identity = process.application_data().ok_or(Status::NotFound)?;
    validate_user_output(process, output_address, HANDLE_OUTPUT_SIZE)?;
    let scope = process
        .handles()
        .application_data_scope(identity, Rights::READ)
        .map_err(map_ipc_error)?;
    let directory = open_application_data_directory(filesystem, scope.app_id())?;
    let handle = process
        .handles_mut()
        .filesystem_directory_create(directory, Rights::READ | Rights::WRITE)
        .map_err(map_ipc_error)?;
    if let Err(status) = copy_to_user(process, output_address, &encode_handle_output(handle)) {
        close_handles(process, core::slice::from_ref(&handle));
        return Err(status);
    }
    Ok(())
}

fn ensure_application_data_directory<B: Disk>(
    filesystem: &mut RedoxFs<B>,
    app_id: &str,
) -> Result<DirectoryHandle, Status> {
    let root = filesystem.root_directory().map_err(map_fs_error)?;
    let appdata = match filesystem.open_directory_at(root, "appdata") {
        Ok(directory) => directory,
        Err(FsError::NotFound) => filesystem
            .create_directory_at(root, "appdata")
            .map_err(map_fs_error)?,
        Err(error) => return Err(map_fs_error(error)),
    };
    match filesystem.open_directory_at(appdata, app_id) {
        Ok(directory) => Ok(directory),
        Err(FsError::NotFound) => filesystem
            .create_directory_at(appdata, app_id)
            .map_err(map_fs_error),
        Err(error) => Err(map_fs_error(error)),
    }
}

fn open_application_data_directory<B: Disk>(
    filesystem: &mut RedoxFs<B>,
    app_id: &str,
) -> Result<DirectoryHandle, Status> {
    let root = filesystem.root_directory().map_err(map_fs_error)?;
    let appdata = filesystem
        .open_directory_at(root, "appdata")
        .map_err(map_fs_error)?;
    filesystem
        .open_directory_at(appdata, app_id)
        .map_err(map_fs_error)
}

fn bounded_startup_length(raw: u64) -> Result<usize, Status> {
    checked_array_bytes(
        raw,
        1,
        PROCESS_MAX_STARTUP_BYTES as u64,
        Status::ResourceLimit,
    )
}

fn reclaim_unstarted_process(process: Process, frame_allocator: &mut UsableFrameAllocator<'_>) {
    let retired = process
        .retire()
        .expect("unstarted child address space unexpectedly active");
    retired
        .reclaim(frame_allocator)
        .expect("failed to reclaim unstarted child process");
}

const fn map_process_create_error(error: ProcessCreateError) -> Status {
    match error {
        ProcessCreateError::ResourceLimit => Status::ResourceLimit,
        ProcessCreateError::AddressSpace(AddressSpaceError::OutOfFrames)
        | ProcessCreateError::AddressSpace(AddressSpaceError::FrameAllocator(_))
        | ProcessCreateError::StackPage {
            error: AddressSpaceError::OutOfFrames,
            ..
        }
        | ProcessCreateError::StackPage {
            error: AddressSpaceError::FrameAllocator(_),
            ..
        } => Status::OutOfMemory,
        ProcessCreateError::AddressSpace(_)
        | ProcessCreateError::Elf(_)
        | ProcessCreateError::ElfPage(_)
        | ProcessCreateError::StackCollision
        | ProcessCreateError::StackPage { .. }
        | ProcessCreateError::EntryNotExecutable(_)
        | ProcessCreateError::StackNotWritable(_) => Status::InvalidArgument,
    }
}

fn copy_block_from_user<const N: usize>(
    process: &Process,
    address: u64,
) -> Result<[u8; N], Status> {
    let mut bytes = [0_u8; N];
    process
        .address_space()
        .copy_from_user(&mut bytes, address)
        .map_err(map_address_space_error)?;
    Ok(bytes)
}

fn copy_vec_from_user(process: &Process, address: u64, length: usize) -> Result<Vec<u8>, Status> {
    let mut bytes = zeroed_vec(length)?;
    process
        .address_space()
        .copy_from_user(&mut bytes, address)
        .map_err(map_address_space_error)?;
    Ok(bytes)
}

fn copy_to_user(process: &Process, address: u64, bytes: &[u8]) -> Result<(), Status> {
    process
        .address_space()
        .copy_to_user(address, bytes)
        .map_err(map_address_space_error)
}

fn validate_user_output(process: &Process, address: u64, length: usize) -> Result<(), Status> {
    process
        .address_space()
        .validate_user_range(address, length, UserAccess::Write)
        .map_err(map_address_space_error)
}

fn zeroed_vec(length: usize) -> Result<Vec<u8>, Status> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| Status::OutOfMemory)?;
    bytes.resize(length, 0);
    Ok(bytes)
}

fn checked_array_bytes(
    count: u64,
    element_size: usize,
    maximum_count: u64,
    too_many: Status,
) -> Result<usize, Status> {
    if count > maximum_count {
        return Err(too_many);
    }
    let count = usize::try_from(count).map_err(|_| Status::OutOfRange)?;
    count.checked_mul(element_size).ok_or(Status::OutOfRange)
}

fn checked_debug_length(raw_length: u64) -> Result<usize, Status> {
    checked_array_bytes(
        raw_length,
        1,
        DEBUG_WRITE_MAX_BYTES as u64,
        Status::OutOfRange,
    )
}

fn decode_handle(raw: u64) -> Result<Handle, Status> {
    let raw = u32::try_from(raw).map_err(|_| Status::InvalidHandle)?;
    Ok(Handle::from_raw(raw))
}

fn decode_rights_u64(raw: u64) -> Result<Rights, Status> {
    let raw = u32::try_from(raw).map_err(|_| Status::InvalidRights)?;
    decode_rights(raw)
}

fn decode_rights(raw: u32) -> Result<Rights, Status> {
    Rights::from_bits(raw).ok_or(Status::InvalidRights)
}

fn decode_signals(raw: u32) -> Result<Signals, Status> {
    Signals::from_bits(raw).ok_or(Status::InvalidArgument)
}

fn parse_wait_item(raw: &[u8]) -> Result<WaitItem, Status> {
    if raw.len() != WAIT_ITEM_SIZE {
        return Err(Status::InvalidArgument);
    }
    Ok(WaitItem {
        handle: Handle::from_raw(read_u32(raw, 0)),
        wait_for: decode_signals(read_u32(raw, 4))?,
        pending: decode_signals(read_u32(raw, 8))?,
    })
}

fn parse_handle_disposition(raw: &[u8]) -> Result<HandleOperationDisposition, Status> {
    if raw.len() != HANDLE_DISPOSITION_SIZE {
        return Err(Status::InvalidArgument);
    }
    let handle = Handle::from_raw(read_u32(raw, 0));
    let operation = match read_u32(raw, 4) {
        0 => HandleOperation::Move,
        1 => HandleOperation::Duplicate,
        _ => return Err(Status::InvalidArgument),
    };
    let rights = decode_rights(read_u32(raw, 8))?;
    if read_u32(raw, 12) != 0 {
        return Err(Status::InvalidArgument);
    }
    Ok(HandleOperationDisposition {
        handle,
        operation,
        rights,
    })
}

fn parse_shared_memory_map_args(
    raw: &[u8; SHARED_MEMORY_MAP_ARGS_SIZE],
) -> Result<SharedMemoryMapArgs, Status> {
    let protection = MapProtection::from_bits(read_u32(raw, 24)).ok_or(Status::InvalidArgument)?;
    let flags = MapFlags::from_bits(read_u32(raw, 28)).ok_or(Status::InvalidArgument)?;
    Ok(SharedMemoryMapArgs {
        address: read_u64(raw, 0),
        offset: read_u64(raw, 8),
        length: read_u64(raw, 16),
        protection,
        flags,
    })
}

fn encode_handle_output(handle: Handle) -> [u8; HANDLE_OUTPUT_SIZE] {
    let mut output = [0_u8; HANDLE_OUTPUT_SIZE];
    put_u32(&mut output, 0, handle.raw());
    output
}

fn encode_channel_create_output(first: Handle, second: Handle) -> [u8; CHANNEL_CREATE_OUTPUT_SIZE] {
    let mut output = [0_u8; CHANNEL_CREATE_OUTPUT_SIZE];
    put_u32(&mut output, 0, first.raw());
    put_u32(&mut output, 4, second.raw());
    output
}

fn encode_channel_read_output(info: MessageInfo) -> [u8; CHANNEL_READ_OUTPUT_SIZE] {
    let mut output = [0_u8; CHANNEL_READ_OUTPUT_SIZE];
    put_u32(&mut output, 0, info.byte_count);
    put_u16(&mut output, 4, info.handle_count);
    put_u16(&mut output, 6, 0);
    output
}

fn encode_wait_items_into(items: &[WaitItem], output: &mut [u8]) {
    assert_eq!(
        output.len(),
        items.len() * WAIT_ITEM_SIZE,
        "wait-many encoding storage has the wrong length"
    );
    for (index, item) in items.iter().enumerate() {
        let offset = index * WAIT_ITEM_SIZE;
        put_u32(output, offset, item.handle.raw());
        put_u32(output, offset + 4, item.wait_for.bits());
        put_u32(output, offset + 8, item.pending.bits());
    }
}

fn fill_received_handle_metadata(
    process: &Process,
    handles: &[Handle],
    output: &mut [u8],
) -> Result<(), Status> {
    fill_received_handle_metadata_with(handles, output, |handle| {
        let rights = process.handles().handle_rights(handle).map_err(|_| ())?;
        let object_type = process.handles().object_type(handle).map_err(|_| ())?;
        Ok((rights, object_type))
    })
}

fn fill_received_handle_metadata_with<F>(
    handles: &[Handle],
    output: &mut [u8],
    mut metadata_for: F,
) -> Result<(), Status>
where
    F: FnMut(Handle) -> Result<(Rights, ObjectType), ()>,
{
    let expected_length = handles
        .len()
        .checked_mul(RECEIVED_HANDLE_SIZE)
        .ok_or(Status::InvalidMessage)?;
    if output.len() != expected_length {
        return Err(Status::InvalidMessage);
    }

    for (handle, record) in handles
        .iter()
        .copied()
        .zip(output.chunks_exact_mut(RECEIVED_HANDLE_SIZE))
    {
        // channel_read just installed these handles, so both lookups are
        // logically infallible. Treat a failure as handle-table corruption and
        // let the caller close every installed handle.
        let (rights, object_type) = metadata_for(handle).map_err(|()| Status::InvalidMessage)?;
        put_u32(record, 0, handle.raw());
        put_u32(record, 4, rights.bits());
        put_u32(record, 8, object_type as u32);
        put_u32(record, 12, 0);
    }
    Ok(())
}

fn close_handles(process: &mut Process, handles: &[Handle]) {
    for handle in handles.iter().copied().filter(|handle| handle.is_valid()) {
        let _ = process.handles_mut().handle_close(handle);
    }
}

const fn map_ipc_error(error: IpcError) -> Status {
    error.status()
}

const fn map_map_error(error: MapError) -> Status {
    match error {
        MapError::AlreadyMapped => Status::AlreadyMapped,
        MapError::OutOfFrames | MapError::FrameAllocator(_) => Status::OutOfMemory,
        MapError::AddressOverflow => Status::OutOfRange,
        MapError::InvalidHhdmOffset
        | MapError::CorruptPageTable
        | MapError::ParentPermissionConflict
        | MapError::HugePageConflict => Status::InvalidAddress,
    }
}

const fn map_address_space_error(error: AddressSpaceError) -> Status {
    match error {
        AddressSpaceError::AlreadyMapped(_) => Status::AlreadyMapped,
        AddressSpaceError::PermissionDenied { .. } => Status::AccessDenied,
        AddressSpaceError::OutOfFrames | AddressSpaceError::FrameAllocator(_) => {
            Status::OutOfMemory
        }
        AddressSpaceError::InvalidRangeLength(_) | AddressSpaceError::WritableExecutable => {
            Status::InvalidArgument
        }
        AddressSpaceError::KernelPageTable(error) => map_map_error(error),
        AddressSpaceError::AddressOverflow
        | AddressSpaceError::InvalidHhdmOffset
        | AddressSpaceError::NonCanonicalAddress(_)
        | AddressSpaceError::HigherHalfAddress(_)
        | AddressSpaceError::ZeroPage
        | AddressSpaceError::UnalignedAddress(_)
        | AddressSpaceError::NotMapped(_)
        | AddressSpaceError::CorruptPageTable
        | AddressSpaceError::HugePageConflict
        | AddressSpaceError::FrameAlreadyOwned(_)
        | AddressSpaceError::DuplicateSharedAlias(_)
        | AddressSpaceError::MappedFrameNotOwned(_)
        | AddressSpaceError::UntrackedMapping(_)
        | AddressSpaceError::ActiveAddressSpaceRequired
        | AddressSpaceError::UserCopyFault
        | AddressSpaceError::ActiveKernelPageTableRequired
        | AddressSpaceError::UserAccessibleKernelP4Entry(_) => Status::InvalidAddress,
    }
}

const fn map_shared_mapping_error(error: SharedMappingError) -> Status {
    match error {
        SharedMappingError::Ipc(error) => map_ipc_error(error),
        SharedMappingError::InvalidProtection(_)
        | SharedMappingError::UnsupportedFlags(_)
        | SharedMappingError::UnalignedOffset(_)
        | SharedMappingError::ZeroLength => Status::InvalidArgument,
        SharedMappingError::RangeOverflow | SharedMappingError::RangeOutsideObject { .. } => {
            Status::OutOfRange
        }
        SharedMappingError::OutOfMemory | SharedMappingError::NoAddressSpace => Status::OutOfMemory,
        SharedMappingError::ResourceLimit => Status::ResourceLimit,
        SharedMappingError::AlreadyMapped(_) => Status::AlreadyMapped,
        SharedMappingError::AddressSpace(error) => map_address_space_error(error),
        SharedMappingError::RollbackFailed {
            mapping_error,
            rollback_error: _,
        } => map_address_space_error(mapping_error),
        SharedMappingError::InvalidBackingAlignment(_)
        | SharedMappingError::InvalidBackingLength
        | SharedMappingError::InvalidKernelAddress(_)
        | SharedMappingError::KernelAddressNotMapped(_)
        | SharedMappingError::PhysicalAddressNotPageAligned(_)
        | SharedMappingError::UnalignedFixedAddress(_)
        | SharedMappingError::InvalidFixedAddress(_)
        | SharedMappingError::ExactMappingNotFound { .. } => Status::InvalidAddress,
    }
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

fn read_i64(bytes: &[u8], offset: usize) -> i64 {
    i64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + size_of::<u16>()].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + size_of::<u32>()].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + size_of::<u64>()].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syscall_number_decode_is_total_for_the_current_abi() {
        let expected = [
            SyscallNumber::ProcessYield,
            SyscallNumber::ProcessExit,
            SyscallNumber::HandleClose,
            SyscallNumber::HandleDuplicate,
            SyscallNumber::WaitMany,
            SyscallNumber::ChannelCreate,
            SyscallNumber::ChannelWrite,
            SyscallNumber::ChannelRead,
            SyscallNumber::SharedMemoryCreate,
            SyscallNumber::SharedMemoryGetSize,
            SyscallNumber::SharedMemoryMap,
            SyscallNumber::SharedMemoryUnmap,
            SyscallNumber::DebugWrite,
            SyscallNumber::FilesystemOpen,
            SyscallNumber::FilesystemRead,
            SyscallNumber::FilesystemWrite,
            SyscallNumber::FilesystemStat,
            SyscallNumber::FilesystemReadDirectory,
            SyscallNumber::FilesystemTruncate,
            SyscallNumber::FilesystemUnlink,
            SyscallNumber::AudioWrite,
            SyscallNumber::ClockGetMonotonic,
            SyscallNumber::RandomFill,
            SyscallNumber::ProcessCreate,
            SyscallNumber::ProcessGetInfo,
            SyscallNumber::ProcessTerminate,
            SyscallNumber::ApplicationGetDataDirectory,
            SyscallNumber::FilesystemOpenDirectory,
            SyscallNumber::FilesystemCreateDirectory,
            SyscallNumber::FilesystemRemoveDirectory,
            SyscallNumber::FilesystemRename,
            SyscallNumber::FilesystemSync,
            SyscallNumber::FilesystemGetInfo,
            SyscallNumber::FilesystemGetMetadata,
            SyscallNumber::FilesystemReadDirectory2,
            SyscallNumber::ApplicationDataCreate,
            SyscallNumber::SystemPowerRequest,
            SyscallNumber::SystemPowerCancel,
            SyscallNumber::SystemPowerGetInfo,
            SyscallNumber::AnonymousMap,
            SyscallNumber::AnonymousUnmap,
            SyscallNumber::AnonymousProtect,
        ];
        for number in expected {
            assert_eq!(decode_syscall_number(number as u64), Some(number));
        }
        assert_eq!(
            decode_syscall_number(21),
            Some(SyscallNumber::ClockGetMonotonic)
        );
        assert_eq!(decode_syscall_number(22), Some(SyscallNumber::RandomFill));
        assert_eq!(
            decode_syscall_number(23),
            Some(SyscallNumber::ProcessCreate)
        );
        assert_eq!(
            decode_syscall_number(26),
            Some(SyscallNumber::ApplicationGetDataDirectory)
        );
        assert_eq!(
            decode_syscall_number(27),
            Some(SyscallNumber::FilesystemOpenDirectory)
        );
        assert_eq!(
            decode_syscall_number(34),
            Some(SyscallNumber::FilesystemReadDirectory2)
        );
        assert_eq!(
            decode_syscall_number(35),
            Some(SyscallNumber::ApplicationDataCreate)
        );
        assert_eq!(
            decode_syscall_number(38),
            Some(SyscallNumber::SystemPowerGetInfo)
        );
        assert_eq!(decode_syscall_number(39), Some(SyscallNumber::AnonymousMap));
        assert_eq!(
            decode_syscall_number(40),
            Some(SyscallNumber::AnonymousUnmap)
        );
        assert_eq!(
            decode_syscall_number(41),
            Some(SyscallNumber::AnonymousProtect)
        );
        assert_eq!(decode_syscall_number(42), None);
        assert_eq!(decode_syscall_number(u64::MAX), None);
    }

    #[test]
    fn wait_resolution_prefers_readiness_then_uses_inclusive_deadlines() {
        assert_eq!(
            resolve_wait_completion(Some(3), WaitDeadline::At(10), 10),
            Some(WaitManyCompletion::Ready(3))
        );
        assert_eq!(resolve_wait_completion(None, WaitDeadline::At(10), 9), None);
        assert_eq!(
            resolve_wait_completion(None, WaitDeadline::At(10), 10),
            Some(WaitManyCompletion::Failed(Status::TimedOut))
        );
        assert_eq!(
            resolve_wait_completion(None, WaitDeadline::Infinite, u64::MAX),
            None
        );
    }

    #[test]
    fn wait_item_encoding_updates_complete_fixed_layout_records() {
        let items = [WaitItem {
            handle: Handle::from_raw(0x1122_3344),
            wait_for: Signals::READABLE | Signals::PEER_CLOSED,
            pending: Signals::PEER_CLOSED,
        }];
        let mut output = [0_u8; WAIT_ITEM_SIZE];
        encode_wait_items_into(&items, &mut output);

        assert_eq!(read_u32(&output, 0), 0x1122_3344);
        assert_eq!(
            read_u32(&output, 4),
            (Signals::READABLE | Signals::PEER_CLOSED).bits()
        );
        assert_eq!(read_u32(&output, 8), Signals::PEER_CLOSED.bits());
    }

    #[test]
    fn application_data_create_parser_validates_layout_reserved_and_bounds() {
        let mut raw = [0_u8; APPLICATION_DATA_CREATE_ARGS_SIZE];
        put_u32(&mut raw, 0, 7);
        raw[8..16].copy_from_slice(&0x1000_u64.to_le_bytes());
        raw[16..24].copy_from_slice(&12_u64.to_le_bytes());
        raw[24..32].copy_from_slice(&0x2000_u64.to_le_bytes());
        assert_eq!(
            parse_application_data_create_args(&raw),
            Ok(ApplicationDataCreateRequest {
                root: Handle::from_raw(7),
                app_id_address: 0x1000,
                app_id_length: 12,
                output_address: 0x2000,
            })
        );

        put_u32(&mut raw, 4, 1);
        assert_eq!(
            parse_application_data_create_args(&raw),
            Err(Status::InvalidArgument)
        );
        put_u32(&mut raw, 4, 0);
        raw[16..24].copy_from_slice(&((APPLICATION_DATA_MAX_APP_ID_LEN + 1) as u64).to_le_bytes());
        assert_eq!(
            parse_application_data_create_args(&raw),
            Err(Status::InvalidArgument)
        );
    }

    #[test]
    fn application_data_create_requires_write_execute_root_authority() {
        let mut handles = HandleTable::new();
        let installer = handles
            .filesystem_root_create_with_rights(Rights::WRITE | Rights::EXECUTE)
            .unwrap();
        let ordinary = handles.filesystem_root_create().unwrap();
        let application_data = handles.application_data_create("example.editor").unwrap();

        assert_eq!(
            require_application_data_installation_authority(&handles, installer),
            Ok(())
        );
        assert_eq!(
            require_application_data_installation_authority(&handles, ordinary),
            Err(Status::AccessDenied)
        );
        assert_eq!(
            require_application_data_installation_authority(&handles, application_data),
            Err(Status::AccessDenied)
        );
    }

    #[test]
    fn application_data_directory_creation_is_idempotent_and_scoped() {
        let mut filesystem = RedoxFs::new().unwrap();

        let first = ensure_application_data_directory(&mut filesystem, "example.editor").unwrap();
        let second = ensure_application_data_directory(&mut filesystem, "example.editor").unwrap();
        assert_eq!(first, second);
        assert!(filesystem.open_file_at(first, "settings").is_err());

        let other = ensure_application_data_directory(&mut filesystem, "example.viewer").unwrap();
        assert_ne!(first, other);
        assert_eq!(
            open_application_data_directory(&mut filesystem, "example.editor"),
            Ok(first)
        );
    }

    #[test]
    fn application_data_dispositions_are_unique_and_require_read_only_scope_rights() {
        let app = HandleOperationDisposition {
            handle: Handle::from_raw(7),
            operation: HandleOperation::Move,
            rights: Rights::READ,
        };
        let ordinary = HandleOperationDisposition {
            handle: Handle::from_raw(9),
            operation: HandleOperation::Move,
            rights: Rights::READ,
        };
        assert_eq!(
            application_data_disposition_index(&[ordinary, app], |handle| Ok(
                if handle == app.handle {
                    ObjectType::ApplicationData
                } else {
                    ObjectType::Channel
                }
            )),
            Ok(Some(1))
        );
        assert_eq!(
            application_data_disposition_index(&[app, app], |_| Ok(ObjectType::ApplicationData)),
            Err(Status::InvalidArgument)
        );

        for rights in [Rights::WRITE, Rights::READ | Rights::TRANSFER] {
            let invalid = HandleOperationDisposition { rights, ..app };
            assert_eq!(
                application_data_disposition_index(&[invalid], |_| Ok(ObjectType::ApplicationData)),
                Err(Status::InvalidRights)
            );
        }
    }

    #[test]
    fn disposition_parser_accepts_move_and_duplicate() {
        let moved = disposition_bytes(7, 0, Rights::READ.bits(), 0);
        assert_eq!(
            parse_handle_disposition(&moved),
            Ok(HandleOperationDisposition {
                handle: Handle::from_raw(7),
                operation: HandleOperation::Move,
                rights: Rights::READ,
            })
        );

        let duplicated = disposition_bytes(9, 1, Rights::WAIT.bits(), 0);
        assert_eq!(
            parse_handle_disposition(&duplicated),
            Ok(HandleOperationDisposition {
                handle: Handle::from_raw(9),
                operation: HandleOperation::Duplicate,
                rights: Rights::WAIT,
            })
        );
    }

    #[test]
    fn disposition_parser_rejects_invalid_operation_reserved_and_rights() {
        assert_eq!(
            parse_handle_disposition(&disposition_bytes(1, 2, Rights::READ.bits(), 0)),
            Err(Status::InvalidArgument)
        );
        assert_eq!(
            parse_handle_disposition(&disposition_bytes(1, 0, Rights::READ.bits(), 1)),
            Err(Status::InvalidArgument)
        );
        assert_eq!(
            parse_handle_disposition(&disposition_bytes(1, 0, 1 << 31, 0)),
            Err(Status::InvalidRights)
        );
        assert_eq!(
            parse_handle_disposition(&[0; HANDLE_DISPOSITION_SIZE - 1]),
            Err(Status::InvalidArgument)
        );
    }

    #[test]
    fn count_helper_enforces_caps_and_detects_overflow() {
        assert_eq!(checked_array_bytes(16, 8, 16, Status::OutOfRange), Ok(128));
        assert_eq!(
            checked_array_bytes(17, 8, 16, Status::MessageTooLarge),
            Err(Status::MessageTooLarge)
        );
        assert_eq!(
            checked_array_bytes(u64::MAX, 2, u64::MAX, Status::OutOfRange),
            Err(Status::OutOfRange)
        );
    }

    #[test]
    fn received_handle_metadata_is_filled_in_place() {
        let handles = [Handle::from_raw(7), Handle::from_raw(9)];
        let mut output = [0xaa; 2 * RECEIVED_HANDLE_SIZE];
        let mut queries = 0;

        assert_eq!(
            fill_received_handle_metadata_with(&handles, &mut output, |handle| {
                queries += 1;
                match handle.raw() {
                    7 => Ok((Rights::READ | Rights::WAIT, ObjectType::Channel)),
                    9 => Ok((Rights::READ | Rights::MAP, ObjectType::SharedMemory)),
                    _ => Err(()),
                }
            }),
            Ok(())
        );

        assert_eq!(queries, 2);
        assert_eq!(read_u32(&output, 0), 7);
        assert_eq!(read_u32(&output, 4), (Rights::READ | Rights::WAIT).bits());
        assert_eq!(read_u32(&output, 8), ObjectType::Channel as u32);
        assert_eq!(read_u32(&output, 12), 0);
        assert_eq!(read_u32(&output, 16), 9);
        assert_eq!(read_u32(&output, 20), (Rights::READ | Rights::MAP).bits());
        assert_eq!(read_u32(&output, 24), ObjectType::SharedMemory as u32);
        assert_eq!(read_u32(&output, 28), 0);
    }

    #[test]
    fn received_handle_metadata_checks_size_and_corruption() {
        let handles = [Handle::from_raw(7)];
        let mut short = [0_u8; RECEIVED_HANDLE_SIZE - 1];
        let mut queried = false;
        assert_eq!(
            fill_received_handle_metadata_with(&handles, &mut short, |_| {
                queried = true;
                Ok((Rights::READ, ObjectType::Channel))
            }),
            Err(Status::InvalidMessage)
        );
        assert!(!queried, "length must be checked before metadata lookup");

        let mut output = [0_u8; RECEIVED_HANDLE_SIZE];
        assert_eq!(
            fill_received_handle_metadata_with(&handles, &mut output, |_| Err(())),
            Err(Status::InvalidMessage)
        );
    }

    #[test]
    fn status_mapping_preserves_public_error_meaning() {
        assert_eq!(
            map_ipc_error(IpcError::InvalidHandle),
            Status::InvalidHandle
        );
        assert_eq!(map_ipc_error(IpcError::AccessDenied), Status::AccessDenied);
        assert_eq!(
            map_ipc_error(IpcError::BufferTooSmall(MessageInfo::new(4, 1))),
            Status::BufferTooSmall
        );
        assert_eq!(
            map_address_space_error(AddressSpaceError::PermissionDenied {
                address: 0x1000,
                access: UserAccess::Write,
            }),
            Status::AccessDenied
        );
        assert_eq!(
            map_address_space_error(AddressSpaceError::AlreadyMapped(0x2000)),
            Status::AlreadyMapped
        );
        assert_eq!(
            map_shared_mapping_error(SharedMappingError::RangeOverflow),
            Status::OutOfRange
        );
        assert_eq!(
            map_shared_mapping_error(SharedMappingError::NoAddressSpace),
            Status::OutOfMemory
        );
    }

    #[test]
    fn filesystem_argument_parsers_follow_fixed_layouts() {
        let mut path = [0_u8; FILESYSTEM_CREATE_DIRECTORY_ARGS_SIZE];
        put_u32(&mut path, 0, 0x1122_3344);
        put_u64(&mut path, 8, 0x0102_0304_0506_0708);
        put_u64(&mut path, 16, 99);
        assert_eq!(
            parse_filesystem_path_args(&path),
            Ok((Handle::from_raw(0x1122_3344), 0x0102_0304_0506_0708, 99))
        );
        put_u32(&mut path, 4, 1);
        assert_eq!(
            parse_filesystem_path_args(&path),
            Err(Status::InvalidArgument)
        );

        let mut rename = [0_u8; FILESYSTEM_RENAME_ARGS_SIZE];
        put_u32(&mut rename, 0, 7);
        put_u32(&mut rename, 4, 9);
        put_u64(&mut rename, 8, 0x1000);
        put_u64(&mut rename, 16, 5);
        put_u64(&mut rename, 24, 0x2000);
        put_u64(&mut rename, 32, 6);
        put_u32(&mut rename, 40, FilesystemRenameFlags::REPLACE.bits());
        assert_eq!(
            parse_filesystem_rename_args(&rename),
            Ok(ParsedFilesystemRenameArgs {
                source_anchor: Handle::from_raw(7),
                destination_anchor: Handle::from_raw(9),
                source_address: 0x1000,
                source_length: 5,
                destination_address: 0x2000,
                destination_length: 6,
                flags: FilesystemRenameFlags::REPLACE,
            })
        );
        put_u32(&mut rename, 40, 2);
        assert_eq!(
            parse_filesystem_rename_args(&rename),
            Err(Status::InvalidArgument)
        );
        put_u32(&mut rename, 40, 0);
        put_u32(&mut rename, 44, 1);
        assert_eq!(
            parse_filesystem_rename_args(&rename),
            Err(Status::InvalidArgument)
        );
    }

    #[test]
    fn filesystem_paths_are_relative_bounded_and_non_traversing() {
        assert_eq!(validate_filesystem_path("file"), Ok(()));
        assert_eq!(validate_filesystem_path("one/two/three"), Ok(()));
        for invalid in [
            "",
            "/absolute",
            "\\absolute",
            ".",
            "..",
            "one/./two",
            "one/../two",
            "one//two",
            "one/",
            "one\\two",
            "drive:name",
            "nul\0name",
        ] {
            assert_eq!(
                validate_filesystem_path(invalid),
                Err(Status::InvalidArgument),
                "accepted invalid path {invalid:?}"
            );
        }

        let long_component = "a".repeat(FILESYSTEM_NAME_MAX + 1);
        assert_eq!(
            validate_filesystem_path(&long_component),
            Err(Status::InvalidArgument)
        );
        let deepest = vec!["a"; MAX_TRAVERSAL_DEPTH].join("/");
        assert_eq!(validate_filesystem_path(&deepest), Ok(()));
        let too_deep = vec!["a"; MAX_TRAVERSAL_DEPTH + 1].join("/");
        assert_eq!(validate_filesystem_path(&too_deep), Err(Status::OutOfRange));
    }

    #[test]
    fn filesystem_namespace_protection_covers_system_subtree_and_legacy_nodes() {
        for protected in [
            "system",
            "system/desktop.elf",
            "system/nested/artifact",
            "desktop.elf",
            "programs.gkr/metadata",
            "system.log/archive",
            "console/child",
        ] {
            assert!(is_protected_system_path(protected));
        }
        for mutable in [
            "applications",
            "applications/example/versions/app.elf",
            "appdata",
            "appdata/example/settings",
            "apps/desktop.elf",
            "desktop.elf.backup",
        ] {
            assert!(!is_protected_system_path(mutable));
        }
    }

    #[test]
    fn directory_rights_are_attenuated_to_anchor_authority() {
        let full = Rights::READ | Rights::WRITE | Rights::DUPLICATE | Rights::TRANSFER;
        assert_eq!(child_directory_rights(full, false, false), full);
        assert_eq!(
            child_directory_rights(Rights::READ | Rights::TRANSFER, false, false),
            Rights::READ | Rights::TRANSFER
        );
        assert_eq!(
            child_directory_rights(Rights::READ | Rights::WRITE, true, false),
            full
        );
        assert_eq!(
            child_directory_rights(Rights::READ, true, false),
            Rights::READ | Rights::DUPLICATE | Rights::TRANSFER
        );
        assert_eq!(
            child_directory_rights(full, true, true),
            Rights::READ | Rights::DUPLICATE | Rights::TRANSFER
        );
    }

    #[test]
    fn filesystem_metadata_encoding_uses_the_stable_layout() {
        let metadata = NodeMetadata {
            kind: NodeKind::Directory,
            size: 123,
            identity: 456,
            mode: 0o40755,
            policy: 0,
            uid: 10,
            gid: 20,
            ctime: ginkgo_filesystem::Timestamp {
                seconds: 2,
                nanoseconds: 3,
            },
            mtime: ginkgo_filesystem::Timestamp {
                seconds: 4,
                nanoseconds: 5,
            },
        };
        let encoded = encode_filesystem_metadata(metadata).unwrap();
        assert_eq!(read_u32(&encoded, 0), 2);
        assert_eq!(read_u32(&encoded, 4), 0o40755);
        assert_eq!(read_u64(&encoded, 8), 123);
        assert_eq!(read_u64(&encoded, 16), 456);
        assert_eq!(read_u64(&encoded, 24), 2_000_000_003);
        assert_eq!(read_u64(&encoded, 32), 4_000_000_005);
        assert_eq!(read_u32(&encoded, 40), 10);
        assert_eq!(read_u32(&encoded, 44), 20);
        assert_eq!(read_u32(&encoded, 48), 0);
        assert_eq!(&encoded[52..], &[0; 12]);
        assert_eq!(timestamp_ns(u64::MAX, 0), Err(Status::OutOfRange));
    }

    #[test]
    fn filesystem_errors_map_to_rich_abi_statuses() {
        assert_eq!(map_fs_error(FsError::InvalidName), Status::InvalidArgument);
        assert_eq!(map_fs_error(FsError::TraversalTooDeep), Status::OutOfRange);
        assert_eq!(map_fs_error(FsError::AlreadyExists), Status::AlreadyExists);
        assert_eq!(map_fs_error(FsError::NotDirectory), Status::NotDirectory);
        assert_eq!(map_fs_error(FsError::IsDirectory), Status::IsDirectory);
        assert_eq!(
            map_fs_error(FsError::DirectoryNotEmpty),
            Status::DirectoryNotEmpty
        );
        assert_eq!(map_fs_error(FsError::WouldCycle), Status::InvalidArgument);
    }

    #[test]
    fn debug_write_length_is_strictly_bounded() {
        assert_eq!(checked_debug_length(0), Ok(0));
        assert_eq!(
            checked_debug_length(DEBUG_WRITE_MAX_BYTES as u64),
            Ok(DEBUG_WRITE_MAX_BYTES)
        );
        assert_eq!(
            checked_debug_length(DEBUG_WRITE_MAX_BYTES as u64 + 1),
            Err(Status::OutOfRange)
        );
        assert_eq!(checked_debug_length(u64::MAX), Err(Status::OutOfRange));
    }

    fn disposition_bytes(
        handle: u32,
        operation: u32,
        rights: u32,
        reserved: u32,
    ) -> [u8; HANDLE_DISPOSITION_SIZE] {
        let mut bytes = [0_u8; HANDLE_DISPOSITION_SIZE];
        put_u32(&mut bytes, 0, handle);
        put_u32(&mut bytes, 4, operation);
        put_u32(&mut bytes, 8, rights);
        put_u32(&mut bytes, 12, reserved);
        bytes
    }
}
