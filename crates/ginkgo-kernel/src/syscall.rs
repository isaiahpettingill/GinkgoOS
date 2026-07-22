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

use alloc::{string::String, vec, vec::Vec};
use core::mem::size_of;

use ginkgo_filesystem::{FsError, RedoxFs};
use ginkgo_ipc::{
    HandleOperation, HandleOperationDisposition, IpcError, MessageInfo, ObjectType, Rights,
    Signals, WaitItem,
};
use ginkgo_sysapi::{
    FilesystemDirectoryEntry, FilesystemOpenFlags, Handle, MapFlags, MapProtection,
    SharedMemoryMapArgs, Status, SyscallNumber, CHANNEL_MAX_BYTES, CHANNEL_MAX_HANDLES,
    DEADLINE_INFINITE, FILESYSTEM_NAME_MAX, FILESYSTEM_READ_MAX_BYTES, RANDOM_MAX_BYTES,
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
    process::{PendingWaitMany, Process, SharedMappingError, WaitDeadline, WaitManyCompletion},
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

/// A bounded destination for early userspace diagnostics.
pub trait DebugSink {
    fn write(&mut self, bytes: &[u8]);
}

/// Scheduler action produced by one syscall dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyscallOutcome {
    /// The syscall completed (successfully or with an error) and the process is
    /// a candidate for a later cooperative scheduling turn.
    Yield,
    /// Syscall completion is deferred until the scheduler wakes the process.
    Blocked,
    /// The process requested termination with this code.
    Exit(i32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DispatchResult {
    Complete(Status),
    Blocked,
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
            debug_sink,
        )
    };
    match result {
        DispatchResult::Complete(status) => {
            set_status(context, status);
            SyscallOutcome::Yield
        }
        DispatchResult::Blocked => SyscallOutcome::Blocked,
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
    raw_root: u64,
    args_address: u64,
    output_address: u64,
) -> Result<(), Status> {
    let root = decode_handle(raw_root)?;
    let raw = copy_block_from_user::<FILESYSTEM_OPEN_ARGS_SIZE>(process, args_address)?;
    let name_address = read_u64(&raw, 0);
    let name_length = read_u64(&raw, 8);
    let flags =
        FilesystemOpenFlags::from_bits(read_u32(&raw, 16)).ok_or(Status::InvalidArgument)?;
    if read_u32(&raw, 20) != 0
        || !flags.intersects(FilesystemOpenFlags::READ | FilesystemOpenFlags::WRITE)
        || (flags.intersects(FilesystemOpenFlags::CREATE | FilesystemOpenFlags::TRUNCATE)
            && !flags.contains(FilesystemOpenFlags::WRITE))
    {
        return Err(Status::InvalidArgument);
    }
    validate_user_output(process, output_address, HANDLE_OUTPUT_SIZE)?;
    let name = copy_filesystem_name(process, name_address, name_length)?;
    let mut required_root = Rights::READ;
    if flags.intersects(
        FilesystemOpenFlags::WRITE | FilesystemOpenFlags::CREATE | FilesystemOpenFlags::TRUNCATE,
    ) {
        required_root |= Rights::WRITE;
        if is_protected_system_file(&name) {
            return Err(Status::AccessDenied);
        }
    }
    process
        .handles()
        .filesystem_root(root, required_root)
        .map_err(map_ipc_error)?;

    let mut path = String::from("/");
    path.push_str(&name);
    let mut created = false;
    let file = match filesystem.open(&path) {
        Ok(file) => file,
        Err(FsError::NotFound) if flags.contains(FilesystemOpenFlags::CREATE) => {
            created = true;
            filesystem.create(&path).map_err(map_fs_error)?
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
    let handle = match process.handles_mut().filesystem_file_create(file, rights) {
        Ok(handle) => handle,
        Err(error) => {
            if created {
                let _ = filesystem.remove(file);
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
    raw_root: u64,
    cookie: u64,
    output_address: u64,
) -> Result<(), Status> {
    let root = decode_handle(raw_root)?;
    validate_user_output(process, output_address, FILESYSTEM_DIRECTORY_ENTRY_SIZE)?;
    process
        .handles()
        .filesystem_root(root, Rights::READ)
        .map_err(map_ipc_error)?;
    let index = usize::try_from(cookie).map_err(|_| Status::OutOfRange)?;
    let entries = filesystem.list_root().map_err(map_fs_error)?;
    let entry = entries.get(index).ok_or(Status::EndOfDirectory)?;
    let next_cookie = cookie.checked_add(1).ok_or(Status::OutOfRange)?;
    let mut output = vec![0_u8; FILESYSTEM_DIRECTORY_ENTRY_SIZE];
    output[0..8].copy_from_slice(&next_cookie.to_le_bytes());
    output[8..16].copy_from_slice(&entry.len.to_le_bytes());
    output[16..18].copy_from_slice(&(entry.name.len() as u16).to_le_bytes());
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
    raw_root: u64,
    name_address: u64,
    name_length: u64,
) -> Result<(), Status> {
    let root = decode_handle(raw_root)?;
    process
        .handles()
        .filesystem_root(root, Rights::WRITE)
        .map_err(map_ipc_error)?;
    let name = copy_filesystem_name(process, name_address, name_length)?;
    if is_protected_system_file(&name) {
        return Err(Status::AccessDenied);
    }
    let mut path = String::from("/");
    path.push_str(&name);
    let file = filesystem.open(&path).map_err(map_fs_error)?;
    filesystem.remove(file).map_err(map_fs_error)
}

fn copy_filesystem_name(
    process: &Process,
    address: u64,
    raw_length: u64,
) -> Result<String, Status> {
    let length = checked_array_bytes(
        raw_length,
        1,
        FILESYSTEM_NAME_MAX as u64,
        Status::OutOfRange,
    )?;
    if length == 0 {
        return Err(Status::InvalidArgument);
    }
    let bytes = copy_vec_from_user(process, address, length)?;
    let name = core::str::from_utf8(&bytes).map_err(|_| Status::InvalidArgument)?;
    if name == "."
        || name == ".."
        || name.contains('/')
        || name.contains(':')
        || name.as_bytes().contains(&0)
    {
        return Err(Status::InvalidArgument);
    }
    Ok(String::from(name))
}

fn is_protected_system_file(name: &str) -> bool {
    name == "desktop.elf"
        || name == "minimal-client.elf"
        || name == "file-navigator.elf"
        || name == "terminal.elf"
        || name == "programs.gkr"
        || name == "system.log"
        || name == "console"
        || name == "input"
}

const fn map_fs_error(error: FsError) -> Status {
    match error {
        FsError::InvalidName => Status::InvalidArgument,
        FsError::AlreadyExists => Status::InvalidArgument,
        FsError::NotFound => Status::NotFound,
        FsError::NoSpace => Status::OutOfMemory,
        FsError::InvalidHandle => Status::InvalidHandle,
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
        ];
        for number in expected {
            assert_eq!(decode_syscall_number(number as u64), Some(number));
        }
        assert_eq!(
            decode_syscall_number(21),
            Some(SyscallNumber::ClockGetMonotonic)
        );
        assert_eq!(decode_syscall_number(22), Some(SyscallNumber::RandomFill));
        assert_eq!(decode_syscall_number(23), None);
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
