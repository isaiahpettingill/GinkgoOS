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
    handle_transfer_batch_between, shared_memory_backing_stats, HandleOperation,
    HandleOperationDisposition, HandleTable, IpcError, MessageInfo, ObjectType, Rights, Signals,
    WaitItem, APPLICATION_DATA_MAX_APP_ID_LEN,
};
use ginkgo_sysapi::{
    FilesystemDirectoryEntry, FilesystemOpenFlags, FilesystemReadOutput, FilesystemRenameFlags,
    Handle, MapFlags, MapProtection, MemoryInfo, ProcessInfo, ProcessMemoryPolicy, RequestBuffer,
    RequestBufferFlags, RequestBufferKind, RequestCompletionMode, RequestDiagnostics, RequestFlags,
    RequestInfo, RequestOperation, RequestResultFlags, RequestState, RequestSubmitArgs,
    RequestSubmitBatchArgs, RequestSubmitOutput, SharedMemoryMapArgs, Status, SyscallNumber,
    SystemPowerAction, SystemPowerFlags, SystemPowerInfo, ThreadInfo, ThreadSchedulingClass,
    ThreadSchedulingInfo, ThreadState as PublicThreadState, VirtualAreaInfo, VirtualMapFileArgs,
    CHANNEL_MAX_BYTES, CHANNEL_MAX_HANDLES, DEADLINE_INFINITE, FILESYSTEM_NAME_MAX,
    FILESYSTEM_READ_MAX_BYTES, MEMORY_INFO_V1_SIZE, MEMORY_INFO_VERSION, MEMORY_INFO_VERSION_V1,
    PROCESS_MAX_STARTUP_BYTES, PROCESS_MAX_STARTUP_HANDLES, PROCESS_MEMORY_POLICY_VERSION,
    RANDOM_MAX_BYTES, REQUEST_DIAGNOSTICS_VERSION, REQUEST_INFO_VERSION, REQUEST_MAX_BATCH,
    REQUEST_MAX_BUFFERS, REQUEST_SUBMIT_ARGS_VERSION, REQUEST_SUBMIT_BATCH_ARGS_VERSION,
    THREAD_CREATE_ARGS_VERSION, THREAD_INFO_VERSION, THREAD_SCHEDULING_INFO_VERSION,
    VIRTUAL_AREA_INFO_VERSION,
};
use redoxfs::Disk;
use zerocopy::IntoBytes;

use crate::{
    arch::UserContext,
    audio::AudioDevice,
    entropy::EntropyPool,
    memory::{UsableFrameAllocator, PAGE_SIZE},
    paging::{
        address_space::{AddressSpaceError, UserAccess},
        ActivePageTable, MapError,
    },
    process::{
        file_max_protection, select_child_process_limits, BlockedKind, DirectStartupBlock,
        ElfPageLoadError, PendingRequest, PendingRequestCountOutput, PendingRequestOutput,
        PendingWaitMany, Process, ProcessCreateError, ProcessId, ProcessLimits, SharedMappingError,
        ThreadCreateError, ThreadId, ThreadState, WaitDeadline, WaitManyCompletion,
    },
    request::{RequestError, RequestId, RequestOwner, RequestTarget},
    request_broker::{
        BrokerError, BrokerPayload, FileCapabilityLease, PreparedBrokerRequest,
        PreparedRequestBuffer, PreparedRequestTarget, RequestBroker,
    },
    shared_memory::{SharedFrameArena, SharedMemoryFactory},
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
const PROCESS_CREATE_ARGS2_SIZE: usize = 80;
const PROCESS_MEMORY_POLICY_SIZE: usize = size_of::<ProcessMemoryPolicy>();
const PROCESS_INFO_SIZE: usize = size_of::<ProcessInfo>();
const THREAD_INFO_SIZE: usize = size_of::<ThreadInfo>();
const THREAD_CREATE_ARGS_SIZE: usize = 56;
const THREAD_SCHEDULING_INFO_SIZE: usize = size_of::<ThreadSchedulingInfo>();
const SYSTEM_POWER_INFO_SIZE: usize = size_of::<SystemPowerInfo>();
const VIRTUAL_AREA_INFO_SIZE: usize = size_of::<VirtualAreaInfo>();
const SYSTEM_POWER_CANCELLATION_NS: u64 = 2_000_000_000;
const APPLICATION_DATA_CREATE_ARGS_SIZE: usize = 32;
const REQUEST_BUFFER_SIZE: usize = size_of::<RequestBuffer>();
const REQUEST_SUBMIT_ARGS_SIZE: usize = size_of::<RequestSubmitArgs>();
const REQUEST_SUBMIT_OUTPUT_SIZE: usize = size_of::<RequestSubmitOutput>();
const REQUEST_INFO_SIZE: usize = size_of::<RequestInfo>();
const REQUEST_SUBMIT_BATCH_ARGS_SIZE: usize = size_of::<RequestSubmitBatchArgs>();
const REQUEST_DIAGNOSTICS_SIZE: usize = size_of::<RequestDiagnostics>();
const REQUEST_TARGET_FILESYSTEM_ROOT: u64 = u64::MAX;
const REQUEST_TARGET_AUDIO: u64 = u64::MAX - 1;
const REQUEST_TARGET_SYNTHETIC_TAG: u64 = 0x5359_4e54_0000_0000;
/// Heap values captured immediately before syscall dispatch.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct KernelHeapStats {
    pub committed_bytes: u64,
    pub available_bytes: u64,
    pub growth_failures: u64,
}

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
    /// Only the calling thread exited; sibling threads may remain runnable.
    ThreadExited(i32),
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
    process_id: ProcessId,
    process: &mut Process,
    thread_id: ThreadId,
    context: &mut UserContext,
    now_ns: u64,
    kernel_page_table: &ActivePageTable,
    frame_allocator: &mut UsableFrameAllocator<'_>,
    kernel_heap: KernelHeapStats,
    shared_frame_arena: &SharedFrameArena,
    filesystem: &mut RedoxFs<B>,
    audio: &mut Option<AudioDevice>,
    entropy: &mut EntropyPool,
    requests: &mut RequestBroker,
    process_creation_allowed: bool,
    child_slot_reserved: bool,
    debug_sink: &mut D,
) -> SyscallOutcome {
    assert!(
        process.thread(thread_id).is_some(),
        "syscall dispatch received a stale thread identity"
    );
    let Some(number) = decode_syscall_number(context.rax) else {
        set_status(context, Status::UnknownSyscall);
        return SyscallOutcome::Yield;
    };

    if matches!(
        number,
        SyscallNumber::ProcessExit | SyscallNumber::ThreadExit
    ) {
        return match decode_exit_code(context.rdi) {
            Ok(code) if number == SyscallNumber::ProcessExit => {
                process.exit_process(thread_id, code);
                SyscallOutcome::Exit(code)
            }
            Ok(code) => {
                process.exit_thread(thread_id, code);
                SyscallOutcome::ThreadExited(code)
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
            process_id,
            process,
            thread_id,
            context,
            now_ns,
            kernel_page_table,
            frame_allocator,
            kernel_heap,
            shared_frame_arena,
            filesystem,
            audio,
            entropy,
            requests,
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
    process_id: ProcessId,
    process: &mut Process,
    thread_id: ThreadId,
    context: &UserContext,
    now_ns: u64,
    kernel_page_table: &ActivePageTable,
    frame_allocator: &mut UsableFrameAllocator<'_>,
    kernel_heap: KernelHeapStats,
    shared_frame_arena: &SharedFrameArena,
    filesystem: &mut RedoxFs<B>,
    audio: &mut Option<AudioDevice>,
    entropy: &mut EntropyPool,
    requests: &mut RequestBroker,
    process_creation_allowed: bool,
    child_slot_reserved: bool,
    debug_sink: &mut D,
) -> DispatchResult {
    if number == SyscallNumber::WaitMany {
        return wait_many(process, thread_id, context.rdi, context.rsi, now_ns);
    }

    let memory_failures_before = process.usage();
    let result = match number {
        SyscallNumber::ProcessYield | SyscallNumber::ThreadYield => Ok(()),
        SyscallNumber::ProcessExit | SyscallNumber::ThreadExit => {
            unreachable!("exit syscalls are handled before dispatch")
        }
        SyscallNumber::HandleClose => handle_close(process, context.rdi),
        SyscallNumber::HandleDuplicate => {
            handle_duplicate(process, context.rdi, context.rsi, context.rdx)
        }
        SyscallNumber::WaitMany => unreachable!("wait-many is handled before ordinary dispatch"),
        SyscallNumber::ChannelCreate => channel_create(process, context.rdi),
        SyscallNumber::ChannelWrite => channel_write(process, context.rdi, context.rsi),
        SyscallNumber::ChannelRead => channel_read(process, context.rdi, context.rsi),
        SyscallNumber::SharedMemoryCreate => shared_memory_create(
            process,
            context.rdi,
            context.rsi,
            shared_frame_arena,
            kernel_page_table,
            frame_allocator,
        ),
        SyscallNumber::SharedMemoryGetSize => {
            shared_memory_get_size(process, context.rdi, context.rsi)
        }
        SyscallNumber::SharedMemoryMap => shared_memory_map(
            process,
            context.rdi,
            context.rsi,
            context.rdx,
            frame_allocator,
        ),
        SyscallNumber::SharedMemoryUnmap => shared_memory_unmap(process, context.rdi, context.rsi),
        SyscallNumber::DebugWrite => debug_write(process, context.rdi, context.rsi, debug_sink),
        SyscallNumber::FilesystemOpen => {
            return filesystem_open_request(
                process_id,
                process,
                thread_id,
                filesystem,
                requests,
                context.rdi,
                context.rsi,
                context.rdx,
                now_ns,
            );
        }
        SyscallNumber::FilesystemRead => {
            return filesystem_read_request(
                process_id,
                process,
                thread_id,
                requests,
                context.rdi,
                context.rsi,
                context.rdx,
                context.r10,
                context.r8,
                now_ns,
            );
        }
        SyscallNumber::FilesystemWrite => {
            return filesystem_write_request(
                process_id,
                process,
                thread_id,
                requests,
                context.rdi,
                context.rsi,
                context.rdx,
                context.r10,
                context.r8,
                now_ns,
            );
        }
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
        SyscallNumber::ProcessCreate | SyscallNumber::ProcessCreate2
            if !process_creation_allowed =>
        {
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
                false,
            ) {
                Ok(child) => DispatchResult::ChildCreated(child),
                Err(status) => {
                    record_memory_failure_once(process, memory_failures_before, status);
                    DispatchResult::Complete(status)
                }
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
        SyscallNumber::FilesystemSync => {
            return filesystem_sync_request(
                process_id,
                process,
                thread_id,
                requests,
                context.rdi,
                now_ns,
            );
        }
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
        SyscallNumber::AnonymousReserve => {
            anonymous_reserve(process, context.rdi, context.rsi, context.rdx)
        }
        SyscallNumber::AnonymousCommit => {
            anonymous_commit(process, context.rdi, context.rsi, frame_allocator)
        }
        SyscallNumber::AnonymousDecommit => {
            anonymous_decommit(process, context.rdi, context.rsi, frame_allocator)
        }
        SyscallNumber::MemoryGetInfo => memory_get_info(
            process,
            context.rdi,
            context.rsi,
            context.rdx,
            frame_allocator,
            kernel_heap,
            shared_frame_arena,
        ),
        SyscallNumber::VirtualMapFile => virtual_map_file(
            process,
            filesystem,
            context.rdi,
            context.rsi,
            context.rdx,
            frame_allocator,
        ),
        SyscallNumber::VirtualCommit => virtual_commit(
            process,
            filesystem,
            context.rdi,
            context.rsi,
            frame_allocator,
        ),
        SyscallNumber::VirtualDecommit => process
            .decommit_file_backed(context.rdi, context.rsi, frame_allocator)
            .map_err(map_shared_mapping_error),
        SyscallNumber::VirtualProtect => {
            virtual_protect(process, context.rdi, context.rsi, context.rdx)
        }
        SyscallNumber::VirtualUnmap => process
            .unmap_file_backed(context.rdi, context.rsi, frame_allocator)
            .map_err(map_shared_mapping_error),
        SyscallNumber::VirtualQuery => {
            virtual_query(process, context.rdi, context.rsi, context.rdx, context.r10)
        }
        SyscallNumber::ThreadCreate => thread_create(process, context.rdi, frame_allocator),
        SyscallNumber::ThreadSleepUntil => {
            return match thread_sleep_until(process, thread_id, context.rdi, now_ns) {
                Ok(true) => DispatchResult::Blocked,
                Ok(false) => DispatchResult::Complete(Status::Ok),
                Err(status) => DispatchResult::Complete(status),
            };
        }
        SyscallNumber::ThreadWake => thread_wake(process, context.rdi),
        SyscallNumber::ThreadTerminate => thread_terminate(process, context.rdi),
        SyscallNumber::ThreadGetInfo => {
            thread_get_info(process, context.rdi, context.rsi, context.rdx, context.r10)
        }
        SyscallNumber::ThreadJoin => {
            return match thread_join(
                process,
                thread_id,
                context.rdi,
                context.rsi,
                context.rdx,
                context.r10,
                context.r8,
                now_ns,
                frame_allocator,
            ) {
                Ok(true) => DispatchResult::Blocked,
                Ok(false) => DispatchResult::Complete(Status::Ok),
                Err(status) => DispatchResult::Complete(status),
            };
        }
        SyscallNumber::ThreadDetach => thread_detach(process, context.rdi, frame_allocator),
        SyscallNumber::ThreadGetCurrent => {
            let id = ginkgo_sysapi::ThreadId(thread_id.raw());
            copy_to_user(process, context.rdi, id.as_bytes())
        }
        SyscallNumber::ThreadSetSchedulingClass => {
            thread_set_scheduling_class(process, context.rdi, context.rsi)
        }
        SyscallNumber::ThreadGetSchedulingInfo => {
            thread_get_scheduling_info(process, context.rdi, context.rsi, context.rdx, context.r10)
        }
        SyscallNumber::ThreadSetSchedulingClassWithAuthority => {
            thread_set_scheduling_class_with_authority(
                process,
                context.rdi,
                context.rsi,
                context.rdx,
            )
        }
        SyscallNumber::RequestSubmit => {
            return request_submit(
                process_id,
                process,
                thread_id,
                requests,
                context.rdi,
                context.rsi,
                now_ns,
            );
        }
        SyscallNumber::RequestCancel => request_cancel(process, requests, context.rdi, now_ns),
        SyscallNumber::RequestGetInfo => {
            request_get_info(process, context.rdi, context.rsi, context.rdx, context.r10)
        }
        SyscallNumber::RequestSubmitBatch => request_submit_batch(
            process_id,
            process,
            thread_id,
            requests,
            context.rdi,
            now_ns,
        ),
        SyscallNumber::RequestGetDiagnostics => {
            request_get_diagnostics(process, requests, context.rdi, context.rsi, context.rdx)
        }
        SyscallNumber::ProcessCreate2 => {
            return match process_create(
                process,
                filesystem,
                context.rdi,
                kernel_page_table,
                frame_allocator,
                entropy,
                child_slot_reserved,
                true,
            ) {
                Ok(child) => DispatchResult::ChildCreated(child),
                Err(status) => {
                    record_memory_failure_once(process, memory_failures_before, status);
                    DispatchResult::Complete(status)
                }
            };
        }
    };
    if let Err(status) = result {
        if is_memory_accounted_syscall(number) {
            record_memory_failure_once(process, memory_failures_before, status);
        }
        DispatchResult::Complete(status)
    } else {
        DispatchResult::Complete(Status::Ok)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MemoryFailureCounter {
    Quota,
    Oom,
}

const fn missing_memory_failure_counter(
    before: crate::process::ProcessUsage,
    after: crate::process::ProcessUsage,
    status: Status,
) -> Option<MemoryFailureCounter> {
    match status {
        Status::ResourceLimit if after.quota_failures == before.quota_failures => {
            Some(MemoryFailureCounter::Quota)
        }
        Status::OutOfMemory if after.oom_failures == before.oom_failures => {
            Some(MemoryFailureCounter::Oom)
        }
        _ => None,
    }
}

fn record_memory_failure_once(
    process: &mut Process,
    before: crate::process::ProcessUsage,
    status: Status,
) {
    match missing_memory_failure_counter(before, process.usage(), status) {
        Some(MemoryFailureCounter::Quota) => process.record_quota_failure(),
        Some(MemoryFailureCounter::Oom) => process.record_oom_failure(),
        None => {}
    }
}

const fn is_memory_accounted_syscall(number: SyscallNumber) -> bool {
    matches!(
        number,
        SyscallNumber::SharedMemoryCreate
            | SyscallNumber::SharedMemoryMap
            | SyscallNumber::AnonymousMap
            | SyscallNumber::AnonymousReserve
            | SyscallNumber::AnonymousCommit
            | SyscallNumber::AnonymousDecommit
            | SyscallNumber::AnonymousUnmap
            | SyscallNumber::AnonymousProtect
            | SyscallNumber::VirtualMapFile
            | SyscallNumber::VirtualCommit
            | SyscallNumber::VirtualDecommit
            | SyscallNumber::VirtualUnmap
            | SyscallNumber::VirtualProtect
    )
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
        42 => SyscallNumber::AnonymousReserve,
        43 => SyscallNumber::AnonymousCommit,
        44 => SyscallNumber::AnonymousDecommit,
        45 => SyscallNumber::MemoryGetInfo,
        46 => SyscallNumber::VirtualMapFile,
        47 => SyscallNumber::VirtualCommit,
        48 => SyscallNumber::VirtualDecommit,
        49 => SyscallNumber::VirtualProtect,
        50 => SyscallNumber::VirtualUnmap,
        51 => SyscallNumber::ProcessCreate2,
        52 => SyscallNumber::VirtualQuery,
        53 => SyscallNumber::ThreadCreate,
        54 => SyscallNumber::ThreadExit,
        55 => SyscallNumber::ThreadYield,
        56 => SyscallNumber::ThreadSleepUntil,
        57 => SyscallNumber::ThreadWake,
        58 => SyscallNumber::ThreadTerminate,
        59 => SyscallNumber::ThreadGetInfo,
        60 => SyscallNumber::ThreadJoin,
        61 => SyscallNumber::ThreadDetach,
        62 => SyscallNumber::ThreadGetCurrent,
        63 => SyscallNumber::ThreadSetSchedulingClass,
        64 => SyscallNumber::ThreadGetSchedulingInfo,
        65 => SyscallNumber::ThreadSetSchedulingClassWithAuthority,
        66 => SyscallNumber::RequestSubmit,
        67 => SyscallNumber::RequestCancel,
        68 => SyscallNumber::RequestGetInfo,
        69 => SyscallNumber::RequestSubmitBatch,
        70 => SyscallNumber::RequestGetDiagnostics,
        _ => return None,
    })
}

fn set_status(context: &mut UserContext, status: Status) {
    context.set_syscall_return((i64::from(status.raw())) as u64);
}

fn decode_exit_code(raw: u64) -> Result<i32, Status> {
    i32::try_from(raw as i64).map_err(|_| Status::InvalidArgument)
}

fn thread_create(
    process: &mut Process,
    args_address: u64,
    allocator: &mut UsableFrameAllocator<'_>,
) -> Result<(), Status> {
    let raw = copy_block_from_user::<THREAD_CREATE_ARGS_SIZE>(process, args_address)?;
    let version = read_u32(&raw, 0);
    let size = read_u32(&raw, 4);
    let entry = read_u64(&raw, 8);
    let argument = read_u64(&raw, 16);
    let stack_size = read_u64(&raw, 24);
    let tls_base = read_u64(&raw, 32);
    let flags = read_u32(&raw, 40);
    let reserved = read_u32(&raw, 44);
    let output_address = read_u64(&raw, 48);
    if version != THREAD_CREATE_ARGS_VERSION
        || size != THREAD_CREATE_ARGS_SIZE as u32
        || flags != 0
        || reserved != 0
    {
        return Err(Status::InvalidArgument);
    }
    validate_user_output(
        process,
        output_address,
        size_of::<ginkgo_sysapi::ThreadId>(),
    )?;
    let id = process
        .create_thread(entry, argument, stack_size, tls_base, allocator)
        .map_err(map_thread_create_error)?;
    let public_id = ginkgo_sysapi::ThreadId(id.raw());
    if let Err(status) = copy_to_user(process, output_address, public_id.as_bytes()) {
        process
            .abort_thread_create(id, allocator)
            .map_err(map_thread_create_error)?;
        return Err(status);
    }
    Ok(())
}

fn map_thread_create_error(error: ThreadCreateError) -> Status {
    match error {
        ThreadCreateError::InvalidEntry
        | ThreadCreateError::InvalidStack
        | ThreadCreateError::InvalidTls => Status::InvalidArgument,
        ThreadCreateError::ResourceLimit => Status::ResourceLimit,
        ThreadCreateError::OutOfMemory => Status::OutOfMemory,
        ThreadCreateError::AddressSpace(AddressSpaceError::OutOfMemory)
        | ThreadCreateError::AddressSpace(AddressSpaceError::OutOfFrames) => Status::OutOfMemory,
        ThreadCreateError::AddressSpace(_) | ThreadCreateError::RollbackFailed => {
            Status::InvalidAddress
        }
    }
}

fn thread_sleep_until(
    process: &mut Process,
    thread_id: ThreadId,
    raw_deadline: u64,
    now_ns: u64,
) -> Result<bool, Status> {
    let deadline = raw_deadline as i64;
    if deadline < 0 {
        return Err(Status::InvalidArgument);
    }
    process.sleep_thread(thread_id, deadline as u64, now_ns)
}

fn thread_wake(process: &mut Process, raw_id: u64) -> Result<(), Status> {
    process.wake_thread(ThreadId::from_raw(raw_id))
}

fn thread_terminate(process: &mut Process, raw_id: u64) -> Result<(), Status> {
    process
        .terminate_thread(ThreadId::from_raw(raw_id))
        .map(|_| ())
}

fn thread_detach(
    process: &mut Process,
    raw_id: u64,
    allocator: &mut UsableFrameAllocator<'_>,
) -> Result<(), Status> {
    let id = ThreadId::from_raw(raw_id);
    if process.detach_thread(id)? {
        process.reap_thread(id, allocator)?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn thread_join(
    process: &mut Process,
    caller: ThreadId,
    raw_target: u64,
    raw_deadline: u64,
    output_address: u64,
    output_size: u64,
    version: u64,
    now_ns: u64,
    allocator: &mut UsableFrameAllocator<'_>,
) -> Result<bool, Status> {
    if version != THREAD_INFO_VERSION as u64 || output_size != THREAD_INFO_SIZE as u64 {
        return Err(Status::InvalidArgument);
    }
    validate_user_output(process, output_address, THREAD_INFO_SIZE)?;
    let deadline_ns = raw_deadline as i64;
    if deadline_ns < 0 {
        return Err(Status::InvalidArgument);
    }
    let deadline = if deadline_ns == DEADLINE_INFINITE {
        WaitDeadline::Infinite
    } else {
        WaitDeadline::At(deadline_ns as u64)
    };
    let target = ThreadId::from_raw(raw_target);
    if process.start_join(caller, target, deadline, output_address, now_ns)? {
        return Ok(true);
    }
    thread_get_info(process, raw_target, output_address, output_size, version)?;
    process.reap_thread(target, allocator)?;
    Ok(false)
}

fn thread_get_info(
    process: &Process,
    raw_id: u64,
    output_address: u64,
    output_size: u64,
    version: u64,
) -> Result<(), Status> {
    if version != THREAD_INFO_VERSION as u64 || output_size != THREAD_INFO_SIZE as u64 {
        return Err(Status::InvalidArgument);
    }
    let id = ThreadId::from_raw(raw_id);
    let thread = process.thread(id).ok_or(Status::InvalidHandle)?;
    let (state, exit_code, fault, fault_code, fault_address) = match thread.state() {
        ThreadState::Ready => (PublicThreadState::Running, 0, 0, 0, 0),
        ThreadState::Blocked => (PublicThreadState::Blocked, 0, 0, 0, 0),
        ThreadState::Exited(code) => (PublicThreadState::Exited, code, 0, 0, 0),
        ThreadState::Faulted(details) => (
            PublicThreadState::Faulted,
            0,
            public_thread_fault(details.reason),
            details.code,
            details.address.unwrap_or(0),
        ),
        ThreadState::Terminated => (PublicThreadState::Terminated, 0, 0, 0, 0),
    };
    let info = ThreadInfo {
        version: THREAD_INFO_VERSION,
        size: THREAD_INFO_SIZE as u32,
        state: state as u32,
        reserved: 0,
        thread_id: ginkgo_sysapi::ThreadId(id.raw()),
        exit_code,
        fault,
        fault_code,
        fault_address,
        cpu_time_ns: thread.cpu_time_ns(),
        preemption_count: thread.preemption_count(),
    };
    copy_to_user(process, output_address, info.as_bytes())
}

fn thread_set_scheduling_class(
    process: &mut Process,
    raw_id: u64,
    raw_class: u64,
) -> Result<(), Status> {
    let public = ThreadSchedulingClass::from_raw(
        u32::try_from(raw_class).map_err(|_| Status::InvalidArgument)?,
    )
    .ok_or(Status::InvalidArgument)?;
    let class = match public {
        ThreadSchedulingClass::Critical => crate::thread_scheduler::SchedulingClass::Critical,
        ThreadSchedulingClass::Audio => crate::thread_scheduler::SchedulingClass::Audio,
        ThreadSchedulingClass::Interactive => crate::thread_scheduler::SchedulingClass::Interactive,
        ThreadSchedulingClass::Normal => crate::thread_scheduler::SchedulingClass::Normal,
        ThreadSchedulingClass::Background => crate::thread_scheduler::SchedulingClass::Background,
    };
    process.set_thread_scheduling_class(ThreadId::from_raw(raw_id), class)
}

fn thread_set_scheduling_class_with_authority(
    process: &mut Process,
    raw_id: u64,
    raw_class: u64,
    raw_authority: u64,
) -> Result<(), Status> {
    let public = ThreadSchedulingClass::from_raw(
        u32::try_from(raw_class).map_err(|_| Status::InvalidArgument)?,
    )
    .ok_or(Status::InvalidArgument)?;
    let class = match public {
        ThreadSchedulingClass::Audio => crate::thread_scheduler::SchedulingClass::Audio,
        ThreadSchedulingClass::Interactive => crate::thread_scheduler::SchedulingClass::Interactive,
        ThreadSchedulingClass::Critical
        | ThreadSchedulingClass::Normal
        | ThreadSchedulingClass::Background => return Err(Status::AccessDenied),
    };
    let authority = decode_handle(raw_authority)?;
    let lease = process
        .handles()
        .scheduling_authority_lease(authority, public)
        .map_err(map_ipc_error)?;
    process.set_thread_scheduling_class_with_authority(ThreadId::from_raw(raw_id), class, lease)
}

fn thread_get_scheduling_info(
    process: &Process,
    raw_id: u64,
    output_address: u64,
    output_size: u64,
    version: u64,
) -> Result<(), Status> {
    if version != THREAD_SCHEDULING_INFO_VERSION as u64
        || output_size != THREAD_SCHEDULING_INFO_SIZE as u64
    {
        return Err(Status::InvalidArgument);
    }
    let (base, effective, budget, metrics, state) = process
        .thread_scheduler_data(ThreadId::from_raw(raw_id))
        .ok_or(Status::InvalidHandle)?;
    let state = match state {
        ThreadState::Ready => PublicThreadState::Running,
        ThreadState::Blocked => PublicThreadState::Blocked,
        ThreadState::Exited(_) => PublicThreadState::Exited,
        ThreadState::Faulted(_) => PublicThreadState::Faulted,
        ThreadState::Terminated => PublicThreadState::Terminated,
    };
    let info = ThreadSchedulingInfo {
        version: THREAD_SCHEDULING_INFO_VERSION,
        size: THREAD_SCHEDULING_INFO_SIZE as u32,
        base_class: base as u32,
        effective_class: effective as u32,
        state: state as u32,
        reserved: 0,
        budget_remaining_ns: budget,
        cpu_time_ns: metrics.cpu_time_ns,
        runnable_wait_ns: metrics.runnable_wait_ns,
        wake_latency_ns: metrics.wake_latency_ns,
        maximum_wake_latency_ns: metrics.maximum_wake_latency_ns,
        wake_latency_samples: metrics.wake_latency_samples,
        wake_latency_target_misses: metrics.wake_latency_target_misses,
        context_switches: metrics.context_switches,
        deadline_misses: metrics.deadline_misses,
        throttling_events: metrics.throttling_events,
        throttled_time_ns: metrics.throttled_time_ns,
    };
    copy_to_user(process, output_address, info.as_bytes())
}

fn public_thread_fault(reason: crate::process::ProcessFaultReason) -> u32 {
    use crate::process::ProcessFaultReason;
    match reason {
        ProcessFaultReason::PageFault => ginkgo_sysapi::ProcessFault::PageFault as u32,
        ProcessFaultReason::GeneralProtection => {
            ginkgo_sysapi::ProcessFault::GeneralProtection as u32
        }
        ProcessFaultReason::InvalidOpcode => ginkgo_sysapi::ProcessFault::InvalidOpcode as u32,
        ProcessFaultReason::InvalidUserContext => {
            ginkgo_sysapi::ProcessFault::InvalidUserContext as u32
        }
        ProcessFaultReason::ResourceLimit => ginkgo_sysapi::ProcessFault::ResourceLimit as u32,
        ProcessFaultReason::OutOfMemory => ginkgo_sysapi::ProcessFault::OutOfMemory as u32,
        ProcessFaultReason::Other(_) => ginkgo_sysapi::ProcessFault::Other as u32,
    }
}

struct ValidatedRequest {
    args: RequestSubmitArgs,
    operation: RequestOperation,
    completion_mode: RequestCompletionMode,
    flags: RequestFlags,
    deadline_ns: Option<u64>,
    target: RequestTarget,
    target_lease: PreparedRequestTarget,
    buffers: Vec<RequestBuffer>,
}

fn request_submit(
    process_id: ProcessId,
    process: &mut Process,
    thread_id: ThreadId,
    requests: &mut RequestBroker,
    args_address: u64,
    output_address: u64,
    now_ns: u64,
) -> DispatchResult {
    let result = (|| {
        validate_user_output(process, output_address, REQUEST_SUBMIT_OUTPUT_SIZE)?;
        let request = copy_and_validate_request(process_id, process, args_address)?;
        if request.operation == RequestOperation::Nop {
            let output = completed_request_output(Status::Ok);
            copy_to_user(process, output_address, output.as_bytes())?;
            return Ok(DispatchResult::Complete(Status::Ok));
        }

        let owner = RequestOwner::new(process_id.raw(), thread_id.raw());
        let mut prepared = prepare_broker_request(process, owner, &request, requests)?;
        if request.completion_mode == RequestCompletionMode::InlineOnly {
            rollback_prepared_buffers(process, &mut prepared.buffers);
            return Ok(DispatchResult::Complete(Status::ShouldWait));
        }

        let output_pages = if request.completion_mode == RequestCompletionMode::Block {
            match process.address_space_mut().pin_user_range(
                output_address,
                REQUEST_SUBMIT_OUTPUT_SIZE,
                UserAccess::Write,
            ) {
                Ok(pages) => Some(pages),
                Err(error) => {
                    rollback_prepared_buffers(process, &mut prepared.buffers);
                    return Err(map_address_space_error(error));
                }
            }
        } else {
            None
        };

        let submission = match requests.submit(prepared, now_ns) {
            Ok(submission) => submission,
            Err(mut failure) => {
                rollback_prepared_buffers(process, &mut failure.request.buffers);
                if let Some(pages) = output_pages.as_deref() {
                    let _ = process.address_space_mut().unpin_user_pages(pages);
                }
                return Err(map_broker_error(failure.error));
            }
        };

        match submission.completion_mode {
            RequestCompletionMode::Handle => {
                let request_handle =
                    match process.handles_mut().request_install(&submission.control) {
                        Ok(handle) => handle,
                        Err(error) => {
                            cancel_broker_submission(requests, submission.id, now_ns);
                            return Err(map_ipc_error(error));
                        }
                    };
                let Some(info) = requests.info(submission.id) else {
                    close_handles(process, core::slice::from_ref(&request_handle));
                    cancel_broker_submission(requests, submission.id, now_ns);
                    return Err(Status::InvalidHandle);
                };
                let output = request_output_from_info(request_handle, info);
                if let Err(status) = copy_to_user(process, output_address, output.as_bytes()) {
                    close_handles(process, core::slice::from_ref(&request_handle));
                    cancel_broker_submission(requests, submission.id, now_ns);
                    return Err(status);
                }
                Ok(DispatchResult::Complete(Status::Ok))
            }
            RequestCompletionMode::Block => {
                let output_pages = output_pages.expect("block output was not pinned");
                let request_handle =
                    match process.handles_mut().request_install(&submission.control) {
                        Ok(handle) => handle,
                        Err(error) => {
                            let _ = process.address_space_mut().unpin_user_pages(&output_pages);
                            cancel_broker_submission(requests, submission.id, now_ns);
                            return Err(map_ipc_error(error));
                        }
                    };
                process.block_thread_request(
                    thread_id,
                    PendingRequest {
                        id: submission.id,
                        output: Some(PendingRequestOutput {
                            address: output_address,
                            pages: output_pages,
                        }),
                        count_output: None,
                        hidden_handle: request_handle,
                        completion: None,
                        return_operation_status: false,
                        registration: None,
                    },
                );
                Ok(DispatchResult::Blocked)
            }
            RequestCompletionMode::InlineOnly => {
                unreachable!("inline-only requests are never submitted to the broker")
            }
        }
    })();

    match result {
        Ok(result) => result,
        Err(status) => DispatchResult::Complete(status),
    }
}

fn request_cancel(
    process: &Process,
    requests: &mut RequestBroker,
    raw_request: u64,
    now_ns: u64,
) -> Result<(), Status> {
    let request = decode_handle(raw_request)?;
    let (control, raw_id) = process
        .handles()
        .request_cancellation_control(request)
        .map_err(map_ipc_error)?;
    requests
        .cancel(RequestId::from_raw(raw_id), now_ns)
        .map_err(map_broker_error)?;
    control.request_cancellation();
    Ok(())
}

fn request_get_info(
    process: &Process,
    raw_request: u64,
    output_address: u64,
    output_size: u64,
    version: u64,
) -> Result<(), Status> {
    if version != REQUEST_INFO_VERSION as u64 || output_size != REQUEST_INFO_SIZE as u64 {
        return Err(Status::InvalidArgument);
    }
    validate_user_output(process, output_address, REQUEST_INFO_SIZE)?;
    let request = decode_handle(raw_request)?;
    let info = process
        .handles()
        .request_info(request)
        .map_err(map_ipc_error)?;
    copy_to_user(process, output_address, info.as_bytes())
}

fn request_get_diagnostics(
    process: &Process,
    requests: &RequestBroker,
    output_address: u64,
    output_size: u64,
    version: u64,
) -> Result<(), Status> {
    if version != REQUEST_DIAGNOSTICS_VERSION as u64
        || output_size != REQUEST_DIAGNOSTICS_SIZE as u64
    {
        return Err(Status::InvalidArgument);
    }
    validate_user_output(process, output_address, REQUEST_DIAGNOSTICS_SIZE)?;
    copy_to_user(process, output_address, requests.diagnostics().as_bytes())
}

fn request_submit_batch(
    process_id: ProcessId,
    process: &mut Process,
    thread_id: ThreadId,
    requests: &mut RequestBroker,
    args_address: u64,
    now_ns: u64,
) -> Result<(), Status> {
    let raw_args = copy_block_from_user::<REQUEST_SUBMIT_BATCH_ARGS_SIZE>(process, args_address)?;
    let version = read_u32(&raw_args, 0);
    let size = read_u32(&raw_args, 4);
    let submissions_address = read_u64(&raw_args, 8);
    let submission_count = read_u32(&raw_args, 16);
    let reserved = read_u32(&raw_args, 20);
    let outputs_address = read_u64(&raw_args, 24);
    if version != REQUEST_SUBMIT_BATCH_ARGS_VERSION
        || size != RequestSubmitBatchArgs::SIZE
        || reserved != 0
        || submission_count == 0
    {
        return Err(Status::InvalidArgument);
    }
    let submissions_len = checked_array_bytes(
        u64::from(submission_count),
        REQUEST_SUBMIT_ARGS_SIZE,
        REQUEST_MAX_BATCH as u64,
        Status::ResourceLimit,
    )?;
    let outputs_len = checked_array_bytes(
        u64::from(submission_count),
        REQUEST_SUBMIT_OUTPUT_SIZE,
        REQUEST_MAX_BATCH as u64,
        Status::ResourceLimit,
    )?;
    if submissions_address == 0 || outputs_address == 0 {
        return Err(Status::InvalidAddress);
    }
    validate_user_output(process, outputs_address, outputs_len)?;
    let raw_submissions = copy_vec_from_user(process, submissions_address, submissions_len)?;

    let count = submission_count as usize;
    let mut validated = Vec::new();
    validated
        .try_reserve_exact(count)
        .map_err(|_| Status::OutOfMemory)?;
    for raw in raw_submissions.chunks_exact(REQUEST_SUBMIT_ARGS_SIZE) {
        let request = parse_and_validate_request(process_id, process, raw)?;
        if request.completion_mode == RequestCompletionMode::Block {
            return Err(Status::InvalidArgument);
        }
        validated.push(request);
    }
    let limits = requests.limits();
    for request in &validated {
        preflight_request_resources(request, limits)?;
    }

    let owner = RequestOwner::new(process_id.raw(), thread_id.raw());
    let mut outputs = Vec::new();
    outputs
        .try_reserve_exact(count)
        .map_err(|_| Status::OutOfMemory)?;
    outputs.resize(count, RequestSubmitOutput::default());
    let mut broker_indices = Vec::new();
    let mut prepared = Vec::new();
    broker_indices
        .try_reserve_exact(count)
        .map_err(|_| Status::OutOfMemory)?;
    prepared
        .try_reserve_exact(count)
        .map_err(|_| Status::OutOfMemory)?;

    for (index, request) in validated.iter().enumerate() {
        if request.operation == RequestOperation::Nop {
            outputs[index] = completed_request_output(Status::Ok);
            continue;
        }
        let mut broker_request = match prepare_broker_request(process, owner, request, requests) {
            Ok(request) => request,
            Err(status) => {
                rollback_prepared_requests(process, &mut prepared);
                return Err(status);
            }
        };
        if request.completion_mode == RequestCompletionMode::InlineOnly {
            rollback_prepared_buffers(process, &mut broker_request.buffers);
            outputs[index] = pending_request_output(Handle::INVALID);
        } else {
            broker_indices.push(index);
            prepared.push(broker_request);
        }
    }

    if prepared.is_empty() {
        return copy_to_user(process, outputs_address, outputs.as_slice().as_bytes());
    }

    let submissions = match requests.submit_batch(prepared, now_ns) {
        Ok(submissions) => submissions,
        Err(mut failure) => {
            rollback_prepared_requests(process, &mut failure.requests);
            return Err(map_broker_error(failure.error));
        }
    };

    let mut installed = Vec::new();
    installed
        .try_reserve_exact(submissions.len())
        .map_err(|_| {
            cancel_broker_submissions(requests, &submissions, now_ns);
            Status::OutOfMemory
        })?;
    for (submission, output_index) in submissions.iter().zip(broker_indices.iter().copied()) {
        let handle = match process.handles_mut().request_install(&submission.control) {
            Ok(handle) => handle,
            Err(error) => {
                close_handles(process, &installed);
                cancel_broker_submissions(requests, &submissions, now_ns);
                return Err(map_ipc_error(error));
            }
        };
        installed.push(handle);
        let Some(info) = requests.info(submission.id) else {
            close_handles(process, &installed);
            cancel_broker_submissions(requests, &submissions, now_ns);
            return Err(Status::InvalidHandle);
        };
        outputs[output_index] = request_output_from_info(handle, info);
    }

    if let Err(status) = copy_to_user(process, outputs_address, outputs.as_slice().as_bytes()) {
        close_handles(process, &installed);
        cancel_broker_submissions(requests, &submissions, now_ns);
        return Err(status);
    }
    Ok(())
}

fn copy_and_validate_request(
    process_id: ProcessId,
    process: &Process,
    address: u64,
) -> Result<ValidatedRequest, Status> {
    let raw = copy_block_from_user::<REQUEST_SUBMIT_ARGS_SIZE>(process, address)?;
    parse_and_validate_request(process_id, process, &raw)
}

fn parse_and_validate_request(
    process_id: ProcessId,
    process: &Process,
    raw: &[u8],
) -> Result<ValidatedRequest, Status> {
    let args = parse_request_submit_args(raw)?;
    let operation = args.operation().ok_or(Status::InvalidArgument)?;
    let completion_mode = args.completion_mode().ok_or(Status::InvalidArgument)?;
    let flags = RequestFlags::from_bits(args.flags).ok_or(Status::InvalidArgument)?;
    let deadline_ns = parse_request_deadline(args.deadline_ns)?;
    validate_public_request_operation(operation)?;
    let buffer_bytes = checked_array_bytes(
        u64::from(args.buffer_count),
        REQUEST_BUFFER_SIZE,
        REQUEST_MAX_BUFFERS as u64,
        Status::ResourceLimit,
    )?;
    if (args.buffer_count == 0) != (args.buffers_address == 0) {
        return Err(Status::InvalidArgument);
    }
    let raw_buffers = copy_vec_from_user(process, args.buffers_address, buffer_bytes)?;
    let mut buffers = Vec::new();
    buffers
        .try_reserve_exact(args.buffer_count as usize)
        .map_err(|_| Status::OutOfMemory)?;
    for raw_buffer in raw_buffers.chunks_exact(REQUEST_BUFFER_SIZE) {
        buffers.push(parse_request_buffer(raw_buffer)?);
    }
    validate_operation_buffers(operation, args.operation_argument, &buffers)?;
    let (target, target_lease) = validate_request_target(
        process_id,
        process,
        args.target,
        operation,
        args.operation_argument,
    )?;
    Ok(ValidatedRequest {
        args,
        operation,
        completion_mode,
        flags,
        deadline_ns,
        target,
        target_lease,
        buffers,
    })
}

fn parse_request_submit_args(raw: &[u8]) -> Result<RequestSubmitArgs, Status> {
    if raw.len() != REQUEST_SUBMIT_ARGS_SIZE {
        return Err(Status::InvalidArgument);
    }
    let args = RequestSubmitArgs {
        version: read_u32(raw, 0),
        size: read_u32(raw, 4),
        target: Handle::from_raw(read_u32(raw, 8)),
        operation: read_u32(raw, 12),
        completion_mode: read_u32(raw, 16),
        flags: read_u32(raw, 20),
        buffers_address: read_u64(raw, 24),
        buffer_count: read_u32(raw, 32),
        reserved: read_u32(raw, 36),
        operation_argument: read_u64(raw, 40),
        deadline_ns: read_i64(raw, 48),
        user_data: read_u64(raw, 56),
    };
    if args.version != REQUEST_SUBMIT_ARGS_VERSION
        || args.size != RequestSubmitArgs::SIZE
        || args.reserved != 0
    {
        return Err(Status::InvalidArgument);
    }
    Ok(args)
}

fn parse_request_buffer(raw: &[u8]) -> Result<RequestBuffer, Status> {
    if raw.len() != REQUEST_BUFFER_SIZE {
        return Err(Status::InvalidArgument);
    }
    let buffer = RequestBuffer {
        kind: read_u32(raw, 0),
        flags: read_u32(raw, 4),
        address: read_u64(raw, 8),
        length: read_u64(raw, 16),
        handle: Handle::from_raw(read_u32(raw, 24)),
        reserved: read_u32(raw, 28),
        offset: read_u64(raw, 32),
    };
    let kind = buffer.buffer_kind().ok_or(Status::InvalidArgument)?;
    let flags = RequestBufferFlags::from_bits(buffer.flags).ok_or(Status::InvalidArgument)?;
    if flags.is_empty() || buffer.length == 0 || buffer.reserved != 0 {
        return Err(Status::InvalidArgument);
    }
    match kind {
        RequestBufferKind::Copy | RequestBufferKind::Pinned => {
            if buffer.address == 0 || buffer.handle.is_valid() || buffer.offset != 0 {
                return Err(Status::InvalidArgument);
            }
        }
        RequestBufferKind::SharedMemory => {
            if buffer.address != 0 || !buffer.handle.is_valid() {
                return Err(Status::InvalidArgument);
            }
        }
    }
    Ok(buffer)
}

fn parse_request_deadline(raw: i64) -> Result<Option<u64>, Status> {
    if raw == DEADLINE_INFINITE {
        Ok(None)
    } else if raw < 0 {
        Err(Status::InvalidArgument)
    } else {
        Ok(Some(raw as u64))
    }
}

const fn validate_public_request_operation(operation: RequestOperation) -> Result<(), Status> {
    match operation {
        RequestOperation::FilesystemOpen
        | RequestOperation::FilesystemTruncate
        | RequestOperation::FilesystemNamespace => Err(Status::AccessDenied),
        RequestOperation::Nop
        | RequestOperation::FilesystemRead
        | RequestOperation::FilesystemWrite
        | RequestOperation::FilesystemSync
        | RequestOperation::AudioWrite => Ok(()),
        RequestOperation::Synthetic => {
            #[cfg(ginkgo_request_smoke)]
            {
                Ok(())
            }
            #[cfg(not(ginkgo_request_smoke))]
            {
                Err(Status::AccessDenied)
            }
        }
    }
}

fn validate_operation_buffers(
    operation: RequestOperation,
    operation_argument: u64,
    buffers: &[RequestBuffer],
) -> Result<(), Status> {
    let exact_flags = |buffer: &RequestBuffer, expected: RequestBufferFlags| {
        RequestBufferFlags::from_bits(buffer.flags) == Some(expected)
    };
    match operation {
        RequestOperation::Nop => {
            if !buffers.is_empty() || operation_argument != 0 {
                return Err(Status::InvalidArgument);
            }
        }
        RequestOperation::FilesystemRead => {
            if buffers.len() != 1 || !exact_flags(&buffers[0], RequestBufferFlags::WRITE) {
                return Err(Status::InvalidArgument);
            }
        }
        RequestOperation::FilesystemWrite | RequestOperation::AudioWrite => {
            if buffers.len() != 1 || !exact_flags(&buffers[0], RequestBufferFlags::READ) {
                return Err(Status::InvalidArgument);
            }
        }
        RequestOperation::FilesystemSync => {
            if !buffers.is_empty() || operation_argument != 0 {
                return Err(Status::InvalidArgument);
            }
        }
        RequestOperation::FilesystemOpen
        | RequestOperation::FilesystemTruncate
        | RequestOperation::FilesystemNamespace => return Err(Status::AccessDenied),
        RequestOperation::Synthetic => {}
    }
    Ok(())
}

fn validate_request_target(
    process_id: ProcessId,
    process: &Process,
    target: Handle,
    operation: RequestOperation,
    operation_argument: u64,
) -> Result<(RequestTarget, PreparedRequestTarget), Status> {
    match operation {
        RequestOperation::Nop => {
            if target.is_valid() {
                return Err(Status::InvalidArgument);
            }
            Ok((RequestTarget(0), PreparedRequestTarget::None))
        }
        RequestOperation::FilesystemRead => {
            let file = process
                .handles()
                .filesystem_file(target, Rights::READ)
                .map_err(map_ipc_error)?;
            Ok((
                filesystem_request_target(file.node_id(), file.generation()),
                PreparedRequestTarget::File(FileCapabilityLease::new(file)),
            ))
        }
        RequestOperation::FilesystemWrite => {
            let file = process
                .handles()
                .filesystem_file(target, Rights::WRITE)
                .map_err(map_ipc_error)?;
            Ok((
                filesystem_request_target(file.node_id(), file.generation()),
                PreparedRequestTarget::File(FileCapabilityLease::new(file)),
            ))
        }
        RequestOperation::FilesystemSync => {
            let object_type = process
                .handles()
                .object_type(target)
                .map_err(map_ipc_error)?;
            match object_type {
                ObjectType::FilesystemRoot => {
                    process
                        .handles()
                        .filesystem_root(target, Rights::WRITE)
                        .map_err(map_ipc_error)?;
                    Ok((
                        RequestTarget(REQUEST_TARGET_FILESYSTEM_ROOT),
                        PreparedRequestTarget::FilesystemSync,
                    ))
                }
                ObjectType::Directory => {
                    let directory = process
                        .handles()
                        .filesystem_directory(target, Rights::WRITE)
                        .map_err(map_ipc_error)?;
                    Ok((
                        filesystem_request_target(directory.node_id(), directory.generation()),
                        PreparedRequestTarget::FilesystemSync,
                    ))
                }
                ObjectType::File => {
                    let file = process
                        .handles()
                        .filesystem_file(target, Rights::WRITE)
                        .map_err(map_ipc_error)?;
                    Ok((
                        filesystem_request_target(file.node_id(), file.generation()),
                        PreparedRequestTarget::FilesystemSync,
                    ))
                }
                _ => Err(Status::WrongObjectType),
            }
        }
        RequestOperation::AudioWrite => {
            if target.is_valid() {
                return Err(Status::InvalidArgument);
            }
            Ok((
                RequestTarget(REQUEST_TARGET_AUDIO),
                PreparedRequestTarget::None,
            ))
        }
        RequestOperation::FilesystemOpen
        | RequestOperation::FilesystemTruncate
        | RequestOperation::FilesystemNamespace => Err(Status::AccessDenied),
        RequestOperation::Synthetic => {
            if target.is_valid() {
                return Err(Status::InvalidArgument);
            }
            let identity = process_id.raw()
                ^ REQUEST_TARGET_SYNTHETIC_TAG
                ^ operation_argument.rotate_left(17);
            Ok((
                RequestTarget(if identity == 0 {
                    REQUEST_TARGET_SYNTHETIC_TAG
                } else {
                    identity
                }),
                PreparedRequestTarget::None,
            ))
        }
    }
}

fn filesystem_request_target(node_id: u32, generation: u32) -> RequestTarget {
    RequestTarget((u64::from(generation) << 32) | u64::from(node_id))
}

fn prepare_broker_request(
    process: &mut Process,
    owner: RequestOwner,
    request: &ValidatedRequest,
    requests: &RequestBroker,
) -> Result<PreparedBrokerRequest, Status> {
    let limits = requests.limits();
    preflight_request_resources(request, limits)?;
    let mut buffers = Vec::new();
    buffers
        .try_reserve_exact(request.buffers.len())
        .map_err(|_| Status::OutOfMemory)?;
    for descriptor in &request.buffers {
        let prepared = match prepare_request_buffer(process, owner, descriptor) {
            Ok(buffer) => buffer,
            Err(status) => {
                rollback_prepared_buffers(process, &mut buffers);
                return Err(status);
            }
        };
        buffers.push(prepared);
    }
    let mut prepared = PreparedBrokerRequest {
        owner,
        target: request.target,
        target_lease: copy_prepared_request_target(&request.target_lease),
        device: None,
        operation: request.operation,
        completion_mode: request.completion_mode,
        payload: BrokerPayload {
            operation_argument: request.args.operation_argument,
            user_data: request.args.user_data,
            request_flags: request.flags,
        },
        deadline_ns: request.deadline_ns,
        buffers,
    };
    #[cfg(ginkgo_request_smoke)]
    if request.operation == RequestOperation::Synthetic {
        let raw_device = request.target.0 as u32;
        prepared.device = Some(crate::request::RequestDevice(if raw_device == 0 {
            u32::MAX
        } else {
            raw_device
        }));
    }
    if let Err(error) = prepared.resources() {
        rollback_prepared_buffers(process, &mut prepared.buffers);
        return Err(map_broker_error(error));
    }
    Ok(prepared)
}

fn copy_prepared_request_target(target: &PreparedRequestTarget) -> PreparedRequestTarget {
    match target {
        PreparedRequestTarget::None => PreparedRequestTarget::None,
        PreparedRequestTarget::File(lease) => {
            PreparedRequestTarget::File(FileCapabilityLease::new(*lease.file()))
        }
        PreparedRequestTarget::Directory {
            directory,
            is_root,
            rights,
        } => PreparedRequestTarget::Directory {
            directory: *directory,
            is_root: *is_root,
            rights: *rights,
        },
        PreparedRequestTarget::FilesystemSync => PreparedRequestTarget::FilesystemSync,
    }
}

fn preflight_request_resources(
    request: &ValidatedRequest,
    limits: crate::request::RequestLimits,
) -> Result<(), Status> {
    let mut copied_bytes = 0usize;
    let mut pinned_pages = 0usize;
    let mut shared_bytes = 0usize;
    for descriptor in &request.buffers {
        let length = usize::try_from(descriptor.length).map_err(|_| Status::OutOfRange)?;
        match descriptor.buffer_kind().ok_or(Status::InvalidArgument)? {
            RequestBufferKind::Copy => {
                descriptor
                    .address
                    .checked_add(descriptor.length - 1)
                    .ok_or(Status::OutOfRange)?;
                copied_bytes = copied_bytes.checked_add(length).ok_or(Status::OutOfRange)?;
            }
            RequestBufferKind::Pinned => {
                let end = descriptor
                    .address
                    .checked_add(descriptor.length - 1)
                    .ok_or(Status::OutOfRange)?;
                let first_page = descriptor.address / PAGE_SIZE;
                let final_page = end / PAGE_SIZE;
                let pages =
                    usize::try_from(final_page - first_page + 1).map_err(|_| Status::OutOfRange)?;
                pinned_pages = pinned_pages.checked_add(pages).ok_or(Status::OutOfRange)?;
            }
            RequestBufferKind::SharedMemory => {
                descriptor
                    .offset
                    .checked_add(descriptor.length)
                    .ok_or(Status::OutOfRange)?;
                shared_bytes = shared_bytes.checked_add(length).ok_or(Status::OutOfRange)?;
            }
        }
    }
    if copied_bytes > limits.copied_bytes_per_request
        || pinned_pages > limits.pinned_pages_per_request
        || shared_bytes > limits.shared_bytes_per_request
    {
        return Err(Status::ResourceLimit);
    }
    Ok(())
}

fn prepare_request_buffer(
    process: &mut Process,
    owner: RequestOwner,
    descriptor: &RequestBuffer,
) -> Result<PreparedRequestBuffer, Status> {
    let flags = RequestBufferFlags::from_bits(descriptor.flags).ok_or(Status::InvalidArgument)?;
    let length = usize::try_from(descriptor.length).map_err(|_| Status::OutOfRange)?;
    match descriptor.buffer_kind().ok_or(Status::InvalidArgument)? {
        RequestBufferKind::Copy => {
            if flags.contains(RequestBufferFlags::WRITE) {
                validate_user_output(process, descriptor.address, length)?;
            }
            let bytes = if flags.contains(RequestBufferFlags::READ) {
                copy_vec_from_user(process, descriptor.address, length)?
            } else {
                zeroed_vec(length)?
            };
            Ok(PreparedRequestBuffer::Copied {
                flags,
                user_address: descriptor.address,
                bytes,
            })
        }
        RequestBufferKind::Pinned => {
            let access = if flags.contains(RequestBufferFlags::WRITE) {
                UserAccess::Write
            } else {
                UserAccess::Read
            };
            let pages = process
                .address_space_mut()
                .pin_user_range(descriptor.address, length, access)
                .map_err(map_address_space_error)?;
            Ok(PreparedRequestBuffer::Pinned {
                flags,
                owner_process_id: owner.process_id,
                pages,
            })
        }
        RequestBufferKind::SharedMemory => {
            let offset = usize::try_from(descriptor.offset).map_err(|_| Status::OutOfRange)?;
            let rights = request_buffer_rights(flags);
            let lease = process
                .handles()
                .shared_memory_request_lease(descriptor.handle, offset, length, rights)
                .map_err(map_ipc_error)?;
            Ok(PreparedRequestBuffer::SharedMemory { flags, lease })
        }
    }
}

fn request_buffer_rights(flags: RequestBufferFlags) -> Rights {
    let mut rights = Rights::empty();
    if flags.contains(RequestBufferFlags::READ) {
        rights |= Rights::READ;
    }
    if flags.contains(RequestBufferFlags::WRITE) {
        rights |= Rights::WRITE;
    }
    rights
}

fn rollback_prepared_requests(process: &mut Process, requests: &mut Vec<PreparedBrokerRequest>) {
    while let Some(mut request) = requests.pop() {
        rollback_prepared_buffers(process, &mut request.buffers);
    }
}

fn rollback_prepared_buffers(process: &mut Process, buffers: &mut Vec<PreparedRequestBuffer>) {
    while let Some(buffer) = buffers.pop() {
        if let PreparedRequestBuffer::Pinned { pages, .. } = buffer {
            let result = process.address_space_mut().unpin_user_pages(&pages);
            debug_assert!(result.is_ok(), "prepared request pin rollback failed");
        }
    }
}

fn cancel_broker_submission(requests: &mut RequestBroker, id: RequestId, now_ns: u64) {
    let _ = requests.cancel(id, now_ns);
}

fn cancel_broker_submissions(
    requests: &mut RequestBroker,
    submissions: &[crate::request_broker::BrokerSubmission],
    now_ns: u64,
) {
    for submission in submissions {
        cancel_broker_submission(requests, submission.id, now_ns);
    }
}

fn completed_request_output(status: Status) -> RequestSubmitOutput {
    RequestSubmitOutput {
        request: Handle::INVALID,
        state: RequestState::Completed as u32,
        result: status.raw(),
        result_flags: RequestResultFlags::empty().bits(),
        bytes_transferred: 0,
    }
}

fn pending_request_output(request: Handle) -> RequestSubmitOutput {
    RequestSubmitOutput {
        request,
        state: RequestState::Pending as u32,
        result: Status::ShouldWait.raw(),
        result_flags: RequestResultFlags::empty().bits(),
        bytes_transferred: 0,
    }
}

fn request_output_from_info(request: Handle, info: RequestInfo) -> RequestSubmitOutput {
    RequestSubmitOutput {
        request,
        state: info.state,
        result: info.result,
        result_flags: info.result_flags,
        bytes_transferred: info.bytes_transferred,
    }
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
    thread_id: ThreadId,
    args_address: u64,
    output_address: u64,
    now_ns: u64,
) -> DispatchResult {
    match submit_wait_many(process, thread_id, args_address, output_address, now_ns) {
        Ok(result) => result,
        Err(status) => DispatchResult::Complete(status),
    }
}

fn submit_wait_many(
    process: &mut Process,
    thread_id: ThreadId,
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

    process.block_thread_wait_many(
        thread_id,
        PendingWaitMany {
            items,
            encoded_items,
            items_address,
            output_address,
            deadline,
            completion: None,
            registration: None,
        },
    );
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
pub fn poll_blocked(
    process: &mut Process,
    thread_id: ThreadId,
    now_ns: u64,
    requests: &RequestBroker,
) -> BlockedPoll {
    match process.blocked_kind(thread_id) {
        Some(BlockedKind::Sleep) => {
            return if process.poll_sleep(thread_id, now_ns) == Some(true) {
                BlockedPoll::Complete
            } else {
                BlockedPoll::Pending
            };
        }
        Some(BlockedKind::Join) => {
            return if process.poll_join(thread_id, now_ns) == Some(true) {
                BlockedPoll::Complete
            } else {
                BlockedPoll::Pending
            };
        }
        Some(BlockedKind::Request) => {
            let Some(id) = process.blocked_request_id(thread_id) else {
                return BlockedPoll::Pending;
            };
            let output = match requests.info(id) {
                Some(info) if request_state_is_terminal(info.state) => {
                    request_output_from_info(Handle::INVALID, info)
                }
                Some(_) => return BlockedPoll::Pending,
                None => RequestSubmitOutput {
                    request: Handle::INVALID,
                    state: RequestState::Failed as u32,
                    result: Status::InvalidHandle.raw(),
                    result_flags: 0,
                    bytes_transferred: 0,
                },
            };
            process.stage_request_completion(thread_id, id, output);
            return BlockedPoll::Complete;
        }
        Some(BlockedKind::WaitMany) => {}
        None => return BlockedPoll::Pending,
    }
    let (handles, wait) = process.blocked_thread_wait_many_parts(thread_id);
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
pub fn complete_blocked(
    process: &mut Process,
    thread_id: ThreadId,
    allocator: &mut UsableFrameAllocator<'_>,
) -> Status {
    if process.blocked_kind(thread_id) == Some(BlockedKind::Sleep) {
        return process
            .complete_sleep(thread_id)
            .err()
            .unwrap_or(Status::Ok);
    }
    if process.blocked_kind(thread_id) == Some(BlockedKind::Request) {
        let mut request = match process.take_completed_request(thread_id) {
            Ok(request) => request,
            Err(status) => return status,
        };
        let completion = request
            .completion
            .expect("blocked request completion was not staged by poll_blocked");
        let operation_status = completion.result_status().unwrap_or(Status::InvalidMessage);
        let mut completion_copy_status = Status::Ok;
        if let Some(mut pending_output) = request.output.take() {
            completion_copy_status = if process.address_space().is_active() {
                copy_to_user(process, pending_output.address, completion.as_bytes())
                    .err()
                    .unwrap_or(Status::Ok)
            } else {
                Status::InvalidAddress
            };
            if process
                .address_space_mut()
                .unpin_user_pages(&pending_output.pages)
                .is_err()
                && completion_copy_status == Status::Ok
            {
                completion_copy_status = Status::InvalidAddress;
            }
            pending_output.pages.clear();
        }
        if let Some(mut count_output) = request.count_output.take() {
            debug_assert!(request.return_operation_status);
            let output = FilesystemReadOutput {
                count: completion.bytes_transferred,
            };
            let count_copy_status = if process.address_space().is_active() {
                copy_to_user(process, count_output.address, &output.count.to_le_bytes())
                    .err()
                    .unwrap_or(Status::Ok)
            } else {
                Status::InvalidAddress
            };
            if completion_copy_status == Status::Ok {
                completion_copy_status = count_copy_status;
            }
            if process
                .address_space_mut()
                .unpin_user_pages(&count_output.pages)
                .is_err()
                && completion_copy_status == Status::Ok
            {
                completion_copy_status = Status::InvalidAddress;
            }
            count_output.pages.clear();
        }
        let mut status = blocked_request_return_status(
            request.return_operation_status,
            operation_status,
            completion_copy_status,
        );
        let _ = process.handles_mut().handle_close(request.hidden_handle);
        if let Err(finish_status) = process.finish_request(thread_id) {
            if status == Status::Ok {
                status = finish_status;
            }
        }
        set_status(
            process
                .thread_context_mut(thread_id)
                .expect("requesting thread disappeared before completion"),
            status,
        );
        return status;
    }
    if process.blocked_kind(thread_id) == Some(BlockedKind::Join) {
        let join = match process.take_completed_join(thread_id) {
            Ok(join) => join,
            Err(status) => return status,
        };
        let mut status = join.completion.unwrap_or(Status::ShouldWait);
        if status == Status::Ok {
            status = thread_get_info(
                process,
                join.target.raw(),
                join.output_address,
                THREAD_INFO_SIZE as u64,
                THREAD_INFO_VERSION as u64,
            )
            .and_then(|()| process.reap_thread(join.target, allocator))
            .err()
            .unwrap_or(Status::Ok);
        }
        process.release_join_claim(join.target, thread_id);
        let _ = process.finish_join(thread_id);
        set_status(
            process
                .thread_context_mut(thread_id)
                .expect("joining thread disappeared before completion"),
            status,
        );
        return status;
    }
    let mut wait = process.take_blocked_thread_wait_many(thread_id);
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

    set_status(
        process
            .thread_context_mut(thread_id)
            .expect("blocked thread disappeared before completion"),
        status,
    );
    process.resume_thread_from_block(thread_id);
    status
}

const fn blocked_request_return_status(
    return_operation_status: bool,
    operation_status: Status,
    completion_copy_status: Status,
) -> Status {
    if return_operation_status {
        operation_status
    } else {
        completion_copy_status
    }
}

fn request_state_is_terminal(raw_state: u32) -> bool {
    matches!(
        RequestState::from_raw(raw_state),
        Some(
            RequestState::Completed
                | RequestState::TimedOut
                | RequestState::Canceled
                | RequestState::Failed
                | RequestState::OwnerTerminated
        )
    )
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

fn memory_get_info(
    process: &Process,
    output_address: u64,
    raw_size: u64,
    raw_version: u64,
    frame_allocator: &UsableFrameAllocator<'_>,
    kernel_heap: KernelHeapStats,
    shared_frame_arena: &SharedFrameArena,
) -> Result<(), Status> {
    let output_size = validate_memory_info_query(raw_version, raw_size)?;
    validate_user_output(process, output_address, output_size)?;

    let frames = frame_allocator.stats();
    let limits = process.limits();
    let usage = process.usage();
    let details = process.memory_observability();
    let arena = shared_frame_arena.stats();
    let shared = shared_memory_backing_stats();
    let info = MemoryInfo {
        version: raw_version as u32,
        size: output_size as u32,
        total_eligible_frames: frames.total_eligible_frames,
        total_eligible_bytes: frames.total_eligible_bytes,
        below_4g_frames: frames.below_4g_frames,
        above_4g_frames: frames.above_4g_frames,
        highest_usable_address: frames.highest_usable_address,
        highest_issued_address: frames.highest_issued_address,
        fresh_issued_frames: frames.fresh_issued_frames,
        fresh_remaining_frames: frames.fresh_remaining_frames,
        available_frames: frames.available_frames,
        available_bytes: frames.available_bytes,
        live_allocated_frames: frames.live_allocated_frames,
        reclaimed_free_frames: frames.reclaimed_free_frames,
        reserved_eligible_frames: frames.reserved_eligible_frames,
        dma_low_allocations: frames.dma_low_allocations,
        dma_low_live_frames: frames.dma_low_live_frames,
        dma_low_failures: frames.dma_low_failures,
        allocation_failures: frames.allocation_failures,
        kernel_heap_committed_bytes: kernel_heap.committed_bytes,
        kernel_heap_available_bytes: kernel_heap.available_bytes,
        kernel_heap_growth_failures: kernel_heap.growth_failures,
        private_page_limit: limits.private_pages,
        shared_memory_byte_limit: limits.shared_memory_bytes,
        mapped_shared_byte_limit: limits.mapped_shared_bytes,
        reserved_virtual_byte_limit: limits.reserved_virtual_bytes,
        vma_limit: limits.vma_count,
        executable_image_page_limit: limits.executable_image_pages,
        executable_source_byte_limit: limits.executable_source_bytes,
        reserved_virtual_bytes: usage.reserved_virtual_bytes,
        committed_private_pages: usage.private_pages,
        resident_owned_frames: usage.resident_owned_frames,
        shared_memory_bytes: usage.shared_memory_bytes,
        mapped_shared_pages: usage.mapped_shared_pages,
        mapped_shared_bytes: usage.mapped_shared_bytes,
        quota_failures: usage.quota_failures,
        oom_failures: usage.oom_failures,
        current_vma_count: details.current_vma_count,
        page_table_frames: details.page_table_frames,
        committed_image_pages: details.committed_image_pages,
        committed_stack_pages: details.committed_stack_pages,
        committed_anonymous_pages: details.committed_anonymous_pages,
        committed_file_backed_pages: details.committed_file_backed_pages,
        shared_arena_owned_frames: arena.owned_frames as u64,
        shared_arena_free_frames: arena.free_frames as u64,
        shared_arena_returned_frames: arena.returned_frames as u64,
        shared_arena_reclaimed_frames: arena.reclaimed_frames as u64,
        shared_arena_reclaim_failures: arena.reclaim_failures as u64,
        system_shared_live_objects: shared.live_objects as u64,
        system_shared_logical_bytes: shared.logical_bytes as u64,
        system_shared_backing_bytes: shared.mapped_allocated_bytes as u64,
    };
    copy_to_user(process, output_address, &info.as_bytes()[..output_size])
}

const fn validate_memory_info_query(raw_version: u64, raw_size: u64) -> Result<usize, Status> {
    let expected = match raw_version {
        version if version == MEMORY_INFO_VERSION_V1 as u64 => MEMORY_INFO_V1_SIZE as u64,
        version if version == MEMORY_INFO_VERSION as u64 => MemoryInfo::SIZE as u64,
        _ => return Err(Status::InvalidArgument),
    };
    if raw_size < expected {
        return Err(Status::BufferTooSmall);
    }
    if raw_size != expected {
        return Err(Status::InvalidArgument);
    }
    Ok(expected as usize)
}

fn virtual_query(
    process: &Process,
    address: u64,
    output_address: u64,
    raw_version: u64,
    raw_size: u64,
) -> Result<(), Status> {
    validate_virtual_query(raw_version, raw_size, address)?;
    validate_user_output(process, output_address, VIRTUAL_AREA_INFO_SIZE)?;
    let info = process.virtual_query(address).ok_or(Status::NotFound)?;
    copy_to_user(process, output_address, info.as_bytes())
}

const fn validate_virtual_query(
    raw_version: u64,
    raw_size: u64,
    address: u64,
) -> Result<(), Status> {
    if raw_version != VIRTUAL_AREA_INFO_VERSION as u64 {
        return Err(Status::InvalidArgument);
    }
    if raw_size < VirtualAreaInfo::SIZE as u64 {
        return Err(Status::BufferTooSmall);
    }
    if raw_size != VirtualAreaInfo::SIZE as u64 {
        return Err(Status::InvalidArgument);
    }
    if !Process::is_user_virtual_address(address) {
        return Err(Status::InvalidAddress);
    }
    Ok(())
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

fn page_rounded_shared_backing_bytes(logical_bytes: usize) -> Result<usize, Status> {
    if logical_bytes == 0 {
        return Ok(0);
    }
    logical_bytes
        .checked_add(crate::memory::PAGE_SIZE as usize - 1)
        .map(|bytes| bytes / crate::memory::PAGE_SIZE as usize * crate::memory::PAGE_SIZE as usize)
        .ok_or(Status::OutOfRange)
}

fn shared_memory_create(
    process: &mut Process,
    raw_size: u64,
    output_address: u64,
    shared_frame_arena: &SharedFrameArena,
    kernel_page_table: &ActivePageTable,
    frame_allocator: &mut UsableFrameAllocator<'_>,
) -> Result<(), Status> {
    let size = usize::try_from(raw_size).map_err(|_| Status::OutOfRange)?;
    let backing_bytes = page_rounded_shared_backing_bytes(size)?;
    if backing_bytes != 0 && !process.can_allocate_shared_memory(backing_bytes) {
        process.record_quota_failure();
        return Err(Status::ResourceLimit);
    }
    validate_user_output(process, output_address, HANDLE_OUTPUT_SIZE)?;
    let mut factory =
        SharedMemoryFactory::new(shared_frame_arena, frame_allocator, kernel_page_table);
    let handle = match factory.create_handle(process.handles_mut(), size) {
        Ok(handle) => handle,
        Err(error) => return Err(map_ipc_error(error)),
    };
    process.record_shared_memory_allocation(backing_bytes);
    let output = encode_handle_output(handle);
    if let Err(status) = copy_to_user(process, output_address, &output) {
        close_handles(process, core::slice::from_ref(&handle));
        process.release_shared_memory_charge(backing_bytes);
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
    frame_allocator: &mut UsableFrameAllocator<'_>,
) -> Result<(), Status> {
    let handle = decode_handle(raw_handle)?;
    let raw_args = copy_block_from_user::<SHARED_MEMORY_MAP_ARGS_SIZE>(process, args_address)?;
    let args = parse_shared_memory_map_args(&raw_args)?;
    validate_user_output(process, output_address, SHARED_MEMORY_MAP_OUTPUT_SIZE)?;

    let mapped_address = match process.map_shared_memory(handle, args, frame_allocator) {
        Ok(address) => address,
        Err(error) => return Err(map_shared_mapping_error(error)),
    };
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
    let address = match process.map_anonymous(length, protection, frame_allocator) {
        Ok(address) => address,
        Err(error) => return Err(map_shared_mapping_error(error)),
    };
    if let Err(status) = copy_to_user(process, output_address, &address.to_le_bytes()) {
        process
            .unmap_anonymous(address, length, frame_allocator)
            .map_err(map_shared_mapping_error)?;
        return Err(status);
    }
    Ok(())
}

fn anonymous_reserve(
    process: &mut Process,
    length: u64,
    raw_protection: u64,
    output_address: u64,
) -> Result<(), Status> {
    let protection_bits = u32::try_from(raw_protection).map_err(|_| Status::InvalidArgument)?;
    let protection = MapProtection::from_bits(protection_bits).ok_or(Status::InvalidArgument)?;
    validate_user_output(process, output_address, SHARED_MEMORY_MAP_OUTPUT_SIZE)?;
    let (address, rollback) = process
        .reserve_anonymous_with_rollback(length, protection)
        .map_err(map_shared_mapping_error)?;
    if let Err(status) = copy_to_user(process, output_address, &address.to_le_bytes()) {
        process.rollback_anonymous_reservation(rollback);
        return Err(status);
    }
    Ok(())
}

fn anonymous_commit(
    process: &mut Process,
    address: u64,
    length: u64,
    frame_allocator: &mut UsableFrameAllocator<'_>,
) -> Result<(), Status> {
    process
        .commit_anonymous(address, length, frame_allocator)
        .map_err(map_shared_mapping_error)
}

fn anonymous_decommit(
    process: &mut Process,
    address: u64,
    length: u64,
    frame_allocator: &mut UsableFrameAllocator<'_>,
) -> Result<(), Status> {
    process
        .decommit_anonymous(address, length, frame_allocator)
        .map_err(map_shared_mapping_error)
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

fn virtual_map_file<B: Disk>(
    process: &mut Process,
    filesystem: &mut RedoxFs<B>,
    raw_file: u64,
    args_address: u64,
    output_address: u64,
    frame_allocator: &mut UsableFrameAllocator<'_>,
) -> Result<(), Status> {
    let handle = decode_handle(raw_file)?;
    let raw_args = copy_block_from_user::<SHARED_MEMORY_MAP_ARGS_SIZE>(process, args_address)?;
    let shared = parse_shared_memory_map_args(&raw_args)?;
    let args = VirtualMapFileArgs {
        address: shared.address,
        offset: shared.offset,
        length: shared.length,
        protection: shared.protection,
        flags: shared.flags,
    };
    validate_user_output(process, output_address, SHARED_MEMORY_MAP_OUTPUT_SIZE)?;
    let rights = process
        .handles()
        .handle_rights(handle)
        .map_err(map_ipc_error)?;
    let mut required = Rights::READ;
    if args.protection.contains(MapProtection::WRITE) {
        required |= Rights::WRITE;
    }
    if args.protection.contains(MapProtection::EXECUTE) {
        required |= Rights::EXECUTE;
    }
    let file = process
        .handles()
        .filesystem_file(handle, required)
        .map_err(map_ipc_error)?;
    let max_protection = file_max_protection(rights).map_err(map_shared_mapping_error)?;
    let file_length = filesystem.stat(file).map_err(map_fs_error)?.len;
    let address = process
        .map_file_backed(
            file,
            file_length,
            max_protection,
            args,
            frame_allocator,
            |offset, bytes| {
                filesystem
                    .read(file, offset, bytes)
                    .map_err(|_| SharedMappingError::Io)
            },
        )
        .map_err(map_shared_mapping_error)?;
    if let Err(status) = copy_to_user(process, output_address, &address.to_le_bytes()) {
        process
            .unmap_file_backed(address, args.length, frame_allocator)
            .map_err(map_shared_mapping_error)?;
        return Err(status);
    }
    Ok(())
}

fn virtual_commit<B: Disk>(
    process: &mut Process,
    filesystem: &mut RedoxFs<B>,
    address: u64,
    length: u64,
    frame_allocator: &mut UsableFrameAllocator<'_>,
) -> Result<(), Status> {
    process
        .commit_file_backed(address, length, frame_allocator, |file, offset, bytes| {
            filesystem
                .read(file, offset, bytes)
                .map_err(|_| SharedMappingError::Io)
        })
        .map_err(map_shared_mapping_error)
}

fn virtual_protect(
    process: &mut Process,
    address: u64,
    length: u64,
    raw_protection: u64,
) -> Result<(), Status> {
    let bits = u32::try_from(raw_protection).map_err(|_| Status::InvalidArgument)?;
    let protection = MapProtection::from_bits(bits).ok_or(Status::InvalidArgument)?;
    process
        .protect_file_backed(address, length, protection)
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ParsedFilesystemOpenArgs {
    path_address: u64,
    path_length: u64,
    flags: FilesystemOpenFlags,
}

fn parse_filesystem_open_args(raw: &[u8]) -> Result<ParsedFilesystemOpenArgs, Status> {
    if raw.len() != FILESYSTEM_OPEN_ARGS_SIZE {
        return Err(Status::InvalidArgument);
    }
    let flags = FilesystemOpenFlags::from_bits(read_u32(raw, 16)).ok_or(Status::InvalidArgument)?;
    let execute = flags.contains(FilesystemOpenFlags::EXECUTE);
    if read_u32(raw, 20) != 0
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
    Ok(ParsedFilesystemOpenArgs {
        path_address: read_u64(raw, 0),
        path_length: read_u64(raw, 8),
        flags,
    })
}

fn filesystem_open_required_rights(flags: FilesystemOpenFlags) -> Rights {
    let mut required = Rights::READ;
    if flags.contains(FilesystemOpenFlags::EXECUTE) {
        required |= Rights::EXECUTE;
    }
    if flags.intersects(
        FilesystemOpenFlags::WRITE | FilesystemOpenFlags::CREATE | FilesystemOpenFlags::TRUNCATE,
    ) {
        required |= Rights::WRITE;
    }
    required
}

fn directory_request_target(directory: Option<DirectoryHandle>) -> RequestTarget {
    match directory {
        Some(directory) => filesystem_request_target(directory.node_id(), directory.generation()),
        None => RequestTarget(REQUEST_TARGET_FILESYSTEM_ROOT),
    }
}

fn prepare_filesystem_open_broker_request(
    owner: RequestOwner,
    anchor: DirectoryAnchor,
    flags: FilesystemOpenFlags,
    buffers: Vec<PreparedRequestBuffer>,
) -> PreparedBrokerRequest {
    let directory = if anchor.is_root {
        None
    } else {
        Some(anchor.directory)
    };
    PreparedBrokerRequest {
        owner,
        target: directory_request_target(directory),
        target_lease: PreparedRequestTarget::Directory {
            directory,
            is_root: anchor.is_root,
            rights: anchor.rights,
        },
        device: None,
        operation: RequestOperation::FilesystemOpen,
        completion_mode: RequestCompletionMode::Block,
        payload: BrokerPayload {
            operation_argument: u64::from(flags.bits()),
            user_data: 0,
            request_flags: RequestFlags::empty(),
        },
        deadline_ns: None,
        buffers,
    }
}

fn filesystem_open_request<B: Disk>(
    process_id: ProcessId,
    process: &mut Process,
    thread_id: ThreadId,
    filesystem: &mut RedoxFs<B>,
    requests: &mut RequestBroker,
    raw_anchor: u64,
    args_address: u64,
    output_address: u64,
    now_ns: u64,
) -> DispatchResult {
    let result = (|| {
        let anchor_handle = decode_handle(raw_anchor)?;
        let raw = copy_block_from_user::<FILESYSTEM_OPEN_ARGS_SIZE>(process, args_address)?;
        let args = parse_filesystem_open_args(&raw)?;
        validate_user_output(process, output_address, HANDLE_OUTPUT_SIZE)?;
        let path = copy_filesystem_path(process, args.path_address, args.path_length)?;
        let required = filesystem_open_required_rights(args.flags);
        let anchor = resolve_directory_anchor(process, filesystem, anchor_handle, required)?;
        if anchor.is_root && required.contains(Rights::WRITE) && is_protected_system_path(&path) {
            return Err(Status::AccessDenied);
        }

        let mut buffers = Vec::new();
        buffers
            .try_reserve_exact(2)
            .map_err(|_| Status::OutOfMemory)?;
        buffers.push(PreparedRequestBuffer::Copied {
            flags: RequestBufferFlags::READ,
            user_address: args.path_address,
            bytes: path.into_bytes(),
        });
        let output_pages = process
            .address_space_mut()
            .pin_user_range(output_address, HANDLE_OUTPUT_SIZE, UserAccess::Write)
            .map_err(map_address_space_error)?;
        buffers.push(PreparedRequestBuffer::Pinned {
            flags: RequestBufferFlags::WRITE,
            owner_process_id: process_id.raw(),
            pages: output_pages,
        });

        submit_legacy_filesystem_request(
            process,
            thread_id,
            requests,
            prepare_filesystem_open_broker_request(
                RequestOwner::new(process_id.raw(), thread_id.raw()),
                anchor,
                args.flags,
                buffers,
            ),
            None,
            now_ns,
        )
    })();
    result.unwrap_or_else(DispatchResult::Complete)
}

#[allow(dead_code)]
fn filesystem_open<B: Disk>(
    process: &mut Process,
    filesystem: &mut RedoxFs<B>,
    raw_anchor: u64,
    args_address: u64,
    output_address: u64,
) -> Result<(), Status> {
    let anchor_handle = decode_handle(raw_anchor)?;
    let raw = copy_block_from_user::<FILESYSTEM_OPEN_ARGS_SIZE>(process, args_address)?;
    let args = parse_filesystem_open_args(&raw)?;
    let path_address = args.path_address;
    let path_length = args.path_length;
    let flags = args.flags;
    let execute = flags.contains(FilesystemOpenFlags::EXECUTE);
    validate_user_output(process, output_address, HANDLE_OUTPUT_SIZE)?;
    let path = copy_filesystem_path(process, path_address, path_length)?;
    let required = filesystem_open_required_rights(flags);
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

fn filesystem_read_request(
    process_id: ProcessId,
    process: &mut Process,
    thread_id: ThreadId,
    requests: &mut RequestBroker,
    raw_file: u64,
    offset: u64,
    output_address: u64,
    raw_length: u64,
    count_address: u64,
    now_ns: u64,
) -> DispatchResult {
    let result = (|| {
        let handle = decode_handle(raw_file)?;
        let length = checked_array_bytes(
            raw_length,
            1,
            FILESYSTEM_READ_MAX_BYTES as u64,
            Status::OutOfRange,
        )?;
        let file = process
            .handles()
            .filesystem_file(handle, Rights::READ)
            .map_err(map_ipc_error)?;
        let mut buffers = Vec::new();
        buffers
            .try_reserve_exact(1)
            .map_err(|_| Status::OutOfMemory)?;
        let output_pages = process
            .address_space_mut()
            .pin_user_range(output_address, length, UserAccess::Write)
            .map_err(map_address_space_error)?;
        buffers.push(PreparedRequestBuffer::Pinned {
            flags: RequestBufferFlags::WRITE,
            owner_process_id: process_id.raw(),
            pages: output_pages,
        });
        let count_output = match pin_pending_request_count_output(process, count_address) {
            Ok(output) => output,
            Err(status) => {
                rollback_prepared_buffers(process, &mut buffers);
                return Err(status);
            }
        };
        submit_legacy_filesystem_request(
            process,
            thread_id,
            requests,
            PreparedBrokerRequest {
                owner: RequestOwner::new(process_id.raw(), thread_id.raw()),
                target: filesystem_request_target(file.node_id(), file.generation()),
                target_lease: PreparedRequestTarget::File(FileCapabilityLease::new(file)),
                device: None,
                operation: RequestOperation::FilesystemRead,
                completion_mode: RequestCompletionMode::Block,
                payload: BrokerPayload {
                    operation_argument: offset,
                    user_data: count_address,
                    request_flags: RequestFlags::ALLOW_PARTIAL,
                },
                deadline_ns: None,
                buffers,
            },
            Some(count_output),
            now_ns,
        )
    })();
    result.unwrap_or_else(DispatchResult::Complete)
}

fn filesystem_write_request(
    process_id: ProcessId,
    process: &mut Process,
    thread_id: ThreadId,
    requests: &mut RequestBroker,
    raw_file: u64,
    offset: u64,
    input_address: u64,
    raw_length: u64,
    count_address: u64,
    now_ns: u64,
) -> DispatchResult {
    let result = (|| {
        let handle = decode_handle(raw_file)?;
        let length = checked_array_bytes(
            raw_length,
            1,
            FILESYSTEM_READ_MAX_BYTES as u64,
            Status::OutOfRange,
        )?;
        let file = process
            .handles()
            .filesystem_file(handle, Rights::WRITE)
            .map_err(map_ipc_error)?;
        let bytes = copy_vec_from_user(process, input_address, length)?;
        let mut buffers = Vec::new();
        buffers
            .try_reserve_exact(1)
            .map_err(|_| Status::OutOfMemory)?;
        buffers.push(PreparedRequestBuffer::Copied {
            flags: RequestBufferFlags::READ,
            user_address: input_address,
            bytes,
        });
        let count_output = pin_pending_request_count_output(process, count_address)?;
        submit_legacy_filesystem_request(
            process,
            thread_id,
            requests,
            PreparedBrokerRequest {
                owner: RequestOwner::new(process_id.raw(), thread_id.raw()),
                target: filesystem_request_target(file.node_id(), file.generation()),
                target_lease: PreparedRequestTarget::File(FileCapabilityLease::new(file)),
                device: None,
                operation: RequestOperation::FilesystemWrite,
                completion_mode: RequestCompletionMode::Block,
                payload: BrokerPayload {
                    operation_argument: offset,
                    user_data: count_address,
                    request_flags: RequestFlags::ALLOW_PARTIAL,
                },
                deadline_ns: None,
                buffers,
            },
            Some(count_output),
            now_ns,
        )
    })();
    result.unwrap_or_else(DispatchResult::Complete)
}

fn filesystem_sync_request(
    process_id: ProcessId,
    process: &mut Process,
    thread_id: ThreadId,
    requests: &mut RequestBroker,
    args_address: u64,
    now_ns: u64,
) -> DispatchResult {
    let result = (|| {
        let raw = copy_block_from_user::<FILESYSTEM_SYNC_ARGS_SIZE>(process, args_address)?;
        let handle = Handle::from_raw(read_u32(&raw, 0));
        if read_u32(&raw, 4) != 0 {
            return Err(Status::InvalidArgument);
        }
        let target = match process
            .handles()
            .object_type(handle)
            .map_err(map_ipc_error)?
        {
            ObjectType::FilesystemRoot => {
                process
                    .handles()
                    .filesystem_root(handle, Rights::WRITE)
                    .map_err(map_ipc_error)?;
                RequestTarget(REQUEST_TARGET_FILESYSTEM_ROOT)
            }
            ObjectType::Directory => {
                let directory = process
                    .handles()
                    .filesystem_directory(handle, Rights::WRITE)
                    .map_err(map_ipc_error)?;
                filesystem_request_target(directory.node_id(), directory.generation())
            }
            ObjectType::File => {
                let file = process
                    .handles()
                    .filesystem_file(handle, Rights::WRITE)
                    .map_err(map_ipc_error)?;
                filesystem_request_target(file.node_id(), file.generation())
            }
            _ => return Err(Status::WrongObjectType),
        };
        submit_legacy_filesystem_request(
            process,
            thread_id,
            requests,
            PreparedBrokerRequest {
                owner: RequestOwner::new(process_id.raw(), thread_id.raw()),
                target,
                target_lease: PreparedRequestTarget::FilesystemSync,
                device: None,
                operation: RequestOperation::FilesystemSync,
                completion_mode: RequestCompletionMode::Block,
                payload: BrokerPayload {
                    operation_argument: 0,
                    user_data: 0,
                    request_flags: RequestFlags::empty(),
                },
                deadline_ns: None,
                buffers: Vec::new(),
            },
            None,
            now_ns,
        )
    })();
    result.unwrap_or_else(DispatchResult::Complete)
}

fn pin_pending_request_count_output(
    process: &mut Process,
    address: u64,
) -> Result<PendingRequestCountOutput, Status> {
    let pages = process
        .address_space_mut()
        .pin_user_range(address, FILESYSTEM_READ_OUTPUT_SIZE, UserAccess::Write)
        .map_err(map_address_space_error)?;
    Ok(PendingRequestCountOutput { address, pages })
}

fn rollback_pending_request_count_output(
    process: &mut Process,
    count_output: &mut Option<PendingRequestCountOutput>,
) {
    let Some(mut output) = count_output.take() else {
        return;
    };
    let result = process.address_space_mut().unpin_user_pages(&output.pages);
    debug_assert!(result.is_ok(), "request count pin rollback failed");
    output.pages.clear();
}

fn submit_legacy_filesystem_request(
    process: &mut Process,
    thread_id: ThreadId,
    requests: &mut RequestBroker,
    request: PreparedBrokerRequest,
    mut count_output: Option<PendingRequestCountOutput>,
    now_ns: u64,
) -> Result<DispatchResult, Status> {
    let submission = match requests.submit(request, now_ns) {
        Ok(submission) => submission,
        Err(mut failure) => {
            rollback_prepared_buffers(process, &mut failure.request.buffers);
            rollback_pending_request_count_output(process, &mut count_output);
            return Err(map_broker_error(failure.error));
        }
    };
    let hidden_handle = match process.handles_mut().request_install(&submission.control) {
        Ok(handle) => handle,
        Err(error) => {
            cancel_broker_submission(requests, submission.id, now_ns);
            rollback_pending_request_count_output(process, &mut count_output);
            return Err(map_ipc_error(error));
        }
    };
    process.block_thread_request(
        thread_id,
        PendingRequest {
            id: submission.id,
            output: None,
            count_output,
            hidden_handle,
            completion: None,
            return_operation_status: true,
            registration: None,
        },
    );
    Ok(DispatchResult::Blocked)
}

#[allow(dead_code)]
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

#[allow(dead_code)]
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

#[allow(dead_code)]
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
    extended: bool,
) -> Result<Box<Process>, Status> {
    if !child_slot_reserved {
        return Err(Status::ResourceLimit);
    }
    let raw_length = if extended {
        PROCESS_CREATE_ARGS2_SIZE
    } else {
        PROCESS_CREATE_ARGS_SIZE
    };
    let raw_vec = copy_vec_from_user(process, args_address, raw_length)?;
    let raw = raw_vec.as_slice();
    let executable = Handle::from_raw(read_u32(raw, 0));
    if read_u32(&raw, 4) != 0 {
        return Err(Status::InvalidArgument);
    }
    let args_address = read_u64(raw, 8);
    let args_length = bounded_startup_length(read_u64(raw, 16))?;
    let dispositions_address = read_u64(raw, 24);
    let disposition_count = checked_array_bytes(
        read_u64(raw, 32),
        1,
        PROCESS_MAX_STARTUP_HANDLES as u64,
        Status::ResourceLimit,
    )?;
    let config_address = read_u64(raw, 40);
    let config_length = bounded_startup_length(read_u64(raw, 48))?;
    let output_address = read_u64(raw, 56);
    let requested_policy = if extended {
        if read_u32(raw, 64) != 1 || read_u32(raw, 68) != PROCESS_CREATE_ARGS2_SIZE as u32 {
            return Err(Status::InvalidArgument);
        }
        let policy_raw =
            copy_block_from_user::<PROCESS_MEMORY_POLICY_SIZE>(process, read_u64(raw, 72))?;
        Some(parse_process_memory_policy(&policy_raw)?)
    } else {
        None
    };
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
    let available_bytes = frame_allocator.available_bytes();
    let inherited_limits = select_child_process_limits(process.limits(), available_bytes, None)
        .expect("legacy child limit selection cannot fail");
    let requested_limits = requested_policy.map(|values| ProcessLimits {
        private_pages: values[0],
        shared_memory_bytes: values[1],
        mapped_shared_bytes: values[2],
        reserved_virtual_bytes: values[3],
        vma_count: values[4],
        executable_image_pages: values[5],
        executable_source_bytes: values[6],
        channel_traffic_bytes: inherited_limits.channel_traffic_bytes,
        cpu_quantum_ns: inherited_limits.cpu_quantum_ns,
    });
    let selected_limits =
        select_child_process_limits(process.limits(), available_bytes, requested_limits)
            .ok_or(Status::ResourceLimit)?;
    if executable_length == 0 || executable_length as u64 > selected_limits.executable_source_bytes
    {
        return Err(Status::ResourceLimit);
    }
    let mut image = zeroed_vec(executable_length)?;
    if filesystem.read(file, 0, &mut image).map_err(map_fs_error)? != executable_length {
        return Err(Status::Io);
    }

    let mut child_storage = Box::<Process>::try_new_uninit().map_err(|_| Status::OutOfMemory)?;
    let randomness = [entropy.next_u64(), entropy.next_u64(), entropy.next_u64()];
    unsafe { kernel_page_table.activate() };
    let child = Process::from_elf_randomized_with_limits(
        &image,
        kernel_page_table,
        frame_allocator,
        randomness,
        selected_limits,
    );
    unsafe { process.address_space().activate() };
    let child = match child {
        Ok(child) => child,
        Err(error) => return Err(map_process_create_error(error)),
    };
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
    let retired = match process.retire() {
        Ok(retired) => retired,
        Err(error) => {
            core::mem::forget(error);
            panic!("unstarted process unexpectedly remained active");
        }
    };
    if let Err(error) = retired.reclaim(frame_allocator) {
        // Reclaim is allocation-free. Retain exact ownership and fail-stop on any
        // allocator invariant violation rather than returning to the scheduler.
        core::mem::forget(error);
        panic!("unstarted process reclaim invariant failed");
    }
}

const fn map_process_create_error(error: ProcessCreateError) -> Status {
    match error {
        ProcessCreateError::MemoryPolicy | ProcessCreateError::ResourceLimit => {
            Status::ResourceLimit
        }
        ProcessCreateError::OutOfMemory
        | ProcessCreateError::ElfPage(ElfPageLoadError::AddressSpace {
            error: AddressSpaceError::OutOfMemory,
            ..
        })
        | ProcessCreateError::ElfPage(ElfPageLoadError::AddressSpace {
            error: AddressSpaceError::OutOfFrames,
            ..
        })
        | ProcessCreateError::ElfPage(ElfPageLoadError::AddressSpace {
            error: AddressSpaceError::FrameAllocator(_),
            ..
        })
        | ProcessCreateError::AddressSpace(AddressSpaceError::OutOfMemory)
        | ProcessCreateError::AddressSpace(AddressSpaceError::OutOfFrames)
        | ProcessCreateError::AddressSpace(AddressSpaceError::FrameAllocator(_))
        | ProcessCreateError::StackPage {
            error: AddressSpaceError::OutOfMemory,
            ..
        }
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

fn parse_process_memory_policy(raw: &[u8; PROCESS_MEMORY_POLICY_SIZE]) -> Result<[u64; 7], Status> {
    if read_u32(raw, 0) != PROCESS_MEMORY_POLICY_VERSION
        || read_u32(raw, 4) != PROCESS_MEMORY_POLICY_SIZE as u32
    {
        return Err(Status::InvalidArgument);
    }
    Ok([
        read_u64(raw, 8),
        read_u64(raw, 16),
        read_u64(raw, 24),
        read_u64(raw, 32),
        read_u64(raw, 40),
        read_u64(raw, 48),
        read_u64(raw, 56),
    ])
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

const fn map_request_error(error: RequestError) -> Status {
    match error {
        RequestError::OutOfMemory => Status::OutOfMemory,
        RequestError::Quiescing | RequestError::CompletionQueueFull => Status::ShouldWait,
        RequestError::EmptyBatch | RequestError::InvalidLimits | RequestError::InvalidState => {
            Status::InvalidArgument
        }
        RequestError::BatchTooLarge
        | RequestError::SystemFull
        | RequestError::OwnerLimit
        | RequestError::TargetLimit
        | RequestError::CopiedBytesLimit
        | RequestError::PinnedPagesLimit
        | RequestError::SharedBytesLimit => Status::ResourceLimit,
        RequestError::OutputTooSmall => Status::BufferTooSmall,
        RequestError::InvalidRequest => Status::InvalidHandle,
        RequestError::ReleaseNotDispatched => Status::ShouldWait,
    }
}

const fn map_broker_error(error: BrokerError) -> Status {
    match error {
        BrokerError::Runtime(error) => map_request_error(error),
        BrokerError::Control(error) => map_ipc_error(error),
        BrokerError::OutOfMemory => Status::OutOfMemory,
        BrokerError::TooManyBuffers => Status::ResourceLimit,
        BrokerError::ResourceOverflow => Status::OutOfRange,
        BrokerError::InvalidDeadline | BrokerError::PinnedPageOwnerMismatch => {
            Status::InvalidArgument
        }
        BrokerError::InvalidRequest => Status::InvalidHandle,
        BrokerError::ReleaseNotDispatched => Status::ShouldWait,
        BrokerError::ResourcesAlreadyTaken | BrokerError::ActionMismatch => Status::InvalidArgument,
    }
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
        AddressSpaceError::PinnedMapping(_) => Status::ShouldWait,
        AddressSpaceError::OutOfMemory
        | AddressSpaceError::OutOfFrames
        | AddressSpaceError::FrameAllocator(_) => Status::OutOfMemory,
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
        SharedMappingError::Io => Status::Io,
        SharedMappingError::ResourceLimit => Status::ResourceLimit,
        SharedMappingError::AlreadyMapped(_) => Status::AlreadyMapped,
        SharedMappingError::AddressSpace(error) => map_address_space_error(error),
        SharedMappingError::RollbackFailed {
            mapping_error,
            rollback_error: _,
        } => map_address_space_error(mapping_error),
        SharedMappingError::InvalidBackingLength
        | SharedMappingError::InvalidPhysicalAddress(_)
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
            SyscallNumber::AnonymousReserve,
            SyscallNumber::AnonymousCommit,
            SyscallNumber::AnonymousDecommit,
            SyscallNumber::MemoryGetInfo,
            SyscallNumber::VirtualMapFile,
            SyscallNumber::VirtualCommit,
            SyscallNumber::VirtualDecommit,
            SyscallNumber::VirtualProtect,
            SyscallNumber::VirtualUnmap,
            SyscallNumber::ProcessCreate2,
            SyscallNumber::VirtualQuery,
            SyscallNumber::ThreadCreate,
            SyscallNumber::ThreadExit,
            SyscallNumber::ThreadYield,
            SyscallNumber::ThreadSleepUntil,
            SyscallNumber::ThreadWake,
            SyscallNumber::ThreadTerminate,
            SyscallNumber::ThreadGetInfo,
            SyscallNumber::ThreadJoin,
            SyscallNumber::ThreadDetach,
            SyscallNumber::ThreadGetCurrent,
            SyscallNumber::ThreadSetSchedulingClass,
            SyscallNumber::ThreadGetSchedulingInfo,
            SyscallNumber::ThreadSetSchedulingClassWithAuthority,
            SyscallNumber::RequestSubmit,
            SyscallNumber::RequestCancel,
            SyscallNumber::RequestGetInfo,
            SyscallNumber::RequestSubmitBatch,
            SyscallNumber::RequestGetDiagnostics,
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
        assert_eq!(
            decode_syscall_number(42),
            Some(SyscallNumber::AnonymousReserve)
        );
        assert_eq!(
            decode_syscall_number(43),
            Some(SyscallNumber::AnonymousCommit)
        );
        assert_eq!(
            decode_syscall_number(44),
            Some(SyscallNumber::AnonymousDecommit)
        );
        assert_eq!(
            decode_syscall_number(45),
            Some(SyscallNumber::MemoryGetInfo)
        );
        assert_eq!(
            decode_syscall_number(46),
            Some(SyscallNumber::VirtualMapFile)
        );
        assert_eq!(
            decode_syscall_number(51),
            Some(SyscallNumber::ProcessCreate2)
        );
        assert_eq!(decode_syscall_number(52), Some(SyscallNumber::VirtualQuery));
        assert_eq!(
            decode_syscall_number(65),
            Some(SyscallNumber::ThreadSetSchedulingClassWithAuthority)
        );
        assert_eq!(
            decode_syscall_number(66),
            Some(SyscallNumber::RequestSubmit)
        );
        assert_eq!(
            decode_syscall_number(70),
            Some(SyscallNumber::RequestGetDiagnostics)
        );
        assert_eq!(decode_syscall_number(71), None);
        assert_eq!(decode_syscall_number(u64::MAX), None);
    }

    fn request_args(
        operation: RequestOperation,
        completion_mode: RequestCompletionMode,
    ) -> RequestSubmitArgs {
        RequestSubmitArgs {
            version: REQUEST_SUBMIT_ARGS_VERSION,
            size: RequestSubmitArgs::SIZE,
            target: Handle::INVALID,
            operation: operation as u32,
            completion_mode: completion_mode as u32,
            flags: RequestFlags::empty().bits(),
            buffers_address: 0,
            buffer_count: 0,
            reserved: 0,
            operation_argument: 0,
            deadline_ns: DEADLINE_INFINITE,
            user_data: 0,
        }
    }

    fn request_buffer(kind: RequestBufferKind, flags: RequestBufferFlags) -> RequestBuffer {
        let shared = kind == RequestBufferKind::SharedMemory;
        RequestBuffer {
            kind: kind as u32,
            flags: flags.bits(),
            address: if shared { 0 } else { 0x4000 },
            length: 16,
            handle: if shared {
                Handle::from_raw(1 << 12)
            } else {
                Handle::INVALID
            },
            reserved: 0,
            offset: 0,
        }
    }

    fn filesystem_open_args(flags: u32, reserved: u32) -> [u8; FILESYSTEM_OPEN_ARGS_SIZE] {
        let mut raw = [0u8; FILESYSTEM_OPEN_ARGS_SIZE];
        put_u64(&mut raw, 0, 0x4000);
        put_u64(&mut raw, 8, 12);
        put_u32(&mut raw, 16, flags);
        put_u32(&mut raw, 20, reserved);
        raw
    }

    #[test]
    fn filesystem_open_argument_and_rights_validation_matches_the_legacy_contract() {
        let read = FilesystemOpenFlags::READ;
        let write = FilesystemOpenFlags::WRITE;
        let execute = FilesystemOpenFlags::EXECUTE;
        let create = FilesystemOpenFlags::CREATE;
        let truncate = FilesystemOpenFlags::TRUNCATE;

        for flags in [
            read,
            write,
            read | write,
            write | create,
            write | truncate,
            read | execute,
        ] {
            let parsed =
                parse_filesystem_open_args(&filesystem_open_args(flags.bits(), 0)).unwrap();
            assert_eq!(parsed.path_address, 0x4000);
            assert_eq!(parsed.path_length, 12);
            assert_eq!(parsed.flags, flags);
        }
        for flags in [
            FilesystemOpenFlags::empty(),
            create,
            truncate,
            execute,
            read | write | execute,
            read | execute | create,
            read | execute | truncate,
        ] {
            assert_eq!(
                parse_filesystem_open_args(&filesystem_open_args(flags.bits(), 0)),
                Err(Status::InvalidArgument)
            );
        }
        assert_eq!(
            parse_filesystem_open_args(&filesystem_open_args(read.bits(), 1)),
            Err(Status::InvalidArgument)
        );
        assert_eq!(
            parse_filesystem_open_args(&filesystem_open_args(1 << 31, 0)),
            Err(Status::InvalidArgument)
        );
        assert_eq!(
            parse_filesystem_open_args(&filesystem_open_args(read.bits(), 0)[..23]),
            Err(Status::InvalidArgument)
        );

        assert_eq!(filesystem_open_required_rights(read), Rights::READ);
        assert_eq!(
            filesystem_open_required_rights(read | execute),
            Rights::READ | Rights::EXECUTE
        );
        assert_eq!(
            filesystem_open_required_rights(write | create | truncate),
            Rights::READ | Rights::WRITE
        );
    }

    #[test]
    fn public_request_submit_rejects_internal_filesystem_operations() {
        for operation in [
            RequestOperation::FilesystemOpen,
            RequestOperation::FilesystemTruncate,
            RequestOperation::FilesystemNamespace,
        ] {
            assert_eq!(
                validate_public_request_operation(operation),
                Err(Status::AccessDenied)
            );
            assert_eq!(
                validate_operation_buffers(operation, 0, &[]),
                Err(Status::AccessDenied)
            );
        }
        for operation in [
            RequestOperation::Nop,
            RequestOperation::FilesystemRead,
            RequestOperation::FilesystemWrite,
            RequestOperation::FilesystemSync,
            RequestOperation::AudioWrite,
        ] {
            assert_eq!(validate_public_request_operation(operation), Ok(()));
        }
        #[cfg(ginkgo_request_smoke)]
        assert_eq!(
            validate_public_request_operation(RequestOperation::Synthetic),
            Ok(())
        );
        #[cfg(not(ginkgo_request_smoke))]
        assert_eq!(
            validate_public_request_operation(RequestOperation::Synthetic),
            Err(Status::AccessDenied)
        );
    }

    #[test]
    fn request_argument_layout_rejects_version_size_and_reserved_changes() {
        let valid = request_args(RequestOperation::Nop, RequestCompletionMode::InlineOnly);
        assert_eq!(parse_request_submit_args(valid.as_bytes()), Ok(valid));

        let mut malformed = valid;
        malformed.version += 1;
        assert_eq!(
            parse_request_submit_args(malformed.as_bytes()),
            Err(Status::InvalidArgument)
        );
        malformed = valid;
        malformed.size -= 8;
        assert_eq!(
            parse_request_submit_args(malformed.as_bytes()),
            Err(Status::InvalidArgument)
        );
        malformed = valid;
        malformed.reserved = 1;
        assert_eq!(
            parse_request_submit_args(malformed.as_bytes()),
            Err(Status::InvalidArgument)
        );
        assert_eq!(
            parse_request_submit_args(&valid.as_bytes()[..REQUEST_SUBMIT_ARGS_SIZE - 1]),
            Err(Status::InvalidArgument)
        );
    }

    #[test]
    fn request_buffer_layout_rejects_unknown_empty_and_cross_kind_fields() {
        for kind in [
            RequestBufferKind::Copy,
            RequestBufferKind::Pinned,
            RequestBufferKind::SharedMemory,
        ] {
            let valid = request_buffer(kind, RequestBufferFlags::READ);
            assert_eq!(parse_request_buffer(valid.as_bytes()), Ok(valid));
        }

        let mut malformed = request_buffer(RequestBufferKind::Copy, RequestBufferFlags::READ);
        malformed.kind = 0;
        assert_eq!(
            parse_request_buffer(malformed.as_bytes()),
            Err(Status::InvalidArgument)
        );
        malformed = request_buffer(RequestBufferKind::Copy, RequestBufferFlags::READ);
        malformed.flags = 1 << 31;
        assert_eq!(
            parse_request_buffer(malformed.as_bytes()),
            Err(Status::InvalidArgument)
        );
        malformed = request_buffer(RequestBufferKind::Pinned, RequestBufferFlags::READ);
        malformed.length = 0;
        assert_eq!(
            parse_request_buffer(malformed.as_bytes()),
            Err(Status::InvalidArgument)
        );
        malformed = request_buffer(RequestBufferKind::SharedMemory, RequestBufferFlags::WRITE);
        malformed.address = 0x8000;
        assert_eq!(
            parse_request_buffer(malformed.as_bytes()),
            Err(Status::InvalidArgument)
        );
        malformed = request_buffer(RequestBufferKind::Copy, RequestBufferFlags::WRITE);
        malformed.handle = Handle::from_raw(1 << 12);
        assert_eq!(
            parse_request_buffer(malformed.as_bytes()),
            Err(Status::InvalidArgument)
        );
    }

    #[test]
    fn request_operation_layout_and_array_limits_are_bounded() {
        assert_eq!(
            validate_operation_buffers(RequestOperation::Nop, 0, &[]),
            Ok(())
        );
        assert_eq!(
            validate_operation_buffers(
                RequestOperation::Nop,
                0,
                &[request_buffer(
                    RequestBufferKind::Copy,
                    RequestBufferFlags::READ
                )]
            ),
            Err(Status::InvalidArgument)
        );
        assert_eq!(
            validate_operation_buffers(
                RequestOperation::FilesystemRead,
                0,
                &[request_buffer(
                    RequestBufferKind::Copy,
                    RequestBufferFlags::WRITE
                )]
            ),
            Ok(())
        );
        assert_eq!(
            validate_operation_buffers(
                RequestOperation::FilesystemRead,
                0,
                &[request_buffer(
                    RequestBufferKind::Copy,
                    RequestBufferFlags::READ
                )]
            ),
            Err(Status::InvalidArgument)
        );
        assert_eq!(
            checked_array_bytes(
                REQUEST_MAX_BUFFERS as u64 + 1,
                REQUEST_BUFFER_SIZE,
                REQUEST_MAX_BUFFERS as u64,
                Status::ResourceLimit
            ),
            Err(Status::ResourceLimit)
        );
        assert_eq!(
            checked_array_bytes(
                REQUEST_MAX_BATCH as u64 + 1,
                REQUEST_SUBMIT_ARGS_SIZE,
                REQUEST_MAX_BATCH as u64,
                Status::ResourceLimit
            ),
            Err(Status::ResourceLimit)
        );

        let limits = crate::request::RequestLimits::default_policy();
        let mut oversized = request_buffer(RequestBufferKind::Copy, RequestBufferFlags::WRITE);
        oversized.length = limits.copied_bytes_per_request as u64 + 1;
        let validated = ValidatedRequest {
            args: request_args(RequestOperation::Synthetic, RequestCompletionMode::Handle),
            operation: RequestOperation::Synthetic,
            completion_mode: RequestCompletionMode::Handle,
            flags: RequestFlags::empty(),
            deadline_ns: None,
            target: RequestTarget(1),
            target_lease: PreparedRequestTarget::None,
            buffers: vec![oversized],
        };
        assert_eq!(
            preflight_request_resources(&validated, limits),
            Err(Status::ResourceLimit)
        );

        let mut too_many_pages =
            request_buffer(RequestBufferKind::Pinned, RequestBufferFlags::WRITE);
        too_many_pages.length = limits.pinned_pages_per_request as u64 * PAGE_SIZE + 1;
        let validated = ValidatedRequest {
            buffers: vec![too_many_pages],
            ..validated
        };
        assert_eq!(
            preflight_request_resources(&validated, limits),
            Err(Status::ResourceLimit)
        );
    }

    #[test]
    fn inline_nop_and_pending_outputs_have_stable_results() {
        let completed = completed_request_output(Status::Ok);
        assert_eq!(completed.request, Handle::INVALID);
        assert_eq!(completed.request_state(), Some(RequestState::Completed));
        assert_eq!(completed.result_status(), Some(Status::Ok));
        assert_eq!(completed.bytes_transferred, 0);

        let pending = pending_request_output(Handle::INVALID);
        assert_eq!(pending.request_state(), Some(RequestState::Pending));
        assert_eq!(pending.result_status(), Some(Status::ShouldWait));
    }

    #[test]
    fn blocked_request_modes_select_the_documented_syscall_status() {
        assert_eq!(
            blocked_request_return_status(true, Status::Io, Status::Ok),
            Status::Io
        );
        assert_eq!(
            blocked_request_return_status(false, Status::Io, Status::Ok),
            Status::Ok
        );
        assert_eq!(
            blocked_request_return_status(false, Status::Ok, Status::InvalidAddress),
            Status::InvalidAddress
        );
    }

    #[test]
    fn prepared_filesystem_open_freezes_anchor_flags_and_buffers() {
        let mut filesystem = RedoxFs::new().unwrap();
        let root = filesystem.root_directory().unwrap();
        let directory = filesystem
            .create_directory_at(root, "syscall-open-request-target")
            .unwrap();
        let flags = FilesystemOpenFlags::READ | FilesystemOpenFlags::WRITE;
        let owner = RequestOwner::new(7, 11);
        let request = prepare_filesystem_open_broker_request(
            owner,
            DirectoryAnchor {
                directory,
                rights: Rights::READ | Rights::WRITE | Rights::TRANSFER,
                is_root: false,
            },
            flags,
            vec![
                PreparedRequestBuffer::Copied {
                    flags: RequestBufferFlags::READ,
                    user_address: 0x4000,
                    bytes: b"folder/file".to_vec(),
                },
                PreparedRequestBuffer::Pinned {
                    flags: RequestBufferFlags::WRITE,
                    owner_process_id: owner.process_id,
                    pages: vec![crate::paging::address_space::PinnedUserPage {
                        virtual_start: 0x8000,
                        physical_start: 0xc000,
                        page_offset: 0,
                        byte_length: HANDLE_OUTPUT_SIZE,
                        permissions: crate::paging::address_space::UserPagePermissions::READ_WRITE,
                        access: UserAccess::Write,
                    }],
                },
            ],
        );

        assert_eq!(request.owner, owner);
        assert_eq!(request.target, directory_request_target(Some(directory)));
        assert_eq!(request.operation, RequestOperation::FilesystemOpen);
        assert_eq!(request.completion_mode, RequestCompletionMode::Block);
        assert_eq!(request.payload.operation_argument, u64::from(flags.bits()));
        assert_eq!(request.payload.user_data, 0);
        assert_eq!(request.payload.request_flags, RequestFlags::empty());
        assert_eq!(request.buffers.len(), 2);
        assert!(matches!(
            &request.buffers[0],
            PreparedRequestBuffer::Copied {
                flags: RequestBufferFlags::READ,
                user_address: 0x4000,
                bytes,
            } if bytes == b"folder/file"
        ));
        assert!(matches!(
            &request.buffers[1],
            PreparedRequestBuffer::Pinned {
                flags: RequestBufferFlags::WRITE,
                owner_process_id: 7,
                pages,
            } if pages.len() == 1 && pages[0].byte_length == HANDLE_OUTPUT_SIZE
        ));
        let expected_target = PreparedRequestTarget::Directory {
            directory: Some(directory),
            is_root: false,
            rights: Rights::READ | Rights::WRITE | Rights::TRANSFER,
        };
        assert_eq!(request.target_lease, expected_target);
        assert_eq!(
            copy_prepared_request_target(&request.target_lease),
            expected_target
        );
        assert!(request.resources().is_ok());

        let root_request = prepare_filesystem_open_broker_request(
            owner,
            DirectoryAnchor {
                directory: root,
                rights: Rights::READ | Rights::WRITE,
                is_root: true,
            },
            FilesystemOpenFlags::WRITE,
            Vec::new(),
        );
        assert_eq!(
            root_request.target,
            RequestTarget(REQUEST_TARGET_FILESYSTEM_ROOT)
        );
        assert!(matches!(
            root_request.target_lease,
            PreparedRequestTarget::Directory {
                directory: None,
                is_root: true,
                rights,
            } if rights == Rights::READ | Rights::WRITE
        ));
    }

    #[test]
    fn prepared_filesystem_targets_match_broker_validation() {
        let mut filesystem = RedoxFs::new().unwrap();
        let file = filesystem.create("/syscall-request-target").unwrap();
        let target = filesystem_request_target(file.node_id(), file.generation());
        let read = PreparedBrokerRequest {
            owner: RequestOwner::new(1, 2),
            target,
            target_lease: PreparedRequestTarget::File(FileCapabilityLease::new(file)),
            device: None,
            operation: RequestOperation::FilesystemRead,
            completion_mode: RequestCompletionMode::Block,
            payload: BrokerPayload {
                operation_argument: 17,
                user_data: 0x8000,
                request_flags: RequestFlags::ALLOW_PARTIAL,
            },
            deadline_ns: None,
            buffers: vec![PreparedRequestBuffer::Pinned {
                flags: RequestBufferFlags::WRITE,
                owner_process_id: 1,
                pages: vec![crate::paging::address_space::PinnedUserPage {
                    virtual_start: 0x4000,
                    physical_start: 0x8000,
                    page_offset: 0,
                    byte_length: 8,
                    permissions: crate::paging::address_space::UserPagePermissions::READ_WRITE,
                    access: UserAccess::Write,
                }],
            }],
        };
        assert!(read.resources().is_ok());

        let sync = PreparedBrokerRequest {
            owner: RequestOwner::new(1, 2),
            target: RequestTarget(REQUEST_TARGET_FILESYSTEM_ROOT),
            target_lease: PreparedRequestTarget::FilesystemSync,
            device: None,
            operation: RequestOperation::FilesystemSync,
            completion_mode: RequestCompletionMode::Block,
            payload: BrokerPayload {
                operation_argument: 0,
                user_data: 0,
                request_flags: RequestFlags::empty(),
            },
            deadline_ns: None,
            buffers: Vec::new(),
        };
        assert!(sync.resources().is_ok());
    }

    #[test]
    fn request_buffer_flags_map_to_exact_data_rights() {
        assert_eq!(
            request_buffer_rights(RequestBufferFlags::READ),
            Rights::READ
        );
        assert_eq!(
            request_buffer_rights(RequestBufferFlags::WRITE),
            Rights::WRITE
        );
        assert_eq!(
            request_buffer_rights(RequestBufferFlags::READ | RequestBufferFlags::WRITE),
            Rights::READ | Rights::WRITE
        );
    }

    #[test]
    fn request_deadlines_and_error_mappings_are_stable() {
        assert_eq!(parse_request_deadline(DEADLINE_INFINITE), Ok(None));
        assert_eq!(parse_request_deadline(0), Ok(Some(0)));
        assert_eq!(parse_request_deadline(-1), Err(Status::InvalidArgument));
        assert_eq!(
            map_request_error(RequestError::CopiedBytesLimit),
            Status::ResourceLimit
        );
        assert_eq!(
            map_request_error(RequestError::CompletionQueueFull),
            Status::ShouldWait
        );
        assert_eq!(
            map_broker_error(BrokerError::Runtime(RequestError::InvalidRequest)),
            Status::InvalidHandle
        );
        assert_eq!(
            map_broker_error(BrokerError::PinnedPageOwnerMismatch),
            Status::InvalidArgument
        );
        assert_eq!(
            map_broker_error(BrokerError::ActionMismatch),
            Status::InvalidArgument
        );
        assert_eq!(
            map_address_space_error(AddressSpaceError::PinnedMapping(0x4000)),
            Status::ShouldWait
        );
    }

    #[test]
    fn process_create_failures_select_exactly_one_missing_counter() {
        let before = crate::process::ProcessUsage::default();
        assert_eq!(
            missing_memory_failure_counter(before, before, Status::ResourceLimit),
            Some(MemoryFailureCounter::Quota)
        );
        assert_eq!(
            missing_memory_failure_counter(before, before, Status::OutOfMemory),
            Some(MemoryFailureCounter::Oom)
        );
        let mut quota_recorded = before;
        quota_recorded.quota_failures = 1;
        assert_eq!(
            missing_memory_failure_counter(before, quota_recorded, Status::ResourceLimit),
            None
        );
        let mut oom_recorded = before;
        oom_recorded.oom_failures = 1;
        assert_eq!(
            missing_memory_failure_counter(before, oom_recorded, Status::OutOfMemory),
            None
        );
        assert_eq!(
            missing_memory_failure_counter(before, before, Status::InvalidArgument),
            None
        );
    }

    #[test]
    fn process_memory_policy_parser_rejects_malformed_version_and_size() {
        let mut raw = [0u8; PROCESS_MEMORY_POLICY_SIZE];
        put_u32(&mut raw, 0, PROCESS_MEMORY_POLICY_VERSION);
        put_u32(&mut raw, 4, PROCESS_MEMORY_POLICY_SIZE as u32);
        for index in 0..7 {
            put_u64(&mut raw, 8 + index * 8, index as u64 + 10);
        }
        assert_eq!(
            parse_process_memory_policy(&raw).unwrap(),
            [10, 11, 12, 13, 14, 15, 16]
        );
        put_u32(&mut raw, 0, PROCESS_MEMORY_POLICY_VERSION + 1);
        assert_eq!(
            parse_process_memory_policy(&raw),
            Err(Status::InvalidArgument)
        );
        put_u32(&mut raw, 0, PROCESS_MEMORY_POLICY_VERSION);
        put_u32(&mut raw, 4, PROCESS_MEMORY_POLICY_SIZE as u32 - 8);
        assert_eq!(
            parse_process_memory_policy(&raw),
            Err(Status::InvalidArgument)
        );
    }

    #[test]
    fn shared_memory_quota_uses_page_rounded_backing_bytes() {
        assert_eq!(page_rounded_shared_backing_bytes(0), Ok(0));
        assert_eq!(
            page_rounded_shared_backing_bytes(1),
            Ok(crate::memory::PAGE_SIZE as usize)
        );
        assert_eq!(
            page_rounded_shared_backing_bytes(crate::memory::PAGE_SIZE as usize + 1),
            Ok(crate::memory::PAGE_SIZE as usize * 2)
        );
        assert_eq!(
            page_rounded_shared_backing_bytes(usize::MAX),
            Err(Status::OutOfRange)
        );
    }

    #[test]
    fn memory_info_query_requires_an_exact_supported_version_size_pair() {
        assert_eq!(
            validate_memory_info_query(MEMORY_INFO_VERSION_V1 as u64, MEMORY_INFO_V1_SIZE as u64),
            Ok(MEMORY_INFO_V1_SIZE as usize)
        );
        assert_eq!(
            validate_memory_info_query(MEMORY_INFO_VERSION as u64, MemoryInfo::SIZE as u64),
            Ok(MemoryInfo::SIZE as usize)
        );
        assert_eq!(
            validate_memory_info_query(0, MemoryInfo::SIZE as u64),
            Err(Status::InvalidArgument)
        );
        assert_eq!(
            validate_memory_info_query(MEMORY_INFO_VERSION as u64, MemoryInfo::SIZE as u64 - 1),
            Err(Status::BufferTooSmall)
        );
        assert_eq!(
            validate_memory_info_query(MEMORY_INFO_VERSION_V1 as u64, MemoryInfo::SIZE as u64),
            Err(Status::InvalidArgument)
        );
        assert_eq!(
            validate_memory_info_query(MEMORY_INFO_VERSION as u64, MemoryInfo::SIZE as u64 + 8),
            Err(Status::InvalidArgument)
        );
    }

    #[test]
    fn virtual_query_rejects_malformed_layouts_and_non_user_addresses() {
        let valid_address = crate::memory::PAGE_SIZE;
        assert_eq!(
            validate_virtual_query(
                VIRTUAL_AREA_INFO_VERSION as u64,
                VirtualAreaInfo::SIZE as u64,
                valid_address
            ),
            Ok(())
        );
        assert_eq!(
            validate_virtual_query(0, VirtualAreaInfo::SIZE as u64, valid_address),
            Err(Status::InvalidArgument)
        );
        assert_eq!(
            validate_virtual_query(
                VIRTUAL_AREA_INFO_VERSION as u64,
                VirtualAreaInfo::SIZE as u64 - 1,
                valid_address
            ),
            Err(Status::BufferTooSmall)
        );
        assert_eq!(
            validate_virtual_query(
                VIRTUAL_AREA_INFO_VERSION as u64,
                VirtualAreaInfo::SIZE as u64 + 8,
                valid_address
            ),
            Err(Status::InvalidArgument)
        );
        for address in [0, 0x0000_8000_0000_0000, u64::MAX] {
            assert_eq!(
                validate_virtual_query(
                    VIRTUAL_AREA_INFO_VERSION as u64,
                    VirtualAreaInfo::SIZE as u64,
                    address
                ),
                Err(Status::InvalidAddress)
            );
        }
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
            map_address_space_error(AddressSpaceError::OutOfMemory),
            Status::OutOfMemory
        );
        assert_eq!(
            map_process_create_error(ProcessCreateError::AddressSpace(
                AddressSpaceError::OutOfMemory,
            )),
            Status::OutOfMemory
        );
        assert_eq!(
            map_process_create_error(ProcessCreateError::ElfPage(
                ElfPageLoadError::AddressSpace {
                    address: 0x3000,
                    error: AddressSpaceError::OutOfMemory,
                },
            )),
            Status::OutOfMemory
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
