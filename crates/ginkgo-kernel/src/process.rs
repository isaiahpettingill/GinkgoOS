//! User process ownership, ELF construction, and shared-memory mappings.

use alloc::{sync::Arc, vec::Vec};
use core::{fmt, mem, ptr};

use ginkgo_filesystem::FileHandle;
use ginkgo_ipc::{
    Handle, HandleTable, IpcError, ProcessControl, SchedulingAuthorityLease,
    SharedMemoryMappingAccess, SharedMemoryMappingInfo, SharedMemoryMappingLease, SignalObserver,
    Signals, WaitItem, WaitSetRegistration, WaitToken,
};
use ginkgo_sysapi::Rights;
use ginkgo_sysapi::{
    MapFlags, MapProtection, ProcessFault as PublicProcessFault, RequestSubmitOutput,
    SharedMemoryMapArgs, Status, ThreadSchedulingClass, VirtualAreaInfo, VirtualAreaKind,
    VirtualMapFileArgs, PROCESS_MAX_ARGS, PROCESS_MAX_STARTUP_BYTES, PROCESS_MAX_STARTUP_HANDLES,
    VIRTUAL_AREA_INFO_VERSION,
};
use x86_64::{
    structures::paging::{PhysFrame, Size4KiB},
    PhysAddr, VirtAddr,
};

use crate::{
    arch::UserContext,
    elf::{self, ElfError, LoadError, SegmentPermissions},
    memory::{UsableFrameAllocator, PAGE_SIZE},
    paging::{
        address_space::{
            AddressSpace, AddressSpaceError, FrameReclaimStats, PinnedUserPage,
            RetiredAddressSpace, UserAccess, UserPagePermissions,
        },
        ActivePageTable,
    },
    request::RequestId,
    thread_scheduler::{SchedulingClass, ThreadMetrics as SchedulerMetrics, ThreadSnapshot},
};

pub const USER_STACK_INITIAL_SIZE: u64 = 64 * 1024;
pub const USER_STACK_MAX_SIZE: u64 = 8 * 1024 * 1024;
pub const USER_STACK_GROWTH_SLOP: u64 = 64 * 1024;
pub const USER_STACK_TOP: u64 = 0x0000_7fff_ffff_f000;
pub const USER_STACK_BOTTOM: u64 = USER_STACK_TOP - USER_STACK_MAX_SIZE;
pub const USER_STACK_INITIAL_BOTTOM: u64 = USER_STACK_TOP - USER_STACK_INITIAL_SIZE;
pub const USER_STACK_GUARD_START: u64 = USER_STACK_BOTTOM - PAGE_SIZE;
pub const SHARED_MAPPING_BASE: u64 = 0x0000_0001_0000_0000;
/// Architectural/metadata ceiling for one process's sorted semantic VMAs.
/// The lower RAM-derived `ProcessLimits::vma_count` is the controlling policy.
pub const MAX_VMAS: usize = 4096;
pub const MAX_THREADS_PER_PROCESS: usize = 64;
pub const KERNEL_ENTRY_STACK_SIZE: usize = 64 * 1024;
const MAIN_THREAD_ID: ThreadId = ThreadId::from_parts(0, 1);
const MIB: u64 = 1024 * 1024;
/// Default maximum executable payload accepted by the package format.
pub const PACKAGE_DEFAULT_EXECUTABLE_BYTES: u64 = 16 * MIB;
/// Stable internal fault reason/code used when page-table rollback cannot restore
/// a process to a coherent mapping state. Such a process is quarantined terminally.
const VM_ROLLBACK_FAILURE_REASON: u16 = 1;
const VM_ROLLBACK_FAILURE_CODE: u64 = 0x564d_0001;
const STACK_GROWTH_INVARIANT_REASON: u16 = 2;
const STACK_GROWTH_INVARIANT_CODE: u64 = 0x5354_0001;
const PAGE_FAULT_PRESENT: u64 = 1 << 0;
const PAGE_FAULT_USER: u64 = 1 << 2;

fn public_scheduling_class(class: SchedulingClass) -> ThreadSchedulingClass {
    match class {
        SchedulingClass::Critical => ThreadSchedulingClass::Critical,
        SchedulingClass::Audio => ThreadSchedulingClass::Audio,
        SchedulingClass::Interactive => ThreadSchedulingClass::Interactive,
        SchedulingClass::Normal => ThreadSchedulingClass::Normal,
        SchedulingClass::Background => ThreadSchedulingClass::Background,
    }
}

/// Magic (`GKSP`) and version for the direct-process startup block passed in RDI.
///
/// Version 1 begins with a 64-byte little-endian header. Every offset is relative
/// to the block address. The header contains, in order: magic (u32), version
/// (u16), header size (u16), total size, argc, argv-offset-table offset, argument
/// blob offset/length, configuration offset/length, startup-handle offset/count,
/// and five reserved u32 values. The argv table contains one u32 offset per
/// NUL-terminated argument, and the handle table contains child-local u32 values.
/// Sections and the total block are 8-byte aligned; the block address and initial
/// RSP are 16-byte aligned. RDI is the block address, RSI its byte length, and RDX
/// and RCX are zero.
pub const DIRECT_STARTUP_MAGIC: u32 = u32::from_le_bytes(*b"GKSP");
pub const DIRECT_STARTUP_VERSION: u16 = 1;
const DIRECT_STARTUP_HEADER_SIZE: usize = 64;
const DIRECT_STARTUP_ALIGNMENT: usize = 16;
const STACK_ASLR_ALIGNMENT: u64 = 2 * 1024 * 1024;
const STACK_ASLR_SLOTS: u64 = 1024;
const MAPPING_ASLR_SLOTS: u64 = 16_384;
const USER_ADDRESS_END: u64 = 0x0000_8000_0000_0000;

/// Stable process identity. Reused slots always receive a different generation.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProcessId(u64);

impl ProcessId {
    pub const INVALID: Self = Self(0);

    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    pub const fn raw(self) -> u64 {
        self.0
    }

    pub const fn is_valid(self) -> bool {
        self.0 != 0 && self.generation() != 0
    }

    pub const fn slot(self) -> u32 {
        self.0 as u32
    }

    pub const fn generation(self) -> u32 {
        (self.0 >> 32) as u32
    }

    const fn from_parts(slot: u32, generation: u32) -> Self {
        debug_assert!(generation != 0);
        Self(((generation as u64) << 32) | slot as u64)
    }
}

/// Stable process-local thread identity. Reused slots receive a new generation.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ThreadId(u64);

impl ThreadId {
    pub const INVALID: Self = Self(0);

    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    pub const fn raw(self) -> u64 {
        self.0
    }

    pub const fn is_valid(self) -> bool {
        self.0 != 0 && self.generation() != 0
    }

    pub const fn slot(self) -> u32 {
        self.0 as u32
    }

    pub const fn generation(self) -> u32 {
        (self.0 >> 32) as u32
    }

    const fn from_parts(slot: u32, generation: u32) -> Self {
        debug_assert!(generation != 0);
        Self(((generation as u64) << 32) | slot as u64)
    }
}

/// Generation-checked scheduler identity for one thread in one process.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ThreadRef {
    pub process_id: ProcessId,
    pub thread_id: ThreadId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessFaultReason {
    PageFault,
    GeneralProtection,
    InvalidOpcode,
    InvalidUserContext,
    ResourceLimit,
    OutOfMemory,
    Other(u16),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessFault {
    pub reason: ProcessFaultReason,
    pub code: u64,
    pub address: Option<u64>,
}

impl ProcessFault {
    pub const fn new(reason: ProcessFaultReason, code: u64) -> Self {
        Self {
            reason,
            code,
            address: None,
        }
    }

    pub const fn at_address(reason: ProcessFaultReason, code: u64, address: u64) -> Self {
        Self {
            reason,
            code,
            address: Some(address),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessState {
    Ready,
    Blocked,
    Exited(i32),
    Faulted(ProcessFault),
    Terminated,
}

impl ProcessState {
    pub const fn is_runnable(self) -> bool {
        matches!(self, Self::Ready)
    }

    pub const fn is_blocked(self) -> bool {
        matches!(self, Self::Blocked)
    }

    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Exited(_) | Self::Faulted(_) | Self::Terminated)
    }
}

/// Scheduler and completion state owned by an individual thread.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThreadState {
    Ready,
    Blocked,
    Exited(i32),
    Faulted(ProcessFault),
    Terminated,
}

impl ThreadState {
    pub const fn is_runnable(self) -> bool {
        matches!(self, Self::Ready)
    }

    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Exited(_) | Self::Faulted(_) | Self::Terminated)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WaitDeadline {
    Infinite,
    At(u64),
}

impl WaitDeadline {
    pub(crate) const fn is_expired(self, now_ns: u64) -> bool {
        matches!(self, Self::At(deadline_ns) if now_ns >= deadline_ns)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WaitManyCompletion {
    Ready(usize),
    Failed(Status),
}

/// Kernel-owned continuation for a blocked wait-many syscall.
///
/// User memory is represented only by validated virtual-address integers. No
/// userspace pointer or Rust borrow survives syscall dispatch.
pub(crate) struct BlockedWaitRegistration {
    pub(crate) token: WaitToken,
    pub(crate) objects: Option<WaitSetRegistration>,
}

pub(crate) struct PendingWaitMany {
    pub(crate) items: Vec<WaitItem>,
    pub(crate) encoded_items: Vec<u8>,
    pub(crate) items_address: u64,
    pub(crate) output_address: u64,
    pub(crate) deadline: WaitDeadline,
    pub(crate) completion: Option<WaitManyCompletion>,
    pub(crate) registration: Option<BlockedWaitRegistration>,
}

pub(crate) struct PendingSleep {
    pub(crate) deadline_ns: u64,
    pub(crate) registration: Option<BlockedWaitRegistration>,
}

pub(crate) struct PendingJoin {
    pub(crate) target: ThreadId,
    pub(crate) deadline: WaitDeadline,
    pub(crate) output_address: u64,
    pub(crate) completion: Option<Status>,
    pub(crate) registration: Option<BlockedWaitRegistration>,
}

pub(crate) struct PendingRequestOutput {
    pub(crate) address: u64,
    pub(crate) pages: Vec<PinnedUserPage>,
}

pub(crate) struct PendingRequestCountOutput {
    pub(crate) address: u64,
    pub(crate) pages: Vec<PinnedUserPage>,
}

pub(crate) struct PendingRequest {
    pub(crate) id: RequestId,
    pub(crate) output: Option<PendingRequestOutput>,
    pub(crate) count_output: Option<PendingRequestCountOutput>,
    pub(crate) hidden_handle: Handle,
    pub(crate) completion: Option<RequestSubmitOutput>,
    pub(crate) return_operation_status: bool,
    pub(crate) registration: Option<BlockedWaitRegistration>,
}

pub(crate) enum BlockedSyscall {
    WaitMany(PendingWaitMany),
    Sleep(PendingSleep),
    Join(PendingJoin),
    Request(PendingRequest),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockedKind {
    WaitMany,
    Sleep,
    Join,
    Request,
}

/// Fully allocated direct-process startup bytes awaiting child-local handles.
pub(crate) struct DirectStartupBlock {
    bytes: Vec<u8>,
    handles_offset: usize,
    handle_count: usize,
}

impl DirectStartupBlock {
    pub(crate) fn new(args: &[u8], config: &[u8], handle_count: usize) -> Result<Self, Status> {
        let argument_offsets = parse_argument_offsets(args)?;
        if argument_offsets.len() > PROCESS_MAX_ARGS
            || handle_count > PROCESS_MAX_STARTUP_HANDLES
            || args
                .len()
                .checked_add(config.len())
                .is_none_or(|length| length > PROCESS_MAX_STARTUP_BYTES)
        {
            return Err(Status::ResourceLimit);
        }

        let argv_offset = DIRECT_STARTUP_HEADER_SIZE;
        let args_offset = align_up_usize(
            argv_offset
                .checked_add(argument_offsets.len() * size_of::<u32>())
                .ok_or(Status::ResourceLimit)?,
            8,
        )
        .ok_or(Status::ResourceLimit)?;
        let config_offset = align_up_usize(
            args_offset
                .checked_add(args.len())
                .ok_or(Status::ResourceLimit)?,
            8,
        )
        .ok_or(Status::ResourceLimit)?;
        let handles_offset = align_up_usize(
            config_offset
                .checked_add(config.len())
                .ok_or(Status::ResourceLimit)?,
            8,
        )
        .ok_or(Status::ResourceLimit)?;
        let total_size = align_up_usize(
            handles_offset
                .checked_add(handle_count * size_of::<u32>())
                .ok_or(Status::ResourceLimit)?,
            DIRECT_STARTUP_ALIGNMENT,
        )
        .ok_or(Status::ResourceLimit)?;
        if total_size > USER_STACK_INITIAL_SIZE as usize {
            return Err(Status::ResourceLimit);
        }

        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(total_size)
            .map_err(|_| Status::OutOfMemory)?;
        bytes.resize(total_size, 0);
        put_startup_u32(&mut bytes, 0, DIRECT_STARTUP_MAGIC);
        bytes[4..6].copy_from_slice(&DIRECT_STARTUP_VERSION.to_le_bytes());
        bytes[6..8].copy_from_slice(&(DIRECT_STARTUP_HEADER_SIZE as u16).to_le_bytes());
        put_startup_u32(&mut bytes, 8, total_size as u32);
        put_startup_u32(&mut bytes, 12, argument_offsets.len() as u32);
        put_startup_u32(&mut bytes, 16, argv_offset as u32);
        put_startup_u32(&mut bytes, 20, args_offset as u32);
        put_startup_u32(&mut bytes, 24, args.len() as u32);
        put_startup_u32(&mut bytes, 28, config_offset as u32);
        put_startup_u32(&mut bytes, 32, config.len() as u32);
        put_startup_u32(&mut bytes, 36, handles_offset as u32);
        put_startup_u32(&mut bytes, 40, handle_count as u32);
        for (index, offset) in argument_offsets.into_iter().enumerate() {
            put_startup_u32(
                &mut bytes,
                argv_offset + index * size_of::<u32>(),
                (args_offset + offset) as u32,
            );
        }
        bytes[args_offset..args_offset + args.len()].copy_from_slice(args);
        bytes[config_offset..config_offset + config.len()].copy_from_slice(config);
        Ok(Self {
            bytes,
            handles_offset,
            handle_count,
        })
    }

    pub(crate) fn set_handles(&mut self, handles: &[Handle]) {
        assert_eq!(handles.len(), self.handle_count);
        for (index, handle) in handles.iter().copied().enumerate() {
            put_startup_u32(
                &mut self.bytes,
                self.handles_offset + index * size_of::<u32>(),
                handle.raw(),
            );
        }
    }
}

fn parse_argument_offsets(args: &[u8]) -> Result<Vec<usize>, Status> {
    if (!args.is_empty() && args.last() != Some(&0)) || core::str::from_utf8(args).is_err() {
        return Err(Status::InvalidArgument);
    }
    let mut offsets = Vec::new();
    offsets
        .try_reserve_exact(args.iter().filter(|byte| **byte == 0).count())
        .map_err(|_| Status::OutOfMemory)?;
    let mut offset = 0;
    while offset < args.len() {
        offsets.push(offset);
        offset += args[offset..]
            .iter()
            .position(|byte| *byte == 0)
            .expect("validated argument blob ends in NUL")
            + 1;
    }
    Ok(offsets)
}

fn align_up_usize(value: usize, alignment: usize) -> Option<usize> {
    value
        .checked_add(alignment - 1)
        .map(|rounded| rounded & !(alignment - 1))
}

fn put_startup_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + size_of::<u32>()].copy_from_slice(&value.to_le_bytes());
}

/// Reserved and initially committed userspace stack layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessLayout {
    pub stack_guard_start: u64,
    pub stack_bottom: u64,
    pub stack_initial_bottom: u64,
    pub stack_top: u64,
}

impl ProcessLayout {
    pub const STANDARD: Self = Self {
        stack_guard_start: USER_STACK_GUARD_START,
        stack_bottom: USER_STACK_BOTTOM,
        stack_initial_bottom: USER_STACK_INITIAL_BOTTOM,
        stack_top: USER_STACK_TOP,
    };

    pub const fn stack_size(self) -> u64 {
        self.stack_top - self.stack_bottom
    }

    pub const fn initial_stack_size(self) -> u64 {
        self.stack_top - self.stack_initial_bottom
    }

    pub const fn for_stack(stack_top: u64, stack_size: u64) -> Self {
        let stack_bottom = stack_top - stack_size;
        let initial_size = if stack_size < USER_STACK_INITIAL_SIZE {
            stack_size
        } else {
            USER_STACK_INITIAL_SIZE
        };
        Self {
            stack_guard_start: stack_bottom - PAGE_SIZE,
            stack_bottom,
            stack_initial_bottom: stack_top - initial_size,
            stack_top,
        }
    }

    pub const fn randomized(random: u64) -> Self {
        let displacement = (random % STACK_ASLR_SLOTS) * STACK_ASLR_ALIGNMENT;
        let stack_top = USER_STACK_TOP - displacement;
        let stack_bottom = stack_top - USER_STACK_MAX_SIZE;
        Self {
            stack_guard_start: stack_bottom - PAGE_SIZE,
            stack_bottom,
            stack_initial_bottom: stack_top - USER_STACK_INITIAL_SIZE,
            stack_top,
        }
    }
}

/// Per-process resource ceilings. Authority is still conveyed by capabilities;
/// these limits only bound damage from an authorized but faulty application.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessLimits {
    pub private_pages: u64,
    /// Page-rounded physical backing bytes created by this process.
    pub shared_memory_bytes: u64,
    pub mapped_shared_bytes: u64,
    pub reserved_virtual_bytes: u64,
    pub vma_count: u64,
    pub executable_image_pages: u64,
    pub executable_source_bytes: u64,
    pub channel_traffic_bytes: u64,
    /// Maximum uninterrupted execution before the scheduler rotates processes.
    pub cpu_quantum_ns: u64,
}

impl ProcessLimits {
    /// Returns the field-by-field lower limits. Scheduling limits are capped too.
    pub fn capped_by(self, ceiling: Self) -> Self {
        Self {
            private_pages: self.private_pages.min(ceiling.private_pages),
            shared_memory_bytes: self.shared_memory_bytes.min(ceiling.shared_memory_bytes),
            mapped_shared_bytes: self.mapped_shared_bytes.min(ceiling.mapped_shared_bytes),
            reserved_virtual_bytes: self
                .reserved_virtual_bytes
                .min(ceiling.reserved_virtual_bytes),
            vma_count: self.vma_count.min(ceiling.vma_count),
            executable_image_pages: self
                .executable_image_pages
                .min(ceiling.executable_image_pages),
            executable_source_bytes: self
                .executable_source_bytes
                .min(ceiling.executable_source_bytes),
            channel_traffic_bytes: self
                .channel_traffic_bytes
                .min(ceiling.channel_traffic_bytes),
            cpu_quantum_ns: self.cpu_quantum_ns.min(ceiling.cpu_quantum_ns),
        }
    }

    /// Rejects escalation and returns these defaults with the requested memory fields applied.
    pub const fn attenuate(self, requested: Self) -> Option<Self> {
        if requested.private_pages > self.private_pages
            || requested.shared_memory_bytes > self.shared_memory_bytes
            || requested.mapped_shared_bytes > self.mapped_shared_bytes
            || requested.reserved_virtual_bytes > self.reserved_virtual_bytes
            || requested.vma_count > self.vma_count
            || requested.executable_image_pages > self.executable_image_pages
            || requested.executable_source_bytes > self.executable_source_bytes
            || requested.channel_traffic_bytes > self.channel_traffic_bytes
            || requested.cpu_quantum_ns > self.cpu_quantum_ns
        {
            return None;
        }
        Some(Self {
            private_pages: requested.private_pages,
            shared_memory_bytes: requested.shared_memory_bytes,
            mapped_shared_bytes: requested.mapped_shared_bytes,
            reserved_virtual_bytes: requested.reserved_virtual_bytes,
            vma_count: requested.vma_count,
            executable_image_pages: requested.executable_image_pages,
            executable_source_bytes: requested.executable_source_bytes,
            channel_traffic_bytes: requested.channel_traffic_bytes,
            cpu_quantum_ns: requested.cpu_quantum_ns,
        })
    }

    /// Conservative package-default policy used only by isolated host fixtures.
    pub const STANDARD: Self = Self::from_available_memory_bytes(512 * MIB);

    /// Derives bounded per-process policy from physical RAM that is currently
    /// allocatable after boot reservations and allocations. Every operation is
    /// saturating or checked, and no physical-memory quota exceeds this snapshot.
    pub const fn from_available_memory_bytes(available_bytes: u64) -> Self {
        let available_pages = available_bytes / PAGE_SIZE;
        let private_pages = bounded_policy(
            available_pages / 4,
            (8 * MIB) / PAGE_SIZE,
            available_pages / 2,
        );
        let private_bytes = private_pages.saturating_mul(PAGE_SIZE);
        let shared_memory_bytes =
            bounded_policy(available_bytes / 16, 4 * MIB, available_bytes / 4);
        let mapped_shared_bytes = bounded_policy(available_bytes / 8, 8 * MIB, available_bytes / 2);
        let reserved_max = (USER_ADDRESS_END / 4).saturating_sub(PAGE_SIZE);
        let reserved_virtual_bytes =
            bounded_policy(available_bytes.saturating_mul(8), 256 * MIB, reserved_max);
        let vma_count = bounded_policy(available_bytes / (8 * MIB), 64, MAX_VMAS as u64);
        let executable_image_pages = bounded_policy(
            available_pages / 8,
            (4 * MIB) / PAGE_SIZE,
            private_pages.saturating_sub(USER_STACK_INITIAL_SIZE / PAGE_SIZE),
        );
        let executable_source_bytes = bounded_policy(
            available_bytes / 32,
            PACKAGE_DEFAULT_EXECUTABLE_BYTES,
            private_bytes / 2,
        );
        Self {
            private_pages,
            shared_memory_bytes,
            mapped_shared_bytes,
            reserved_virtual_bytes,
            vma_count,
            executable_image_pages,
            executable_source_bytes,
            channel_traffic_bytes: bounded_policy(
                available_bytes / 8,
                8 * MIB,
                available_bytes / 2,
            ),
            cpu_quantum_ns: 10_000_000,
        }
    }
}

pub(crate) fn select_child_process_limits(
    caller: ProcessLimits,
    available_bytes: u64,
    requested: Option<ProcessLimits>,
) -> Option<ProcessLimits> {
    let inherited = ProcessLimits::from_available_memory_bytes(available_bytes).capped_by(caller);
    match requested {
        Some(requested) => inherited.attenuate(requested),
        None => Some(inherited),
    }
}

const fn bounded_policy(derived: u64, minimum: u64, maximum: u64) -> u64 {
    if maximum == 0 {
        0
    } else {
        let effective_minimum = if minimum < maximum { minimum } else { maximum };
        if derived < effective_minimum {
            effective_minimum
        } else if derived > maximum {
            maximum
        } else {
            derived
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProcessUsage {
    /// Committed image, stack, anonymous, and private file-backed pages.
    pub private_pages: u64,
    pub reserved_virtual_bytes: u64,
    pub resident_owned_frames: u64,
    /// Page-rounded physical backing bytes charged at object creation.
    pub shared_memory_bytes: u64,
    pub mapped_shared_pages: u64,
    pub mapped_shared_bytes: u64,
    pub quota_failures: u64,
    pub oom_failures: u64,
    pub channel_traffic_bytes: u64,
    pub cpu_time_ns: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProcessMemoryObservability {
    pub current_vma_count: u64,
    pub page_table_frames: u64,
    pub committed_image_pages: u64,
    pub committed_stack_pages: u64,
    pub committed_anonymous_pages: u64,
    pub committed_file_backed_pages: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ElfPageLoadError {
    AddressSpace {
        address: u64,
        error: AddressSpaceError,
    },
    HhdmAddressOverflow {
        hhdm_offset: u64,
        physical_address: u64,
    },
    InvalidHhdmAddress(u64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThreadCreateError {
    InvalidEntry,
    InvalidStack,
    InvalidTls,
    ResourceLimit,
    OutOfMemory,
    AddressSpace(AddressSpaceError),
    RollbackFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessCreateError {
    AddressSpace(AddressSpaceError),
    Elf(ElfError),
    ElfPage(ElfPageLoadError),
    StackCollision,
    StackPage {
        address: u64,
        error: AddressSpaceError,
    },
    EntryNotExecutable(AddressSpaceError),
    StackNotWritable(AddressSpaceError),
    /// Explicit executable/private/VMA/reservation policy rejection.
    MemoryPolicy,
    /// Kernel metadata allocation failed before the process became runnable.
    OutOfMemory,
    ResourceLimit,
}

/// Semantic ownership of one virtual-memory area.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VmAreaKind {
    Image,
    Anonymous {
        reservation_id: u64,
        committed: bool,
    },
    Stack {
        owner: ThreadId,
        committed: bool,
    },
    StackGuard {
        owner: ThreadId,
    },
    Shared {
        /// Stable IPC shared-memory object identity; never an address.
        object_identity: u64,
        /// Object byte offset corresponding to this VMA's first page.
        object_offset: u64,
    },
    FileBacked {
        backing_id: u64,
        /// Source-file offset corresponding to this VMA's first page.
        file_offset: u64,
        committed: bool,
    },
}

/// One page-aligned, nonempty entry in a process's bounded sorted VMA table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VmArea {
    pub start: u64,
    pub end: u64,
    pub kind: VmAreaKind,
    pub protection: MapProtection,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserPageFaultResolution {
    Resolved { pages: u64 },
    Fault(ProcessFault),
}

impl VmArea {
    pub const fn length(self) -> u64 {
        self.end - self.start
    }
}

fn virtual_area_info(area: VmArea) -> VirtualAreaInfo {
    let reserved_bytes = area.length();
    let (kind, committed, backing_identity, file_offset) = match area.kind {
        VmAreaKind::Image => (VirtualAreaKind::Image, true, 0, 0),
        VmAreaKind::Anonymous {
            reservation_id,
            committed,
        } => (VirtualAreaKind::Anonymous, committed, reservation_id, 0),
        VmAreaKind::Stack { committed, .. } => (VirtualAreaKind::Stack, committed, 0, 0),
        VmAreaKind::StackGuard { .. } => (VirtualAreaKind::Guard, false, 0, 0),
        VmAreaKind::Shared {
            object_identity, ..
        } => (VirtualAreaKind::Shared, true, object_identity, 0),
        VmAreaKind::FileBacked {
            backing_id,
            file_offset,
            committed,
        } => (VirtualAreaKind::File, committed, backing_id, file_offset),
    };
    let committed_bytes = if committed { reserved_bytes } else { 0 };
    VirtualAreaInfo {
        version: VIRTUAL_AREA_INFO_VERSION,
        size: VirtualAreaInfo::SIZE,
        start: area.start,
        end: area.end,
        kind: kind as u32,
        protection: area.protection.bits(),
        committed_bytes,
        reserved_bytes,
        committed_pages: committed_bytes / PAGE_SIZE,
        reserved_pages: reserved_bytes / PAGE_SIZE,
        backing_identity,
        file_offset,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AnonymousReservationRollback {
    start: u64,
    end: u64,
    reservation_id: u64,
    previous_cursor: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileBacking {
    id: u64,
    /// Generation-protected RedoxFS identity retained independently of the source handle slot.
    /// Handle closure is harmless. Unlink invalidates the generation, so later recommit may fail.
    file: FileHandle,
    source_end: u64,
    /// Maximum protection authorized by the source capability at map time.
    max_protection: MapProtection,
}

pub struct SharedMemoryMapping {
    address: u64,
    offset: u64,
    length: u64,
    mapped_len: usize,
    protection: MapProtection,
    _lease: SharedMemoryMappingLease,
}

impl SharedMemoryMapping {
    pub const fn address(&self) -> u64 {
        self.address
    }

    pub const fn offset(&self) -> u64 {
        self.offset
    }

    pub const fn length(&self) -> u64 {
        self.length
    }

    pub const fn backing_identity(&self) -> u64 {
        self._lease.info().backing_identity
    }

    pub const fn mapped_len(&self) -> usize {
        self.mapped_len
    }

    pub const fn protection(&self) -> MapProtection {
        self.protection
    }
}

impl fmt::Debug for SharedMemoryMapping {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SharedMemoryMapping")
            .field("address", &self.address)
            .field("offset", &self.offset)
            .field("length", &self.length)
            .field("mapped_len", &self.mapped_len)
            .field("protection", &self.protection)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SharedMappingError {
    Ipc(IpcError),
    InvalidProtection(MapProtection),
    UnsupportedFlags(MapFlags),
    UnalignedOffset(u64),
    ZeroLength,
    RangeOverflow,
    RangeOutsideObject {
        offset: u64,
        length: u64,
        object_length: usize,
    },
    InvalidBackingLength,
    Io,
    OutOfMemory,
    ResourceLimit,
    InvalidPhysicalAddress(u64),
    PhysicalAddressNotPageAligned(u64),
    UnalignedFixedAddress(u64),
    InvalidFixedAddress(u64),
    AlreadyMapped(u64),
    NoAddressSpace,
    AddressSpace(AddressSpaceError),
    RollbackFailed {
        mapping_error: AddressSpaceError,
        rollback_error: AddressSpaceError,
    },
    ExactMappingNotFound {
        address: u64,
        length: u64,
    },
}

impl From<IpcError> for SharedMappingError {
    fn from(error: IpcError) -> Self {
        Self::Ipc(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessTeardown {
    pub handles_closed: usize,
    pub mappings_released: usize,
    pub anonymous_mappings_released: usize,
    pub retained_failed_mapping_leases_released: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessReclaimStats {
    pub frames: FrameReclaimStats,
    pub teardown: ProcessTeardown,
}

/// Reclaim failure retaining the retired process's unreclaimed frame ownership.
pub struct RetiredProcessReclaimError {
    process: RetiredProcess,
    error: crate::memory::FrameAllocatorError,
    reclaimed: FrameReclaimStats,
}

impl RetiredProcessReclaimError {
    pub const fn error(&self) -> crate::memory::FrameAllocatorError {
        self.error
    }

    pub const fn reclaimed(&self) -> FrameReclaimStats {
        self.reclaimed
    }

    pub const fn process(&self) -> &RetiredProcess {
        &self.process
    }

    pub fn into_process(self) -> RetiredProcess {
        self.process
    }
}

impl fmt::Debug for RetiredProcessReclaimError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetiredProcessReclaimError")
            .field("error", &self.error)
            .field("reclaimed", &self.reclaimed)
            .field("remaining", &self.process.address_space.accounting())
            .finish()
    }
}

/// Inactive process resources after capability and mapping leases have been torn down.
pub struct RetiredProcess {
    address_space: RetiredAddressSpace,
    context: UserContext,
    final_state: ProcessState,
    teardown: ProcessTeardown,
}

impl RetiredProcess {
    pub const fn address_space(&self) -> &RetiredAddressSpace {
        &self.address_space
    }

    pub const fn context(&self) -> &UserContext {
        &self.context
    }

    pub const fn final_state(&self) -> ProcessState {
        self.final_state
    }

    pub const fn teardown(&self) -> ProcessTeardown {
        self.teardown
    }

    pub fn into_address_space(self) -> RetiredAddressSpace {
        self.address_space
    }

    /// Consumes this retired process and returns all uniquely owned frames.
    ///
    /// A failure returns the process owner with only unreclaimed frames, allowing
    /// an exact retry without replaying already successful batches.
    pub fn reclaim(
        self,
        allocator: &mut UsableFrameAllocator<'_>,
    ) -> Result<ProcessReclaimStats, RetiredProcessReclaimError> {
        let Self {
            address_space,
            context,
            final_state,
            teardown,
        } = self;
        match address_space.reclaim(allocator) {
            Ok(frames) => Ok(ProcessReclaimStats { frames, teardown }),
            Err(error) => {
                let allocator_error = error.error();
                let reclaimed = error.reclaimed();
                Err(RetiredProcessReclaimError {
                    process: Self {
                        address_space: error.into_address_space(),
                        context,
                        final_state,
                        teardown,
                    },
                    error: allocator_error,
                    reclaimed,
                })
            }
        }
    }
}

/// Retirement refused because the process address-space root is still current.
///
/// The intact process is retained so callers can restore the kernel CR3 and retry
/// without losing mappings, handles, or backing leases.
pub struct ProcessRetireError {
    process: Process,
}

impl ProcessRetireError {
    pub const fn process(&self) -> &Process {
        &self.process
    }

    pub fn into_process(self) -> Process {
        self.process
    }
}

impl fmt::Debug for ProcessRetireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProcessRetireError")
            .field("reason", &"address space is still active")
            .field("root_frame", &self.process.address_space().root_frame())
            .finish()
    }
}

/// Dedicated supervisor-only entry stacks retained for a thread's whole lifetime.
pub struct KernelEntryStacks {
    rsp0: Vec<u8>,
    syscall: Vec<u8>,
}

impl KernelEntryStacks {
    fn try_new() -> Result<Self, ()> {
        fn stack() -> Result<Vec<u8>, ()> {
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(KERNEL_ENTRY_STACK_SIZE + 64)
                .map_err(|_| ())?;
            bytes.resize(KERNEL_ENTRY_STACK_SIZE + 64, 0);
            Ok(bytes)
        }
        Ok(Self {
            rsp0: stack()?,
            syscall: stack()?,
        })
    }

    fn aligned_top(bytes: &[u8]) -> u64 {
        let end = bytes.as_ptr() as usize + bytes.len();
        (end & !0x3f) as u64
    }

    pub fn tops(&self) -> crate::arch::UserEntryStackTops {
        crate::arch::UserEntryStackTops {
            rsp0: Self::aligned_top(&self.rsp0),
            syscall: Self::aligned_top(&self.syscall),
        }
    }
}

/// CPU, stack, blocking, and scheduler state for one independently identified thread.
pub struct Thread {
    context: UserContext,
    layout: ProcessLayout,
    entry_stacks: KernelEntryStacks,
    state: ThreadState,
    detached: bool,
    join_claimed_by: Option<ThreadId>,
    wake_permit: bool,
    fallback_scheduling_class: SchedulingClass,
    kernel_scheduling_class: Option<SchedulingClass>,
    delegated_scheduling_class: Option<(SchedulingClass, SchedulingAuthorityLease)>,
    focused_interactive: bool,
    effective_class: SchedulingClass,
    scheduler_budget_remaining_ns: u64,
    scheduler_metrics: SchedulerMetrics,
    preemption_count: u64,
    cpu_time_ns: u64,
    blocked_syscall: Option<BlockedSyscall>,
}

impl Thread {
    pub const fn state(&self) -> ThreadState {
        self.state
    }

    pub const fn cpu_time_ns(&self) -> u64 {
        self.cpu_time_ns
    }

    pub const fn preemption_count(&self) -> u64 {
        self.preemption_count
    }

    pub fn scheduling_class(&self) -> SchedulingClass {
        if let Some(class) = self.kernel_scheduling_class {
            return class;
        }
        if let Some((class, authority)) = &self.delegated_scheduling_class {
            if authority.authorizes(public_scheduling_class(*class)) {
                return *class;
            }
        }
        if self.focused_interactive && self.fallback_scheduling_class != SchedulingClass::Background
        {
            SchedulingClass::Interactive
        } else {
            self.fallback_scheduling_class
        }
    }

    pub const fn scheduler_metrics(&self) -> SchedulerMetrics {
        self.scheduler_metrics
    }

    pub fn entry_stack_tops(&self) -> crate::arch::UserEntryStackTops {
        self.entry_stacks.tops()
    }
}

struct ThreadSlot {
    generation: u32,
    thread: Option<Thread>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PreparedThreadSlot {
    id: ThreadId,
    append: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThreadTableError {
    Full,
    OutOfMemory,
}

/// Process-owned generation table for live and joinable terminal threads.
struct ThreadTable {
    slots: Vec<ThreadSlot>,
    next_slot: usize,
    len: usize,
    live: usize,
}

impl ThreadTable {
    fn with_main(thread: Thread) -> (Self, ThreadId) {
        let mut slots = Vec::new();
        slots.push(ThreadSlot {
            generation: 1,
            thread: Some(thread),
        });
        (
            Self {
                slots,
                next_slot: 0,
                len: 1,
                live: 1,
            },
            MAIN_THREAD_ID,
        )
    }

    fn prepare_insert(&mut self) -> Result<PreparedThreadSlot, ThreadTableError> {
        if self.len >= MAX_THREADS_PER_PROCESS {
            return Err(ThreadTableError::Full);
        }
        if let Some((index, slot)) = self
            .slots
            .iter()
            .enumerate()
            .find(|(_, slot)| slot.generation != 0 && slot.thread.is_none())
        {
            return Ok(PreparedThreadSlot {
                id: ThreadId::from_parts(index as u32, slot.generation),
                append: false,
            });
        }
        if self.slots.len() > u32::MAX as usize {
            return Err(ThreadTableError::Full);
        }
        self.slots
            .try_reserve(1)
            .map_err(|_| ThreadTableError::OutOfMemory)?;
        Ok(PreparedThreadSlot {
            id: ThreadId::from_parts(self.slots.len() as u32, 1),
            append: true,
        })
    }

    fn insert_prepared(&mut self, prepared: PreparedThreadSlot, thread: Thread) -> ThreadId {
        if prepared.append {
            debug_assert_eq!(prepared.id.slot() as usize, self.slots.len());
            self.slots.push(ThreadSlot {
                generation: prepared.id.generation(),
                thread: Some(thread),
            });
        } else {
            let slot = &mut self.slots[prepared.id.slot() as usize];
            assert_eq!(slot.generation, prepared.id.generation());
            assert!(slot.thread.is_none());
            slot.thread = Some(thread);
        }
        self.len += 1;
        self.live += 1;
        prepared.id
    }

    fn get(&self, id: ThreadId) -> Option<&Thread> {
        let slot = self.slots.get(id.slot() as usize)?;
        (id.is_valid() && slot.generation == id.generation())
            .then(|| slot.thread.as_ref())
            .flatten()
    }

    fn get_mut(&mut self, id: ThreadId) -> Option<&mut Thread> {
        let slot = self.slots.get_mut(id.slot() as usize)?;
        (id.is_valid() && slot.generation == id.generation())
            .then(|| slot.thread.as_mut())
            .flatten()
    }

    fn mark_terminal(&mut self, id: ThreadId) -> bool {
        let Some(thread) = self.get(id) else {
            return false;
        };
        if !thread.state.is_terminal() {
            self.live = self.live.saturating_sub(1);
        }
        true
    }

    fn remove(&mut self, id: ThreadId) -> Option<Thread> {
        let slot = self.slots.get_mut(id.slot() as usize)?;
        if !id.is_valid() || slot.generation != id.generation() {
            return None;
        }
        let thread = slot.thread.take()?;
        self.len -= 1;
        if !thread.state.is_terminal() {
            self.live = self.live.saturating_sub(1);
        }
        slot.generation = slot.generation.checked_add(1).unwrap_or(0);
        Some(thread)
    }

    fn next_schedulable(&mut self) -> Option<ThreadId> {
        if self.live == 0 || self.slots.is_empty() {
            return None;
        }
        self.next_slot %= self.slots.len();
        for _ in 0..self.slots.len() {
            let index = self.next_slot;
            self.next_slot = (index + 1) % self.slots.len();
            let slot = &self.slots[index];
            if slot
                .thread
                .as_ref()
                .is_some_and(|thread| !thread.state.is_terminal())
            {
                return Some(ThreadId::from_parts(index as u32, slot.generation));
            }
        }
        None
    }

    fn any_runnable(&self) -> bool {
        self.slots.iter().any(|slot| {
            slot.thread
                .as_ref()
                .is_some_and(|thread| thread.state.is_runnable())
        })
    }
}

/// Process-wide protection, authority, resource, and thread ownership state.
pub struct Process {
    address_space: Option<AddressSpace>,
    threads: ThreadTable,
    main_thread_id: ThreadId,
    main_layout: ProcessLayout,
    retirement_context: UserContext,
    terminal_state: Option<ProcessState>,
    handles: Option<HandleTable>,
    application_data: Option<Handle>,
    control: Option<ProcessControl>,
    shared_mappings: Option<Vec<SharedMemoryMapping>>,
    file_backings: Option<Vec<FileBacking>>,
    vmas: Option<Vec<VmArea>>,
    // If a corrupt page table prevents rollback, retaining the lease is safer
    // than releasing backing which may still have a live userspace alias.
    retained_failed_mapping_leases: Option<Vec<SharedMemoryMappingLease>>,
    next_mapping_cursor: u64,
    next_thread_stack_cursor: u64,
    next_anonymous_reservation_id: u64,
    next_file_backing_id: u64,
    #[cfg(test)]
    fail_file_rollback_for_test: bool,
    limits: ProcessLimits,
    usage: ProcessUsage,
}

impl Process {
    /// Builds a process in a fresh isolated address-space root.
    ///
    /// ELF pages and stack pages are allocated and zeroed by `AddressSpace`.
    /// ELF bytes are then copied through each returned owned frame's checked HHDM
    /// address, so loading does not require activating the new address space.
    pub fn from_elf(
        file: &[u8],
        kernel: &ActivePageTable,
        allocator: &mut UsableFrameAllocator<'_>,
    ) -> Result<Self, ProcessCreateError> {
        Self::from_elf_with_randomness(file, kernel, allocator, None, None)
    }

    /// Builds a process with independently randomized PIE, stack, and mapping regions.
    pub fn from_elf_randomized(
        file: &[u8],
        kernel: &ActivePageTable,
        allocator: &mut UsableFrameAllocator<'_>,
        randomness: [u64; 3],
    ) -> Result<Self, ProcessCreateError> {
        Self::from_elf_with_randomness(file, kernel, allocator, Some(randomness), None)
    }

    pub fn from_elf_randomized_with_limits(
        file: &[u8],
        kernel: &ActivePageTable,
        allocator: &mut UsableFrameAllocator<'_>,
        randomness: [u64; 3],
        limits: ProcessLimits,
    ) -> Result<Self, ProcessCreateError> {
        Self::from_elf_with_randomness(file, kernel, allocator, Some(randomness), Some(limits))
    }

    fn from_elf_with_randomness(
        file: &[u8],
        kernel: &ActivePageTable,
        allocator: &mut UsableFrameAllocator<'_>,
        randomness: Option<[u64; 3]>,
        requested_limits: Option<ProcessLimits>,
    ) -> Result<Self, ProcessCreateError> {
        let defaults = ProcessLimits::from_available_memory_bytes(allocator.available_bytes());
        let limits = match requested_limits {
            Some(requested) => defaults
                .attenuate(requested)
                .ok_or(ProcessCreateError::MemoryPolicy)?,
            None => defaults,
        };
        if u64::try_from(file.len()).map_or(true, |length| {
            length == 0 || length > limits.executable_source_bytes
        }) {
            return Err(ProcessCreateError::MemoryPolicy);
        }
        let parsed = match randomness {
            Some(values) => elf::parse_randomized(file, values[0]),
            None => elf::parse(file),
        }
        .map_err(ProcessCreateError::Elf)?;
        let layout = randomness
            .map(|values| ProcessLayout::randomized(values[1]))
            .unwrap_or(ProcessLayout::STANDARD);
        let initial_stack_pages = layout.initial_stack_size() / PAGE_SIZE;
        if parsed
            .total_load_pages()
            .saturating_add(initial_stack_pages)
            > limits.private_pages
            || parsed.total_load_pages() > limits.executable_image_pages
        {
            return Err(ProcessCreateError::MemoryPolicy);
        }
        if parsed
            .overlaps_reserved_range(
                layout.stack_guard_start,
                layout.stack_top - layout.stack_guard_start,
            )
            .expect("static stack reservation is a valid user range")
        {
            return Err(ProcessCreateError::StackCollision);
        }

        let page_count = parsed
            .total_load_pages()
            .checked_add(initial_stack_pages)
            .and_then(|count| usize::try_from(count).ok())
            .ok_or(ProcessCreateError::OutOfMemory)?;
        let hhdm_offset = kernel.hhdm_offset();
        let address_space =
            AddressSpace::new_with_private_mapping_capacity(kernel, allocator, page_count)
                .map_err(ProcessCreateError::AddressSpace)?;
        Self::finish_construction(
            parsed,
            address_space,
            hhdm_offset,
            layout,
            limits,
            allocator,
            randomness,
        )
    }

    fn finish_construction(
        parsed: elf::ParsedElf<'_>,
        mut address_space: AddressSpace,
        hhdm_offset: VirtAddr,
        layout: ProcessLayout,
        limits: ProcessLimits,
        allocator: &mut UsableFrameAllocator<'_>,
        randomness: Option<[u64; 3]>,
    ) -> Result<Self, ProcessCreateError> {
        let Some(page_count) = parsed
            .total_load_pages()
            .checked_add(layout.initial_stack_size() / PAGE_SIZE)
            .and_then(|count| usize::try_from(count).ok())
        else {
            return reclaim_failed_construction(
                address_space,
                allocator,
                ProcessCreateError::OutOfMemory,
            );
        };
        if let Err(error) = address_space.preflight_owned_user_mappings(page_count) {
            return reclaim_failed_construction(
                address_space,
                allocator,
                ProcessCreateError::AddressSpace(error),
            );
        }
        let Some(initial_vma_need) = parsed.segment_count().checked_add(3) else {
            return reclaim_failed_construction(
                address_space,
                allocator,
                ProcessCreateError::ResourceLimit,
            );
        };
        let vma_capacity = usize::try_from(limits.vma_count)
            .unwrap_or(MAX_VMAS)
            .min(MAX_VMAS);
        if initial_vma_need > vma_capacity {
            return reclaim_failed_construction(
                address_space,
                allocator,
                ProcessCreateError::ResourceLimit,
            );
        }
        let mut initial_vma_storage = Vec::new();
        if initial_vma_storage.try_reserve_exact(vma_capacity).is_err() {
            return reclaim_failed_construction(
                address_space,
                allocator,
                ProcessCreateError::OutOfMemory,
            );
        }
        let loaded = parsed.load_with(|address, permissions, contents| {
            let permissions = user_permissions(permissions);
            let frame = address_space
                .map_zeroed_user_4k(address, permissions, allocator)
                .map_err(|error| ElfPageLoadError::AddressSpace { address, error })?;
            copy_page_through_hhdm(hhdm_offset, frame, contents)
        });
        let image = match loaded {
            Ok(image) => image,
            Err(LoadError::Elf(error)) => {
                return reclaim_failed_construction(
                    address_space,
                    allocator,
                    ProcessCreateError::Elf(error),
                )
            }
            Err(LoadError::Page(error)) => {
                return reclaim_failed_construction(
                    address_space,
                    allocator,
                    ProcessCreateError::ElfPage(error),
                )
            }
        };

        let mut stack_page = layout.stack_initial_bottom;
        while stack_page < layout.stack_top {
            if let Err(error) = address_space.map_zeroed_user_4k(
                stack_page,
                UserPagePermissions::READ_WRITE,
                allocator,
            ) {
                return reclaim_failed_construction(
                    address_space,
                    allocator,
                    ProcessCreateError::StackPage {
                        address: stack_page,
                        error,
                    },
                );
            }
            stack_page += PAGE_SIZE;
        }

        if let Err(error) = address_space.validate_user_range(image.entry, 1, UserAccess::Execute) {
            return reclaim_failed_construction(
                address_space,
                allocator,
                ProcessCreateError::EntryNotExecutable(error),
            );
        }
        if let Err(error) = address_space.validate_user_range(
            layout.stack_initial_bottom,
            layout.initial_stack_size() as usize,
            UserAccess::Write,
        ) {
            return reclaim_failed_construction(
                address_space,
                allocator,
                ProcessCreateError::StackNotWritable(error),
            );
        }

        let vmas = match initial_vmas(&image, layout, initial_vma_storage) {
            Ok(vmas) => vmas,
            Err(error) => {
                return reclaim_failed_construction(address_space, allocator, error);
            }
        };
        if vmas.len() as u64 > limits.vma_count {
            return reclaim_failed_construction(
                address_space,
                allocator,
                ProcessCreateError::MemoryPolicy,
            );
        }
        let reserved_virtual_bytes = vmas
            .iter()
            .fold(0u64, |total, vma| total.saturating_add(vma.length()));
        if reserved_virtual_bytes > limits.reserved_virtual_bytes {
            return reclaim_failed_construction(
                address_space,
                allocator,
                ProcessCreateError::MemoryPolicy,
            );
        }
        let private_pages = image
            .segments
            .iter()
            .map(|segment| segment.page_count)
            .sum::<u64>()
            .saturating_add(layout.initial_stack_size() / PAGE_SIZE);
        let context = UserContext::new(image.entry, layout.stack_top);
        debug_assert_eq!(context.rsp & 0xf, 0);
        let entry_stacks = match KernelEntryStacks::try_new() {
            Ok(stacks) => stacks,
            Err(()) => {
                return reclaim_failed_construction(
                    address_space,
                    allocator,
                    ProcessCreateError::OutOfMemory,
                )
            }
        };
        let (threads, main_thread_id) = ThreadTable::with_main(Thread {
            context,
            layout,
            entry_stacks,
            state: ThreadState::Ready,
            detached: false,
            join_claimed_by: None,
            wake_permit: false,
            fallback_scheduling_class: SchedulingClass::Normal,
            kernel_scheduling_class: None,
            delegated_scheduling_class: None,
            focused_interactive: false,
            effective_class: SchedulingClass::Normal,
            scheduler_budget_remaining_ns: 0,
            scheduler_metrics: SchedulerMetrics::default(),
            preemption_count: 0,
            cpu_time_ns: 0,
            blocked_syscall: None,
        });

        Ok(Self {
            address_space: Some(address_space),
            threads,
            main_thread_id,
            main_layout: layout,
            retirement_context: context,
            terminal_state: None,
            handles: Some(HandleTable::new()),
            application_data: None,
            control: None,
            shared_mappings: Some(Vec::new()),
            file_backings: Some(Vec::new()),
            vmas: Some(vmas),
            retained_failed_mapping_leases: Some(Vec::new()),
            next_mapping_cursor: SHARED_MAPPING_BASE
                + randomness
                    .map(|values| values[2] % MAPPING_ASLR_SLOTS)
                    .unwrap_or(0)
                    * PAGE_SIZE,
            next_thread_stack_cursor: layout.stack_guard_start,
            next_anonymous_reservation_id: 1,
            next_file_backing_id: 1,
            #[cfg(test)]
            fail_file_rollback_for_test: false,
            limits,
            usage: ProcessUsage {
                private_pages,
                reserved_virtual_bytes,
                ..ProcessUsage::default()
            },
        })
    }

    pub const fn layout(&self) -> ProcessLayout {
        self.main_layout
    }

    pub fn state(&self) -> ProcessState {
        if let Some(state) = self.terminal_state {
            return state;
        }
        if self.threads.any_runnable() {
            ProcessState::Ready
        } else {
            ProcessState::Blocked
        }
    }

    pub const fn main_thread_id(&self) -> ThreadId {
        self.main_thread_id
    }

    pub fn thread(&self, id: ThreadId) -> Option<&Thread> {
        self.threads.get(id)
    }

    pub fn thread_mut(&mut self, id: ThreadId) -> Option<&mut Thread> {
        self.threads.get_mut(id)
    }

    pub fn thread_state(&self, id: ThreadId) -> Option<ThreadState> {
        self.thread(id).map(Thread::state)
    }

    pub fn thread_context(&self, id: ThreadId) -> Option<&UserContext> {
        self.thread(id).map(|thread| &thread.context)
    }

    pub fn thread_entry_stack_tops(&self, id: ThreadId) -> Option<crate::arch::UserEntryStackTops> {
        self.thread(id).map(Thread::entry_stack_tops)
    }

    pub fn thread_context_mut(&mut self, id: ThreadId) -> Option<&mut UserContext> {
        self.thread_mut(id).map(|thread| &mut thread.context)
    }

    pub fn record_retirement_context(&mut self, id: ThreadId, context: UserContext) {
        if id == self.main_thread_id {
            self.retirement_context = context;
        }
    }

    pub fn thread_ids(&self) -> impl Iterator<Item = ThreadId> + '_ {
        self.threads
            .slots
            .iter()
            .enumerate()
            .filter_map(|(index, slot)| {
                slot.thread
                    .as_ref()
                    .map(|_| ThreadId::from_parts(index as u32, slot.generation))
            })
    }

    pub fn record_thread_cpu_time(&mut self, id: ThreadId, elapsed_ns: u64) -> bool {
        let Some(thread) = self.thread_mut(id) else {
            return false;
        };
        thread.cpu_time_ns = thread.cpu_time_ns.saturating_add(elapsed_ns);
        self.usage.cpu_time_ns = self.usage.cpu_time_ns.saturating_add(elapsed_ns);
        true
    }

    pub fn thread_scheduling_class(&self, id: ThreadId) -> Option<SchedulingClass> {
        self.thread(id).map(Thread::scheduling_class)
    }

    pub fn thread_scheduler_data(
        &self,
        id: ThreadId,
    ) -> Option<(
        SchedulingClass,
        SchedulingClass,
        u64,
        SchedulerMetrics,
        ThreadState,
    )> {
        self.thread(id).map(|thread| {
            (
                thread.scheduling_class(),
                thread.effective_class,
                thread.scheduler_budget_remaining_ns,
                thread.scheduler_metrics,
                thread.state,
            )
        })
    }

    pub fn set_thread_scheduling_class(
        &mut self,
        id: ThreadId,
        class: SchedulingClass,
    ) -> Result<(), Status> {
        if !matches!(class, SchedulingClass::Normal | SchedulingClass::Background) {
            return Err(Status::AccessDenied);
        }
        let thread = self.thread_mut(id).ok_or(Status::InvalidHandle)?;
        thread.fallback_scheduling_class = class;
        thread.delegated_scheduling_class = None;
        Ok(())
    }

    pub fn set_thread_scheduling_class_with_authority(
        &mut self,
        id: ThreadId,
        class: SchedulingClass,
        authority: SchedulingAuthorityLease,
    ) -> Result<(), Status> {
        if !matches!(class, SchedulingClass::Audio | SchedulingClass::Interactive)
            || !authority.authorizes(public_scheduling_class(class))
        {
            return Err(Status::AccessDenied);
        }
        self.thread_mut(id)
            .ok_or(Status::InvalidHandle)?
            .delegated_scheduling_class = Some((class, authority));
        Ok(())
    }

    pub fn set_thread_scheduling_class_by_kernel(
        &mut self,
        id: ThreadId,
        class: SchedulingClass,
    ) -> Result<(), Status> {
        self.thread_mut(id)
            .ok_or(Status::InvalidHandle)?
            .kernel_scheduling_class = Some(class);
        Ok(())
    }

    pub fn set_focused_interactive(&mut self, focused: bool) {
        for slot in &mut self.threads.slots {
            if let Some(thread) = slot.thread.as_mut() {
                thread.focused_interactive = focused;
            }
        }
    }

    pub fn record_scheduler_snapshot(&mut self, id: ThreadId, snapshot: ThreadSnapshot) {
        if let Some(thread) = self.thread_mut(id) {
            thread.effective_class = snapshot.effective_class;
            thread.scheduler_budget_remaining_ns = snapshot.budget_remaining_ns;
            thread.scheduler_metrics = snapshot.metrics;
        }
    }

    pub fn record_thread_preemption(&mut self, id: ThreadId) -> bool {
        let Some(thread) = self.thread_mut(id) else {
            return false;
        };
        thread.preemption_count = thread.preemption_count.saturating_add(1);
        true
    }

    fn find_thread_stack_top(&self, stack_size: u64) -> Option<u64> {
        let extent = stack_size.checked_add(PAGE_SIZE)?;
        let mut top = self.main_layout.stack_guard_start;
        loop {
            let bottom = top.checked_sub(extent)?;
            if bottom < SHARED_MAPPING_BASE {
                return None;
            }
            let overlap = self
                .vmas()
                .iter()
                .rev()
                .find(|area| area.start < top && area.end > bottom);
            match overlap {
                Some(area) => top = area.start,
                None => return Some(top),
            }
        }
    }

    pub fn create_thread(
        &mut self,
        entry: u64,
        argument: u64,
        requested_stack_size: u64,
        tls_base: u64,
        allocator: &mut UsableFrameAllocator<'_>,
    ) -> Result<ThreadId, ThreadCreateError> {
        if self.terminal_state.is_some() {
            return Err(ThreadCreateError::ResourceLimit);
        }
        self.address_space()
            .validate_user_range(entry, 1, UserAccess::Execute)
            .map_err(|_| ThreadCreateError::InvalidEntry)?;
        if tls_base != 0 && !Self::is_user_virtual_address(tls_base) {
            return Err(ThreadCreateError::InvalidTls);
        }
        let stack_size = if requested_stack_size == 0 {
            USER_STACK_MAX_SIZE
        } else {
            align_up(requested_stack_size, PAGE_SIZE).ok_or(ThreadCreateError::InvalidStack)?
        };
        if !(USER_STACK_INITIAL_SIZE..=USER_STACK_MAX_SIZE).contains(&stack_size) {
            return Err(ThreadCreateError::InvalidStack);
        }
        let prepared = self.threads.prepare_insert().map_err(|error| match error {
            ThreadTableError::Full => ThreadCreateError::ResourceLimit,
            ThreadTableError::OutOfMemory => ThreadCreateError::OutOfMemory,
        })?;
        let stack_top = self
            .find_thread_stack_top(stack_size)
            .ok_or(ThreadCreateError::ResourceLimit)?;
        let layout = ProcessLayout::for_stack(stack_top, stack_size);
        let committed_pages = layout.initial_stack_size() / PAGE_SIZE;
        let new_private_pages = self
            .usage
            .private_pages
            .checked_add(committed_pages)
            .filter(|pages| *pages <= self.limits.private_pages)
            .ok_or(ThreadCreateError::ResourceLimit)?;
        let reserved = stack_size
            .checked_add(PAGE_SIZE)
            .and_then(|bytes| self.usage.reserved_virtual_bytes.checked_add(bytes))
            .filter(|bytes| *bytes <= self.limits.reserved_virtual_bytes)
            .ok_or(ThreadCreateError::ResourceLimit)?;
        let mut planned = plan_vma_insert(
            self.vmas(),
            VmArea {
                start: layout.stack_guard_start,
                end: layout.stack_bottom,
                kind: VmAreaKind::StackGuard { owner: prepared.id },
                protection: MapProtection::empty(),
            },
        )
        .map_err(map_thread_vma_error)?;
        if layout.stack_bottom < layout.stack_initial_bottom {
            planned = plan_vma_insert(
                &planned,
                VmArea {
                    start: layout.stack_bottom,
                    end: layout.stack_initial_bottom,
                    kind: VmAreaKind::Stack {
                        owner: prepared.id,
                        committed: false,
                    },
                    protection: MapProtection::READ | MapProtection::WRITE,
                },
            )
            .map_err(map_thread_vma_error)?;
        }
        planned = plan_vma_insert(
            &planned,
            VmArea {
                start: layout.stack_initial_bottom,
                end: layout.stack_top,
                kind: VmAreaKind::Stack {
                    owner: prepared.id,
                    committed: true,
                },
                protection: MapProtection::READ | MapProtection::WRITE,
            },
        )
        .map_err(map_thread_vma_error)?;
        if planned.len() as u64 > self.limits.vma_count {
            return Err(ThreadCreateError::ResourceLimit);
        }
        let entry_stacks =
            KernelEntryStacks::try_new().map_err(|_| ThreadCreateError::OutOfMemory)?;
        self.address_space_mut()
            .preflight_owned_user_mappings(committed_pages as usize)
            .map_err(ThreadCreateError::AddressSpace)?;
        let mut mapped = 0usize;
        let mapped_len = layout.initial_stack_size() as usize;
        while mapped < mapped_len {
            let address = layout.stack_initial_bottom + mapped as u64;
            if let Err(error) = self.address_space_mut().map_zeroed_user_4k(
                address,
                UserPagePermissions::READ_WRITE,
                allocator,
            ) {
                if mapped != 0
                    && self
                        .address_space_mut()
                        .unmap_user_range(layout.stack_initial_bottom, mapped)
                        .is_err()
                {
                    return Err(ThreadCreateError::RollbackFailed);
                }
                if self
                    .address_space_mut()
                    .reclaim_retired_data_frames(allocator)
                    .is_err()
                {
                    return Err(ThreadCreateError::RollbackFailed);
                }
                return Err(ThreadCreateError::AddressSpace(error));
            }
            mapped += PAGE_SIZE as usize;
        }
        let initial_rsp = layout
            .stack_top
            .checked_sub(8)
            .ok_or(ThreadCreateError::InvalidStack)?;
        // Every newly mapped stack page is zero-filled, so the synthetic return
        // address at `initial_rsp` is already zero without requiring the child CR3.
        let mut context = UserContext::new(entry, initial_rsp);
        context.fs_base = tls_base;
        context.rdi = argument;
        let id = self.threads.insert_prepared(
            prepared,
            Thread {
                context,
                layout,
                entry_stacks,
                state: ThreadState::Ready,
                detached: false,
                join_claimed_by: None,
                wake_permit: false,
                fallback_scheduling_class: SchedulingClass::Normal,
                kernel_scheduling_class: None,
                delegated_scheduling_class: None,
                focused_interactive: false,
                effective_class: SchedulingClass::Normal,
                scheduler_budget_remaining_ns: 0,
                scheduler_metrics: SchedulerMetrics::default(),
                preemption_count: 0,
                cpu_time_ns: 0,
                blocked_syscall: None,
            },
        );
        *self.vmas.as_mut().expect("live process lost its VMA table") = planned;
        self.usage.private_pages = new_private_pages;
        self.usage.reserved_virtual_bytes = reserved;
        self.next_thread_stack_cursor = self.next_thread_stack_cursor.min(layout.stack_guard_start);
        Ok(id)
    }

    pub fn abort_thread_create(
        &mut self,
        id: ThreadId,
        allocator: &mut UsableFrameAllocator<'_>,
    ) -> Result<(), ThreadCreateError> {
        let layout = self
            .thread(id)
            .map(|thread| thread.layout)
            .ok_or(ThreadCreateError::InvalidStack)?;
        let planned = plan_thread_stack_remove(self.vmas(), id).map_err(map_thread_vma_error)?;
        self.address_space_mut()
            .unmap_user_range(
                layout.stack_initial_bottom,
                layout.initial_stack_size() as usize,
            )
            .map_err(|_| ThreadCreateError::RollbackFailed)?;
        self.address_space_mut()
            .reclaim_retired_data_frames(allocator)
            .map_err(|_| ThreadCreateError::RollbackFailed)?;
        self.threads
            .remove(id)
            .ok_or(ThreadCreateError::InvalidStack)?;
        *self.vmas.as_mut().expect("live process lost its VMA table") = planned;
        self.usage.private_pages = self
            .usage
            .private_pages
            .saturating_sub(layout.initial_stack_size() / PAGE_SIZE);
        self.usage.reserved_virtual_bytes = self
            .usage
            .reserved_virtual_bytes
            .saturating_sub(layout.stack_size().saturating_add(PAGE_SIZE));
        if self.next_thread_stack_cursor == layout.stack_guard_start {
            self.next_thread_stack_cursor = layout.stack_top;
        }
        Ok(())
    }

    fn main_thread(&self) -> &Thread {
        self.threads
            .get(self.main_thread_id)
            .expect("live process lost its main thread")
    }

    fn main_thread_mut(&mut self) -> &mut Thread {
        self.threads
            .get_mut(self.main_thread_id)
            .expect("live process lost its main thread")
    }

    /// Designates a process-local application-data identity owned by this process's
    /// handle table. The raw handle is kernel-internal and is never returned by the
    /// data-directory syscall.
    pub fn set_application_data(&mut self, handle: Handle) -> Result<(), IpcError> {
        if self.application_data.is_some() {
            return Err(IpcError::InvalidMessage);
        }
        self.handles()
            .application_data_scope(handle, ginkgo_sysapi::Rights::READ)?;
        self.application_data = Some(handle);
        Ok(())
    }

    pub const fn application_data(&self) -> Option<Handle> {
        self.application_data
    }

    pub fn attach_control(&mut self, control: ProcessControl) {
        assert!(
            self.control.is_none(),
            "process control was already attached"
        );
        self.control = Some(control);
    }

    pub fn register_termination_observer(
        &self,
        token: WaitToken,
        observer: &Arc<dyn SignalObserver>,
    ) -> Result<bool, IpcError> {
        let Some(control) = &self.control else {
            return Ok(false);
        };
        control.register_termination_observer(token, observer)?;
        Ok(true)
    }

    pub fn termination_requested(&self) -> bool {
        self.control
            .as_ref()
            .is_some_and(ProcessControl::terminate_requested)
    }

    pub fn mark_terminated(&mut self) {
        if self.terminal_state.is_some() {
            return;
        }
        self.cancel_all_blocked_syscalls();
        for slot in &mut self.threads.slots {
            let Some(thread) = slot.thread.as_mut() else {
                continue;
            };
            if !thread.state.is_terminal() {
                thread.state = ThreadState::Terminated;
            }
        }
        self.threads.live = 0;
        self.terminal_state = Some(ProcessState::Terminated);
        if let Some(control) = &self.control {
            control.mark_terminated();
        }
    }

    pub fn publish_terminal_status(&self) {
        let Some(control) = &self.control else {
            return;
        };
        match self.state() {
            ProcessState::Exited(code) => {
                control.mark_exited(code);
            }
            ProcessState::Faulted(fault) => {
                control.mark_faulted(
                    public_fault(fault.reason),
                    fault.code,
                    fault.address.unwrap_or(0),
                );
            }
            ProcessState::Terminated => {
                control.mark_terminated();
            }
            ProcessState::Ready | ProcessState::Blocked => {}
        }
    }

    pub fn is_runnable(&self) -> bool {
        self.terminal_state.is_none() && self.threads.any_runnable()
    }

    pub const fn limits(&self) -> ProcessLimits {
        self.limits
    }

    pub fn usage(&self) -> ProcessUsage {
        let accounting = self.address_space().accounting();
        let mut usage = self.usage;
        usage.resident_owned_frames = (accounting.mapped_data_frames as u64)
            .saturating_add(accounting.retired_data_frames as u64)
            .saturating_add(accounting.page_table_frames as u64);
        usage
    }

    pub fn memory_observability(&self) -> ProcessMemoryObservability {
        let mut details = ProcessMemoryObservability {
            current_vma_count: self.vmas().len() as u64,
            page_table_frames: self.address_space().accounting().page_table_frames as u64,
            ..ProcessMemoryObservability::default()
        };
        for area in self.vmas() {
            let pages = area.length() / PAGE_SIZE;
            match area.kind {
                VmAreaKind::Image => {
                    details.committed_image_pages =
                        details.committed_image_pages.saturating_add(pages);
                }
                VmAreaKind::Anonymous {
                    committed: true, ..
                } => {
                    details.committed_anonymous_pages =
                        details.committed_anonymous_pages.saturating_add(pages);
                }
                VmAreaKind::Stack {
                    committed: true, ..
                } => {
                    details.committed_stack_pages =
                        details.committed_stack_pages.saturating_add(pages);
                }
                VmAreaKind::FileBacked {
                    committed: true, ..
                } => {
                    details.committed_file_backed_pages =
                        details.committed_file_backed_pages.saturating_add(pages);
                }
                VmAreaKind::Anonymous {
                    committed: false, ..
                }
                | VmAreaKind::Stack {
                    committed: false, ..
                }
                | VmAreaKind::StackGuard { .. }
                | VmAreaKind::Shared { .. }
                | VmAreaKind::FileBacked {
                    committed: false, ..
                } => {}
            }
        }
        details
    }

    pub const fn is_user_virtual_address(address: u64) -> bool {
        address >= PAGE_SIZE && address < USER_ADDRESS_END
    }

    pub fn virtual_query(&self, address: u64) -> Option<VirtualAreaInfo> {
        let area = self
            .vmas()
            .iter()
            .copied()
            .find(|area| area.start <= address && address < area.end)?;
        Some(virtual_area_info(area))
    }

    pub fn record_quota_failure(&mut self) {
        self.usage.quota_failures = self.usage.quota_failures.saturating_add(1);
    }

    pub fn record_oom_failure(&mut self) {
        self.usage.oom_failures = self.usage.oom_failures.saturating_add(1);
    }

    /// Resolves an eligible non-present userspace stack fault transactionally.
    ///
    /// The supplied `user_rsp` must be the context captured with this fault, not
    /// the process's previously saved scheduler context. Ineligible faults retain
    /// their original page-fault code and address. Resource exhaustion is attributed
    /// only to this process; allocator invariants and rollback failures quarantine it
    /// with a stable `Other` fault rather than panicking the kernel.
    pub fn resolve_thread_user_page_fault(
        &mut self,
        thread_id: ThreadId,
        fault_address: u64,
        error_code: u64,
        user_rsp: u64,
        allocator: &mut UsableFrameAllocator<'_>,
    ) -> UserPageFaultResolution {
        let page_fault = || {
            UserPageFaultResolution::Fault(ProcessFault::at_address(
                ProcessFaultReason::PageFault,
                error_code,
                fault_address,
            ))
        };
        if error_code & PAGE_FAULT_PRESENT != 0 || error_code & PAGE_FAULT_USER == 0 {
            return page_fault();
        }
        if fault_address > user_rsp
            || fault_address < user_rsp.saturating_sub(USER_STACK_GROWTH_SLOP)
        {
            return page_fault();
        }

        let fault_page = fault_address & !(PAGE_SIZE - 1);
        let Some(committed_bottom) = self.stack_committed_bottom(thread_id) else {
            return self.stack_growth_invariant_fault(fault_address);
        };
        let Some(layout) = self.thread(thread_id).map(|thread| thread.layout) else {
            return page_fault();
        };
        if fault_page < layout.stack_bottom || fault_page >= committed_bottom {
            return page_fault();
        }

        let pages = (committed_bottom - fault_page) / PAGE_SIZE;
        let Some(new_private_pages) = self.usage.private_pages.checked_add(pages) else {
            self.record_quota_failure();
            return UserPageFaultResolution::Fault(ProcessFault::at_address(
                ProcessFaultReason::ResourceLimit,
                error_code,
                fault_address,
            ));
        };
        if new_private_pages > self.limits.private_pages {
            self.record_quota_failure();
            return UserPageFaultResolution::Fault(ProcessFault::at_address(
                ProcessFaultReason::ResourceLimit,
                error_code,
                fault_address,
            ));
        }
        let planned_vmas =
            match plan_stack_growth(self.vmas(), thread_id, fault_page, committed_bottom) {
                Ok(planned) => planned,
                Err(error) => {
                    return stack_growth_planning_fault(error, error_code, fault_address);
                }
            };

        let mut mapped = 0usize;
        let mapped_len = (committed_bottom - fault_page) as usize;
        if let Err(error) = self
            .address_space_mut()
            .preflight_owned_user_mappings(mapped_len / PAGE_SIZE as usize)
        {
            if error == AddressSpaceError::OutOfMemory {
                self.record_oom_failure();
                return UserPageFaultResolution::Fault(ProcessFault::at_address(
                    ProcessFaultReason::OutOfMemory,
                    error_code,
                    fault_address,
                ));
            }
            return self.stack_growth_invariant_fault(fault_address);
        }
        while mapped < mapped_len {
            let page_address = fault_page + mapped as u64;
            if let Err(mapping_error) = self.address_space_mut().map_zeroed_user_4k(
                page_address,
                UserPagePermissions::READ_WRITE,
                allocator,
            ) {
                if mapped != 0
                    && self
                        .address_space_mut()
                        .unmap_user_range(fault_page, mapped)
                        .is_err()
                {
                    return self.stack_growth_invariant_fault(fault_address);
                }
                if self
                    .address_space_mut()
                    .reclaim_retired_data_frames(allocator)
                    .is_err()
                {
                    return self.stack_growth_invariant_fault(fault_address);
                }
                return match mapping_error {
                    AddressSpaceError::OutOfMemory | AddressSpaceError::OutOfFrames => {
                        self.record_oom_failure();
                        UserPageFaultResolution::Fault(ProcessFault::at_address(
                            ProcessFaultReason::OutOfMemory,
                            error_code,
                            fault_address,
                        ))
                    }
                    AddressSpaceError::FrameAllocator(_) => {
                        self.stack_growth_invariant_fault(fault_address)
                    }
                    _ => self.stack_growth_invariant_fault(fault_address),
                };
            }
            mapped += PAGE_SIZE as usize;
        }

        *self.vmas.as_mut().expect("live process lost its VMA table") = planned_vmas;
        self.usage.private_pages = new_private_pages;
        UserPageFaultResolution::Resolved { pages }
    }

    fn stack_committed_bottom(&self, thread_id: ThreadId) -> Option<u64> {
        self.vmas()
            .iter()
            .filter_map(|vma| match vma.kind {
                VmAreaKind::Stack {
                    owner,
                    committed: true,
                } if owner == thread_id => Some(vma.start),
                _ => None,
            })
            .min()
    }

    fn stack_growth_invariant_fault(&self, fault_address: u64) -> UserPageFaultResolution {
        UserPageFaultResolution::Fault(ProcessFault::at_address(
            ProcessFaultReason::Other(STACK_GROWTH_INVARIANT_REASON),
            STACK_GROWTH_INVARIANT_CODE,
            fault_address,
        ))
    }

    /// Checks a page-rounded shared backing charge, not its logical byte length.
    pub fn can_allocate_shared_memory(&self, backing_bytes: usize) -> bool {
        backing_bytes != 0
            && backing_bytes % PAGE_SIZE as usize == 0
            && self
                .usage
                .shared_memory_bytes
                .checked_add(backing_bytes as u64)
                .is_some_and(|total| total <= self.limits.shared_memory_bytes)
    }

    pub fn record_shared_memory_allocation(&mut self, bytes: usize) {
        self.usage.shared_memory_bytes =
            self.usage.shared_memory_bytes.saturating_add(bytes as u64);
    }

    pub fn release_shared_memory_charge(&mut self, bytes: usize) {
        self.usage.shared_memory_bytes =
            self.usage.shared_memory_bytes.saturating_sub(bytes as u64);
    }

    pub fn can_send_channel_bytes(&self, bytes: usize) -> bool {
        self.usage
            .channel_traffic_bytes
            .checked_add(bytes as u64)
            .is_some_and(|total| total <= self.limits.channel_traffic_bytes)
    }

    pub fn record_channel_bytes(&mut self, bytes: usize) {
        self.usage.channel_traffic_bytes = self
            .usage
            .channel_traffic_bytes
            .saturating_add(bytes as u64);
    }

    pub fn record_cpu_time(&mut self, elapsed_ns: u64) {
        self.usage.cpu_time_ns = self.usage.cpu_time_ns.saturating_add(elapsed_ns);
        let thread = self.main_thread_mut();
        thread.cpu_time_ns = thread.cpu_time_ns.saturating_add(elapsed_ns);
    }

    pub fn preemption_count(&self) -> u64 {
        self.main_thread().preemption_count
    }

    pub fn record_preemption(&mut self) {
        let thread = self.main_thread_mut();
        thread.preemption_count = thread.preemption_count.saturating_add(1);
    }

    pub(crate) fn block_thread_wait_many(&mut self, thread_id: ThreadId, wait: PendingWaitMany) {
        let thread = self
            .thread_mut(thread_id)
            .expect("wait caller thread disappeared");
        assert_eq!(
            thread.state,
            ThreadState::Ready,
            "only a ready thread can block"
        );
        assert!(
            thread.blocked_syscall.is_none(),
            "ready thread retained a blocked syscall"
        );
        thread.blocked_syscall = Some(BlockedSyscall::WaitMany(wait));
        thread.state = ThreadState::Blocked;
    }

    pub(crate) fn blocked_thread_wait_many_parts(
        &mut self,
        thread_id: ThreadId,
    ) -> (&HandleTable, &mut PendingWaitMany) {
        let handles =
            self.handles
                .as_ref()
                .expect("live process lost its handle table") as *const HandleTable;
        let thread = self
            .threads
            .get_mut(thread_id)
            .expect("blocked thread disappeared");
        assert_eq!(thread.state, ThreadState::Blocked, "thread is not blocked");
        let wait = match thread
            .blocked_syscall
            .as_mut()
            .expect("blocked thread lost its syscall continuation")
        {
            BlockedSyscall::WaitMany(wait) => wait,
            BlockedSyscall::Sleep(_) | BlockedSyscall::Join(_) | BlockedSyscall::Request(_) => {
                panic!("blocked thread does not own a wait-many continuation")
            }
        };
        // SAFETY: `handles` and `threads` are disjoint fields and neither is moved
        // while the returned borrows are live.
        (unsafe { &*handles }, wait)
    }

    pub(crate) fn take_blocked_thread_wait_many(&mut self, thread_id: ThreadId) -> PendingWaitMany {
        let thread = self
            .thread_mut(thread_id)
            .expect("blocked thread disappeared");
        assert_eq!(thread.state, ThreadState::Blocked, "thread is not blocked");
        match thread
            .blocked_syscall
            .take()
            .expect("blocked thread lost its syscall continuation")
        {
            BlockedSyscall::WaitMany(wait) => wait,
            BlockedSyscall::Sleep(_) | BlockedSyscall::Join(_) | BlockedSyscall::Request(_) => {
                panic!("blocked thread does not own a wait-many continuation")
            }
        }
    }

    pub(crate) fn block_thread_request(&mut self, thread_id: ThreadId, pending: PendingRequest) {
        let thread = self
            .thread_mut(thread_id)
            .expect("request caller thread disappeared");
        assert_eq!(
            thread.state,
            ThreadState::Ready,
            "only a ready thread can block"
        );
        assert!(
            thread.blocked_syscall.is_none(),
            "ready thread retained a blocked syscall"
        );
        thread.blocked_syscall = Some(BlockedSyscall::Request(pending));
        thread.state = ThreadState::Blocked;
    }

    pub fn blocked_request_id(&self, thread_id: ThreadId) -> Option<RequestId> {
        let BlockedSyscall::Request(request) = self.thread(thread_id)?.blocked_syscall.as_ref()?
        else {
            return None;
        };
        Some(request.id)
    }

    pub fn stage_request_completion(
        &mut self,
        thread_id: ThreadId,
        id: RequestId,
        output: RequestSubmitOutput,
    ) -> bool {
        let Some(BlockedSyscall::Request(request)) = self
            .thread_mut(thread_id)
            .and_then(|thread| thread.blocked_syscall.as_mut())
        else {
            return false;
        };
        if request.id != id || request.completion.is_some() {
            return false;
        }
        request.completion = Some(output);
        true
    }

    pub(crate) fn take_completed_request(
        &mut self,
        thread_id: ThreadId,
    ) -> Result<PendingRequest, Status> {
        let thread = self.thread_mut(thread_id).ok_or(Status::InvalidHandle)?;
        let Some(blocked) = thread.blocked_syscall.take() else {
            return Err(Status::InvalidArgument);
        };
        let BlockedSyscall::Request(request) = blocked else {
            thread.blocked_syscall = Some(blocked);
            return Err(Status::InvalidArgument);
        };
        if request.completion.is_none() {
            thread.blocked_syscall = Some(BlockedSyscall::Request(request));
            return Err(Status::ShouldWait);
        }
        Ok(request)
    }

    pub(crate) fn finish_request(&mut self, thread_id: ThreadId) -> Result<(), Status> {
        let thread = self.thread_mut(thread_id).ok_or(Status::InvalidHandle)?;
        if thread.state != ThreadState::Blocked || thread.blocked_syscall.is_some() {
            return Err(Status::InvalidArgument);
        }
        thread.state = ThreadState::Ready;
        Ok(())
    }

    pub(crate) fn resume_thread_from_block(&mut self, thread_id: ThreadId) {
        let thread = self
            .thread_mut(thread_id)
            .expect("blocked thread disappeared");
        assert_eq!(thread.state, ThreadState::Blocked, "thread is not blocked");
        assert!(
            thread.blocked_syscall.is_none(),
            "blocked syscall must be consumed before resuming"
        );
        thread.state = ThreadState::Ready;
    }

    #[cfg(test)]
    pub(crate) fn block_wait_many(&mut self, wait: PendingWaitMany) {
        self.block_thread_wait_many(self.main_thread_id, wait);
    }

    #[cfg(test)]
    pub(crate) fn take_blocked_wait_many(&mut self) -> PendingWaitMany {
        self.take_blocked_thread_wait_many(self.main_thread_id)
    }

    #[cfg(test)]
    pub(crate) fn resume_from_block(&mut self) {
        self.resume_thread_from_block(self.main_thread_id);
    }

    #[cfg(test)]
    pub fn resolve_user_page_fault(
        &mut self,
        fault_address: u64,
        error_code: u64,
        user_rsp: u64,
        allocator: &mut UsableFrameAllocator<'_>,
    ) -> UserPageFaultResolution {
        self.resolve_thread_user_page_fault(
            self.main_thread_id,
            fault_address,
            error_code,
            user_rsp,
            allocator,
        )
    }

    pub fn exit_thread(&mut self, thread_id: ThreadId, code: i32) -> bool {
        if self.terminal_state.is_some() || !self.threads.mark_terminal(thread_id) {
            return false;
        }
        self.cancel_blocked_syscall(thread_id);
        let thread = self
            .thread_mut(thread_id)
            .expect("validated thread disappeared during exit");
        thread.state = ThreadState::Exited(code);
        if self.threads.live == 0 {
            self.terminal_state = Some(ProcessState::Exited(code));
            self.publish_terminal_status();
            true
        } else {
            false
        }
    }

    pub fn sleep_thread(
        &mut self,
        thread_id: ThreadId,
        deadline_ns: u64,
        now_ns: u64,
    ) -> Result<bool, Status> {
        let thread = self.thread_mut(thread_id).ok_or(Status::InvalidHandle)?;
        if thread.state.is_terminal() {
            return Err(Status::InvalidHandle);
        }
        if deadline_ns <= now_ns {
            return Ok(false);
        }
        if thread.wake_permit {
            thread.wake_permit = false;
            return Ok(false);
        }
        if thread.state != ThreadState::Ready || thread.blocked_syscall.is_some() {
            return Err(Status::InvalidArgument);
        }
        thread.blocked_syscall = Some(BlockedSyscall::Sleep(PendingSleep {
            deadline_ns,
            registration: None,
        }));
        thread.state = ThreadState::Blocked;
        Ok(true)
    }

    pub fn wake_thread(&mut self, thread_id: ThreadId) -> Result<(), Status> {
        let sleeping = {
            let thread = self.thread(thread_id).ok_or(Status::InvalidHandle)?;
            if thread.state.is_terminal() {
                return Err(Status::InvalidHandle);
            }
            matches!(thread.blocked_syscall, Some(BlockedSyscall::Sleep(_)))
        };
        if sleeping {
            self.cancel_blocked_syscall(thread_id);
            let thread = self
                .thread_mut(thread_id)
                .expect("validated sleeping thread disappeared");
            thread
                .context
                .set_syscall_return(Status::Ok.raw() as i64 as u64);
            thread.state = ThreadState::Ready;
        } else {
            self.thread_mut(thread_id)
                .expect("validated thread disappeared")
                .wake_permit = true;
        }
        Ok(())
    }

    pub(crate) fn blocked_kind(&self, thread_id: ThreadId) -> Option<BlockedKind> {
        match self.thread(thread_id)?.blocked_syscall.as_ref()? {
            BlockedSyscall::WaitMany(_) => Some(BlockedKind::WaitMany),
            BlockedSyscall::Sleep(_) => Some(BlockedKind::Sleep),
            BlockedSyscall::Join(_) => Some(BlockedKind::Join),
            BlockedSyscall::Request(_) => Some(BlockedKind::Request),
        }
    }

    pub fn blocked_wait_spec(
        &self,
        thread_id: ThreadId,
    ) -> Option<(BlockedKind, Option<u64>, Option<WaitToken>)> {
        let blocked = self.thread(thread_id)?.blocked_syscall.as_ref()?;
        let (kind, deadline, registration) = match blocked {
            BlockedSyscall::WaitMany(wait) => (
                BlockedKind::WaitMany,
                match wait.deadline {
                    WaitDeadline::Infinite => None,
                    WaitDeadline::At(deadline) => Some(deadline),
                },
                wait.registration.as_ref(),
            ),
            BlockedSyscall::Sleep(sleep) => (
                BlockedKind::Sleep,
                Some(sleep.deadline_ns),
                sleep.registration.as_ref(),
            ),
            BlockedSyscall::Join(join) => (
                BlockedKind::Join,
                match join.deadline {
                    WaitDeadline::Infinite => None,
                    WaitDeadline::At(deadline) => Some(deadline),
                },
                join.registration.as_ref(),
            ),
            BlockedSyscall::Request(request) => {
                (BlockedKind::Request, None, request.registration.as_ref())
            }
        };
        Some((
            kind,
            deadline,
            registration.map(|registration| registration.token),
        ))
    }

    pub fn install_blocked_wait_registration(
        &mut self,
        thread_id: ThreadId,
        token: WaitToken,
        observer: &Arc<dyn SignalObserver>,
    ) -> Result<(), IpcError> {
        let handles =
            self.handles
                .as_ref()
                .expect("live process lost its handle table") as *const HandleTable;
        let thread = self
            .thread_mut(thread_id)
            .expect("blocked wait thread disappeared");
        assert_eq!(thread.state, ThreadState::Blocked, "thread is not blocked");
        let blocked = thread
            .blocked_syscall
            .as_mut()
            .expect("blocked thread lost its syscall continuation");
        match blocked {
            BlockedSyscall::WaitMany(wait) => {
                assert!(wait.registration.is_none(), "wait was registered twice");
                wait.registration = Some(BlockedWaitRegistration {
                    token,
                    objects: None,
                });
                // SAFETY: `handles` and `threads` are disjoint process fields and the
                // handle table is not moved while this method runs.
                let objects =
                    unsafe { &*handles }.register_wait_many(&wait.items, token, observer)?;
                wait.registration
                    .as_mut()
                    .expect("wait registration disappeared")
                    .objects = Some(objects);
            }
            BlockedSyscall::Sleep(sleep) => {
                assert!(sleep.registration.is_none(), "sleep was registered twice");
                sleep.registration = Some(BlockedWaitRegistration {
                    token,
                    objects: None,
                });
            }
            BlockedSyscall::Join(join) => {
                assert!(join.registration.is_none(), "join was registered twice");
                join.registration = Some(BlockedWaitRegistration {
                    token,
                    objects: None,
                });
            }
            BlockedSyscall::Request(request) => {
                assert!(
                    request.registration.is_none(),
                    "request was registered twice"
                );
                request.registration = Some(BlockedWaitRegistration {
                    token,
                    objects: None,
                });
                let item = WaitItem::new(request.hidden_handle, Signals::SIGNALED);
                // SAFETY: `handles` and `threads` are disjoint process fields and the
                // handle table is not moved while this method runs.
                let objects = unsafe { &*handles }.register_wait_many(&[item], token, observer)?;
                request
                    .registration
                    .as_mut()
                    .expect("request registration disappeared")
                    .objects = Some(objects);
            }
        }
        Ok(())
    }

    pub fn fail_blocked_wait_registration(&mut self, thread_id: ThreadId, status: Status) -> bool {
        let kind = self.blocked_kind(thread_id);
        match kind {
            Some(BlockedKind::WaitMany) => {
                let (_, wait) = self.blocked_thread_wait_many_parts(thread_id);
                wait.completion = Some(WaitManyCompletion::Failed(status));
                true
            }
            Some(BlockedKind::Join) => {
                let target = {
                    let Some(thread) = self.thread_mut(thread_id) else {
                        return false;
                    };
                    let Some(BlockedSyscall::Join(join)) = thread.blocked_syscall.as_mut() else {
                        return false;
                    };
                    join.completion = Some(status);
                    join.target
                };
                self.release_join_claim(target, thread_id);
                true
            }
            Some(BlockedKind::Sleep | BlockedKind::Request) => {
                self.cancel_blocked_syscall(thread_id);
                let Some(thread) = self.thread_mut(thread_id) else {
                    return false;
                };
                thread
                    .context
                    .set_syscall_return(status.raw() as i64 as u64);
                thread.state = ThreadState::Ready;
                true
            }
            None => false,
        }
    }

    pub fn clear_blocked_wait_registration(
        &mut self,
        thread_id: ThreadId,
        token: WaitToken,
    ) -> bool {
        let Some(blocked) = self
            .thread_mut(thread_id)
            .and_then(|thread| thread.blocked_syscall.as_mut())
        else {
            return false;
        };
        let registration = match blocked {
            BlockedSyscall::WaitMany(wait) => &mut wait.registration,
            BlockedSyscall::Sleep(sleep) => &mut sleep.registration,
            BlockedSyscall::Join(join) => &mut join.registration,
            BlockedSyscall::Request(request) => &mut request.registration,
        };
        if registration
            .as_ref()
            .is_some_and(|registration| registration.token == token)
        {
            *registration = None;
            true
        } else {
            false
        }
    }

    pub fn blocked_join_target(&self, caller: ThreadId) -> Option<ThreadId> {
        let BlockedSyscall::Join(join) = self.thread(caller)?.blocked_syscall.as_ref()? else {
            return None;
        };
        Some(join.target)
    }

    pub fn blocked_join_claimant(&self, target: ThreadId) -> Option<ThreadId> {
        self.thread(target)?.join_claimed_by
    }

    pub fn poll_sleep(&mut self, thread_id: ThreadId, now_ns: u64) -> Option<bool> {
        let thread = self.thread_mut(thread_id)?;
        match thread.blocked_syscall.as_ref()? {
            BlockedSyscall::Sleep(sleep) => Some(now_ns >= sleep.deadline_ns),
            BlockedSyscall::WaitMany(_) | BlockedSyscall::Join(_) | BlockedSyscall::Request(_) => {
                None
            }
        }
    }

    pub fn complete_sleep(&mut self, thread_id: ThreadId) -> Result<(), Status> {
        let thread = self.thread_mut(thread_id).ok_or(Status::InvalidHandle)?;
        if !matches!(thread.blocked_syscall, Some(BlockedSyscall::Sleep(_))) {
            return Err(Status::InvalidArgument);
        }
        thread.blocked_syscall = None;
        thread
            .context
            .set_syscall_return(Status::Ok.raw() as i64 as u64);
        thread.state = ThreadState::Ready;
        Ok(())
    }

    pub(crate) fn start_join(
        &mut self,
        caller: ThreadId,
        target: ThreadId,
        deadline: WaitDeadline,
        output_address: u64,
        now_ns: u64,
    ) -> Result<bool, Status> {
        if caller == target {
            return Err(Status::InvalidArgument);
        }
        let target_thread = self.thread(target).ok_or(Status::InvalidHandle)?;
        if target_thread.detached {
            return Err(Status::InvalidArgument);
        }
        if target_thread.join_claimed_by.is_some() {
            return Err(Status::AlreadyExists);
        }
        if target_thread.state.is_terminal() {
            return Ok(false);
        }
        if deadline.is_expired(now_ns) {
            return Err(Status::TimedOut);
        }
        self.thread_mut(target)
            .expect("join target disappeared")
            .join_claimed_by = Some(caller);
        let caller_thread = self.thread_mut(caller).ok_or(Status::InvalidHandle)?;
        if caller_thread.state != ThreadState::Ready || caller_thread.blocked_syscall.is_some() {
            self.thread_mut(target)
                .expect("join target disappeared during rollback")
                .join_claimed_by = None;
            return Err(Status::InvalidArgument);
        }
        caller_thread.blocked_syscall = Some(BlockedSyscall::Join(PendingJoin {
            target,
            deadline,
            output_address,
            completion: None,
            registration: None,
        }));
        caller_thread.state = ThreadState::Blocked;
        Ok(true)
    }

    pub(crate) fn poll_join(&mut self, caller: ThreadId, now_ns: u64) -> Option<bool> {
        let (target, deadline, already_complete) = {
            let thread = self.thread(caller)?;
            let BlockedSyscall::Join(join) = thread.blocked_syscall.as_ref()? else {
                return None;
            };
            (join.target, join.deadline, join.completion.is_some())
        };
        if already_complete {
            return Some(true);
        }
        let completion = if self
            .thread(target)
            .is_some_and(|thread| thread.state.is_terminal())
        {
            Some(Status::Ok)
        } else if deadline.is_expired(now_ns) {
            Some(Status::TimedOut)
        } else {
            None
        };
        if let Some(status) = completion {
            if status != Status::Ok {
                if let Some(target_thread) = self.thread_mut(target) {
                    if target_thread.join_claimed_by == Some(caller) {
                        target_thread.join_claimed_by = None;
                    }
                }
            }
            let caller_thread = self.thread_mut(caller)?;
            let BlockedSyscall::Join(join) = caller_thread.blocked_syscall.as_mut()? else {
                return None;
            };
            join.completion = Some(status);
            Some(true)
        } else {
            Some(false)
        }
    }

    pub(crate) fn take_completed_join(&mut self, caller: ThreadId) -> Result<PendingJoin, Status> {
        let thread = self.thread_mut(caller).ok_or(Status::InvalidHandle)?;
        let Some(BlockedSyscall::Join(join)) = thread.blocked_syscall.take() else {
            return Err(Status::InvalidArgument);
        };
        if join.completion.is_none() {
            thread.blocked_syscall = Some(BlockedSyscall::Join(join));
            return Err(Status::ShouldWait);
        }
        Ok(join)
    }

    pub(crate) fn release_join_claim(&mut self, target: ThreadId, caller: ThreadId) {
        if let Some(thread) = self.thread_mut(target) {
            if thread.join_claimed_by == Some(caller) {
                thread.join_claimed_by = None;
            }
        }
    }

    fn release_pending_request(&mut self, mut request: PendingRequest) {
        if let Some(output) = request.output.as_mut() {
            if let Some(address_space) = self.address_space.as_mut() {
                let _ = address_space.unpin_user_pages(&output.pages);
            }
            output.pages.clear();
        }
        if let Some(count_output) = request.count_output.as_mut() {
            if let Some(address_space) = self.address_space.as_mut() {
                let _ = address_space.unpin_user_pages(&count_output.pages);
            }
            count_output.pages.clear();
        }
        if let Some(handles) = self.handles.as_mut() {
            let _ = handles.handle_close(request.hidden_handle);
        }
        request.hidden_handle = Handle::INVALID;
    }

    fn cancel_blocked_syscall(&mut self, thread_id: ThreadId) {
        let blocked = self
            .thread_mut(thread_id)
            .and_then(|thread| thread.blocked_syscall.take());
        match blocked {
            Some(BlockedSyscall::Join(join)) => {
                self.release_join_claim(join.target, thread_id);
            }
            Some(BlockedSyscall::Request(request)) => self.release_pending_request(request),
            Some(BlockedSyscall::WaitMany(_) | BlockedSyscall::Sleep(_)) | None => {}
        }
    }

    fn cancel_all_blocked_syscalls(&mut self) {
        for index in 0..self.threads.slots.len() {
            let generation = self.threads.slots[index].generation;
            if self.threads.slots[index].thread.is_some() {
                self.cancel_blocked_syscall(ThreadId::from_parts(index as u32, generation));
            }
        }
    }

    pub(crate) fn finish_join(&mut self, caller: ThreadId) -> Result<(), Status> {
        let thread = self.thread_mut(caller).ok_or(Status::InvalidHandle)?;
        thread.state = ThreadState::Ready;
        Ok(())
    }

    pub fn thread_is_detached_terminal(&self, target: ThreadId) -> bool {
        self.thread(target)
            .is_some_and(|thread| thread.detached && thread.state.is_terminal())
    }

    pub fn next_detached_terminal_thread(&self) -> Option<ThreadId> {
        self.threads
            .slots
            .iter()
            .enumerate()
            .find_map(|(index, slot)| {
                let thread = slot.thread.as_ref()?;
                (thread.detached && thread.state.is_terminal())
                    .then(|| ThreadId::from_parts(index as u32, slot.generation))
            })
    }

    pub fn detach_thread(&mut self, target: ThreadId) -> Result<bool, Status> {
        let thread = self.thread_mut(target).ok_or(Status::InvalidHandle)?;
        if thread.join_claimed_by.is_some() {
            return Err(Status::AlreadyExists);
        }
        thread.detached = true;
        Ok(thread.state.is_terminal())
    }

    pub fn reap_thread(
        &mut self,
        target: ThreadId,
        allocator: &mut UsableFrameAllocator<'_>,
    ) -> Result<(), Status> {
        let layout = self
            .thread(target)
            .filter(|thread| thread.state.is_terminal())
            .map(|thread| thread.layout)
            .ok_or(Status::InvalidHandle)?;
        let planned =
            plan_thread_stack_remove(self.vmas(), target).map_err(|_| Status::OutOfMemory)?;
        let mut committed_ranges = [None; 2];
        let mut committed_count = 0usize;
        for area in self.vmas() {
            if matches!(
                area.kind,
                VmAreaKind::Stack {
                    owner,
                    committed: true,
                } if owner == target
            ) {
                let Some(slot) = committed_ranges.get_mut(committed_count) else {
                    return Err(Status::InvalidAddress);
                };
                *slot = Some((area.start, area.length() as usize));
                committed_count += 1;
            }
        }
        for (start, length) in committed_ranges[..committed_count]
            .iter()
            .flatten()
            .copied()
        {
            self.address_space_mut()
                .unmap_user_range(start, length)
                .map_err(|_| Status::InvalidAddress)?;
        }
        self.address_space_mut()
            .reclaim_retired_data_frames(allocator)
            .map_err(|_| Status::InvalidAddress)?;
        self.threads.remove(target).ok_or(Status::InvalidHandle)?;
        *self.vmas.as_mut().expect("live process lost its VMA table") = planned;
        let committed_pages = committed_ranges[..committed_count]
            .iter()
            .flatten()
            .fold(0u64, |total, (_, length)| {
                total.saturating_add(*length as u64 / PAGE_SIZE)
            });
        self.usage.private_pages = self.usage.private_pages.saturating_sub(committed_pages);
        self.usage.reserved_virtual_bytes = self
            .usage
            .reserved_virtual_bytes
            .saturating_sub(layout.stack_size().saturating_add(PAGE_SIZE));
        Ok(())
    }

    pub fn terminate_thread(&mut self, thread_id: ThreadId) -> Result<bool, Status> {
        if self.terminal_state.is_some() || !self.threads.mark_terminal(thread_id) {
            return Err(Status::InvalidHandle);
        }
        self.cancel_blocked_syscall(thread_id);
        let thread = self
            .thread_mut(thread_id)
            .expect("validated thread disappeared during termination");
        thread.state = ThreadState::Terminated;
        if self.threads.live == 0 {
            self.terminal_state = Some(ProcessState::Terminated);
            self.publish_terminal_status();
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn exit_process(&mut self, caller_id: ThreadId, code: i32) {
        if self.terminal_state.is_some() {
            return;
        }
        self.cancel_all_blocked_syscalls();
        for slot in &mut self.threads.slots {
            if let Some(thread) = slot.thread.as_mut() {
                thread.join_claimed_by = None;
                thread.state = if thread.state.is_terminal() {
                    thread.state
                } else {
                    ThreadState::Terminated
                };
            }
        }
        if let Some(caller) = self.threads.get_mut(caller_id) {
            caller.state = ThreadState::Exited(code);
        }
        self.threads.live = 0;
        self.terminal_state = Some(ProcessState::Exited(code));
        self.publish_terminal_status();
    }

    pub fn mark_exited(&mut self, code: i32) {
        self.exit_process(self.main_thread_id, code);
    }

    pub fn fault_process(&mut self, thread_id: ThreadId, reason: ProcessFault) {
        if self.terminal_state.is_some() {
            return;
        }
        self.cancel_all_blocked_syscalls();
        for slot in &mut self.threads.slots {
            if let Some(thread) = slot.thread.as_mut() {
                thread.join_claimed_by = None;
                thread.state = if thread.state.is_terminal() {
                    thread.state
                } else {
                    ThreadState::Terminated
                };
            }
        }
        if let Some(faulting) = self.threads.get_mut(thread_id) {
            faulting.state = ThreadState::Faulted(reason);
        }
        self.threads.live = 0;
        self.terminal_state = Some(ProcessState::Faulted(reason));
        self.publish_terminal_status();
    }

    pub fn mark_faulted(&mut self, reason: ProcessFault) {
        self.fault_process(self.main_thread_id, reason);
    }

    pub fn address_space(&self) -> &AddressSpace {
        self.address_space
            .as_ref()
            .expect("live process lost its address space")
    }

    pub fn address_space_mut(&mut self) -> &mut AddressSpace {
        self.address_space
            .as_mut()
            .expect("live process lost its address space")
    }

    pub fn next_schedulable_thread(&mut self) -> Option<ThreadId> {
        self.threads.next_schedulable()
    }

    pub fn next_blocked_thread(&mut self) -> Option<ThreadId> {
        if self.threads.slots.is_empty() {
            return None;
        }
        self.threads.next_slot %= self.threads.slots.len();
        for _ in 0..self.threads.slots.len() {
            let index = self.threads.next_slot;
            self.threads.next_slot = (index + 1) % self.threads.slots.len();
            let slot = &self.threads.slots[index];
            if slot
                .thread
                .as_ref()
                .is_some_and(|thread| thread.state == ThreadState::Blocked)
            {
                return Some(ThreadId::from_parts(index as u32, slot.generation));
            }
        }
        None
    }

    pub fn context(&self) -> &UserContext {
        &self.main_thread().context
    }

    /// Installs a prepared direct-process startup block in the active child stack.
    pub(crate) fn install_direct_startup(
        &mut self,
        startup: &DirectStartupBlock,
    ) -> Result<(), AddressSpaceError> {
        let block_address = self
            .layout()
            .stack_top
            .checked_sub(startup.bytes.len() as u64)
            .ok_or(AddressSpaceError::AddressOverflow)?
            & !((DIRECT_STARTUP_ALIGNMENT as u64) - 1);
        self.address_space().validate_user_range(
            block_address,
            startup.bytes.len(),
            UserAccess::Write,
        )?;
        self.address_space()
            .copy_to_user(block_address, &startup.bytes)?;
        self.main_thread_mut().context.rsp = block_address;
        self.set_start_arguments([block_address, startup.bytes.len() as u64, 0, 0]);
        Ok(())
    }

    /// Sets the first four System V AMD64 arguments for the initial user entry.
    pub fn set_start_arguments(&mut self, [rdi, rsi, rdx, rcx]: [u64; 4]) {
        self.set_start_arguments6([rdi, rsi, rdx, rcx, 0, 0]);
    }

    /// Sets all six integer System V AMD64 arguments for the initial user entry.
    pub fn set_start_arguments6(&mut self, [rdi, rsi, rdx, rcx, r8, r9]: [u64; 6]) {
        let context = &mut self.main_thread_mut().context;
        context.rdi = rdi;
        context.rsi = rsi;
        context.rdx = rdx;
        context.rcx = rcx;
        context.r8 = r8;
        context.r9 = r9;
    }

    pub fn context_mut(&mut self) -> &mut UserContext {
        &mut self.main_thread_mut().context
    }

    pub fn handles(&self) -> &HandleTable {
        self.handles
            .as_ref()
            .expect("live process lost its handle table")
    }

    pub fn handles_mut(&mut self) -> &mut HandleTable {
        self.handles
            .as_mut()
            .expect("live process lost its handle table")
    }

    pub fn shared_mappings(&self) -> &[SharedMemoryMapping] {
        self.shared_mappings
            .as_ref()
            .expect("live process lost its mapping records")
    }

    pub const fn next_mapping_cursor(&self) -> u64 {
        self.next_mapping_cursor
    }

    pub fn vmas(&self) -> &[VmArea] {
        self.vmas
            .as_ref()
            .expect("live process lost its semantic VMA table")
    }

    /// Reserves page-rounded anonymous address space without frames or private-page quota.
    pub fn reserve_anonymous(
        &mut self,
        length: u64,
        protection: MapProtection,
    ) -> Result<u64, SharedMappingError> {
        self.reserve_anonymous_with_rollback(length, protection)
            .map(|(address, _)| address)
    }

    pub(crate) fn reserve_anonymous_with_rollback(
        &mut self,
        length: u64,
        protection: MapProtection,
    ) -> Result<(u64, AnonymousReservationRollback), SharedMappingError> {
        let protection = anonymous_permissions(protection)?.0;
        let (_, mapped_len) = normalize_anonymous_range(PAGE_SIZE, length)?;
        let reservation_id = self.next_anonymous_reservation_id;
        let next_reservation_id = reservation_id
            .checked_add(1)
            .ok_or(SharedMappingError::ResourceLimit)?;
        let previous_cursor = self.next_mapping_cursor;
        let occupied = self.occupied_ranges()?;
        let address = select_mapping_address(
            0,
            false,
            mapped_len,
            previous_cursor,
            self.layout().stack_guard_start,
            &occupied,
        )?;
        let end = address
            .checked_add(mapped_len as u64)
            .ok_or(SharedMappingError::RangeOverflow)?;
        let planned = plan_vma_insert(
            self.vmas(),
            VmArea {
                start: address,
                end,
                kind: VmAreaKind::Anonymous {
                    reservation_id,
                    committed: false,
                },
                protection,
            },
        )?;
        let new_reserved = self
            .usage
            .reserved_virtual_bytes
            .checked_add(mapped_len as u64)
            .filter(|total| *total <= self.limits.reserved_virtual_bytes);
        if planned.len() as u64 > self.limits.vma_count || new_reserved.is_none() {
            self.record_quota_failure();
            return Err(SharedMappingError::ResourceLimit);
        }
        *self.vmas.as_mut().expect("live process lost its VMA table") = planned;
        self.usage.reserved_virtual_bytes = new_reserved.expect("checked above");
        self.next_mapping_cursor = if end < self.layout().stack_guard_start {
            end
        } else {
            SHARED_MAPPING_BASE
        };
        self.next_anonymous_reservation_id = next_reservation_id;
        Ok((
            address,
            AnonymousReservationRollback {
                start: address,
                end,
                reservation_id,
                previous_cursor,
            },
        ))
    }

    /// Removes a fresh reservation and restores placement state without allocating.
    pub(crate) fn rollback_anonymous_reservation(
        &mut self,
        rollback: AnonymousReservationRollback,
    ) {
        let index = self
            .vmas()
            .iter()
            .position(|vma| {
                vma.start == rollback.start
                    && vma.end == rollback.end
                    && vma.kind
                        == (VmAreaKind::Anonymous {
                            reservation_id: rollback.reservation_id,
                            committed: false,
                        })
            })
            .expect("fresh anonymous reservation rollback lost its exact VMA");
        self.vmas
            .as_mut()
            .expect("live process lost its semantic VMA table")
            .remove(index);
        self.next_mapping_cursor = rollback.previous_cursor;
        self.usage.reserved_virtual_bytes = self
            .usage
            .reserved_virtual_bytes
            .saturating_sub(rollback.end - rollback.start);
    }

    fn restore_mapping_cursor(&mut self, rollback: AnonymousReservationRollback) {
        self.next_mapping_cursor = rollback.previous_cursor;
    }

    fn fail_stop_vm_rollback(&mut self, address: u64) {
        self.mark_faulted(ProcessFault::at_address(
            ProcessFaultReason::Other(VM_ROLLBACK_FAILURE_REASON),
            VM_ROLLBACK_FAILURE_CODE,
            address,
        ));
    }

    /// Maps eager, zero-filled private pages at a kernel-selected address.
    pub fn map_anonymous(
        &mut self,
        length: u64,
        protection: MapProtection,
        allocator: &mut UsableFrameAllocator<'_>,
    ) -> Result<u64, SharedMappingError> {
        let (address, rollback) = self.reserve_anonymous_with_rollback(length, protection)?;
        if let Err(error) = self.commit_anonymous(address, length, allocator) {
            if matches!(error, SharedMappingError::RollbackFailed { .. }) {
                // The VMA quarantines any aliases that rollback could not remove.
                self.restore_mapping_cursor(rollback);
            } else {
                self.rollback_anonymous_reservation(rollback);
            }
            return Err(error);
        }
        Ok(address)
    }

    /// Eagerly commits a reserved anonymous subrange with transactional rollback.
    pub fn commit_anonymous(
        &mut self,
        address: u64,
        length: u64,
        allocator: &mut UsableFrameAllocator<'_>,
    ) -> Result<(), SharedMappingError> {
        let (end, mapped_len) = normalize_anonymous_range(address, length)?;
        let planned = plan_anonymous_change(self.vmas(), address, end, AnonymousChange::Commit)?;
        if planned.len() as u64 > self.limits.vma_count {
            self.record_quota_failure();
            return Err(SharedMappingError::ResourceLimit);
        }
        let pages = mapped_len as u64 / PAGE_SIZE;
        let Some(new_private_pages) = self
            .usage
            .private_pages
            .checked_add(pages)
            .filter(|total| *total <= self.limits.private_pages)
        else {
            self.record_quota_failure();
            return Err(SharedMappingError::ResourceLimit);
        };

        if let Err(error) = self
            .address_space_mut()
            .preflight_owned_user_mappings(mapped_len / PAGE_SIZE as usize)
        {
            if error == AddressSpaceError::OutOfMemory {
                self.record_oom_failure();
                return Err(SharedMappingError::OutOfMemory);
            }
            return Err(SharedMappingError::AddressSpace(error));
        }
        let mut mapped = 0usize;
        while mapped < mapped_len {
            let page_address = address + mapped as u64;
            let protection = self
                .vmas()
                .iter()
                .find(|vma| vma.start <= page_address && page_address < vma.end)
                .expect("committed range was completely covered")
                .protection;
            let (_, permissions) = anonymous_permissions(protection)?;
            if let Err(mapping_error) =
                self.address_space_mut()
                    .map_zeroed_user_4k(page_address, permissions, allocator)
            {
                if mapped != 0 {
                    if let Err(rollback_error) =
                        self.address_space_mut().unmap_user_range(address, mapped)
                    {
                        let error = SharedMappingError::RollbackFailed {
                            mapping_error,
                            rollback_error,
                        };
                        self.fail_stop_vm_rollback(page_address);
                        return Err(error);
                    }
                }
                self.address_space_mut()
                    .reclaim_retired_data_frames(allocator)
                    .map_err(|error| {
                        SharedMappingError::AddressSpace(AddressSpaceError::FrameAllocator(error))
                    })?;
                if matches!(
                    mapping_error,
                    AddressSpaceError::OutOfMemory | AddressSpaceError::OutOfFrames
                ) {
                    self.record_oom_failure();
                }
                return Err(SharedMappingError::AddressSpace(mapping_error));
            }
            mapped += PAGE_SIZE as usize;
        }

        *self.vmas.as_mut().expect("live process lost its VMA table") = planned;
        self.usage.private_pages = new_private_pages;
        Ok(())
    }

    pub fn protect_anonymous(
        &mut self,
        address: u64,
        length: u64,
        protection: MapProtection,
    ) -> Result<(), SharedMappingError> {
        let (protection, permissions) = anonymous_permissions(protection)?;
        let (end, _) = normalize_anonymous_range(address, length)?;
        let planned = plan_anonymous_change(
            self.vmas(),
            address,
            end,
            AnonymousChange::Protect(protection),
        )?;
        if planned.len() as u64 > self.limits.vma_count {
            self.record_quota_failure();
            return Err(SharedMappingError::ResourceLimit);
        }
        let ranges = committed_anonymous_ranges(self.vmas(), address, end)?;
        self.address_space_mut()
            .protect_user_ranges(&ranges, permissions)
            .map_err(SharedMappingError::AddressSpace)?;
        *self.vmas.as_mut().expect("live process lost its VMA table") = planned;
        Ok(())
    }

    /// Releases committed pages while preserving their anonymous reservation.
    pub fn decommit_anonymous(
        &mut self,
        address: u64,
        length: u64,
        allocator: &mut UsableFrameAllocator<'_>,
    ) -> Result<(), SharedMappingError> {
        let (end, _) = normalize_anonymous_range(address, length)?;
        let ranges = committed_anonymous_ranges(self.vmas(), address, end)?;
        let planned = plan_anonymous_change(self.vmas(), address, end, AnonymousChange::Decommit)?;
        if planned.len() as u64 > self.limits.vma_count {
            self.record_quota_failure();
            return Err(SharedMappingError::ResourceLimit);
        }
        let committed_pages = ranges
            .iter()
            .map(|(_, length)| *length as u64 / PAGE_SIZE)
            .sum::<u64>();
        self.address_space_mut()
            .unmap_user_ranges(&ranges)
            .map_err(SharedMappingError::AddressSpace)?;
        *self.vmas.as_mut().expect("live process lost its VMA table") = planned;
        self.usage.private_pages = self.usage.private_pages.saturating_sub(committed_pages);
        // PTE and VMA mutation is already committed. Reclamation failure leaves
        // exact retired ownership in AddressSpace and the allocator's sticky error.
        let _ = self
            .address_space_mut()
            .reclaim_retired_data_frames(allocator);
        Ok(())
    }

    /// Removes an arbitrary anonymous subrange and releases any committed pages.
    pub fn unmap_anonymous(
        &mut self,
        address: u64,
        length: u64,
        allocator: &mut UsableFrameAllocator<'_>,
    ) -> Result<(), SharedMappingError> {
        let (end, _) = normalize_anonymous_range(address, length)?;
        let planned = plan_anonymous_change(self.vmas(), address, end, AnonymousChange::Unmap)?;
        if planned.len() as u64 > self.limits.vma_count {
            self.record_quota_failure();
            return Err(SharedMappingError::ResourceLimit);
        }
        let ranges = committed_anonymous_ranges(self.vmas(), address, end)?;
        let committed_pages = ranges
            .iter()
            .map(|(_, length)| *length as u64 / PAGE_SIZE)
            .sum::<u64>();
        self.address_space_mut()
            .unmap_user_ranges(&ranges)
            .map_err(SharedMappingError::AddressSpace)?;
        *self.vmas.as_mut().expect("live process lost its VMA table") = planned;
        self.usage.private_pages = self.usage.private_pages.saturating_sub(committed_pages);
        self.usage.reserved_virtual_bytes = self
            .usage
            .reserved_virtual_bytes
            .saturating_sub(end - address);
        // The reservation removal is semantically complete even if physical-frame
        // reclamation is deferred; retired ownership and sticky allocator error remain.
        let _ = self
            .address_space_mut()
            .reclaim_retired_data_frames(allocator);
        Ok(())
    }

    /// Maps an eager private snapshot of a file range and retains immutable backing authority.
    pub fn map_file_backed<F>(
        &mut self,
        file: FileHandle,
        file_length: u64,
        max_protection: MapProtection,
        args: VirtualMapFileArgs,
        allocator: &mut UsableFrameAllocator<'_>,
        mut read: F,
    ) -> Result<u64, SharedMappingError>
    where
        F: FnMut(u64, &mut [u8]) -> Result<usize, SharedMappingError>,
    {
        anonymous_permissions(max_protection)?;
        let (_, permissions) = file_permissions(args.protection, max_protection)?;
        validate_flags(args.flags)?;
        if args.offset % PAGE_SIZE != 0 {
            return Err(SharedMappingError::UnalignedOffset(args.offset));
        }
        let source_end = args
            .offset
            .checked_add(args.length)
            .ok_or(SharedMappingError::RangeOverflow)?;
        if args.length == 0 || source_end > file_length {
            return Err(if args.length == 0 {
                SharedMappingError::ZeroLength
            } else {
                SharedMappingError::RangeOutsideObject {
                    offset: args.offset,
                    length: args.length,
                    object_length: usize::try_from(file_length).unwrap_or(usize::MAX),
                }
            });
        }
        let (_, mapped_len) = normalize_anonymous_range(PAGE_SIZE, args.length)?;
        let pages = mapped_len as u64 / PAGE_SIZE;
        let Some(new_private) = self
            .usage
            .private_pages
            .checked_add(pages)
            .filter(|total| *total <= self.limits.private_pages)
        else {
            self.record_quota_failure();
            return Err(SharedMappingError::ResourceLimit);
        };
        let Some(new_reserved) = self
            .usage
            .reserved_virtual_bytes
            .checked_add(mapped_len as u64)
            .filter(|total| *total <= self.limits.reserved_virtual_bytes)
        else {
            self.record_quota_failure();
            return Err(SharedMappingError::ResourceLimit);
        };
        let occupied = self.occupied_ranges()?;
        let address = select_mapping_address(
            args.address,
            args.flags.contains(MapFlags::FIXED),
            mapped_len,
            self.next_mapping_cursor,
            self.layout().stack_guard_start,
            &occupied,
        )?;
        let backing_id = self.next_file_backing_id;
        let next_backing_id = backing_id
            .checked_add(1)
            .ok_or(SharedMappingError::ResourceLimit)?;
        let end = address
            .checked_add(mapped_len as u64)
            .ok_or(SharedMappingError::RangeOverflow)?;
        let planned = plan_vma_insert(
            self.vmas(),
            VmArea {
                start: address,
                end,
                kind: VmAreaKind::FileBacked {
                    backing_id,
                    file_offset: args.offset,
                    committed: true,
                },
                protection: args.protection,
            },
        )?;
        if planned.len() as u64 > self.limits.vma_count {
            self.record_quota_failure();
            return Err(SharedMappingError::ResourceLimit);
        }
        self.file_backings
            .as_mut()
            .expect("live process lost its file backing records")
            .try_reserve(1)
            .map_err(|_| SharedMappingError::OutOfMemory)?;
        self.address_space_mut()
            .preflight_owned_user_mappings(mapped_len / PAGE_SIZE as usize)
            .map_err(SharedMappingError::AddressSpace)?;
        let backing = FileBacking {
            id: backing_id,
            file,
            source_end,
            max_protection,
        };
        let load_result = self.load_file_pages(
            address,
            args.offset,
            source_end,
            mapped_len,
            permissions,
            allocator,
            &mut read,
        );
        if let Err(error) = load_result {
            if matches!(error, SharedMappingError::RollbackFailed { .. }) {
                self.file_backings
                    .as_mut()
                    .expect("live process lost its file backing records")
                    .push(backing);
                *self
                    .vmas
                    .as_mut()
                    .expect("live process lost its semantic VMA table") = planned;
                self.usage.private_pages = new_private;
                self.usage.reserved_virtual_bytes = new_reserved;
                self.next_file_backing_id = next_backing_id;
            }
            return Err(error);
        }
        self.file_backings
            .as_mut()
            .expect("live process lost its file backing records")
            .push(backing);
        *self
            .vmas
            .as_mut()
            .expect("live process lost its semantic VMA table") = planned;
        self.usage.private_pages = new_private;
        self.usage.reserved_virtual_bytes = new_reserved;
        self.next_file_backing_id = next_backing_id;
        if !args.flags.contains(MapFlags::FIXED) {
            self.next_mapping_cursor = if end < self.layout().stack_guard_start {
                end
            } else {
                SHARED_MAPPING_BASE
            };
        }
        Ok(address)
    }

    fn load_file_pages<F>(
        &mut self,
        address: u64,
        file_offset: u64,
        source_end: u64,
        mapped_len: usize,
        permissions: UserPagePermissions,
        allocator: &mut UsableFrameAllocator<'_>,
        read: &mut F,
    ) -> Result<(), SharedMappingError>
    where
        F: FnMut(u64, &mut [u8]) -> Result<usize, SharedMappingError>,
    {
        let mut mapped = 0usize;
        while mapped < mapped_len {
            let page_address = address + mapped as u64;
            let page_offset = file_offset
                .checked_add(mapped as u64)
                .ok_or(SharedMappingError::RangeOverflow)?;
            let readable = usize::try_from(source_end.saturating_sub(page_offset).min(PAGE_SIZE))
                .map_err(|_| SharedMappingError::RangeOverflow)?;
            let mut contents = [0u8; PAGE_SIZE as usize];
            if readable != 0 {
                match read(page_offset, &mut contents[..readable]) {
                    Ok(count) if count == readable => {}
                    Ok(_) => {
                        self.rollback_file_pages(address, mapped, allocator)?;
                        return Err(SharedMappingError::Io);
                    }
                    Err(error) => {
                        self.rollback_file_pages(address, mapped, allocator)?;
                        return Err(error);
                    }
                }
            }
            let frame = match self.address_space_mut().map_zeroed_user_4k(
                page_address,
                permissions,
                allocator,
            ) {
                Ok(frame) => frame,
                Err(mapping_error) => {
                    self.rollback_file_pages(address, mapped, allocator)?;
                    if matches!(
                        mapping_error,
                        AddressSpaceError::OutOfMemory | AddressSpaceError::OutOfFrames
                    ) {
                        self.record_oom_failure();
                    }
                    return Err(SharedMappingError::AddressSpace(mapping_error));
                }
            };
            if let Err(mapping_error) = self.address_space().write_owned_frame(frame, &contents) {
                if let Err(rollback_error) = self
                    .address_space_mut()
                    .unmap_user_range(address, mapped + PAGE_SIZE as usize)
                {
                    self.fail_stop_vm_rollback(page_address);
                    return Err(SharedMappingError::RollbackFailed {
                        mapping_error,
                        rollback_error,
                    });
                }
                let _ = self
                    .address_space_mut()
                    .reclaim_retired_data_frames(allocator);
                return Err(SharedMappingError::AddressSpace(mapping_error));
            }
            mapped += PAGE_SIZE as usize;
        }
        Ok(())
    }

    fn rollback_file_pages(
        &mut self,
        address: u64,
        mapped: usize,
        allocator: &mut UsableFrameAllocator<'_>,
    ) -> Result<(), SharedMappingError> {
        if mapped != 0 {
            #[cfg(test)]
            if self.fail_file_rollback_for_test {
                self.fail_stop_vm_rollback(address);
                return Err(SharedMappingError::RollbackFailed {
                    mapping_error: AddressSpaceError::CorruptPageTable,
                    rollback_error: AddressSpaceError::CorruptPageTable,
                });
            }
            if let Err(rollback_error) = self.address_space_mut().unmap_user_range(address, mapped)
            {
                self.fail_stop_vm_rollback(address);
                return Err(SharedMappingError::RollbackFailed {
                    mapping_error: AddressSpaceError::CorruptPageTable,
                    rollback_error,
                });
            }
        }
        self.address_space_mut()
            .reclaim_retired_data_frames(allocator)
            .map_err(|error| {
                SharedMappingError::AddressSpace(AddressSpaceError::FrameAllocator(error))
            })?;
        Ok(())
    }

    pub fn commit_file_backed<F>(
        &mut self,
        address: u64,
        length: u64,
        allocator: &mut UsableFrameAllocator<'_>,
        mut read: F,
    ) -> Result<(), SharedMappingError>
    where
        F: FnMut(FileHandle, u64, &mut [u8]) -> Result<usize, SharedMappingError>,
    {
        let (end, _) = normalize_anonymous_range(address, length)?;
        let planned = plan_file_change(self.vmas(), address, end, FileChange::Commit)?;
        if planned.len() as u64 > self.limits.vma_count {
            self.record_quota_failure();
            return Err(SharedMappingError::ResourceLimit);
        }
        let pages = (end - address) / PAGE_SIZE;
        let Some(new_private) = self
            .usage
            .private_pages
            .checked_add(pages)
            .filter(|total| *total <= self.limits.private_pages)
        else {
            self.record_quota_failure();
            return Err(SharedMappingError::ResourceLimit);
        };
        let segments = file_segments(self.vmas(), address, end, false)?;
        self.address_space_mut()
            .preflight_owned_user_mappings(pages as usize)
            .map_err(SharedMappingError::AddressSpace)?;
        let mut loaded = 0usize;
        for segment in segments {
            let backing = *self
                .file_backings
                .as_ref()
                .expect("live process lost its file backing records")
                .iter()
                .find(|backing| backing.id == segment.backing_id)
                .ok_or(SharedMappingError::InvalidBackingLength)?;
            let (_, permissions) = file_permissions(segment.protection, backing.max_protection)?;
            let segment_len = usize::try_from(segment.end - segment.start)
                .map_err(|_| SharedMappingError::RangeOverflow)?;
            let result = self.load_file_pages(
                segment.start,
                segment.file_offset,
                backing.source_end,
                segment_len,
                permissions,
                allocator,
                &mut |offset, bytes| read(backing.file, offset, bytes),
            );
            if let Err(error) = result {
                let failure = if loaded == 0 {
                    error
                } else {
                    match self.rollback_file_pages(address, loaded, allocator) {
                        Ok(()) => error,
                        Err(rollback_error) => rollback_error,
                    }
                };
                if matches!(failure, SharedMappingError::RollbackFailed { .. }) {
                    // Rollback could not prove the range unmapped. The process is already
                    // fail-stopped, so publish the prechecked full commit charge and committed
                    // VMA plan as conservative quarantine metadata for retirement.
                    *self
                        .vmas
                        .as_mut()
                        .expect("live process lost its semantic VMA table") = planned;
                    self.usage.private_pages = new_private;
                }
                return Err(failure);
            }
            loaded += segment_len;
        }
        *self
            .vmas
            .as_mut()
            .expect("live process lost its semantic VMA table") = planned;
        self.usage.private_pages = new_private;
        Ok(())
    }

    pub fn decommit_file_backed(
        &mut self,
        address: u64,
        length: u64,
        allocator: &mut UsableFrameAllocator<'_>,
    ) -> Result<(), SharedMappingError> {
        self.change_file_residency(address, length, allocator, FileChange::Decommit)
    }

    pub fn protect_file_backed(
        &mut self,
        address: u64,
        length: u64,
        protection: MapProtection,
    ) -> Result<(), SharedMappingError> {
        let (_, permissions) = anonymous_permissions(protection)?;
        let (end, _) = normalize_anonymous_range(address, length)?;
        authorize_file_protection(
            self.vmas(),
            self.file_backings
                .as_ref()
                .expect("live process lost its file backing records"),
            address,
            end,
            protection,
        )?;
        let planned = plan_file_change(self.vmas(), address, end, FileChange::Protect(protection))?;
        if planned.len() as u64 > self.limits.vma_count {
            self.record_quota_failure();
            return Err(SharedMappingError::ResourceLimit);
        }
        let ranges = committed_file_ranges(self.vmas(), address, end)?;
        self.address_space_mut()
            .protect_user_ranges(&ranges, permissions)
            .map_err(SharedMappingError::AddressSpace)?;
        *self
            .vmas
            .as_mut()
            .expect("live process lost its semantic VMA table") = planned;
        Ok(())
    }

    pub fn unmap_file_backed(
        &mut self,
        address: u64,
        length: u64,
        allocator: &mut UsableFrameAllocator<'_>,
    ) -> Result<(), SharedMappingError> {
        self.change_file_residency(address, length, allocator, FileChange::Unmap)
    }

    fn change_file_residency(
        &mut self,
        address: u64,
        length: u64,
        allocator: &mut UsableFrameAllocator<'_>,
        change: FileChange,
    ) -> Result<(), SharedMappingError> {
        let (end, _) = normalize_anonymous_range(address, length)?;
        let planned = plan_file_change(self.vmas(), address, end, change)?;
        if planned.len() as u64 > self.limits.vma_count {
            self.record_quota_failure();
            return Err(SharedMappingError::ResourceLimit);
        }
        let ranges = committed_file_ranges(self.vmas(), address, end)?;
        let committed_pages = ranges
            .iter()
            .map(|(_, len)| *len as u64 / PAGE_SIZE)
            .sum::<u64>();
        self.address_space_mut()
            .unmap_user_ranges(&ranges)
            .map_err(SharedMappingError::AddressSpace)?;
        self.usage.private_pages = self.usage.private_pages.saturating_sub(committed_pages);
        if matches!(change, FileChange::Unmap) {
            self.usage.reserved_virtual_bytes = self
                .usage
                .reserved_virtual_bytes
                .saturating_sub(end - address);
            self.file_backings.as_mut().expect("live process lost its file backing records")
                .retain(|backing| planned.iter().any(|vma| matches!(vma.kind, VmAreaKind::FileBacked { backing_id, .. } if backing_id == backing.id)));
        }
        *self
            .vmas
            .as_mut()
            .expect("live process lost its semantic VMA table") = planned;
        let _ = self
            .address_space_mut()
            .reclaim_retired_data_frames(allocator);
        Ok(())
    }

    /// Maps an exact logical range of a shared-memory handle.
    ///
    /// The offset must be page aligned. The logical range need not end on a page
    /// boundary; the installed span is rounded up and remains within the backing's
    /// page-rounded allocation. Physical page identities come directly from the
    /// owning lease, so no kernel heap virtual address is translated.
    pub fn map_shared_memory(
        &mut self,
        handle: Handle,
        args: SharedMemoryMapArgs,
        allocator: &mut UsableFrameAllocator<'_>,
    ) -> Result<u64, SharedMappingError> {
        let access = validate_protection(args.protection)?;
        validate_flags(args.flags)?;

        let lease = self.handles().shared_memory_mapping_lease(handle, access)?;
        let request = validate_mapping_range(lease.info(), args.offset, args.length)?;
        let Some(new_mapped_total) = self
            .usage
            .mapped_shared_bytes
            .checked_add(request.mapped_len as u64)
            .filter(|total| *total <= self.limits.mapped_shared_bytes)
        else {
            self.record_quota_failure();
            return Err(SharedMappingError::ResourceLimit);
        };
        let Some(new_reserved_total) = self
            .usage
            .reserved_virtual_bytes
            .checked_add(request.mapped_len as u64)
            .filter(|total| *total <= self.limits.reserved_virtual_bytes)
        else {
            self.record_quota_failure();
            return Err(SharedMappingError::ResourceLimit);
        };

        let occupied = self.occupied_ranges()?;
        let address = select_mapping_address(
            args.address,
            args.flags.contains(MapFlags::FIXED),
            request.mapped_len,
            self.next_mapping_cursor,
            self.layout().stack_guard_start,
            &occupied,
        )?;

        let object_identity = lease.info().backing_identity;
        let planned_vmas = plan_vma_insert(
            self.vmas(),
            VmArea {
                start: address,
                end: address
                    .checked_add(request.mapped_len as u64)
                    .ok_or(SharedMappingError::RangeOverflow)?,
                kind: VmAreaKind::Shared {
                    object_identity,
                    object_offset: args.offset,
                },
                protection: args.protection,
            },
        )?;
        if planned_vmas.len() as u64 > self.limits.vma_count {
            self.record_quota_failure();
            return Err(SharedMappingError::ResourceLimit);
        }
        let frames = backing_pages(&lease, request)?;
        self.shared_mappings
            .as_mut()
            .expect("live process lost its mapping records")
            .try_reserve(1)
            .map_err(|_| SharedMappingError::OutOfMemory)?;
        self.retained_failed_mapping_leases
            .as_mut()
            .expect("live process lost its retained leases")
            .try_reserve(1)
            .map_err(|_| SharedMappingError::OutOfMemory)?;

        if let Err(error) = self
            .address_space_mut()
            .preflight_shared_user_mappings(request.mapped_len / PAGE_SIZE as usize)
        {
            if error == AddressSpaceError::OutOfMemory {
                self.record_oom_failure();
                return Err(SharedMappingError::OutOfMemory);
            }
            return Err(SharedMappingError::AddressSpace(error));
        }

        let permissions = if args.protection.contains(MapProtection::WRITE) {
            UserPagePermissions::READ_WRITE
        } else {
            UserPagePermissions::READ_ONLY
        };
        let mut mapped_len = 0usize;
        for frame in frames {
            let page_address = address
                .checked_add(mapped_len as u64)
                .ok_or(SharedMappingError::RangeOverflow)?;
            let result = unsafe {
                self.address_space_mut().map_shared_user_4k(
                    page_address,
                    frame,
                    permissions,
                    allocator,
                )
            };
            if let Err(mapping_error) = result {
                if mapped_len != 0 {
                    if let Err(rollback_error) = self
                        .address_space_mut()
                        .unmap_user_range(address, mapped_len)
                    {
                        self.retained_failed_mapping_leases
                            .as_mut()
                            .expect("live process lost its retained leases")
                            .push(lease);
                        let error = SharedMappingError::RollbackFailed {
                            mapping_error,
                            rollback_error,
                        };
                        self.fail_stop_vm_rollback(page_address);
                        return Err(error);
                    }
                }
                return Err(SharedMappingError::AddressSpace(mapping_error));
            }
            mapped_len += PAGE_SIZE as usize;
        }

        self.shared_mappings
            .as_mut()
            .expect("live process lost its mapping records")
            .push(SharedMemoryMapping {
                address,
                offset: args.offset,
                length: args.length,
                mapped_len: request.mapped_len,
                protection: args.protection,
                _lease: lease,
            });
        *self.vmas.as_mut().expect("live process lost its VMA table") = planned_vmas;
        self.usage.mapped_shared_bytes = new_mapped_total;
        self.usage.mapped_shared_pages = self
            .usage
            .mapped_shared_pages
            .saturating_add(request.mapped_len as u64 / PAGE_SIZE);
        self.usage.reserved_virtual_bytes = new_reserved_total;
        if !args.flags.contains(MapFlags::FIXED) {
            self.next_mapping_cursor = address
                .checked_add(request.mapped_len as u64)
                .filter(|next| *next < self.layout().stack_guard_start)
                .unwrap_or(SHARED_MAPPING_BASE);
        }
        Ok(address)
    }

    /// Removes only a mapping whose address and logical length exactly match the
    /// application-visible mapping request. The owning lease is dropped only after
    /// every installed alias has been removed successfully.
    pub fn unmap_shared_memory(
        &mut self,
        address: u64,
        length: u64,
    ) -> Result<(), SharedMappingError> {
        let index = self
            .shared_mappings()
            .iter()
            .position(|mapping| mapping.address == address && mapping.length == length)
            .ok_or(SharedMappingError::ExactMappingNotFound { address, length })?;
        let mapping = &self.shared_mappings()[index];
        let mapped_len = mapping.mapped_len;
        let kind = VmAreaKind::Shared {
            object_identity: mapping.backing_identity(),
            object_offset: mapping.offset,
        };
        let end = address
            .checked_add(mapped_len as u64)
            .ok_or(SharedMappingError::RangeOverflow)?;
        let planned_vmas = plan_vma_remove_kind(self.vmas(), address, end, kind)?;
        self.address_space_mut()
            .unmap_user_range(address, mapped_len)
            .map_err(SharedMappingError::AddressSpace)?;
        self.shared_mappings
            .as_mut()
            .expect("live process lost its mapping records")
            .swap_remove(index);
        *self.vmas.as_mut().expect("live process lost its VMA table") = planned_vmas;
        self.usage.mapped_shared_bytes = self
            .usage
            .mapped_shared_bytes
            .saturating_sub(mapped_len as u64);
        self.usage.mapped_shared_pages = self
            .usage
            .mapped_shared_pages
            .saturating_sub(mapped_len as u64 / PAGE_SIZE);
        self.usage.reserved_virtual_bytes = self
            .usage
            .reserved_virtual_bytes
            .saturating_sub(mapped_len as u64);
        Ok(())
    }

    /// Retires an inactive process after the kernel address-space root is restored.
    ///
    /// The current CPU must no longer use this process's root. A still-active root
    /// returns the intact process in [`ProcessRetireError`]. The scheduler must also
    /// ensure no other CPU can activate or is still running this process; that
    /// cross-CPU invariant cannot be checked here.
    ///
    /// On success the address-space ownership records are preserved, while shared
    /// mapping leases and every process handle are dropped in that order. This makes
    /// it safe to release shared backing only after the process PTEs are unreachable.
    pub fn retire(mut self) -> Result<RetiredProcess, ProcessRetireError> {
        if self.address_space().is_active() {
            return Err(ProcessRetireError { process: self });
        }

        self.cancel_all_blocked_syscalls();
        let final_state = self.state();
        let context = self.retirement_context;
        let address_space = self
            .address_space
            .take()
            .expect("live process lost its address space");
        let handles = self
            .handles
            .take()
            .expect("live process lost its handle table");
        let shared_mappings = self
            .shared_mappings
            .take()
            .expect("live process lost its mapping records");
        let file_backings = self
            .file_backings
            .take()
            .expect("live process lost its file backing records");
        let vmas = self
            .vmas
            .take()
            .expect("live process lost its semantic VMA table");
        let retained_failed_mapping_leases = self
            .retained_failed_mapping_leases
            .take()
            .expect("live process lost its retained leases");
        let teardown = ProcessTeardown {
            handles_closed: handles.len(),
            mappings_released: shared_mappings.len().saturating_add(file_backings.len()),
            anonymous_mappings_released: count_anonymous_reservations(&vmas),
            retained_failed_mapping_leases_released: retained_failed_mapping_leases.len(),
        };
        let address_space = unsafe { address_space.retire() };
        drop(shared_mappings);
        drop(file_backings);
        drop(vmas);
        drop(retained_failed_mapping_leases);
        drop(handles);

        Ok(RetiredProcess {
            address_space,
            context,
            final_state,
            teardown,
        })
    }

    fn occupied_ranges(&self) -> Result<Vec<VirtualRange>, SharedMappingError> {
        let mut occupied = Vec::new();
        occupied
            .try_reserve_exact(self.vmas().len())
            .map_err(|_| SharedMappingError::OutOfMemory)?;
        occupied.extend(self.vmas().iter().map(|vma| VirtualRange {
            start: vma.start,
            end: vma.end,
        }));
        Ok(occupied)
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        // AddressSpace does not tear down its PTE tree on Drop. Releasing a lease
        // or shared-memory handle here could therefore free backing still named by
        // those PTEs. An unretired process is a lifecycle bug, so retain all such
        // resources as a fail-safe. Process::retire takes these fields first and
        // performs the normal clean teardown after the root is no longer active.
        retain_unretired_resource(&mut self.shared_mappings);
        retain_unretired_resource(&mut self.file_backings);
        retain_unretired_resource(&mut self.vmas);
        retain_unretired_resource(&mut self.retained_failed_mapping_leases);
        retain_unretired_resource(&mut self.handles);
    }
}

fn count_anonymous_reservations(vmas: &[VmArea]) -> usize {
    vmas.iter()
        .enumerate()
        .filter(|(index, vma)| {
            let VmAreaKind::Anonymous { reservation_id, .. } = vma.kind else {
                return false;
            };
            !vmas[..*index].iter().any(|previous| {
                matches!(
                    previous.kind,
                    VmAreaKind::Anonymous {
                        reservation_id: previous_id,
                        ..
                    } if previous_id == reservation_id
                )
            })
        })
        .count()
}

fn retain_unretired_resource<T>(resource: &mut Option<T>) {
    if let Some(resource) = resource.take() {
        mem::forget(resource);
    }
}

fn reclaim_failed_construction(
    address_space: AddressSpace,
    allocator: &mut UsableFrameAllocator<'_>,
    original_error: ProcessCreateError,
) -> Result<Process, ProcessCreateError> {
    if let Err(cleanup_error) = address_space.cleanup_inactive(allocator) {
        // Reclaim is allocation-free. Any failure here is an ownership invariant
        // violation, so retain the exact owner and stop instead of continuing.
        mem::forget(cleanup_error);
        panic!("failed process construction cleanup invariant");
    }
    Err(original_error)
}

const fn public_fault(reason: ProcessFaultReason) -> PublicProcessFault {
    match reason {
        ProcessFaultReason::PageFault => PublicProcessFault::PageFault,
        ProcessFaultReason::GeneralProtection => PublicProcessFault::GeneralProtection,
        ProcessFaultReason::InvalidOpcode => PublicProcessFault::InvalidOpcode,
        ProcessFaultReason::InvalidUserContext => PublicProcessFault::InvalidUserContext,
        ProcessFaultReason::ResourceLimit => PublicProcessFault::ResourceLimit,
        ProcessFaultReason::OutOfMemory => PublicProcessFault::OutOfMemory,
        ProcessFaultReason::Other(_) => PublicProcessFault::Other,
    }
}

fn user_permissions(permissions: SegmentPermissions) -> UserPagePermissions {
    match (permissions.is_writable(), permissions.is_executable()) {
        (false, false) => UserPagePermissions::READ_ONLY,
        (true, false) => UserPagePermissions::READ_WRITE,
        (false, true) => UserPagePermissions::READ_EXECUTE,
        (true, true) => unreachable!("ELF validation rejected writable executable pages"),
    }
}

fn copy_page_through_hhdm(
    hhdm_offset: VirtAddr,
    frame: PhysFrame<Size4KiB>,
    contents: &[u8; PAGE_SIZE as usize],
) -> Result<(), ElfPageLoadError> {
    let hhdm_offset = hhdm_offset.as_u64();
    let physical_address = frame.start_address().as_u64();
    let destination =
        hhdm_offset
            .checked_add(physical_address)
            .ok_or(ElfPageLoadError::HhdmAddressOverflow {
                hhdm_offset,
                physical_address,
            })?;
    let final_byte =
        destination
            .checked_add(PAGE_SIZE - 1)
            .ok_or(ElfPageLoadError::HhdmAddressOverflow {
                hhdm_offset,
                physical_address,
            })?;
    let destination = VirtAddr::try_new(destination)
        .map_err(|_| ElfPageLoadError::InvalidHhdmAddress(destination))?;
    VirtAddr::try_new(final_byte).map_err(|_| ElfPageLoadError::InvalidHhdmAddress(final_byte))?;
    unsafe {
        ptr::copy_nonoverlapping(
            contents.as_ptr(),
            destination.as_mut_ptr::<u8>(),
            contents.len(),
        )
    };
    Ok(())
}

fn initial_vmas(
    image: &elf::LoadedImage,
    layout: ProcessLayout,
    mut vmas: Vec<VmArea>,
) -> Result<Vec<VmArea>, ProcessCreateError> {
    debug_assert!(vmas.capacity() >= image.segments.len().saturating_add(3));
    for segment in &image.segments {
        let mut protection = MapProtection::READ;
        if segment.permissions.is_writable() {
            protection |= MapProtection::WRITE;
        }
        if segment.permissions.is_executable() {
            protection |= MapProtection::EXECUTE;
        }
        push_merged_vma(
            &mut vmas,
            VmArea {
                start: segment.page_start,
                end: segment.page_start + segment.page_count * PAGE_SIZE,
                kind: VmAreaKind::Image,
                protection,
            },
        )
        .map_err(|_| ProcessCreateError::ResourceLimit)?;
    }
    push_merged_vma(
        &mut vmas,
        VmArea {
            start: layout.stack_guard_start,
            end: layout.stack_bottom,
            kind: VmAreaKind::StackGuard {
                owner: MAIN_THREAD_ID,
            },
            protection: MapProtection::empty(),
        },
    )
    .map_err(|_| ProcessCreateError::ResourceLimit)?;
    push_merged_vma(
        &mut vmas,
        VmArea {
            start: layout.stack_bottom,
            end: layout.stack_initial_bottom,
            kind: VmAreaKind::Stack {
                owner: MAIN_THREAD_ID,
                committed: false,
            },
            protection: MapProtection::READ | MapProtection::WRITE,
        },
    )
    .map_err(|_| ProcessCreateError::ResourceLimit)?;
    push_merged_vma(
        &mut vmas,
        VmArea {
            start: layout.stack_initial_bottom,
            end: layout.stack_top,
            kind: VmAreaKind::Stack {
                owner: MAIN_THREAD_ID,
                committed: true,
            },
            protection: MapProtection::READ | MapProtection::WRITE,
        },
    )
    .map_err(|_| ProcessCreateError::ResourceLimit)?;
    vmas.sort_unstable_by_key(|vma| vma.start);
    let mut write_index = 0usize;
    for read_index in 0..vmas.len() {
        let area = vmas[read_index];
        if write_index != 0
            && vmas[write_index - 1].end == area.start
            && vm_kinds_merge(vmas[write_index - 1], area)
            && vmas[write_index - 1].protection == area.protection
        {
            vmas[write_index - 1].end = area.end;
        } else {
            vmas[write_index] = area;
            write_index += 1;
        }
    }
    vmas.truncate(write_index);
    Ok(vmas)
}

#[derive(Clone, Copy)]
enum AnonymousChange {
    Commit,
    Decommit,
    Protect(MapProtection),
    Unmap,
}

#[derive(Clone, Copy)]
enum FileChange {
    Commit,
    Decommit,
    Protect(MapProtection),
    Unmap,
}

#[derive(Clone, Copy)]
struct FileSegment {
    start: u64,
    end: u64,
    backing_id: u64,
    file_offset: u64,
    protection: MapProtection,
}

fn map_thread_vma_error(error: SharedMappingError) -> ThreadCreateError {
    match error {
        SharedMappingError::OutOfMemory => ThreadCreateError::OutOfMemory,
        SharedMappingError::ResourceLimit | SharedMappingError::AlreadyMapped(_) => {
            ThreadCreateError::ResourceLimit
        }
        _ => ThreadCreateError::InvalidStack,
    }
}

fn plan_thread_stack_remove(
    vmas: &[VmArea],
    owner: ThreadId,
) -> Result<Vec<VmArea>, SharedMappingError> {
    let mut planned = Vec::new();
    planned
        .try_reserve_exact(vmas.len())
        .map_err(|_| SharedMappingError::OutOfMemory)?;
    for area in vmas.iter().copied() {
        let belongs = matches!(
            area.kind,
            VmAreaKind::Stack { owner: area_owner, .. }
                | VmAreaKind::StackGuard { owner: area_owner }
                if area_owner == owner
        );
        if !belongs {
            planned.push(area);
        }
    }
    Ok(planned)
}

fn clone_vma_plan(vmas: &[VmArea]) -> Result<Vec<VmArea>, SharedMappingError> {
    let mut planned = Vec::new();
    planned
        .try_reserve_exact(vmas.len())
        .map_err(|_| SharedMappingError::OutOfMemory)?;
    planned.extend_from_slice(vmas);
    Ok(planned)
}

fn vm_kinds_merge(left: VmArea, right: VmArea) -> bool {
    match (left.kind, right.kind) {
        (
            VmAreaKind::FileBacked {
                backing_id: left_id,
                file_offset: left_offset,
                committed: left_committed,
            },
            VmAreaKind::FileBacked {
                backing_id: right_id,
                file_offset: right_offset,
                committed: right_committed,
            },
        ) => {
            left_id == right_id
                && left_committed == right_committed
                && left_offset.checked_add(left.length()) == Some(right_offset)
        }
        (VmAreaKind::Shared { .. }, VmAreaKind::Shared { .. }) => false,
        (left, right) => left == right,
    }
}

fn push_merged_vma(vmas: &mut Vec<VmArea>, area: VmArea) -> Result<(), SharedMappingError> {
    if area.start >= area.end {
        return Err(SharedMappingError::RangeOverflow);
    }
    if let Some(previous) = vmas.last_mut() {
        if previous.end == area.start
            && vm_kinds_merge(*previous, area)
            && previous.protection == area.protection
        {
            previous.end = area.end;
            return Ok(());
        }
    }
    if vmas.len() == MAX_VMAS {
        return Err(SharedMappingError::ResourceLimit);
    }
    vmas.push(area);
    Ok(())
}

fn plan_vma_insert(vmas: &[VmArea], area: VmArea) -> Result<Vec<VmArea>, SharedMappingError> {
    let mut planned = Vec::new();
    planned
        .try_reserve_exact(vmas.len().saturating_add(1).min(MAX_VMAS))
        .map_err(|_| SharedMappingError::OutOfMemory)?;
    let mut inserted = false;
    for current in vmas.iter().copied() {
        if current.start < area.end && area.start < current.end {
            return Err(SharedMappingError::AlreadyMapped(area.start));
        }
        if !inserted && area.end <= current.start {
            push_merged_vma(&mut planned, area)?;
            inserted = true;
        }
        push_merged_vma(&mut planned, current)?;
    }
    if !inserted {
        push_merged_vma(&mut planned, area)?;
    }
    Ok(planned)
}

fn stack_growth_planning_fault(
    error: SharedMappingError,
    error_code: u64,
    fault_address: u64,
) -> UserPageFaultResolution {
    let reason = match error {
        SharedMappingError::OutOfMemory => ProcessFaultReason::OutOfMemory,
        SharedMappingError::ResourceLimit => ProcessFaultReason::ResourceLimit,
        _ => ProcessFaultReason::Other(STACK_GROWTH_INVARIANT_REASON),
    };
    let code = if matches!(reason, ProcessFaultReason::Other(_)) {
        STACK_GROWTH_INVARIANT_CODE
    } else {
        error_code
    };
    UserPageFaultResolution::Fault(ProcessFault::at_address(reason, code, fault_address))
}

fn plan_stack_growth(
    vmas: &[VmArea],
    owner: ThreadId,
    start: u64,
    end: u64,
) -> Result<Vec<VmArea>, SharedMappingError> {
    if start >= end || start % PAGE_SIZE != 0 || end % PAGE_SIZE != 0 {
        return Err(SharedMappingError::RangeOverflow);
    }
    let mut planned = clone_vma_plan(vmas)?;
    planned.clear();
    let mut covered = start;
    for area in vmas.iter().copied() {
        if area.end <= start || area.start >= end {
            push_merged_vma(&mut planned, area)?;
            continue;
        }
        if area.start > covered
            || area.kind
                != (VmAreaKind::Stack {
                    owner,
                    committed: false,
                })
        {
            return Err(SharedMappingError::ExactMappingNotFound {
                address: start,
                length: end - start,
            });
        }
        let middle_start = area.start.max(start);
        let middle_end = area.end.min(end);
        if area.start < middle_start {
            push_merged_vma(
                &mut planned,
                VmArea {
                    end: middle_start,
                    ..area
                },
            )?;
        }
        push_merged_vma(
            &mut planned,
            VmArea {
                start: middle_start,
                end: middle_end,
                kind: VmAreaKind::Stack {
                    owner,
                    committed: true,
                },
                ..area
            },
        )?;
        if middle_end < area.end {
            push_merged_vma(
                &mut planned,
                VmArea {
                    start: middle_end,
                    ..area
                },
            )?;
        }
        covered = middle_end;
    }
    if covered != end {
        return Err(SharedMappingError::ExactMappingNotFound {
            address: start,
            length: end - start,
        });
    }
    Ok(planned)
}

fn plan_anonymous_change(
    vmas: &[VmArea],
    start: u64,
    end: u64,
    change: AnonymousChange,
) -> Result<Vec<VmArea>, SharedMappingError> {
    let mut planned = Vec::new();
    planned
        .try_reserve_exact(vmas.len().saturating_add(2).min(MAX_VMAS))
        .map_err(|_| SharedMappingError::OutOfMemory)?;
    let mut covered = start;
    for area in vmas.iter().copied() {
        if area.end <= start || area.start >= end {
            push_merged_vma(&mut planned, area)?;
            continue;
        }
        if area.start > covered {
            return Err(SharedMappingError::ExactMappingNotFound {
                address: start,
                length: end - start,
            });
        }
        let VmAreaKind::Anonymous {
            reservation_id,
            committed,
        } = area.kind
        else {
            return Err(SharedMappingError::ExactMappingNotFound {
                address: start,
                length: end - start,
            });
        };
        if matches!(change, AnonymousChange::Commit) && committed {
            return Err(SharedMappingError::AlreadyMapped(covered));
        }
        let middle_start = area.start.max(start);
        let middle_end = area.end.min(end);
        if area.start < middle_start {
            push_merged_vma(
                &mut planned,
                VmArea {
                    end: middle_start,
                    ..area
                },
            )?;
        }
        if !matches!(change, AnonymousChange::Unmap) {
            let (kind, protection) = match change {
                AnonymousChange::Commit => (
                    VmAreaKind::Anonymous {
                        reservation_id,
                        committed: true,
                    },
                    area.protection,
                ),
                AnonymousChange::Decommit => (
                    VmAreaKind::Anonymous {
                        reservation_id,
                        committed: false,
                    },
                    area.protection,
                ),
                AnonymousChange::Protect(protection) => (area.kind, protection),
                AnonymousChange::Unmap => unreachable!(),
            };
            push_merged_vma(
                &mut planned,
                VmArea {
                    start: middle_start,
                    end: middle_end,
                    kind,
                    protection,
                },
            )?;
        }
        if middle_end < area.end {
            push_merged_vma(
                &mut planned,
                VmArea {
                    start: middle_end,
                    ..area
                },
            )?;
        }
        covered = middle_end;
    }
    if covered != end {
        return Err(SharedMappingError::ExactMappingNotFound {
            address: start,
            length: end - start,
        });
    }
    Ok(planned)
}

fn plan_file_change(
    vmas: &[VmArea],
    start: u64,
    end: u64,
    change: FileChange,
) -> Result<Vec<VmArea>, SharedMappingError> {
    let mut planned = Vec::new();
    planned
        .try_reserve_exact(vmas.len().saturating_add(2).min(MAX_VMAS))
        .map_err(|_| SharedMappingError::OutOfMemory)?;
    let mut covered = start;
    for area in vmas.iter().copied() {
        if area.end <= start || area.start >= end {
            push_merged_vma(&mut planned, area)?;
            continue;
        }
        let VmAreaKind::FileBacked {
            backing_id,
            file_offset,
            committed,
        } = area.kind
        else {
            return Err(SharedMappingError::ExactMappingNotFound {
                address: start,
                length: end - start,
            });
        };
        if area.start > covered || matches!(change, FileChange::Commit) && committed {
            return Err(if area.start > covered {
                SharedMappingError::ExactMappingNotFound {
                    address: start,
                    length: end - start,
                }
            } else {
                SharedMappingError::AlreadyMapped(covered)
            });
        }
        let middle_start = area.start.max(start);
        let middle_end = area.end.min(end);
        if area.start < middle_start {
            push_merged_vma(
                &mut planned,
                VmArea {
                    end: middle_start,
                    ..area
                },
            )?;
        }
        let middle_offset = file_offset
            .checked_add(middle_start - area.start)
            .ok_or(SharedMappingError::RangeOverflow)?;
        if !matches!(change, FileChange::Unmap) {
            let (middle_committed, protection) = match change {
                FileChange::Commit => (true, area.protection),
                FileChange::Decommit => (false, area.protection),
                FileChange::Protect(protection) => (committed, protection),
                FileChange::Unmap => unreachable!(),
            };
            push_merged_vma(
                &mut planned,
                VmArea {
                    start: middle_start,
                    end: middle_end,
                    kind: VmAreaKind::FileBacked {
                        backing_id,
                        file_offset: middle_offset,
                        committed: middle_committed,
                    },
                    protection,
                },
            )?;
        }
        if middle_end < area.end {
            let right_offset = file_offset
                .checked_add(middle_end - area.start)
                .ok_or(SharedMappingError::RangeOverflow)?;
            push_merged_vma(
                &mut planned,
                VmArea {
                    start: middle_end,
                    kind: VmAreaKind::FileBacked {
                        backing_id,
                        file_offset: right_offset,
                        committed,
                    },
                    ..area
                },
            )?;
        }
        covered = middle_end;
    }
    if covered != end {
        return Err(SharedMappingError::ExactMappingNotFound {
            address: start,
            length: end - start,
        });
    }
    Ok(planned)
}

fn file_segments(
    vmas: &[VmArea],
    start: u64,
    end: u64,
    committed_expected: bool,
) -> Result<Vec<FileSegment>, SharedMappingError> {
    let mut segments = Vec::new();
    segments
        .try_reserve_exact(vmas.len())
        .map_err(|_| SharedMappingError::OutOfMemory)?;
    let mut covered = start;
    for area in vmas.iter().copied() {
        if area.end <= start || area.start >= end {
            continue;
        }
        let VmAreaKind::FileBacked {
            backing_id,
            file_offset,
            committed,
        } = area.kind
        else {
            return Err(SharedMappingError::ExactMappingNotFound {
                address: start,
                length: end - start,
            });
        };
        if area.start > covered || committed != committed_expected {
            return Err(SharedMappingError::ExactMappingNotFound {
                address: start,
                length: end - start,
            });
        }
        let segment_start = area.start.max(start);
        let segment_end = area.end.min(end);
        segments.push(FileSegment {
            start: segment_start,
            end: segment_end,
            backing_id,
            file_offset: file_offset
                .checked_add(segment_start - area.start)
                .ok_or(SharedMappingError::RangeOverflow)?,
            protection: area.protection,
        });
        covered = segment_end;
    }
    if covered != end {
        return Err(SharedMappingError::ExactMappingNotFound {
            address: start,
            length: end - start,
        });
    }
    Ok(segments)
}

fn committed_file_ranges(
    vmas: &[VmArea],
    start: u64,
    end: u64,
) -> Result<Vec<(u64, usize)>, SharedMappingError> {
    let mut ranges = Vec::new();
    ranges
        .try_reserve_exact(vmas.len())
        .map_err(|_| SharedMappingError::OutOfMemory)?;
    let mut covered = start;
    for area in vmas {
        if area.end <= start || area.start >= end {
            continue;
        }
        let VmAreaKind::FileBacked { committed, .. } = area.kind else {
            return Err(SharedMappingError::ExactMappingNotFound {
                address: start,
                length: end - start,
            });
        };
        if area.start > covered {
            return Err(SharedMappingError::ExactMappingNotFound {
                address: start,
                length: end - start,
            });
        }
        let range_start = area.start.max(start);
        let range_end = area.end.min(end);
        if committed {
            let length = usize::try_from(range_end - range_start)
                .map_err(|_| SharedMappingError::RangeOverflow)?;
            if let Some((previous_start, previous_length)) = ranges.last_mut() {
                if *previous_start + *previous_length as u64 == range_start {
                    *previous_length += length;
                } else {
                    ranges.push((range_start, length));
                }
            } else {
                ranges.push((range_start, length));
            }
        }
        covered = range_end;
    }
    if covered != end {
        return Err(SharedMappingError::ExactMappingNotFound {
            address: start,
            length: end - start,
        });
    }
    Ok(ranges)
}

fn plan_vma_remove_kind(
    vmas: &[VmArea],
    start: u64,
    end: u64,
    kind: VmAreaKind,
) -> Result<Vec<VmArea>, SharedMappingError> {
    if matches!(kind, VmAreaKind::Anonymous { .. }) {
        return plan_anonymous_change(vmas, start, end, AnonymousChange::Unmap);
    }
    let mut result = clone_vma_plan(vmas)?;
    result.clear();
    let mut covered = start;
    for area in vmas.iter().copied() {
        if area.end <= start || area.start >= end {
            push_merged_vma(&mut result, area)?;
            continue;
        }
        if area.kind != kind || area.start > covered {
            return Err(SharedMappingError::ExactMappingNotFound {
                address: start,
                length: end - start,
            });
        }
        let middle_start = area.start.max(start);
        let middle_end = area.end.min(end);
        if area.start < middle_start {
            push_merged_vma(
                &mut result,
                VmArea {
                    end: middle_start,
                    ..area
                },
            )?;
        }
        if middle_end < area.end {
            push_merged_vma(
                &mut result,
                VmArea {
                    start: middle_end,
                    ..area
                },
            )?;
        }
        covered = middle_end;
    }
    if covered != end {
        return Err(SharedMappingError::ExactMappingNotFound {
            address: start,
            length: end - start,
        });
    }
    Ok(result)
}

fn committed_anonymous_ranges(
    vmas: &[VmArea],
    start: u64,
    end: u64,
) -> Result<Vec<(u64, usize)>, SharedMappingError> {
    let mut ranges = Vec::new();
    ranges
        .try_reserve_exact(vmas.len())
        .map_err(|_| SharedMappingError::OutOfMemory)?;
    let mut covered = start;
    for area in vmas {
        if area.end <= start || area.start >= end {
            continue;
        }
        if area.start > covered || !matches!(area.kind, VmAreaKind::Anonymous { .. }) {
            return Err(SharedMappingError::ExactMappingNotFound {
                address: start,
                length: end - start,
            });
        }
        let range_start = area.start.max(start);
        let range_end = area.end.min(end);
        if matches!(
            area.kind,
            VmAreaKind::Anonymous {
                committed: true,
                ..
            }
        ) {
            let length = usize::try_from(range_end - range_start)
                .map_err(|_| SharedMappingError::RangeOverflow)?;
            if let Some((previous_start, previous_length)) = ranges.last_mut() {
                if *previous_start + *previous_length as u64 == range_start {
                    *previous_length += length;
                } else {
                    ranges.push((range_start, length));
                }
            } else {
                ranges.push((range_start, length));
            }
        }
        covered = range_end;
    }
    if covered != end {
        return Err(SharedMappingError::ExactMappingNotFound {
            address: start,
            length: end - start,
        });
    }
    Ok(ranges)
}

fn normalize_anonymous_range(
    address: u64,
    length: u64,
) -> Result<(u64, usize), SharedMappingError> {
    if address % PAGE_SIZE != 0 {
        return Err(SharedMappingError::UnalignedFixedAddress(address));
    }
    if length == 0 {
        return Err(SharedMappingError::ZeroLength);
    }
    let mapped_length = length
        .checked_add(PAGE_SIZE - 1)
        .map(|rounded| rounded & !(PAGE_SIZE - 1))
        .ok_or(SharedMappingError::RangeOverflow)?;
    let end = address
        .checked_add(mapped_length)
        .ok_or(SharedMappingError::RangeOverflow)?;
    user_mapping_range(address, mapped_length)
        .ok_or(SharedMappingError::InvalidFixedAddress(address))?;
    Ok((
        end,
        usize::try_from(mapped_length).map_err(|_| SharedMappingError::RangeOverflow)?,
    ))
}

fn anonymous_permissions(
    protection: MapProtection,
) -> Result<(MapProtection, UserPagePermissions), SharedMappingError> {
    let known = MapProtection::READ | MapProtection::WRITE | MapProtection::EXECUTE;
    if protection.bits() & !known.bits() != 0
        || !protection.contains(MapProtection::READ)
        || protection.contains(MapProtection::WRITE) && protection.contains(MapProtection::EXECUTE)
    {
        return Err(SharedMappingError::InvalidProtection(protection));
    }
    let permissions = if protection.contains(MapProtection::WRITE) {
        UserPagePermissions::READ_WRITE
    } else if protection.contains(MapProtection::EXECUTE) {
        UserPagePermissions::READ_EXECUTE
    } else {
        UserPagePermissions::READ_ONLY
    };
    Ok((protection, permissions))
}

pub(crate) fn file_max_protection(rights: Rights) -> Result<MapProtection, SharedMappingError> {
    if !rights.contains(Rights::READ)
        || rights.contains(Rights::WRITE) && rights.contains(Rights::EXECUTE)
    {
        return Err(SharedMappingError::Ipc(IpcError::InvalidRights));
    }
    let mut maximum = MapProtection::READ;
    if rights.contains(Rights::WRITE) {
        maximum |= MapProtection::WRITE;
    }
    if rights.contains(Rights::EXECUTE) {
        maximum |= MapProtection::EXECUTE;
    }
    Ok(maximum)
}

fn file_permissions(
    protection: MapProtection,
    maximum: MapProtection,
) -> Result<(MapProtection, UserPagePermissions), SharedMappingError> {
    let validated = anonymous_permissions(protection)?;
    if protection.bits() & !maximum.bits() != 0 {
        return Err(SharedMappingError::InvalidProtection(protection));
    }
    Ok(validated)
}

fn authorize_file_protection(
    vmas: &[VmArea],
    backings: &[FileBacking],
    start: u64,
    end: u64,
    protection: MapProtection,
) -> Result<(), SharedMappingError> {
    let mut covered = start;
    for area in vmas {
        if area.end <= start || area.start >= end {
            continue;
        }
        let VmAreaKind::FileBacked { backing_id, .. } = area.kind else {
            return Err(SharedMappingError::ExactMappingNotFound {
                address: start,
                length: end - start,
            });
        };
        if area.start > covered {
            return Err(SharedMappingError::ExactMappingNotFound {
                address: start,
                length: end - start,
            });
        }
        let backing = backings
            .iter()
            .find(|backing| backing.id == backing_id)
            .ok_or(SharedMappingError::InvalidBackingLength)?;
        file_permissions(protection, backing.max_protection)?;
        covered = area.end.min(end);
    }
    if covered != end {
        return Err(SharedMappingError::ExactMappingNotFound {
            address: start,
            length: end - start,
        });
    }
    Ok(())
}

fn validate_protection(
    protection: MapProtection,
) -> Result<SharedMemoryMappingAccess, SharedMappingError> {
    let known = MapProtection::READ | MapProtection::WRITE | MapProtection::EXECUTE;
    if protection.bits() & !known.bits() != 0
        || !protection.contains(MapProtection::READ)
        || protection.contains(MapProtection::EXECUTE)
    {
        return Err(SharedMappingError::InvalidProtection(protection));
    }
    if protection.contains(MapProtection::WRITE) {
        Ok(SharedMemoryMappingAccess::ReadWrite)
    } else {
        Ok(SharedMemoryMappingAccess::ReadOnly)
    }
}

fn validate_flags(flags: MapFlags) -> Result<(), SharedMappingError> {
    if flags.bits() & !MapFlags::FIXED.bits() != 0 {
        Err(SharedMappingError::UnsupportedFlags(flags))
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ValidatedMappingRange {
    offset: usize,
    mapped_len: usize,
}

fn validate_mapping_range(
    info: SharedMemoryMappingInfo,
    offset: u64,
    length: u64,
) -> Result<ValidatedMappingRange, SharedMappingError> {
    if offset % PAGE_SIZE != 0 {
        return Err(SharedMappingError::UnalignedOffset(offset));
    }
    if length == 0 {
        return Err(SharedMappingError::ZeroLength);
    }
    if info.mapped_len == 0 || info.mapped_len % PAGE_SIZE as usize != 0 {
        return Err(SharedMappingError::InvalidBackingLength);
    }

    let offset_usize = usize::try_from(offset).map_err(|_| SharedMappingError::RangeOverflow)?;
    let length_usize = usize::try_from(length).map_err(|_| SharedMappingError::RangeOverflow)?;
    let logical_end = offset_usize
        .checked_add(length_usize)
        .ok_or(SharedMappingError::RangeOverflow)?;
    if logical_end > info.logical_len {
        return Err(SharedMappingError::RangeOutsideObject {
            offset,
            length,
            object_length: info.logical_len,
        });
    }
    let mapped_len = length_usize
        .checked_add(PAGE_SIZE as usize - 1)
        .ok_or(SharedMappingError::RangeOverflow)?
        & !(PAGE_SIZE as usize - 1);
    let mapped_end = offset_usize
        .checked_add(mapped_len)
        .ok_or(SharedMappingError::RangeOverflow)?;
    if mapped_end > info.mapped_len {
        return Err(SharedMappingError::InvalidBackingLength);
    }
    Ok(ValidatedMappingRange {
        offset: offset_usize,
        mapped_len,
    })
}

fn backing_pages(
    lease: &SharedMemoryMappingLease,
    request: ValidatedMappingRange,
) -> Result<Vec<PhysFrame<Size4KiB>>, SharedMappingError> {
    let page_count = request.mapped_len / PAGE_SIZE as usize;
    let first_page = request.offset / PAGE_SIZE as usize;
    let mut frames = Vec::new();
    frames
        .try_reserve_exact(page_count)
        .map_err(|_| SharedMappingError::OutOfMemory)?;
    for relative_page in 0..page_count {
        let page_index = first_page
            .checked_add(relative_page)
            .ok_or(SharedMappingError::RangeOverflow)?;
        let physical = lease
            .physical_page(page_index)
            .ok_or(SharedMappingError::InvalidBackingLength)?;
        let physical_address = PhysAddr::try_new(physical)
            .map_err(|_| SharedMappingError::InvalidPhysicalAddress(physical))?;
        let frame = PhysFrame::from_start_address(physical_address)
            .map_err(|_| SharedMappingError::PhysicalAddressNotPageAligned(physical))?;
        frames.push(frame);
    }
    Ok(frames)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct VirtualRange {
    start: u64,
    end: u64,
}

impl VirtualRange {
    #[cfg(test)]
    const fn new(start: u64, end: u64) -> Option<Self> {
        if start < end {
            Some(Self { start, end })
        } else {
            None
        }
    }

    const fn overlaps(self, other: Self) -> bool {
        self.start < other.end && other.start < self.end
    }
}

fn select_mapping_address(
    requested: u64,
    fixed: bool,
    mapped_len: usize,
    cursor: u64,
    automatic_limit: u64,
    occupied: &[VirtualRange],
) -> Result<u64, SharedMappingError> {
    let mapped_len = u64::try_from(mapped_len).map_err(|_| SharedMappingError::RangeOverflow)?;
    if fixed {
        if requested % PAGE_SIZE != 0 {
            return Err(SharedMappingError::UnalignedFixedAddress(requested));
        }
        let candidate = user_mapping_range(requested, mapped_len)
            .ok_or(SharedMappingError::InvalidFixedAddress(requested))?;
        if occupied.iter().any(|range| range.overlaps(candidate)) {
            return Err(SharedMappingError::AlreadyMapped(requested));
        }
        return Ok(requested);
    }

    if requested != 0 {
        if let Some(hint) = align_up(requested, PAGE_SIZE)
            .and_then(|address| user_mapping_range(address, mapped_len))
        {
            if !occupied.iter().any(|range| range.overlaps(hint)) {
                return Ok(hint.start);
            }
        }
    }

    let start = align_up(cursor.max(SHARED_MAPPING_BASE), PAGE_SIZE)
        .filter(|address| *address < automatic_limit)
        .unwrap_or(SHARED_MAPPING_BASE);
    if let Some(address) = first_fit_mapping(start, automatic_limit, mapped_len, occupied)? {
        return Ok(address);
    }
    if start > SHARED_MAPPING_BASE {
        if let Some(address) = first_fit_mapping(SHARED_MAPPING_BASE, start, mapped_len, occupied)?
        {
            return Ok(address);
        }
    }
    Err(SharedMappingError::NoAddressSpace)
}

fn first_fit_mapping(
    mut candidate: u64,
    limit: u64,
    mapped_len: u64,
    occupied: &[VirtualRange],
) -> Result<Option<u64>, SharedMappingError> {
    loop {
        let end = candidate
            .checked_add(mapped_len)
            .ok_or(SharedMappingError::RangeOverflow)?;
        if end > limit {
            return Ok(None);
        }
        let range = VirtualRange {
            start: candidate,
            end,
        };
        let next = occupied
            .iter()
            .filter(|occupied| occupied.overlaps(range))
            .map(|occupied| occupied.end)
            .max();
        let Some(next) = next else {
            return Ok(Some(candidate));
        };
        candidate = align_up(next, PAGE_SIZE).ok_or(SharedMappingError::RangeOverflow)?;
    }
}

fn user_mapping_range(address: u64, length: u64) -> Option<VirtualRange> {
    if address < PAGE_SIZE || address % PAGE_SIZE != 0 || length == 0 {
        return None;
    }
    let end = address.checked_add(length)?;
    (end <= USER_ADDRESS_END).then_some(VirtualRange {
        start: address,
        end,
    })
}

fn align_up(value: u64, alignment: u64) -> Option<u64> {
    debug_assert!(alignment.is_power_of_two());
    value
        .checked_add(alignment - 1)
        .map(|rounded| rounded & !(alignment - 1))
}

pub const PROCESS_TABLE_CAPACITY: usize = 32;
pub const USER_SCHEDULER_CAPACITY: usize = PROCESS_TABLE_CAPACITY * MAX_THREADS_PER_PROCESS;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessTableError {
    Full,
    OutOfMemory,
}

struct ProcessSlot<T> {
    generation: u32,
    value: Option<T>,
}

struct GenerationalSlots<T> {
    slots: Vec<ProcessSlot<T>>,
    next_slot: usize,
    len: usize,
}

impl<T> GenerationalSlots<T> {
    const fn new() -> Self {
        Self {
            slots: Vec::new(),
            next_slot: 0,
            len: 0,
        }
    }

    fn prepare_insert(&mut self) -> Result<(), ProcessTableError> {
        if self.len >= PROCESS_TABLE_CAPACITY {
            return Err(ProcessTableError::Full);
        }
        let has_vacant = self
            .slots
            .iter()
            .any(|slot| slot.generation != 0 && slot.value.is_none());
        if !has_vacant {
            if self.slots.len() > u32::MAX as usize {
                return Err(ProcessTableError::Full);
            }
            self.slots
                .try_reserve(1)
                .map_err(|_| ProcessTableError::OutOfMemory)?;
        }
        Ok(())
    }

    fn insert(&mut self, value: T) -> Result<ProcessId, ProcessTableError> {
        if self.len >= PROCESS_TABLE_CAPACITY {
            return Err(ProcessTableError::Full);
        }
        if let Some((index, slot)) = self
            .slots
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| slot.generation != 0 && slot.value.is_none())
        {
            let id = ProcessId::from_parts(index as u32, slot.generation);
            slot.value = Some(value);
            self.len += 1;
            return Ok(id);
        }

        let index = self.slots.len();
        if index > u32::MAX as usize {
            return Err(ProcessTableError::Full);
        }
        self.slots
            .try_reserve(1)
            .map_err(|_| ProcessTableError::OutOfMemory)?;
        self.slots.push(ProcessSlot {
            generation: 1,
            value: Some(value),
        });
        self.len += 1;
        Ok(ProcessId::from_parts(index as u32, 1))
    }

    fn get(&self, id: ProcessId) -> Option<&T> {
        let slot = self.slots.get(id.slot() as usize)?;
        (id.is_valid() && slot.generation == id.generation())
            .then(|| slot.value.as_ref())
            .flatten()
    }

    fn get_mut(&mut self, id: ProcessId) -> Option<&mut T> {
        let slot = self.slots.get_mut(id.slot() as usize)?;
        (id.is_valid() && slot.generation == id.generation())
            .then(|| slot.value.as_mut())
            .flatten()
    }

    fn remove(&mut self, id: ProcessId) -> Option<T> {
        let slot = self.slots.get_mut(id.slot() as usize)?;
        if !id.is_valid() || slot.generation != id.generation() {
            return None;
        }
        let value = slot.value.take()?;
        self.len -= 1;
        slot.generation = slot.generation.checked_add(1).unwrap_or(0);
        Some(value)
    }

    fn next_id(&mut self) -> Option<ProcessId> {
        if self.len == 0 {
            return None;
        }

        let slot_count = self.slots.len();
        debug_assert_ne!(slot_count, 0);
        self.next_slot %= slot_count;
        for _ in 0..slot_count {
            let index = self.next_slot;
            self.next_slot = if index + 1 == slot_count {
                0
            } else {
                index + 1
            };
            let slot = &self.slots[index];
            if slot.value.is_some() {
                debug_assert_ne!(slot.generation, 0);
                return Some(ProcessId::from_parts(index as u32, slot.generation));
            }
        }

        debug_assert!(false, "live process count does not match occupied slots");
        None
    }
}

/// Generation-checked owner of all live processes.
pub struct ProcessTable {
    inner: GenerationalSlots<Process>,
}

impl ProcessTable {
    pub const fn new() -> Self {
        Self {
            inner: GenerationalSlots::new(),
        }
    }

    pub const fn len(&self) -> usize {
        self.inner.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns whether any live process is eligible to enter userspace.
    pub fn has_runnable(&self) -> bool {
        self.inner
            .slots
            .iter()
            .any(|slot| slot.value.as_ref().is_some_and(Process::is_runnable))
    }

    /// Marks every live process terminal after an orderly-shutdown grace period expires.
    pub fn force_terminate_all(&mut self) -> usize {
        self.force_terminate_all_except(None)
    }

    /// Marks every live process except one trusted coordinator terminal.
    pub fn force_terminate_all_except(&mut self, retained: Option<ProcessId>) -> usize {
        let mut terminated = 0;
        for (index, slot) in self.inner.slots.iter_mut().enumerate() {
            let Some(process) = slot.value.as_mut() else {
                continue;
            };
            let id = ProcessId::from_parts(index as u32, slot.generation);
            if Some(id) != retained && !process.state().is_terminal() {
                process.mark_terminated();
                terminated += 1;
            }
        }
        terminated
    }

    /// Reserves capacity before callers allocate an address space and handles.
    pub fn prepare_insert(&mut self) -> Result<(), ProcessTableError> {
        self.inner.prepare_insert()
    }

    pub fn insert(&mut self, process: Process) -> Result<ProcessId, ProcessTableError> {
        self.inner.insert(process)
    }

    pub fn get(&self, id: ProcessId) -> Option<&Process> {
        self.inner.get(id)
    }

    pub fn get_mut(&mut self, id: ProcessId) -> Option<&mut Process> {
        self.inner.get_mut(id)
    }

    pub fn thread_refs(&self) -> impl Iterator<Item = ThreadRef> + '_ {
        self.inner
            .slots
            .iter()
            .enumerate()
            .flat_map(|(process_index, process_slot)| {
                let process_id =
                    ProcessId::from_parts(process_index as u32, process_slot.generation);
                process_slot.value.iter().flat_map(move |process| {
                    process.threads.slots.iter().enumerate().filter_map(
                        move |(thread_index, thread_slot)| {
                            thread_slot.thread.as_ref().map(|_| ThreadRef {
                                process_id,
                                thread_id: ThreadId::from_parts(
                                    thread_index as u32,
                                    thread_slot.generation,
                                ),
                            })
                        },
                    )
                })
            })
    }

    /// Selects the next live thread in deterministic process-slot order.
    ///
    /// Selection includes blocked and terminal threads so the permanent runner can
    /// poll continuations and retire their owning processes. Both generations are
    /// carried by the scheduler reference, so stale process or thread identities
    /// cannot alias replacements.
    pub fn next_thread(&mut self) -> Option<ThreadRef> {
        let process_count = self.inner.len;
        for _ in 0..process_count {
            let process_id = self.inner.next_id()?;
            let process = self.inner.get_mut(process_id)?;
            if let Some(thread_id) = process.next_schedulable_thread() {
                return Some(ThreadRef {
                    process_id,
                    thread_id,
                });
            }
            if process.state().is_terminal() {
                return Some(ThreadRef {
                    process_id,
                    thread_id: process.main_thread_id(),
                });
            }
        }
        None
    }

    pub fn next_terminal_thread(&mut self) -> Option<ThreadRef> {
        let process_count = self.inner.len;
        for _ in 0..process_count {
            let process_id = self.inner.next_id()?;
            let process = self.inner.get_mut(process_id)?;
            if process.state().is_terminal() {
                let thread_id = process.thread_ids().next()?;
                return Some(ThreadRef {
                    process_id,
                    thread_id,
                });
            }
        }
        None
    }

    #[cfg(test)]
    pub fn next_blocked_or_terminal_thread(&mut self) -> Option<ThreadRef> {
        let process_count = self.inner.len;
        for _ in 0..process_count {
            let process_id = self.inner.next_id()?;
            let process = self.inner.get_mut(process_id)?;
            if let Some(thread_id) = process.next_blocked_thread() {
                return Some(ThreadRef {
                    process_id,
                    thread_id,
                });
            }
            if process.state().is_terminal() {
                let thread_id = process.thread_ids().next()?;
                return Some(ThreadRef {
                    process_id,
                    thread_id,
                });
            }
        }
        None
    }

    /// Compatibility selector for process-inspection code and existing host tests.
    pub fn next_id(&mut self) -> Option<ProcessId> {
        self.next_thread().map(|thread| thread.process_id)
    }

    /// Takes a process out of the table so the scheduler can restore the kernel
    /// root and call [`Process::retire`].
    ///
    /// Dropping the returned process without retirement is memory-safe but leaks
    /// its handles and backing leases by design; clean process removal must finish
    /// the retirement lifecycle.
    pub fn take_for_retirement(&mut self, id: ProcessId) -> Option<Process> {
        self.inner.remove(id)
    }
}

impl Default for ProcessTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use alloc::{
        alloc::{alloc_zeroed, dealloc, Layout},
        vec,
    };
    use core::{
        ptr::NonNull,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use ginkgo_filesystem::{MemoryDisk, RedoxFs};
    use ginkgo_ipc::RequestControl;
    use ginkgo_sysapi::{RequestInfo, RequestState};

    use super::*;
    use crate::shared_memory::test_support::TestSharedMemoryContext;

    static FRAME_RECLAIM_TEST_ELF: &[u8] =
        include_bytes!(concat!(env!("OUT_DIR"), "/ginkgo-frame-reclaim-exit.elf"));

    #[test]
    fn ram_derived_policy_scales_across_low_normal_and_high_memory() {
        let low = ProcessLimits::from_available_memory_bytes(32 * MIB);
        let normal = ProcessLimits::from_available_memory_bytes(512 * MIB);
        let high = ProcessLimits::from_available_memory_bytes(16 * 1024 * MIB);

        assert!(low.private_pages < normal.private_pages);
        assert!(normal.private_pages < high.private_pages);
        assert!(low.shared_memory_bytes <= normal.shared_memory_bytes);
        assert!(normal.shared_memory_bytes < high.shared_memory_bytes);
        assert!(low.reserved_virtual_bytes <= normal.reserved_virtual_bytes);
        assert!(normal.reserved_virtual_bytes < high.reserved_virtual_bytes);
        assert!(low.vma_count <= normal.vma_count);
        assert!(normal.vma_count < high.vma_count);
        assert!(low.executable_source_bytes <= normal.executable_source_bytes);
        assert!(normal.executable_source_bytes < high.executable_source_bytes);
        assert!(high.executable_image_pages <= high.private_pages);
        assert!(high.vma_count <= MAX_VMAS as u64);
    }

    #[test]
    fn memory_policy_attenuates_every_public_limit_and_rejects_escalation() {
        let defaults = ProcessLimits::from_available_memory_bytes(512 * MIB);
        let requested = ProcessLimits {
            private_pages: defaults.private_pages - 1,
            shared_memory_bytes: defaults.shared_memory_bytes - 1,
            mapped_shared_bytes: defaults.mapped_shared_bytes - 1,
            reserved_virtual_bytes: defaults.reserved_virtual_bytes - 1,
            vma_count: defaults.vma_count - 1,
            executable_image_pages: defaults.executable_image_pages - 1,
            executable_source_bytes: defaults.executable_source_bytes - 1,
            channel_traffic_bytes: defaults.channel_traffic_bytes,
            cpu_quantum_ns: defaults.cpu_quantum_ns,
        };
        let selected = defaults.attenuate(requested).unwrap();
        assert_eq!(selected.private_pages, requested.private_pages);
        assert_eq!(selected.shared_memory_bytes, requested.shared_memory_bytes);
        assert_eq!(selected.mapped_shared_bytes, requested.mapped_shared_bytes);
        assert_eq!(
            selected.reserved_virtual_bytes,
            requested.reserved_virtual_bytes
        );
        assert_eq!(selected.vma_count, requested.vma_count);
        assert_eq!(
            selected.executable_image_pages,
            requested.executable_image_pages
        );
        assert_eq!(
            selected.executable_source_bytes,
            requested.executable_source_bytes
        );
        assert_eq!(
            selected.channel_traffic_bytes,
            defaults.channel_traffic_bytes
        );
        assert_eq!(selected.cpu_quantum_ns, defaults.cpu_quantum_ns);

        let mut escalation = requested;
        escalation.private_pages = defaults.private_pages + 1;
        assert_eq!(defaults.attenuate(escalation), None);
    }

    #[test]
    fn child_policy_is_transitively_capped_for_legacy_and_versioned_creation() {
        let ram = ProcessLimits::from_available_memory_bytes(512 * MIB);
        let mut caller = ram;
        caller.private_pages /= 2;
        caller.shared_memory_bytes /= 2;
        caller.mapped_shared_bytes /= 2;
        caller.reserved_virtual_bytes /= 2;
        caller.vma_count /= 2;
        caller.executable_image_pages /= 2;
        caller.executable_source_bytes /= 2;

        let legacy = select_child_process_limits(caller, 512 * MIB, None).unwrap();
        assert_eq!(legacy.private_pages, caller.private_pages);
        assert_eq!(
            legacy.executable_source_bytes,
            caller.executable_source_bytes
        );

        let lower_ram = ProcessLimits::from_available_memory_bytes(64 * MIB);
        let low_memory_legacy = select_child_process_limits(caller, 64 * MIB, None).unwrap();
        assert_eq!(low_memory_legacy, lower_ram.capped_by(caller));

        let mut requested = legacy;
        requested.private_pages -= 1;
        requested.vma_count -= 1;
        let selected = select_child_process_limits(caller, 512 * MIB, Some(requested)).unwrap();
        assert_eq!(selected.private_pages, requested.private_pages);
        assert_eq!(selected.vma_count, requested.vma_count);

        let mut escalation = requested;
        escalation.private_pages = caller.private_pages + 1;
        assert_eq!(
            select_child_process_limits(caller, 512 * MIB, Some(escalation)),
            None
        );
    }

    #[test]
    fn process_memory_failure_counters_saturate() {
        let (_region, mut allocator) = TestFrameRegion::allocator(64);
        let mut process = construct_test_process(&mut allocator).unwrap();
        process.usage.quota_failures = u64::MAX;
        process.usage.oom_failures = u64::MAX;
        process.record_quota_failure();
        process.record_oom_failure();
        assert_eq!(process.usage().quota_failures, u64::MAX);
        assert_eq!(process.usage().oom_failures, u64::MAX);
    }

    #[test]
    fn tiny_ram_policy_never_inverts_checked_minimum_and_maximum() {
        let limits = ProcessLimits::from_available_memory_bytes(2 * MIB);
        assert!(limits.private_pages <= (2 * MIB) / PAGE_SIZE / 2);
        assert!(limits.shared_memory_bytes <= (2 * MIB) / 4);
        assert!(limits.executable_source_bytes <= limits.private_pages * PAGE_SIZE / 2);
        assert!(limits.executable_image_pages <= limits.private_pages);
    }

    struct TestFrameRegion {
        pointer: NonNull<u8>,
        layout: Layout,
    }

    impl TestFrameRegion {
        fn allocator(pages: usize) -> (Self, UsableFrameAllocator<'static>) {
            let size = pages * PAGE_SIZE as usize;
            let layout = Layout::from_size_align(size, PAGE_SIZE as usize).unwrap();
            let pointer = NonNull::new(unsafe { alloc_zeroed(layout) }).expect("test frame region");
            let allocator = unsafe {
                UsableFrameAllocator::from_test_region(pointer.as_ptr() as u64, size as u64, 52)
            };
            (Self { pointer, layout }, allocator)
        }
    }

    impl Drop for TestFrameRegion {
        fn drop(&mut self) {
            unsafe { dealloc(self.pointer.as_ptr(), self.layout) };
        }
    }

    struct DropProbe<'a>(&'a AtomicUsize);

    impl Drop for DropProbe<'_> {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn info(logical_len: usize, mapped_len: usize) -> SharedMemoryMappingInfo {
        SharedMemoryMappingInfo {
            backing_identity: 1,
            logical_len,
            mapped_len,
        }
    }

    fn construct_test_process(
        allocator: &mut UsableFrameAllocator<'_>,
    ) -> Result<Process, ProcessCreateError> {
        construct_test_process_with_limits(allocator, ProcessLimits::STANDARD)
    }

    fn construct_test_process_with_limits(
        allocator: &mut UsableFrameAllocator<'_>,
        limits: ProcessLimits,
    ) -> Result<Process, ProcessCreateError> {
        let parsed = elf::parse(FRAME_RECLAIM_TEST_ELF).map_err(ProcessCreateError::Elf)?;
        let address_space =
            AddressSpace::new_for_test(allocator).map_err(ProcessCreateError::AddressSpace)?;
        Process::finish_construction(
            parsed,
            address_space,
            VirtAddr::zero(),
            ProcessLayout::STANDARD,
            limits,
            allocator,
            None,
        )
    }

    fn test_process(state: ProcessState) -> Process {
        let thread_state = match state {
            ProcessState::Ready => ThreadState::Ready,
            ProcessState::Blocked => ThreadState::Blocked,
            ProcessState::Exited(code) => ThreadState::Exited(code),
            ProcessState::Faulted(fault) => ThreadState::Faulted(fault),
            ProcessState::Terminated => ThreadState::Terminated,
        };
        let (mut threads, main_thread_id) = ThreadTable::with_main(Thread {
            context: UserContext::new(0x1000, USER_STACK_TOP),
            layout: ProcessLayout::STANDARD,
            entry_stacks: KernelEntryStacks::try_new().unwrap(),
            state: thread_state,
            detached: false,
            join_claimed_by: None,
            wake_permit: false,
            fallback_scheduling_class: SchedulingClass::Normal,
            kernel_scheduling_class: None,
            delegated_scheduling_class: None,
            focused_interactive: false,
            effective_class: SchedulingClass::Normal,
            scheduler_budget_remaining_ns: 0,
            scheduler_metrics: SchedulerMetrics::default(),
            preemption_count: 0,
            cpu_time_ns: 0,
            blocked_syscall: None,
        });
        let terminal_state = state.is_terminal().then_some(state);
        if terminal_state.is_some() {
            threads.live = 0;
        }
        Process {
            address_space: None,
            threads,
            main_thread_id,
            main_layout: ProcessLayout::STANDARD,
            retirement_context: UserContext::new(0x1000, USER_STACK_TOP),
            terminal_state,
            handles: None,
            application_data: None,
            control: None,
            shared_mappings: None,
            file_backings: None,
            vmas: None,
            retained_failed_mapping_leases: None,
            next_mapping_cursor: SHARED_MAPPING_BASE,
            next_thread_stack_cursor: USER_STACK_GUARD_START,
            next_anonymous_reservation_id: 1,
            next_file_backing_id: 1,
            fail_file_rollback_for_test: false,
            limits: ProcessLimits::STANDARD,
            usage: ProcessUsage::default(),
        }
    }

    fn file_fixture(bytes: &[u8]) -> (RedoxFs<MemoryDisk>, FileHandle) {
        let mut filesystem = RedoxFs::format_disk(MemoryDisk::zeroed(8 * 1024 * 1024)).unwrap();
        let file = filesystem.create("/mapping.bin").unwrap();
        assert_eq!(filesystem.write(file, 0, bytes).unwrap(), bytes.len());
        (filesystem, file)
    }

    unsafe fn frame_bytes(frame: PhysFrame<Size4KiB>) -> &'static [u8] {
        unsafe {
            core::slice::from_raw_parts(
                frame.start_address().as_u64() as usize as *const u8,
                PAGE_SIZE as usize,
            )
        }
    }

    #[test]
    fn virtual_area_info_has_stable_semantics_for_every_vma_kind() {
        let protection = MapProtection::READ | MapProtection::WRITE;
        let cases = [
            (VmAreaKind::Image, VirtualAreaKind::Image, true, 0, 0),
            (
                VmAreaKind::Anonymous {
                    reservation_id: 17,
                    committed: false,
                },
                VirtualAreaKind::Anonymous,
                false,
                17,
                0,
            ),
            (
                VmAreaKind::Stack {
                    owner: MAIN_THREAD_ID,
                    committed: true,
                },
                VirtualAreaKind::Stack,
                true,
                0,
                0,
            ),
            (
                VmAreaKind::StackGuard {
                    owner: MAIN_THREAD_ID,
                },
                VirtualAreaKind::Guard,
                false,
                0,
                0,
            ),
            (
                VmAreaKind::Shared {
                    object_identity: 29,
                    object_offset: PAGE_SIZE,
                },
                VirtualAreaKind::Shared,
                true,
                29,
                0,
            ),
            (
                VmAreaKind::FileBacked {
                    backing_id: 41,
                    file_offset: PAGE_SIZE * 3,
                    committed: false,
                },
                VirtualAreaKind::File,
                false,
                41,
                PAGE_SIZE * 3,
            ),
        ];

        for (kind, expected_kind, committed, backing_identity, file_offset) in cases {
            let info = virtual_area_info(VmArea {
                start: PAGE_SIZE * 10,
                end: PAGE_SIZE * 12,
                kind,
                protection,
            });
            assert_eq!(info.version, VIRTUAL_AREA_INFO_VERSION);
            assert_eq!(info.size, VirtualAreaInfo::SIZE);
            assert_eq!(info.area_kind(), Some(expected_kind));
            assert_eq!(info.map_protection(), protection);
            assert_eq!(info.reserved_bytes, PAGE_SIZE * 2);
            assert_eq!(info.reserved_pages, 2);
            assert_eq!(
                info.committed_bytes,
                if committed { PAGE_SIZE * 2 } else { 0 }
            );
            assert_eq!(info.committed_pages, if committed { 2 } else { 0 });
            assert_eq!(info.backing_identity, backing_identity);
            assert_eq!(info.file_offset, file_offset);
        }
    }

    #[test]
    fn file_mapping_loads_offset_and_zero_fills_tail_then_recommits_after_handle_loss() {
        let mut source = vec![0u8; PAGE_SIZE as usize * 2 + 1];
        for (index, byte) in source[PAGE_SIZE as usize..PAGE_SIZE as usize * 2]
            .iter_mut()
            .enumerate()
        {
            *byte = (index as u8).wrapping_mul(17).wrapping_add(3);
        }
        source[PAGE_SIZE as usize * 2] = 0xa5;
        let (mut filesystem, file) = file_fixture(&source);
        let (_region, mut allocator) = TestFrameRegion::allocator(128);
        let mut process = construct_test_process(&mut allocator).unwrap();
        let baseline_usage = process.usage();
        let baseline_frames = process.address_space().owned_data_frames().len();
        let args = VirtualMapFileArgs {
            address: 0,
            offset: PAGE_SIZE,
            length: PAGE_SIZE + 1,
            protection: MapProtection::READ,
            flags: MapFlags::empty(),
        };
        let address = process
            .map_file_backed(
                file,
                source.len() as u64,
                MapProtection::READ,
                args,
                &mut allocator,
                |offset, output| {
                    filesystem
                        .read(file, offset, output)
                        .map_err(|_| SharedMappingError::Io)
                },
            )
            .unwrap();
        let frames = &process.address_space().owned_data_frames()[baseline_frames..];
        assert_eq!(frames.len(), 2);
        let first = unsafe { frame_bytes(frames[0]) };
        let tail = unsafe { frame_bytes(frames[1]) };
        assert_eq!(first, &source[PAGE_SIZE as usize..PAGE_SIZE as usize * 2]);
        assert_eq!(tail[0], 0xa5);
        assert!(tail[1..].iter().all(|byte| *byte == 0));
        assert_eq!(
            process.usage().private_pages,
            baseline_usage.private_pages + 2
        );

        process
            .decommit_file_backed(address, args.length, &mut allocator)
            .unwrap();
        assert_eq!(
            process.address_space().owned_data_frames().len(),
            baseline_frames
        );
        assert_eq!(process.usage().private_pages, baseline_usage.private_pages);
        assert_eq!(process.file_backings.as_ref().unwrap().len(), 1);

        process
            .commit_file_backed(
                address,
                args.length,
                &mut allocator,
                |authority, offset, output| {
                    filesystem
                        .read(authority, offset, output)
                        .map_err(|_| SharedMappingError::Io)
                },
            )
            .unwrap();
        let recommitted = &process.address_space().owned_data_frames()[baseline_frames..];
        assert_eq!(unsafe { frame_bytes(recommitted[1]) }[0], 0xa5);
        assert!(unsafe { frame_bytes(recommitted[1]) }[1..]
            .iter()
            .all(|byte| *byte == 0));

        process
            .unmap_file_backed(address, PAGE_SIZE, &mut allocator)
            .unwrap();
        assert_eq!(process.file_backings.as_ref().unwrap().len(), 1);
        process
            .unmap_file_backed(address + PAGE_SIZE, PAGE_SIZE, &mut allocator)
            .unwrap();
        assert!(process.file_backings.as_ref().unwrap().is_empty());
        assert_eq!(process.usage().private_pages, baseline_usage.private_pages);
        assert_eq!(
            process.usage().reserved_virtual_bytes,
            baseline_usage.reserved_virtual_bytes
        );
    }

    #[test]
    fn file_lifecycle_splits_remerges_and_enforces_wx() {
        let area = VmArea {
            start: 0x4000,
            end: 0x7000,
            kind: VmAreaKind::FileBacked {
                backing_id: 9,
                file_offset: 0x2000,
                committed: true,
            },
            protection: MapProtection::READ,
        };
        let split = plan_file_change(
            &[area],
            0x5000,
            0x6000,
            FileChange::Protect(MapProtection::READ | MapProtection::WRITE),
        )
        .unwrap();
        assert_eq!(split.len(), 3);
        assert!(matches!(
            split[1].kind,
            VmAreaKind::FileBacked {
                backing_id: 9,
                file_offset: 0x3000,
                committed: true
            }
        ));
        let merged = plan_file_change(
            &split,
            0x5000,
            0x6000,
            FileChange::Protect(MapProtection::READ),
        )
        .unwrap();
        assert_eq!(merged, vec![area]);
        assert!(matches!(
            anonymous_permissions(
                MapProtection::READ | MapProtection::WRITE | MapProtection::EXECUTE
            ),
            Err(SharedMappingError::InvalidProtection(_))
        ));
    }

    #[test]
    fn retained_file_authority_limits_later_protection_changes() {
        let source = vec![0x90u8; PAGE_SIZE as usize];
        let (mut filesystem, file) = file_fixture(&source);
        let (_region, mut allocator) = TestFrameRegion::allocator(128);
        let mut process = construct_test_process(&mut allocator).unwrap();
        let mut map = |process: &mut Process, rights, protection| {
            let source_handle = process
                .handles_mut()
                .filesystem_file_create(file, rights)
                .unwrap();
            let retained_file = process
                .handles()
                .filesystem_file(source_handle, Rights::READ)
                .unwrap();
            let maximum =
                file_max_protection(process.handles().handle_rights(source_handle).unwrap())
                    .unwrap();
            process.handles_mut().handle_close(source_handle).unwrap();
            process
                .map_file_backed(
                    retained_file,
                    source.len() as u64,
                    maximum,
                    VirtualMapFileArgs {
                        address: 0,
                        offset: 0,
                        length: PAGE_SIZE,
                        protection,
                        flags: MapFlags::empty(),
                    },
                    &mut allocator,
                    |offset, output| {
                        filesystem
                            .read(file, offset, output)
                            .map_err(|_| SharedMappingError::Io)
                    },
                )
                .unwrap()
        };

        let read_only = map(&mut process, Rights::READ, MapProtection::READ);
        let executable = map(
            &mut process,
            Rights::READ | Rights::EXECUTE,
            MapProtection::READ,
        );
        let writable = map(
            &mut process,
            Rights::READ | Rights::WRITE,
            MapProtection::READ | MapProtection::WRITE,
        );
        drop(map);

        assert!(matches!(
            process.protect_file_backed(
                read_only,
                PAGE_SIZE,
                MapProtection::READ | MapProtection::EXECUTE
            ),
            Err(SharedMappingError::InvalidProtection(_))
        ));

        process
            .protect_file_backed(
                executable,
                PAGE_SIZE,
                MapProtection::READ | MapProtection::EXECUTE,
            )
            .unwrap();
        process
            .protect_file_backed(executable, PAGE_SIZE, MapProtection::READ)
            .unwrap();

        assert!(matches!(
            process.protect_file_backed(
                writable,
                PAGE_SIZE,
                MapProtection::READ | MapProtection::EXECUTE
            ),
            Err(SharedMappingError::InvalidProtection(_))
        ));
        for address in [read_only, executable, writable] {
            process
                .unmap_file_backed(address, PAGE_SIZE, &mut allocator)
                .unwrap();
        }
    }

    #[test]
    fn file_partial_map_rollback_failure_quarantines_and_retains_retirement_owners() {
        let source = vec![0x44u8; PAGE_SIZE as usize * 2];
        let (_filesystem, file) = file_fixture(&source);
        let (_region, mut allocator) = TestFrameRegion::allocator(96);
        let mut process = construct_test_process(&mut allocator).unwrap();
        process.fail_file_rollback_for_test = true;
        let baseline_private = process.usage().private_pages;
        let mut reads = 0;
        let result = process.map_file_backed(
            file,
            source.len() as u64,
            MapProtection::READ,
            VirtualMapFileArgs {
                address: 0,
                offset: 0,
                length: PAGE_SIZE * 2,
                protection: MapProtection::READ,
                flags: MapFlags::empty(),
            },
            &mut allocator,
            |offset, output| {
                reads += 1;
                if reads == 2 {
                    Err(SharedMappingError::Io)
                } else {
                    let start = offset as usize;
                    output.copy_from_slice(&source[start..start + output.len()]);
                    Ok(output.len())
                }
            },
        );

        assert!(matches!(
            result,
            Err(SharedMappingError::RollbackFailed { .. })
        ));
        assert!(process.state().is_terminal());
        assert_eq!(process.file_backings.as_ref().unwrap().len(), 1);
        assert_eq!(process.usage().private_pages, baseline_private + 2);
        assert!(process
            .vmas()
            .iter()
            .any(|vma| matches!(vma.kind, VmAreaKind::FileBacked { backing_id: 1, .. })));
        process.retire().unwrap().reclaim(&mut allocator).unwrap();
        assert_eq!(allocator.allocated_count(), 0);
    }

    #[test]
    fn file_recommit_rollback_failure_publishes_conservative_quarantine_metadata() {
        let source = vec![0x66u8; PAGE_SIZE as usize * 2];
        let (mut filesystem, file) = file_fixture(&source);
        let (_region, mut allocator) = TestFrameRegion::allocator(96);
        let mut process = construct_test_process(&mut allocator).unwrap();
        let baseline_private = process.usage().private_pages;
        let address = process
            .map_file_backed(
                file,
                source.len() as u64,
                MapProtection::READ,
                VirtualMapFileArgs {
                    address: 0,
                    offset: 0,
                    length: PAGE_SIZE * 2,
                    protection: MapProtection::READ,
                    flags: MapFlags::empty(),
                },
                &mut allocator,
                |offset, output| {
                    filesystem
                        .read(file, offset, output)
                        .map_err(|_| SharedMappingError::Io)
                },
            )
            .unwrap();
        process
            .decommit_file_backed(address, PAGE_SIZE * 2, &mut allocator)
            .unwrap();
        let reserved_before = process.usage().reserved_virtual_bytes;
        let owned_before = process.address_space().owned_data_frames().len();
        process.fail_file_rollback_for_test = true;
        let mut reads = 0;

        let result = process.commit_file_backed(
            address,
            PAGE_SIZE * 2,
            &mut allocator,
            |authority, offset, output| {
                reads += 1;
                if reads == 2 {
                    Err(SharedMappingError::Io)
                } else {
                    filesystem
                        .read(authority, offset, output)
                        .map_err(|_| SharedMappingError::Io)
                }
            },
        );

        assert!(matches!(
            result,
            Err(SharedMappingError::RollbackFailed { .. })
        ));
        assert!(process.state().is_terminal());
        assert_eq!(process.file_backings.as_ref().unwrap().len(), 1);
        assert_eq!(process.usage().reserved_virtual_bytes, reserved_before);
        assert_eq!(process.usage().private_pages, baseline_private + 2);
        let quarantined = process
            .vmas()
            .iter()
            .filter(|vma| vma.start < address + PAGE_SIZE * 2 && address < vma.end)
            .collect::<Vec<_>>();
        assert!(!quarantined.is_empty());
        assert_eq!(
            quarantined.iter().map(|vma| vma.length()).sum::<u64>(),
            PAGE_SIZE * 2
        );
        assert!(quarantined.iter().all(|vma| matches!(
            vma.kind,
            VmAreaKind::FileBacked {
                committed: true,
                ..
            }
        )));
        assert_eq!(
            process.address_space().owned_data_frames().len(),
            owned_before + 1
        );
        let accounting = process.address_space().accounting();
        assert_eq!(accounting.mapped_data_frames, owned_before + 1);
        assert_eq!(
            process.usage().resident_owned_frames,
            (accounting.mapped_data_frames
                + accounting.retired_data_frames
                + accounting.page_table_frames) as u64
        );

        process.retire().unwrap().reclaim(&mut allocator).unwrap();
        assert_eq!(allocator.allocated_count(), 0);
    }

    #[test]
    fn file_mapping_read_failure_rolls_back_pages_vmas_quota_and_backing() {
        let source = vec![0x5au8; PAGE_SIZE as usize * 2];
        let (_filesystem, file) = file_fixture(&source);
        let (_region, mut allocator) = TestFrameRegion::allocator(128);
        let mut process = construct_test_process(&mut allocator).unwrap();
        let usage = process.usage();
        let vmas = process.vmas().to_vec();
        let frames = process.address_space().owned_data_frames().len();
        let mut reads = 0;
        let result = process.map_file_backed(
            file,
            source.len() as u64,
            MapProtection::READ,
            VirtualMapFileArgs {
                address: 0,
                offset: 0,
                length: source.len() as u64,
                protection: MapProtection::READ,
                flags: MapFlags::empty(),
            },
            &mut allocator,
            |offset, output| {
                reads += 1;
                if reads == 2 {
                    Err(SharedMappingError::Io)
                } else {
                    let start = offset as usize;
                    output.copy_from_slice(&source[start..start + output.len()]);
                    Ok(output.len())
                }
            },
        );
        assert_eq!(result, Err(SharedMappingError::Io));
        let after = process.usage();
        assert_eq!(after.private_pages, usage.private_pages);
        assert_eq!(after.reserved_virtual_bytes, usage.reserved_virtual_bytes);
        assert_eq!(after.shared_memory_bytes, usage.shared_memory_bytes);
        assert_eq!(after.mapped_shared_bytes, usage.mapped_shared_bytes);
        assert_eq!(after.quota_failures, usage.quota_failures);
        assert_eq!(after.oom_failures, usage.oom_failures);
        assert_eq!(process.vmas(), vmas);
        assert_eq!(process.address_space().owned_data_frames().len(), frames);
        assert!(process.file_backings.as_ref().unwrap().is_empty());
    }

    #[test]
    fn partial_file_mapping_oom_reclaims_data_and_keeps_metadata_atomic() {
        let source = vec![0x33u8; PAGE_SIZE as usize * 2];
        let (_filesystem, file) = file_fixture(&source);
        let (_region, mut allocator) = TestFrameRegion::allocator(80);
        let mut process = construct_test_process(&mut allocator).unwrap();
        let mut held = Vec::new();
        while let Some(frame) = allocator.allocate_frame().unwrap() {
            held.push(frame);
        }
        for _ in 0..3 {
            let frame = held.pop().expect("enough frames for one mapping page");
            allocator.deallocate_frame(frame).unwrap();
        }
        let usage = process.usage();
        let vmas = process.vmas().to_vec();
        let owned_frames = process.address_space().owned_data_frames().len();

        let result = process.map_file_backed(
            file,
            source.len() as u64,
            MapProtection::READ,
            VirtualMapFileArgs {
                address: 0,
                offset: 0,
                length: source.len() as u64,
                protection: MapProtection::READ,
                flags: MapFlags::empty(),
            },
            &mut allocator,
            |offset, output| {
                let start = offset as usize;
                output.copy_from_slice(&source[start..start + output.len()]);
                Ok(output.len())
            },
        );
        assert!(
            matches!(
                result,
                Err(SharedMappingError::AddressSpace(
                    AddressSpaceError::OutOfFrames
                )) | Err(SharedMappingError::AddressSpace(
                    AddressSpaceError::OutOfMemory
                ))
            ),
            "unexpected file mapping result: {result:?}"
        );
        assert_eq!(process.usage().private_pages, usage.private_pages);
        assert_eq!(
            process.usage().reserved_virtual_bytes,
            usage.reserved_virtual_bytes
        );
        assert_eq!(process.vmas(), vmas);
        assert_eq!(
            process.address_space().owned_data_frames().len(),
            owned_frames
        );
        assert!(process.file_backings.as_ref().unwrap().is_empty());
        allocator.reclaim_frames(&held).unwrap();
        process.retire().unwrap().reclaim(&mut allocator).unwrap();
        assert_eq!(allocator.allocated_count(), 0);
    }

    #[test]
    fn partial_elf_load_exhaustion_reclaims_every_allocated_frame() {
        let (_region, mut allocator) = TestFrameRegion::allocator(4);

        assert!(matches!(
            construct_test_process(&mut allocator),
            Err(ProcessCreateError::ElfPage(_))
        ));
        assert_eq!(allocator.allocated_count(), 0);
        assert_eq!(allocator.free_count(), 4);
    }

    #[test]
    fn partial_stack_exhaustion_reclaims_every_allocated_frame() {
        let (_region, mut allocator) = TestFrameRegion::allocator(10);

        assert!(matches!(
            construct_test_process(&mut allocator),
            Err(ProcessCreateError::StackPage { .. })
        ));
        assert_eq!(allocator.allocated_count(), 0);
        assert_eq!(allocator.free_count(), 10);
    }

    #[test]
    fn process_maps_noncontiguous_shared_frames_and_lease_controls_lifetime() {
        let (_region, mut allocator) = TestFrameRegion::allocator(80);
        let mut process = construct_test_process(&mut allocator).unwrap();
        let mut shared_memory = TestSharedMemoryContext::new(4);

        let priming = shared_memory
            .create_storage(PAGE_SIZE as usize * 3)
            .unwrap();
        drop(priming);
        let handle = shared_memory
            .factory()
            .create_handle(process.handles_mut(), PAGE_SIZE as usize * 2)
            .unwrap();
        let lease = process
            .handles()
            .shared_memory_mapping_lease(handle, SharedMemoryMappingAccess::ReadWrite)
            .unwrap();
        let physical_pages = [
            lease.physical_page(0).unwrap(),
            lease.physical_page(1).unwrap(),
        ];
        assert_ne!(physical_pages[1], physical_pages[0] + PAGE_SIZE);
        drop(lease);

        let address = process
            .map_shared_memory(
                handle,
                SharedMemoryMapArgs {
                    address: 0,
                    offset: 0,
                    length: PAGE_SIZE * 2,
                    protection: MapProtection::READ | MapProtection::WRITE,
                    flags: MapFlags::empty(),
                },
                &mut allocator,
            )
            .unwrap();
        process.handles_mut().handle_close(handle).unwrap();
        assert_eq!(shared_memory.arena().stats().free_frames, 1);

        let mapped_frames = process
            .address_space()
            .mappings()
            .iter()
            .filter(|mapping| {
                mapping.virtual_address >= address
                    && mapping.virtual_address < address + PAGE_SIZE * 2
            })
            .map(|mapping| mapping.frame.start_address().as_u64())
            .collect::<Vec<_>>();
        assert_eq!(mapped_frames, physical_pages);

        process.unmap_shared_memory(address, PAGE_SIZE * 2).unwrap();
        assert_eq!(shared_memory.arena().stats().free_frames, 3);
        assert_eq!(shared_memory.reclaim_idle().unwrap(), 3);
        process.retire().unwrap().reclaim(&mut allocator).unwrap();
    }

    #[test]
    fn adjacent_shared_mappings_keep_object_identity_scoped_bounds() {
        let (_region, mut allocator) = TestFrameRegion::allocator(96);
        let mut process = construct_test_process(&mut allocator).unwrap();
        let mut shared_memory = TestSharedMemoryContext::new(4);
        let first = shared_memory
            .factory()
            .create_handle(process.handles_mut(), PAGE_SIZE as usize)
            .unwrap();
        let second = shared_memory
            .factory()
            .create_handle(process.handles_mut(), PAGE_SIZE as usize)
            .unwrap();
        let first_identity = process
            .handles()
            .shared_memory_mapping_lease(first, SharedMemoryMappingAccess::ReadOnly)
            .unwrap()
            .info()
            .backing_identity;
        let second_identity = process
            .handles()
            .shared_memory_mapping_lease(second, SharedMemoryMappingAccess::ReadOnly)
            .unwrap()
            .info()
            .backing_identity;
        assert_ne!(first_identity, second_identity);

        let base = SHARED_MAPPING_BASE + PAGE_SIZE * 128;
        let protection = MapProtection::READ;
        for (handle, address) in [(first, base), (second, base + PAGE_SIZE)] {
            assert_eq!(
                process.map_shared_memory(
                    handle,
                    SharedMemoryMapArgs {
                        address,
                        offset: 0,
                        length: PAGE_SIZE,
                        protection,
                        flags: MapFlags::FIXED,
                    },
                    &mut allocator,
                ),
                Ok(address)
            );
        }

        let infos = [base, base + PAGE_SIZE].map(|address| process.virtual_query(address).unwrap());
        assert_eq!(infos[0].backing_identity, first_identity);
        assert_eq!(infos[1].backing_identity, second_identity);
        for (index, info) in infos.into_iter().enumerate() {
            let start = base + index as u64 * PAGE_SIZE;
            assert_eq!(info.start, start);
            assert_eq!(info.end, start + PAGE_SIZE);
            assert_eq!(info.area_kind(), Some(VirtualAreaKind::Shared));
        }
        assert_eq!(
            process
                .vmas()
                .iter()
                .filter(|area| matches!(area.kind, VmAreaKind::Shared { .. })
                    && base <= area.start
                    && area.end <= base + PAGE_SIZE * 2)
                .inspect(|area| assert!(matches!(
                    area.kind,
                    VmAreaKind::Shared {
                        object_offset: 0,
                        ..
                    }
                )))
                .count(),
            2
        );

        for address in [base, base + PAGE_SIZE] {
            process.unmap_shared_memory(address, PAGE_SIZE).unwrap();
        }
        process.handles_mut().handle_close(first).unwrap();
        process.handles_mut().handle_close(second).unwrap();
        assert_eq!(shared_memory.reclaim_idle().unwrap(), 2);
        process.retire().unwrap().reclaim(&mut allocator).unwrap();
    }

    #[test]
    fn anonymous_mapping_is_zero_filled_accounted_and_immediately_reclaimed() {
        let (_region, mut allocator) = TestFrameRegion::allocator(64);
        let mut process = construct_test_process(&mut allocator).unwrap();
        let baseline_frames = allocator.allocated_count();
        let baseline_private = process.usage().private_pages;
        let length = PAGE_SIZE * 2 + 1;

        let address = process
            .map_anonymous(
                length,
                MapProtection::READ | MapProtection::WRITE,
                &mut allocator,
            )
            .unwrap();
        assert_eq!(
            process
                .vmas()
                .iter()
                .filter(|vma| matches!(vma.kind, VmAreaKind::Anonymous { .. }))
                .count(),
            1
        );
        assert_eq!(process.usage().private_pages, baseline_private + 3);
        let mapped_frames = allocator.allocated_count();
        assert!(mapped_frames >= baseline_frames + 3);
        assert_eq!(
            process.address_space().validate_user_range(
                address,
                length as usize,
                UserAccess::Write
            ),
            Ok(())
        );
        process
            .protect_anonymous(address, length, MapProtection::READ)
            .unwrap();
        assert!(matches!(
            process.address_space().validate_user_range(
                address,
                length as usize,
                UserAccess::Write
            ),
            Err(AddressSpaceError::PermissionDenied { .. })
        ));
        assert_eq!(
            process.protect_anonymous(
                address,
                length,
                MapProtection::READ | MapProtection::WRITE | MapProtection::EXECUTE,
            ),
            Err(SharedMappingError::InvalidProtection(
                MapProtection::READ | MapProtection::WRITE | MapProtection::EXECUTE
            ))
        );

        process
            .unmap_anonymous(address, length, &mut allocator)
            .unwrap();
        assert!(!process
            .vmas()
            .iter()
            .any(|vma| matches!(vma.kind, VmAreaKind::Anonymous { .. })));
        assert_eq!(process.usage().private_pages, baseline_private);
        assert_eq!(allocator.allocated_count(), mapped_frames - 3);

        process.retire().unwrap().reclaim(&mut allocator).unwrap();
        assert_eq!(allocator.allocated_count(), 0);
    }

    #[test]
    fn anonymous_reserve_commit_decommit_protect_and_partial_unmap_are_semantic() {
        let (_region, mut allocator) = TestFrameRegion::allocator(96);
        let mut process = construct_test_process(&mut allocator).unwrap();
        let baseline_frames = allocator.allocated_count();
        let baseline_private = process.usage().private_pages;
        let address = process
            .reserve_anonymous(PAGE_SIZE * 4, MapProtection::READ | MapProtection::WRITE)
            .unwrap();

        assert_eq!(allocator.allocated_count(), baseline_frames);
        assert_eq!(process.usage().private_pages, baseline_private);
        assert!(matches!(
            process.address_space().validate_user_range(
                address,
                PAGE_SIZE as usize,
                UserAccess::Read
            ),
            Err(AddressSpaceError::NotMapped(_))
        ));
        assert!(process
            .vmas()
            .windows(2)
            .all(|pair| pair[0].end <= pair[1].start));
        let reserved = process.virtual_query(address).unwrap();
        assert_eq!(reserved.area_kind(), Some(VirtualAreaKind::Anonymous));
        assert_eq!(reserved.committed_pages, 0);
        assert_eq!(reserved.reserved_pages, 4);

        process
            .commit_anonymous(address + PAGE_SIZE, PAGE_SIZE * 2, &mut allocator)
            .unwrap();
        assert_eq!(process.usage().private_pages, baseline_private + 2);
        let committed = process.virtual_query(address + PAGE_SIZE).unwrap();
        assert_eq!(committed.start, address + PAGE_SIZE);
        assert_eq!(committed.end, address + PAGE_SIZE * 3);
        assert_eq!(committed.committed_pages, 2);
        process
            .protect_anonymous(
                address,
                PAGE_SIZE * 3,
                MapProtection::READ | MapProtection::EXECUTE,
            )
            .unwrap();
        assert_eq!(
            process.address_space().validate_user_range(
                address + PAGE_SIZE,
                PAGE_SIZE as usize,
                UserAccess::Execute,
            ),
            Ok(())
        );
        process
            .decommit_anonymous(address + PAGE_SIZE * 2, PAGE_SIZE, &mut allocator)
            .unwrap();
        assert_eq!(process.usage().private_pages, baseline_private + 1);
        let left = process.virtual_query(address + PAGE_SIZE).unwrap();
        let decommitted = process.virtual_query(address + PAGE_SIZE * 2).unwrap();
        assert_eq!(left.committed_pages, 1);
        assert_eq!(decommitted.committed_pages, 0);
        assert_eq!(decommitted.reserved_pages, 1);
        assert_eq!(left.backing_identity, decommitted.backing_identity);
        assert!(matches!(
            process.address_space().validate_user_range(
                address + PAGE_SIZE * 2,
                PAGE_SIZE as usize,
                UserAccess::Read,
            ),
            Err(AddressSpaceError::NotMapped(_))
        ));
        process
            .commit_anonymous(address + PAGE_SIZE * 3, PAGE_SIZE, &mut allocator)
            .unwrap();
        process
            .protect_anonymous(address, PAGE_SIZE * 4, MapProtection::READ)
            .unwrap();

        process
            .unmap_anonymous(address, PAGE_SIZE * 3, &mut allocator)
            .unwrap();
        assert_eq!(process.usage().private_pages, baseline_private + 1);
        assert!(process.vmas().iter().any(|vma| {
            vma.start == address + PAGE_SIZE * 3
                && vma.end == address + PAGE_SIZE * 4
                && matches!(
                    vma.kind,
                    VmAreaKind::Anonymous {
                        committed: true,
                        ..
                    }
                )
        }));
        process
            .unmap_anonymous(address + PAGE_SIZE * 3, PAGE_SIZE, &mut allocator)
            .unwrap();
        process.retire().unwrap().reclaim(&mut allocator).unwrap();
        assert_eq!(allocator.allocated_count(), 0);
    }

    #[test]
    fn decommit_and_partial_unmap_cannot_bypass_vma_limit() {
        let (_region, mut allocator) = TestFrameRegion::allocator(96);
        let mut process = construct_test_process(&mut allocator).unwrap();
        let address = process
            .reserve_anonymous(PAGE_SIZE * 4, MapProtection::READ | MapProtection::WRITE)
            .unwrap();
        process
            .commit_anonymous(address, PAGE_SIZE * 4, &mut allocator)
            .unwrap();

        let original_vmas = process.vmas().to_vec();
        let original_usage = process.usage();
        let original_frames = allocator.allocated_count();
        process.limits.vma_count = original_vmas.len() as u64 + 1;
        assert_eq!(
            process.decommit_anonymous(address + PAGE_SIZE, PAGE_SIZE, &mut allocator),
            Err(SharedMappingError::ResourceLimit)
        );
        assert_eq!(process.vmas(), original_vmas);
        assert_eq!(process.usage().private_pages, original_usage.private_pages);
        assert_eq!(allocator.allocated_count(), original_frames);
        assert_eq!(
            process.address_space().validate_user_range(
                address + PAGE_SIZE,
                PAGE_SIZE as usize,
                UserAccess::Write,
            ),
            Ok(())
        );

        process.limits.vma_count = original_vmas.len() as u64;
        assert_eq!(
            process.unmap_anonymous(address + PAGE_SIZE, PAGE_SIZE, &mut allocator),
            Err(SharedMappingError::ResourceLimit)
        );
        assert_eq!(process.vmas(), original_vmas);
        assert_eq!(process.usage().private_pages, original_usage.private_pages);
        assert_eq!(allocator.allocated_count(), original_frames);
        assert_eq!(
            process.usage().quota_failures,
            original_usage.quota_failures + 2
        );

        process.limits = ProcessLimits::STANDARD;
        process
            .unmap_anonymous(address, PAGE_SIZE * 4, &mut allocator)
            .unwrap();
        process.retire().unwrap().reclaim(&mut allocator).unwrap();
    }

    #[test]
    fn failed_anonymous_commit_preserves_reservation_quota_and_page_tables() {
        let (_region, mut allocator) = TestFrameRegion::allocator(64);
        let mut process = construct_test_process(&mut allocator).unwrap();
        let baseline_private = process.usage().private_pages;
        let address = process
            .reserve_anonymous(PAGE_SIZE * 2, MapProtection::READ | MapProtection::WRITE)
            .unwrap();
        let mut held = Vec::new();
        while let Some(frame) = allocator.allocate_frame().unwrap() {
            held.push(frame);
        }
        let exhausted_count = allocator.allocated_count();

        assert!(process
            .commit_anonymous(address, PAGE_SIZE * 2, &mut allocator)
            .is_err());
        assert_eq!(allocator.allocated_count(), exhausted_count);
        assert_eq!(process.usage().private_pages, baseline_private);
        assert!(process.vmas().iter().any(|vma| {
            vma.start == address
                && vma.end == address + PAGE_SIZE * 2
                && matches!(
                    vma.kind,
                    VmAreaKind::Anonymous {
                        committed: false,
                        ..
                    }
                )
        }));
        assert!(matches!(
            process.address_space().validate_user_range(
                address,
                PAGE_SIZE as usize,
                UserAccess::Read
            ),
            Err(AddressSpaceError::NotMapped(_))
        ));

        allocator.reclaim_frames(&held).unwrap();
        process
            .commit_anonymous(address, PAGE_SIZE * 2, &mut allocator)
            .unwrap();
        process
            .unmap_anonymous(address, PAGE_SIZE * 2, &mut allocator)
            .unwrap();
        process.retire().unwrap().reclaim(&mut allocator).unwrap();
        assert_eq!(allocator.allocated_count(), 0);
    }

    #[test]
    fn decommit_is_idempotent_and_charges_only_committed_pages_in_mixed_range() {
        let (_region, mut allocator) = TestFrameRegion::allocator(96);
        let mut process = construct_test_process(&mut allocator).unwrap();
        let baseline_private = process.usage().private_pages;
        let address = process
            .reserve_anonymous(PAGE_SIZE * 4, MapProtection::READ | MapProtection::WRITE)
            .unwrap();
        process
            .commit_anonymous(address + PAGE_SIZE, PAGE_SIZE * 2, &mut allocator)
            .unwrap();
        assert_eq!(process.usage().private_pages, baseline_private + 2);

        process
            .decommit_anonymous(address, PAGE_SIZE * 4, &mut allocator)
            .unwrap();
        assert_eq!(process.usage().private_pages, baseline_private);
        process
            .decommit_anonymous(address, PAGE_SIZE * 4, &mut allocator)
            .unwrap();
        assert_eq!(process.usage().private_pages, baseline_private);
        assert_eq!(
            process
                .vmas()
                .iter()
                .filter(|vma| matches!(vma.kind, VmAreaKind::Anonymous { .. }))
                .count(),
            1
        );

        process
            .unmap_anonymous(address, PAGE_SIZE * 4, &mut allocator)
            .unwrap();
        process.retire().unwrap().reclaim(&mut allocator).unwrap();
        assert_eq!(allocator.allocated_count(), 0);
    }

    #[test]
    fn anonymous_reservation_rollback_restores_cursor_and_failed_map_leaves_no_vma() {
        let (_region, mut allocator) = TestFrameRegion::allocator(64);
        let mut process = construct_test_process(&mut allocator).unwrap();
        let original_cursor = process.next_mapping_cursor();
        let (_, rollback) = process
            .reserve_anonymous_with_rollback(PAGE_SIZE, MapProtection::READ)
            .unwrap();
        let rolled_back_id = rollback.reservation_id;
        assert_ne!(process.next_mapping_cursor(), original_cursor);
        process.rollback_anonymous_reservation(rollback);
        assert_eq!(process.next_mapping_cursor(), original_cursor);
        let (_, next_rollback) = process
            .reserve_anonymous_with_rollback(PAGE_SIZE, MapProtection::READ)
            .unwrap();
        assert!(next_rollback.reservation_id > rolled_back_id);
        process.rollback_anonymous_reservation(next_rollback);
        assert_eq!(process.next_mapping_cursor(), original_cursor);
        assert!(!process
            .vmas()
            .iter()
            .any(|vma| matches!(vma.kind, VmAreaKind::Anonymous { .. })));

        let mut held = Vec::new();
        while let Some(frame) = allocator.allocate_frame().unwrap() {
            held.push(frame);
        }
        assert!(process
            .map_anonymous(PAGE_SIZE, MapProtection::READ, &mut allocator)
            .is_err());
        assert_eq!(process.next_mapping_cursor(), original_cursor);
        assert!(!process
            .vmas()
            .iter()
            .any(|vma| matches!(vma.kind, VmAreaKind::Anonymous { .. })));

        allocator.reclaim_frames(&held).unwrap();
        process.retire().unwrap().reclaim(&mut allocator).unwrap();
        assert_eq!(allocator.allocated_count(), 0);
    }

    #[test]
    fn reservation_identity_prevents_merge_and_teardown_counts_unique_ids() {
        let (_region, mut allocator) = TestFrameRegion::allocator(64);
        let mut process = construct_test_process(&mut allocator).unwrap();
        let first = process
            .reserve_anonymous(PAGE_SIZE * 3, MapProtection::READ)
            .unwrap();
        process
            .protect_anonymous(
                first + PAGE_SIZE,
                PAGE_SIZE,
                MapProtection::READ | MapProtection::WRITE,
            )
            .unwrap();
        let second = process
            .reserve_anonymous(PAGE_SIZE, MapProtection::READ)
            .unwrap();
        assert_eq!(second, first + PAGE_SIZE * 3);
        assert_eq!(count_anonymous_reservations(process.vmas()), 2);
        let ids = process
            .vmas()
            .iter()
            .filter_map(|vma| match vma.kind {
                VmAreaKind::Anonymous { reservation_id, .. } => Some(reservation_id),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(ids.windows(2).any(|pair| pair[0] != pair[1]));

        let reclaimed = process.retire().unwrap().reclaim(&mut allocator).unwrap();
        assert_eq!(reclaimed.teardown.anonymous_mappings_released, 2);
        assert_eq!(allocator.allocated_count(), 0);
    }

    #[test]
    fn vm_rollback_fail_stop_is_terminal_and_uses_stable_internal_fault() {
        let (_region, mut allocator) = TestFrameRegion::allocator(64);
        let mut process = construct_test_process(&mut allocator).unwrap();
        process.fail_stop_vm_rollback(0x1234_5000);

        assert_eq!(
            process.state(),
            ProcessState::Faulted(ProcessFault::at_address(
                ProcessFaultReason::Other(VM_ROLLBACK_FAILURE_REASON),
                VM_ROLLBACK_FAILURE_CODE,
                0x1234_5000,
            ))
        );
        assert!(process.state().is_terminal());
        assert!(!process.is_runnable());
        process.retire().unwrap().reclaim(&mut allocator).unwrap();
    }

    #[test]
    fn vma_split_limit_failure_leaves_the_sorted_source_unchanged() {
        let mut vmas = Vec::new();
        vmas.push(VmArea {
            start: 0x10_0000,
            end: 0x10_0000 + PAGE_SIZE * 3,
            kind: VmAreaKind::Anonymous {
                reservation_id: 1,
                committed: false,
            },
            protection: MapProtection::READ,
        });
        for index in 1..MAX_VMAS {
            let start = 0x20_0000 + index as u64 * PAGE_SIZE * 2;
            vmas.push(VmArea {
                start,
                end: start + PAGE_SIZE,
                kind: VmAreaKind::Image,
                protection: MapProtection::READ,
            });
        }
        let original = vmas.clone();

        assert_eq!(
            plan_anonymous_change(
                &vmas,
                0x10_0000 + PAGE_SIZE,
                0x10_0000 + PAGE_SIZE * 2,
                AnonymousChange::Protect(MapProtection::READ | MapProtection::WRITE),
            ),
            Err(SharedMappingError::ResourceLimit)
        );
        assert_eq!(vmas, original);
        assert!(vmas.windows(2).all(|pair| pair[0].end <= pair[1].start));
    }

    #[test]
    fn exhausted_allocator_recovers_after_constructor_and_external_reclamation() {
        let (_region, mut allocator) = TestFrameRegion::allocator(40);
        let mut held = Vec::new();
        for _ in 0..30 {
            held.push(allocator.allocate_frame().unwrap().unwrap());
        }
        let baseline = allocator.allocated_count();

        assert!(matches!(
            construct_test_process(&mut allocator),
            Err(ProcessCreateError::StackPage { .. })
        ));
        assert_eq!(allocator.allocated_count(), baseline);

        allocator.reclaim_frames(&held).unwrap();
        let process =
            construct_test_process(&mut allocator).expect("reclaimed frames are reusable");
        let retired = process
            .retire()
            .expect("host test address space is inactive");
        retired
            .reclaim(&mut allocator)
            .expect("process reclamation");
        assert_eq!(allocator.allocated_count(), 0);
    }

    #[test]
    #[should_panic(expected = "failed process construction cleanup invariant")]
    fn construction_cleanup_invariant_failure_is_fail_stop() {
        let (_region, mut allocator) = TestFrameRegion::allocator(1);
        let address_space = AddressSpace::new_for_test(&mut allocator).unwrap();
        allocator.reserve_frame(address_space.root_frame()).unwrap();

        let _ = reclaim_failed_construction(
            address_space,
            &mut allocator,
            ProcessCreateError::ResourceLimit,
        );
    }

    #[test]
    fn low_memory_process_reserves_only_its_vma_limit() {
        let (_region, mut allocator) = TestFrameRegion::allocator(64);
        let limits = ProcessLimits::from_available_memory_bytes(32 * MIB);
        let process = construct_test_process_with_limits(&mut allocator, limits).unwrap();
        let capacity = process.vmas.as_ref().unwrap().capacity();

        assert!(capacity >= limits.vma_count as usize);
        assert!(capacity < MAX_VMAS);
        process.retire().unwrap().reclaim(&mut allocator).unwrap();
    }

    #[test]
    fn process_creation_metadata_oom_reclaims_partial_ownership() {
        let (_region, mut allocator) = TestFrameRegion::allocator(64);
        allocator.fail_ownership_reservation_after_for_test(1);

        assert!(matches!(
            construct_test_process(&mut allocator),
            Err(ProcessCreateError::ElfPage(
                ElfPageLoadError::AddressSpace {
                    error: AddressSpaceError::FrameAllocator(
                        crate::memory::FrameAllocatorError::OwnershipTrackingAllocationFailed
                    ),
                    ..
                }
            ))
        ));
        assert_eq!(allocator.allocated_count(), 0);
        assert_eq!(allocator.free_count(), 1);
    }

    #[test]
    fn anonymous_commit_metadata_oom_is_atomic() {
        let (_region, mut allocator) = TestFrameRegion::allocator(64);
        let mut process = construct_test_process(&mut allocator).unwrap();
        let address = process
            .reserve_anonymous(PAGE_SIZE, MapProtection::READ | MapProtection::WRITE)
            .unwrap();
        let vmas_before = process.vmas().to_vec();
        let usage_before = process.usage();
        let accounting_before = process.address_space().accounting();
        let allocated_before = allocator.allocated_count();
        process
            .address_space_mut()
            .fail_next_metadata_reservation_for_test();

        assert_eq!(
            process.commit_anonymous(address, PAGE_SIZE, &mut allocator),
            Err(SharedMappingError::OutOfMemory),
        );
        assert_eq!(process.vmas(), vmas_before);
        assert_eq!(process.address_space().accounting(), accounting_before);
        assert_eq!(allocator.allocated_count(), allocated_before);
        assert_eq!(process.usage().private_pages, usage_before.private_pages);
        assert_eq!(
            process.usage().reserved_virtual_bytes,
            usage_before.reserved_virtual_bytes
        );
        process.retire().unwrap().reclaim(&mut allocator).unwrap();
    }

    #[test]
    fn shared_map_metadata_oom_is_atomic() {
        let (_region, mut allocator) = TestFrameRegion::allocator(80);
        let mut process = construct_test_process(&mut allocator).unwrap();
        let mut shared_memory = TestSharedMemoryContext::new(2);
        let handle = shared_memory
            .factory()
            .create_handle(process.handles_mut(), PAGE_SIZE as usize)
            .unwrap();
        let vmas_before = process.vmas().to_vec();
        let usage_before = process.usage();
        let accounting_before = process.address_space().accounting();
        let allocated_before = allocator.allocated_count();
        let shared_before = shared_memory.arena().stats();
        process
            .address_space_mut()
            .fail_next_metadata_reservation_for_test();

        assert_eq!(
            process.map_shared_memory(
                handle,
                SharedMemoryMapArgs {
                    address: 0,
                    offset: 0,
                    length: PAGE_SIZE,
                    protection: MapProtection::READ,
                    flags: MapFlags::empty(),
                },
                &mut allocator,
            ),
            Err(SharedMappingError::OutOfMemory),
        );
        assert_eq!(process.vmas(), vmas_before);
        assert_eq!(process.address_space().accounting(), accounting_before);
        assert_eq!(allocator.allocated_count(), allocated_before);
        assert_eq!(shared_memory.arena().stats(), shared_before);
        let usage_after = process.usage();
        assert_eq!(usage_after.oom_failures, usage_before.oom_failures + 1);
        assert_eq!(
            ProcessUsage {
                oom_failures: usage_before.oom_failures,
                ..usage_after
            },
            usage_before,
        );
        assert!(process.shared_mappings().is_empty());
        process.handles_mut().handle_close(handle).unwrap();
        assert_eq!(shared_memory.reclaim_idle().unwrap(), 1);
        process.retire().unwrap().reclaim(&mut allocator).unwrap();
    }

    #[test]
    fn anonymous_unmap_metadata_oom_is_atomic() {
        let (_region, mut allocator) = TestFrameRegion::allocator(64);
        let mut process = construct_test_process(&mut allocator).unwrap();
        let address = process
            .map_anonymous(
                PAGE_SIZE,
                MapProtection::READ | MapProtection::WRITE,
                &mut allocator,
            )
            .unwrap();
        let vmas_before = process.vmas().to_vec();
        let usage_before = process.usage();
        let accounting_before = process.address_space().accounting();
        let allocated_before = allocator.allocated_count();
        process
            .address_space_mut()
            .fail_next_metadata_reservation_for_test();

        assert_eq!(
            process.unmap_anonymous(address, PAGE_SIZE, &mut allocator),
            Err(SharedMappingError::AddressSpace(
                AddressSpaceError::OutOfMemory
            )),
        );
        assert_eq!(process.vmas(), vmas_before);
        assert_eq!(process.address_space().accounting(), accounting_before);
        assert_eq!(process.usage(), usage_before);
        assert_eq!(allocator.allocated_count(), allocated_before);
        assert!(process
            .address_space()
            .validate_user_range(address, 1, UserAccess::Write)
            .is_ok());
        process.retire().unwrap().reclaim(&mut allocator).unwrap();
    }

    #[test]
    fn unretired_resource_retention_suppresses_destructors() {
        let drops = AtomicUsize::new(0);
        let mut retained = Some(DropProbe(&drops));
        retain_unretired_resource(&mut retained);
        assert!(retained.is_none());
        assert_eq!(drops.load(Ordering::Relaxed), 0);

        drop(DropProbe(&drops));
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }

    fn pending_wait(deadline: WaitDeadline) -> PendingWaitMany {
        PendingWaitMany {
            items: Vec::new(),
            encoded_items: Vec::new(),
            items_address: 0x1000,
            output_address: 0x2000,
            deadline,
            completion: None,
            registration: None,
        }
    }

    struct RequestObserver(AtomicUsize);

    impl SignalObserver for RequestObserver {
        fn notify(&self, _token: WaitToken) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn pending_request(
        process: &mut Process,
        allocator: &mut UsableFrameAllocator<'_>,
        id: RequestId,
    ) -> (PendingRequest, RequestControl) {
        let output_address = process
            .map_anonymous(
                PAGE_SIZE,
                MapProtection::READ | MapProtection::WRITE,
                allocator,
            )
            .unwrap();
        let output_pages = process
            .address_space_mut()
            .pin_user_range(
                output_address,
                mem::size_of::<RequestSubmitOutput>(),
                UserAccess::Write,
            )
            .unwrap();
        let control = RequestControl::new(
            id.raw(),
            RequestInfo {
                state: RequestState::Pending as u32,
                ..RequestInfo::default()
            },
        )
        .unwrap();
        let hidden_handle = process.handles_mut().request_install(&control).unwrap();
        (
            PendingRequest {
                id,
                output: Some(PendingRequestOutput {
                    address: output_address,
                    pages: output_pages,
                }),
                count_output: None,
                hidden_handle,
                completion: None,
                return_operation_status: false,
                registration: None,
            },
            control,
        )
    }

    fn outputless_pending_request(
        process: &mut Process,
        id: RequestId,
    ) -> (PendingRequest, RequestControl) {
        let control = RequestControl::new(
            id.raw(),
            RequestInfo {
                state: RequestState::Pending as u32,
                ..RequestInfo::default()
            },
        )
        .unwrap();
        let hidden_handle = process.handles_mut().request_install(&control).unwrap();
        (
            PendingRequest {
                id,
                output: None,
                count_output: None,
                hidden_handle,
                completion: None,
                return_operation_status: true,
                registration: None,
            },
            control,
        )
    }

    #[test]
    fn request_block_stage_take_and_finish_preserve_completion_resources() {
        let (_region, mut allocator) = TestFrameRegion::allocator(96);
        let mut process = construct_test_process(&mut allocator).unwrap();
        let thread_id = process.main_thread_id();
        let id = RequestId::from_raw(0x0000_0001_0000_0001);
        let other_id = RequestId::from_raw(0x0000_0001_0000_0002);
        let (pending, _control) = pending_request(&mut process, &mut allocator, id);
        let hidden_handle = pending.hidden_handle;
        let output_address = pending.output.as_ref().unwrap().address;

        process.block_thread_request(thread_id, pending);
        assert_eq!(process.blocked_request_id(thread_id), Some(id));
        assert_eq!(process.blocked_kind(thread_id), Some(BlockedKind::Request));
        assert!(matches!(
            process.take_completed_request(thread_id),
            Err(Status::ShouldWait)
        ));

        let output = RequestSubmitOutput {
            request: Handle::from_raw(77),
            state: RequestState::Completed as u32,
            result: Status::Ok as i32,
            result_flags: 3,
            bytes_transferred: 41,
        };
        assert!(!process.stage_request_completion(thread_id, other_id, output));
        assert!(process.stage_request_completion(thread_id, id, output));
        assert!(!process.stage_request_completion(thread_id, id, output));

        let completed = process.take_completed_request(thread_id).unwrap();
        assert_eq!(completed.id, id);
        let completed_output = completed.output.as_ref().unwrap();
        assert_eq!(completed_output.address, output_address);
        assert_eq!(completed.completion, Some(output));
        assert!(!completed.return_operation_status);
        process
            .address_space_mut()
            .unpin_user_pages(&completed_output.pages)
            .unwrap();
        process.handles_mut().handle_close(hidden_handle).unwrap();
        process.finish_request(thread_id).unwrap();
        assert_eq!(process.thread_state(thread_id), Some(ThreadState::Ready));

        process.mark_exited(0);
        process.retire().unwrap().reclaim(&mut allocator).unwrap();
    }

    #[test]
    fn outputless_request_cancellation_closes_handle_without_releasing_other_pins() {
        let (_region, mut allocator) = TestFrameRegion::allocator(96);
        let mut process = construct_test_process(&mut allocator).unwrap();
        let thread_id = process.main_thread_id();
        let unrelated_address = process
            .map_anonymous(
                PAGE_SIZE,
                MapProtection::READ | MapProtection::WRITE,
                &mut allocator,
            )
            .unwrap();
        let unrelated_pages = process
            .address_space_mut()
            .pin_user_range(unrelated_address, 1, UserAccess::Write)
            .unwrap();
        let id = RequestId::from_raw(0x0000_0005_0000_0001);
        let (pending, _control) = outputless_pending_request(&mut process, id);
        let hidden_handle = pending.hidden_handle;
        assert!(pending.output.is_none());
        assert!(pending.return_operation_status);
        process.block_thread_request(thread_id, pending);

        process.cancel_blocked_syscall(thread_id);
        assert_eq!(process.address_space().pinned_page_references(), 1);
        assert_eq!(
            process.handles().handle_rights(hidden_handle),
            Err(IpcError::InvalidHandle)
        );
        process
            .address_space_mut()
            .unpin_user_pages(&unrelated_pages)
            .unwrap();

        process.mark_exited(0);
        process.retire().unwrap().reclaim(&mut allocator).unwrap();
    }

    #[test]
    fn blocked_request_registers_hidden_signaled_handle() {
        let (_region, mut allocator) = TestFrameRegion::allocator(96);
        let mut process = construct_test_process(&mut allocator).unwrap();
        let thread_id = process.main_thread_id();
        let id = RequestId::from_raw(0x0000_0002_0000_0001);
        let (pending, control) = pending_request(&mut process, &mut allocator, id);
        process.block_thread_request(thread_id, pending);

        let token = WaitToken::from_raw(9).unwrap();
        let observer = Arc::new(RequestObserver(AtomicUsize::new(0)));
        let sink: Arc<dyn SignalObserver> = observer.clone();
        process
            .install_blocked_wait_registration(thread_id, token, &sink)
            .unwrap();
        assert_eq!(
            process.blocked_wait_spec(thread_id),
            Some((BlockedKind::Request, None, Some(token)))
        );

        assert!(control.publish_terminal(RequestInfo {
            state: RequestState::Completed as u32,
            ..RequestInfo::default()
        }));
        assert_eq!(observer.0.load(Ordering::Relaxed), 1);
        assert!(process.clear_blocked_wait_registration(thread_id, token));
        assert_eq!(
            process.blocked_wait_spec(thread_id),
            Some((BlockedKind::Request, None, None))
        );

        process.mark_exited(0);
        process.retire().unwrap().reclaim(&mut allocator).unwrap();
    }

    #[test]
    fn blocked_request_cancellation_unpins_output_and_closes_hidden_handle_once() {
        let (_region, mut allocator) = TestFrameRegion::allocator(96);
        let mut process = construct_test_process(&mut allocator).unwrap();
        let thread_id = process.main_thread_id();
        let id = RequestId::from_raw(0x0000_0003_0000_0001);
        let (pending, _control) = pending_request(&mut process, &mut allocator, id);
        let hidden_handle = pending.hidden_handle;
        assert_eq!(process.address_space().pinned_page_references(), 1);
        assert!(process.handles().handle_rights(hidden_handle).is_ok());
        process.block_thread_request(thread_id, pending);

        process.cancel_blocked_syscall(thread_id);
        assert_eq!(process.address_space().pinned_page_references(), 0);
        assert_eq!(
            process.handles().handle_rights(hidden_handle),
            Err(IpcError::InvalidHandle)
        );
        assert!(process.thread(thread_id).unwrap().blocked_syscall.is_none());
        process.cancel_blocked_syscall(thread_id);
        assert_eq!(process.address_space().pinned_page_references(), 0);

        process.mark_exited(0);
        process.retire().unwrap().reclaim(&mut allocator).unwrap();
    }

    #[test]
    fn blocked_request_cancellation_unpins_count_output_once_alongside_output() {
        let (_region, mut allocator) = TestFrameRegion::allocator(128);
        let mut process = construct_test_process(&mut allocator).unwrap();
        let thread_id = process.main_thread_id();
        let id = RequestId::from_raw(0x0000_0006_0000_0001);
        let (mut pending, _control) = pending_request(&mut process, &mut allocator, id);
        let count_address = process
            .map_anonymous(
                PAGE_SIZE,
                MapProtection::READ | MapProtection::WRITE,
                &mut allocator,
            )
            .unwrap();
        let count_pages = process
            .address_space_mut()
            .pin_user_range(count_address, mem::size_of::<u64>(), UserAccess::Write)
            .unwrap();
        pending.count_output = Some(PendingRequestCountOutput {
            address: count_address,
            pages: count_pages,
        });
        assert_eq!(
            pending.count_output.as_ref().unwrap().address,
            count_address
        );
        assert_eq!(process.address_space().pinned_page_references(), 2);
        process.block_thread_request(thread_id, pending);

        process.cancel_blocked_syscall(thread_id);
        assert_eq!(process.address_space().pinned_page_references(), 0);
        process.cancel_blocked_syscall(thread_id);
        assert_eq!(process.address_space().pinned_page_references(), 0);

        process.mark_exited(0);
        process.retire().unwrap().reclaim(&mut allocator).unwrap();
    }

    #[test]
    fn process_teardown_releases_blocked_request_resources_before_retirement() {
        let (_region, mut allocator) = TestFrameRegion::allocator(96);
        let mut process = construct_test_process(&mut allocator).unwrap();
        let thread_id = process.main_thread_id();
        let id = RequestId::from_raw(0x0000_0004_0000_0001);
        let (pending, _control) = pending_request(&mut process, &mut allocator, id);
        let hidden_handle = pending.hidden_handle;
        process.block_thread_request(thread_id, pending);

        process.mark_exited(7);
        assert_eq!(process.address_space().pinned_page_references(), 0);
        assert_eq!(
            process.handles().handle_rights(hidden_handle),
            Err(IpcError::InvalidHandle)
        );
        assert!(process.thread(thread_id).unwrap().blocked_syscall.is_none());
        let reclaimed = process.retire().unwrap().reclaim(&mut allocator).unwrap();
        assert_eq!(reclaimed.teardown.handles_closed, 0);
    }

    #[test]
    fn process_ids_reject_stale_generations() {
        let mut table = GenerationalSlots::new();
        let first = table.insert(10).unwrap();
        assert_eq!(table.get(first), Some(&10));
        assert_eq!(table.remove(first), Some(10));
        assert_eq!(table.get(first), None);
        assert_eq!(table.get_mut(first), None);
        assert_eq!(table.remove(first), None);

        let second = table.insert(20).unwrap();
        assert_eq!(first.slot(), second.slot());
        assert_ne!(first.generation(), second.generation());
        assert_eq!(table.get(second), Some(&20));
    }

    #[test]
    fn generation_wrap_retires_a_slot_permanently() {
        let mut table = GenerationalSlots {
            slots: alloc::vec![ProcessSlot {
                generation: u32::MAX,
                value: Some(7),
            }],
            next_slot: 0,
            len: 1,
        };
        let final_id = ProcessId::from_parts(0, u32::MAX);
        assert_eq!(table.remove(final_id), Some(7));
        assert_eq!(table.slots[0].generation, 0);

        let replacement = table.insert(8).unwrap();
        assert_eq!(replacement.slot(), 1);
        assert_eq!(table.get(final_id), None);
        assert_eq!(table.get(replacement), Some(&8));
        assert_eq!(table.next_id(), Some(replacement));
        assert_eq!(table.next_id(), Some(replacement));
    }

    #[test]
    fn invalid_process_ids_never_resolve() {
        let mut table = GenerationalSlots::new();
        let id = table.insert(()).unwrap();
        assert_eq!(table.get(ProcessId::INVALID), None);
        assert_eq!(table.get(ProcessId::from_raw(id.slot() as u64)), None);
        assert_eq!(table.get(ProcessId::from_raw(u64::MAX)), None);
    }

    #[test]
    fn real_threads_have_independent_contexts_stacks_and_round_robin_selection() {
        let (_region, mut allocator) = TestFrameRegion::allocator(512);
        let mut process = construct_test_process(&mut allocator).unwrap();
        let entry = process.context().rip;
        let first = process
            .create_thread(entry, 11, USER_STACK_INITIAL_SIZE, 0x4000, &mut allocator)
            .unwrap();
        let second = process
            .create_thread(entry, 22, USER_STACK_INITIAL_SIZE, 0x8000, &mut allocator)
            .unwrap();

        assert_ne!(first, second);
        assert_ne!(
            process.thread(first).unwrap().layout,
            process.thread(second).unwrap().layout
        );
        assert_eq!(process.thread_context(first).unwrap().rdi, 11);
        assert_eq!(process.thread_context(second).unwrap().rdi, 22);
        assert_eq!(process.thread_context(first).unwrap().fs_base, 0x4000);
        assert_eq!(process.thread_context(second).unwrap().fs_base, 0x8000);
        assert_ne!(
            process.thread_entry_stack_tops(first),
            process.thread_entry_stack_tops(second)
        );

        let selected = [
            process.next_schedulable_thread().unwrap(),
            process.next_schedulable_thread().unwrap(),
            process.next_schedulable_thread().unwrap(),
        ];
        assert!(selected.contains(&process.main_thread_id()));
        assert!(selected.contains(&first));
        assert!(selected.contains(&second));
    }

    #[test]
    fn fatal_sibling_fault_terminates_the_complete_process() {
        let (_region, mut allocator) = TestFrameRegion::allocator(384);
        let mut process = construct_test_process(&mut allocator).unwrap();
        let main = process.main_thread_id();
        let sibling = process
            .create_thread(
                process.context().rip,
                0,
                USER_STACK_INITIAL_SIZE,
                0,
                &mut allocator,
            )
            .unwrap();
        let fault = ProcessFault::new(ProcessFaultReason::InvalidOpcode, 6);
        process.fault_process(sibling, fault);
        assert_eq!(process.state(), ProcessState::Faulted(fault));
        assert_eq!(
            process.thread_state(sibling),
            Some(ThreadState::Faulted(fault))
        );
        assert_eq!(process.thread_state(main), Some(ThreadState::Terminated));
    }

    #[test]
    fn reaping_reuses_stack_space_and_invalidates_stale_thread_id() {
        let (_region, mut allocator) = TestFrameRegion::allocator(384);
        let mut process = construct_test_process(&mut allocator).unwrap();
        let entry = process.context().rip;
        let first = process
            .create_thread(entry, 0, USER_STACK_INITIAL_SIZE, 0, &mut allocator)
            .unwrap();
        let first_layout = process.thread(first).unwrap().layout;
        assert!(!process.exit_thread(first, 0));
        process.reap_thread(first, &mut allocator).unwrap();
        assert!(process.thread(first).is_none());

        let replacement = process
            .create_thread(entry, 0, USER_STACK_INITIAL_SIZE, 0, &mut allocator)
            .unwrap();
        assert_eq!(replacement.slot(), first.slot());
        assert_ne!(replacement.generation(), first.generation());
        assert_eq!(process.thread(replacement).unwrap().layout, first_layout);
    }

    #[test]
    fn sleep_wake_and_last_thread_exit_are_thread_scoped() {
        let (_region, mut allocator) = TestFrameRegion::allocator(384);
        let mut process = construct_test_process(&mut allocator).unwrap();
        let main = process.main_thread_id();
        let sibling = process
            .create_thread(
                process.context().rip,
                0,
                USER_STACK_INITIAL_SIZE,
                0,
                &mut allocator,
            )
            .unwrap();

        assert!(process.sleep_thread(sibling, 100, 10).unwrap());
        assert_eq!(process.thread_state(sibling), Some(ThreadState::Blocked));
        process.wake_thread(sibling).unwrap();
        assert_eq!(process.thread_state(sibling), Some(ThreadState::Ready));

        assert!(!process.exit_thread(main, 3));
        assert_eq!(process.state(), ProcessState::Ready);
        assert_eq!(process.thread_state(main), Some(ThreadState::Exited(3)));
        assert!(process.exit_thread(sibling, 7));
        assert_eq!(process.state(), ProcessState::Exited(7));
    }

    #[test]
    fn terminating_joiner_releases_target_claim() {
        let (_region, mut allocator) = TestFrameRegion::allocator(384);
        let mut process = construct_test_process(&mut allocator).unwrap();
        let caller = process.main_thread_id();
        let target = process
            .create_thread(
                process.context().rip,
                0,
                USER_STACK_INITIAL_SIZE,
                0,
                &mut allocator,
            )
            .unwrap();
        assert!(process
            .start_join(caller, target, WaitDeadline::Infinite, 0x1000, 0)
            .unwrap());
        assert_eq!(
            process.thread(target).unwrap().join_claimed_by,
            Some(caller)
        );
        assert!(!process.terminate_thread(caller).unwrap());
        assert_eq!(process.thread(target).unwrap().join_claimed_by, None);
    }

    #[test]
    fn reaped_main_thread_does_not_break_final_retirement() {
        let (_region, mut allocator) = TestFrameRegion::allocator(384);
        let mut process = construct_test_process(&mut allocator).unwrap();
        let main = process.main_thread_id();
        let sibling = process
            .create_thread(
                process.context().rip,
                0,
                USER_STACK_INITIAL_SIZE,
                0,
                &mut allocator,
            )
            .unwrap();
        assert!(!process.exit_thread(main, 1));
        process.reap_thread(main, &mut allocator).unwrap();
        assert!(process.thread(main).is_none());
        assert!(process.exit_thread(sibling, 2));
        let retired = process.retire().unwrap();
        assert_eq!(retired.final_state(), ProcessState::Exited(2));
        retired.reclaim(&mut allocator).unwrap();
    }

    #[test]
    fn wake_before_sleep_banks_one_permit() {
        let mut process = test_process(ProcessState::Ready);
        let main = process.main_thread_id();
        process.wake_thread(main).unwrap();
        assert!(!process.sleep_thread(main, 100, 0).unwrap());
        assert!(process.sleep_thread(main, 100, 0).unwrap());
        assert_eq!(process.thread_state(main), Some(ThreadState::Blocked));
        assert_eq!(process.poll_sleep(main, 99), Some(false));
        assert_eq!(process.poll_sleep(main, 100), Some(true));
        process.complete_sleep(main).unwrap();
        assert_eq!(process.thread_state(main), Some(ThreadState::Ready));
    }

    #[test]
    fn main_thread_has_a_generation_tagged_process_local_identity() {
        let process = test_process(ProcessState::Ready);
        let id = process.main_thread_id();
        assert!(id.is_valid());
        assert_eq!(id.slot(), 0);
        assert_eq!(id.generation(), 1);
        assert!(process.thread(id).is_some());
        assert!(process.thread(ThreadId::INVALID).is_none());
        assert!(process
            .thread(ThreadId::from_raw(id.slot() as u64))
            .is_none());
    }

    #[test]
    fn delegated_and_focus_classes_restore_the_user_fallback_on_revocation() {
        let (_region, mut allocator) = TestFrameRegion::allocator(64);
        let mut process = construct_test_process(&mut allocator).unwrap();
        let main = process.main_thread_id();
        process
            .set_thread_scheduling_class(main, SchedulingClass::Background)
            .unwrap();
        assert_eq!(
            process.thread_scheduling_class(main),
            Some(SchedulingClass::Background)
        );

        let (handle, control) = process
            .handles_mut()
            .scheduling_authority_create(ThreadSchedulingClass::Audio, true)
            .unwrap();
        let lease = process
            .handles()
            .scheduling_authority_lease(handle, ThreadSchedulingClass::Audio)
            .unwrap();
        process
            .set_thread_scheduling_class_with_authority(main, SchedulingClass::Audio, lease)
            .unwrap();
        assert_eq!(
            process.thread_scheduling_class(main),
            Some(SchedulingClass::Audio)
        );
        control.revoke();
        assert_eq!(
            process.thread_scheduling_class(main),
            Some(SchedulingClass::Background)
        );

        process
            .set_thread_scheduling_class(main, SchedulingClass::Normal)
            .unwrap();
        process.set_focused_interactive(true);
        assert_eq!(
            process.thread_scheduling_class(main),
            Some(SchedulingClass::Interactive)
        );
        process.set_focused_interactive(false);
        assert_eq!(
            process.thread_scheduling_class(main),
            Some(SchedulingClass::Normal)
        );
    }

    #[test]
    fn scheduler_selects_thread_references_not_bare_processes() {
        let mut table = ProcessTable::new();
        let process_id = table.insert(test_process(ProcessState::Ready)).unwrap();
        let expected_thread = table.get(process_id).unwrap().main_thread_id();

        assert_eq!(
            table.next_thread(),
            Some(ThreadRef {
                process_id,
                thread_id: expected_thread,
            })
        );
    }

    #[test]
    fn process_table_selects_live_ids_in_round_robin_order() {
        let mut table = ProcessTable::new();
        assert_eq!(table.next_id(), None);

        let first = table.insert(test_process(ProcessState::Ready)).unwrap();
        let second = table.insert(test_process(ProcessState::Ready)).unwrap();
        let third = table.insert(test_process(ProcessState::Ready)).unwrap();

        assert_eq!(table.next_id(), Some(first));
        assert_eq!(table.next_id(), Some(second));
        assert_eq!(table.next_id(), Some(third));
        assert_eq!(table.next_id(), Some(first));
        assert_eq!(table.next_id(), Some(second));
        assert_eq!(table.next_id(), Some(third));
    }

    #[test]
    fn process_table_reports_only_ready_entries_as_runnable() {
        let mut table = ProcessTable::new();
        assert!(!table.has_runnable());

        let ready = table.insert(test_process(ProcessState::Ready)).unwrap();
        let _blocked = table.insert(test_process(ProcessState::Blocked)).unwrap();
        assert!(table.has_runnable());

        table.get_mut(ready).unwrap().mark_exited(0);
        assert!(!table.has_runnable());
    }

    #[test]
    fn process_table_new_slot_joins_at_its_deterministic_slot_position() {
        let mut table = ProcessTable::new();
        let first = table.insert(test_process(ProcessState::Ready)).unwrap();
        let second = table.insert(test_process(ProcessState::Ready)).unwrap();

        assert_eq!(table.next_id(), Some(first));
        let third = table.insert(test_process(ProcessState::Ready)).unwrap();
        assert_eq!(table.next_id(), Some(second));
        assert_eq!(table.next_id(), Some(third));
        assert_eq!(table.next_id(), Some(first));
    }

    #[test]
    fn process_table_selection_skips_holes_and_becomes_idle_when_empty() {
        let mut table = ProcessTable::new();
        let first = table.insert(test_process(ProcessState::Ready)).unwrap();
        let second = table.insert(test_process(ProcessState::Ready)).unwrap();
        let third = table.insert(test_process(ProcessState::Ready)).unwrap();
        let fourth = table.insert(test_process(ProcessState::Ready)).unwrap();

        assert_eq!(table.next_id(), Some(first));
        drop(table.take_for_retirement(second).unwrap());
        drop(table.take_for_retirement(fourth).unwrap());
        assert_eq!(table.next_id(), Some(third));
        assert_eq!(table.next_id(), Some(first));

        drop(table.take_for_retirement(first).unwrap());
        drop(table.take_for_retirement(third).unwrap());
        assert!(table.is_empty());
        assert_eq!(table.next_id(), None);
        assert_eq!(table.next_id(), None);
    }

    #[test]
    fn process_table_reused_slot_is_selected_with_its_new_generation() {
        let mut table = ProcessTable::new();
        let first = table.insert(test_process(ProcessState::Ready)).unwrap();
        let stale = table.insert(test_process(ProcessState::Ready)).unwrap();
        let third = table.insert(test_process(ProcessState::Ready)).unwrap();

        assert_eq!(table.next_id(), Some(first));
        drop(table.take_for_retirement(stale).unwrap());
        let replacement = table.insert(test_process(ProcessState::Ready)).unwrap();
        assert_eq!(replacement.slot(), stale.slot());
        assert_ne!(replacement.generation(), stale.generation());
        assert!(table.get(stale).is_none());
        assert!(table.take_for_retirement(stale).is_none());

        assert_eq!(table.next_id(), Some(replacement));
        assert_eq!(table.next_id(), Some(third));
        assert_eq!(table.next_id(), Some(first));
    }

    #[test]
    fn process_table_slot_reuse_does_not_reset_the_cursor() {
        let mut table = ProcessTable::new();
        let first = table.insert(test_process(ProcessState::Ready)).unwrap();
        let second = table.insert(test_process(ProcessState::Ready)).unwrap();

        assert_eq!(table.next_id(), Some(first));
        drop(table.take_for_retirement(first).unwrap());
        let replacement = table.insert(test_process(ProcessState::Ready)).unwrap();
        assert_eq!(replacement.slot(), first.slot());

        assert_eq!(table.next_id(), Some(second));
        assert_eq!(table.next_id(), Some(replacement));
    }

    #[test]
    fn process_table_selection_includes_non_runnable_live_processes() {
        let mut table = ProcessTable::new();
        let mut blocked_process = test_process(ProcessState::Ready);
        blocked_process.block_wait_many(pending_wait(WaitDeadline::Infinite));
        let blocked = table.insert(blocked_process).unwrap();
        let exited = table
            .insert(test_process(ProcessState::Exited(23)))
            .unwrap();
        let fault = ProcessFault::new(ProcessFaultReason::InvalidOpcode, 6);
        let faulted = table
            .insert(test_process(ProcessState::Faulted(fault)))
            .unwrap();

        assert_eq!(table.next_id(), Some(blocked));
        assert_eq!(table.next_id(), Some(exited));
        assert_eq!(table.next_id(), Some(faulted));
        assert_eq!(table.get(blocked).unwrap().state(), ProcessState::Blocked);
        assert_eq!(table.get(exited).unwrap().state(), ProcessState::Exited(23));
        assert_eq!(
            table.get(faulted).unwrap().state(),
            ProcessState::Faulted(fault)
        );
    }

    #[test]
    fn process_preemption_accounting_saturates() {
        let mut process = test_process(ProcessState::Ready);
        assert_eq!(process.preemption_count(), 0);
        process.record_preemption();
        assert_eq!(process.preemption_count(), 1);
        process.main_thread_mut().preemption_count = u64::MAX;
        process.record_preemption();
        assert_eq!(process.preemption_count(), u64::MAX);
    }

    #[test]
    fn direct_startup_block_has_versioned_offsets_and_child_handles() {
        let mut startup = DirectStartupBlock::new(b"first\0second\0", b"cfg", 2).unwrap();
        startup.set_handles(&[Handle::from_raw(7), Handle::from_raw(9)]);
        let read =
            |offset| u32::from_le_bytes(startup.bytes[offset..offset + 4].try_into().unwrap());

        assert_eq!(read(0), DIRECT_STARTUP_MAGIC);
        assert_eq!(
            u16::from_le_bytes(startup.bytes[4..6].try_into().unwrap()),
            1
        );
        assert_eq!(read(12), 2);
        let argv = read(16) as usize;
        let args = read(20) as usize;
        let config = read(28) as usize;
        let handles = read(36) as usize;
        assert_eq!(read(argv) as usize, args);
        assert_eq!(read(argv + 4) as usize, args + 6);
        assert_eq!(&startup.bytes[args..args + 13], b"first\0second\0");
        assert_eq!(&startup.bytes[config..config + 3], b"cfg");
        assert_eq!(read(handles), 7);
        assert_eq!(read(handles + 4), 9);
        assert_eq!(startup.bytes.len() % DIRECT_STARTUP_ALIGNMENT, 0);
    }

    #[test]
    fn direct_startup_rejects_malformed_and_excessive_arguments() {
        assert!(matches!(
            DirectStartupBlock::new(b"not-terminated", &[], 0),
            Err(Status::InvalidArgument)
        ));
        assert!(matches!(
            DirectStartupBlock::new(&[0xff, 0], &[], 0),
            Err(Status::InvalidArgument)
        ));
        let too_many = vec![0; PROCESS_MAX_ARGS + 1];
        assert!(matches!(
            DirectStartupBlock::new(&too_many, &[], 0),
            Err(Status::ResourceLimit)
        ));
    }

    #[test]
    fn application_data_identity_is_child_local_owned_and_single_assignment() {
        let mut handles = HandleTable::new();
        let application_data = handles.application_data_create("example.editor").unwrap();
        let (channel, _) = handles.channel_create().unwrap();
        let mut process = test_process(ProcessState::Ready);
        process.handles = Some(handles);

        assert_eq!(
            process.set_application_data(channel),
            Err(IpcError::WrongObjectType)
        );
        assert!(process.set_application_data(application_data).is_ok());
        assert_eq!(process.application_data(), Some(application_data));
        assert_eq!(
            process.set_application_data(application_data),
            Err(IpcError::InvalidMessage)
        );

        drop(process.handles.take());
    }

    #[test]
    fn process_control_handles_enforce_inspect_and_terminate_rights() {
        let mut table = HandleTable::new();
        let (handle, _) = table.process_create().unwrap();
        let inspect = table.handle_duplicate(handle, Rights::INSPECT).unwrap();
        let terminate = table.handle_duplicate(handle, Rights::TERMINATE).unwrap();

        assert!(table.process_info(inspect).is_ok());
        assert_eq!(
            table.process_terminate(inspect),
            Err(IpcError::AccessDenied)
        );
        assert_eq!(table.process_info(terminate), Err(IpcError::AccessDenied));
        assert!(table.process_terminate(terminate).is_ok());
    }

    #[test]
    fn attached_control_publishes_exit_fault_and_external_termination() {
        let mut table = HandleTable::new();
        let (handle, control) = table.process_create().unwrap();
        let mut terminated = test_process(ProcessState::Ready);
        terminated.attach_control(control);
        table.process_terminate(handle).unwrap();
        assert!(terminated.termination_requested());
        terminated.mark_terminated();
        let info = table.process_info(handle).unwrap();
        assert_eq!(
            info.termination_cause(),
            Some(ginkgo_sysapi::ProcessTerminationCause::Terminated)
        );

        let (handle, control) = table.process_create().unwrap();
        let mut exited = test_process(ProcessState::Ready);
        exited.attach_control(control);
        exited.mark_exited(-3);
        let info = table.process_info(handle).unwrap();
        assert_eq!(info.exit_code, -3);
        assert_eq!(
            info.termination_cause(),
            Some(ginkgo_sysapi::ProcessTerminationCause::Exited)
        );

        let (handle, control) = table.process_create().unwrap();
        let mut faulted = test_process(ProcessState::Ready);
        faulted.attach_control(control);
        faulted.mark_faulted(ProcessFault::at_address(
            ProcessFaultReason::PageFault,
            5,
            0xdead_beef,
        ));
        let info = table.process_info(handle).unwrap();
        assert_eq!(info.process_fault(), Some(PublicProcessFault::PageFault));
        assert_eq!(info.fault_code, 5);
        assert_eq!(info.fault_address, 0xdead_beef);
    }

    #[test]
    fn process_states_retain_completion_details_and_classify_lifecycle() {
        let fault = ProcessFault::at_address(ProcessFaultReason::PageFault, 0b101, 0xdead_beef);
        let ready = ProcessState::Ready;
        let blocked = ProcessState::Blocked;
        let exited = ProcessState::Exited(-17);
        let faulted = ProcessState::Faulted(fault);
        let terminated = ProcessState::Terminated;

        assert!(ready.is_runnable());
        assert!(!ready.is_blocked());
        assert!(!ready.is_terminal());
        assert!(!blocked.is_runnable());
        assert!(blocked.is_blocked());
        assert!(!blocked.is_terminal());
        assert!(!exited.is_runnable());
        assert!(exited.is_terminal());
        assert!(!faulted.is_runnable());
        assert!(faulted.is_terminal());
        assert!(!terminated.is_runnable());
        assert!(terminated.is_terminal());
        assert_eq!(exited, ProcessState::Exited(-17));
        assert_eq!(fault.reason, ProcessFaultReason::PageFault);
        assert_eq!(fault.code, 0b101);
        assert_eq!(fault.address, Some(0xdead_beef));
        assert_ne!(
            ProcessFault::new(ProcessFaultReason::InvalidOpcode, 6),
            fault
        );
    }

    #[test]
    fn blocked_wait_state_is_owned_and_cleared_before_resume() {
        let mut process = test_process(ProcessState::Ready);
        process.block_wait_many(pending_wait(WaitDeadline::At(25)));
        assert_eq!(process.state(), ProcessState::Blocked);
        assert!(process.main_thread().blocked_syscall.is_some());

        let wait = process.take_blocked_wait_many();
        assert_eq!(wait.deadline, WaitDeadline::At(25));
        assert!(process.main_thread().blocked_syscall.is_none());
        process.resume_from_block();
        assert_eq!(process.state(), ProcessState::Ready);
    }

    #[test]
    fn terminal_transition_drops_blocked_wait_state() {
        let mut exited = test_process(ProcessState::Ready);
        exited.block_wait_many(pending_wait(WaitDeadline::Infinite));
        exited.mark_exited(7);
        assert_eq!(exited.state(), ProcessState::Exited(7));
        assert!(exited.main_thread().blocked_syscall.is_none());

        let mut faulted = test_process(ProcessState::Ready);
        faulted.block_wait_many(pending_wait(WaitDeadline::Infinite));
        let fault = ProcessFault::new(ProcessFaultReason::InvalidOpcode, 6);
        faulted.mark_faulted(fault);
        assert_eq!(faulted.state(), ProcessState::Faulted(fault));
        assert!(faulted.main_thread().blocked_syscall.is_none());
    }

    #[test]
    fn finite_deadlines_expire_inclusively_and_infinite_never_expires() {
        assert!(!WaitDeadline::At(25).is_expired(24));
        assert!(WaitDeadline::At(25).is_expired(25));
        assert!(WaitDeadline::At(25).is_expired(26));
        assert!(!WaitDeadline::Infinite.is_expired(u64::MAX));
    }

    #[test]
    fn stack_vmas_reserve_the_full_maximum_and_reject_anonymous_overlap() {
        let (_region, mut allocator) = TestFrameRegion::allocator(64);
        let process = construct_test_process(&mut allocator).unwrap();
        let layout = process.layout();
        assert!(process.vmas().iter().any(|vma| {
            vma.start == layout.stack_guard_start
                && vma.end == layout.stack_bottom
                && vma.kind
                    == (VmAreaKind::StackGuard {
                        owner: MAIN_THREAD_ID,
                    })
        }));
        assert!(process.vmas().iter().any(|vma| {
            vma.start == layout.stack_bottom
                && vma.end == layout.stack_initial_bottom
                && vma.kind
                    == (VmAreaKind::Stack {
                        owner: MAIN_THREAD_ID,
                        committed: false,
                    })
        }));
        assert!(process.vmas().iter().any(|vma| {
            vma.start == layout.stack_initial_bottom
                && vma.end == layout.stack_top
                && vma.kind
                    == (VmAreaKind::Stack {
                        owner: MAIN_THREAD_ID,
                        committed: true,
                    })
        }));
        assert_eq!(
            plan_vma_insert(
                process.vmas(),
                VmArea {
                    start: layout.stack_bottom,
                    end: layout.stack_bottom + PAGE_SIZE,
                    kind: VmAreaKind::Anonymous {
                        reservation_id: 99,
                        committed: false,
                    },
                    protection: MapProtection::READ,
                },
            ),
            Err(SharedMappingError::AlreadyMapped(layout.stack_bottom))
        );
        process.retire().unwrap().reclaim(&mut allocator).unwrap();
    }

    #[test]
    fn eligible_stack_fault_grows_zeroed_pages_and_updates_vma_accounting() {
        let (_region, mut allocator) = TestFrameRegion::allocator(96);
        let mut process = construct_test_process(&mut allocator).unwrap();
        let old_bottom = process.layout().stack_initial_bottom;
        let fault_page = old_bottom - PAGE_SIZE * 2;
        let fault_address = fault_page + 24;
        let baseline_private = process.usage().private_pages;

        assert_eq!(
            process.resolve_user_page_fault(
                fault_address,
                PAGE_FAULT_USER,
                fault_address + 8,
                &mut allocator,
            ),
            UserPageFaultResolution::Resolved { pages: 2 }
        );
        assert_eq!(process.usage().private_pages, baseline_private + 2);
        assert_eq!(
            process.stack_committed_bottom(process.main_thread_id()),
            Some(fault_page)
        );
        assert_eq!(
            process.address_space().validate_user_range(
                fault_page,
                (PAGE_SIZE * 2) as usize,
                UserAccess::Write,
            ),
            Ok(())
        );
        for page in [fault_page, fault_page + PAGE_SIZE] {
            let frame = process
                .address_space()
                .mappings()
                .iter()
                .find(|mapping| mapping.virtual_address == page)
                .expect("grown stack page mapping")
                .frame;
            let bytes = unsafe {
                core::slice::from_raw_parts(
                    frame.start_address().as_u64() as *const u8,
                    PAGE_SIZE as usize,
                )
            };
            assert!(bytes.iter().all(|byte| *byte == 0));
        }
        process.retire().unwrap().reclaim(&mut allocator).unwrap();
    }

    #[test]
    fn stack_fault_uses_current_captured_rsp_not_saved_process_rsp() {
        let (_region, mut allocator) = TestFrameRegion::allocator(80);
        let mut process = construct_test_process(&mut allocator).unwrap();
        let old_bottom = process.layout().stack_initial_bottom;
        let fault_address = old_bottom - 8;
        assert_eq!(process.context().rsp, process.layout().stack_top);
        assert!(fault_address < process.context().rsp.saturating_sub(USER_STACK_GROWTH_SLOP));

        assert_eq!(
            process.resolve_user_page_fault(
                fault_address,
                PAGE_FAULT_USER,
                fault_address,
                &mut allocator,
            ),
            UserPageFaultResolution::Resolved { pages: 1 }
        );
        process.retire().unwrap().reclaim(&mut allocator).unwrap();
    }

    #[test]
    fn guard_limit_protection_kernel_and_far_rsp_faults_remain_page_faults() {
        let (_region, mut allocator) = TestFrameRegion::allocator(80);
        let mut process = construct_test_process(&mut allocator).unwrap();
        let layout = process.layout();
        let old_bottom = layout.stack_initial_bottom;
        let cases = [
            (
                layout.stack_bottom - 1,
                PAGE_FAULT_USER,
                layout.stack_bottom - 1,
            ),
            (
                layout.stack_guard_start,
                PAGE_FAULT_USER,
                layout.stack_guard_start,
            ),
            (
                old_bottom - 8,
                PAGE_FAULT_USER | PAGE_FAULT_PRESENT,
                old_bottom - 8,
            ),
            (old_bottom - 8, 0, old_bottom - 8),
            (
                old_bottom - USER_STACK_GROWTH_SLOP - PAGE_SIZE,
                PAGE_FAULT_USER,
                old_bottom,
            ),
        ];
        let baseline_vmas = process.vmas().to_vec();
        let baseline_private = process.usage().private_pages;
        for (address, code, rsp) in cases {
            assert_eq!(
                process.resolve_user_page_fault(address, code, rsp, &mut allocator),
                UserPageFaultResolution::Fault(ProcessFault::at_address(
                    ProcessFaultReason::PageFault,
                    code,
                    address,
                ))
            );
        }
        assert_eq!(process.vmas(), baseline_vmas);
        assert_eq!(process.usage().private_pages, baseline_private);
        process.retire().unwrap().reclaim(&mut allocator).unwrap();
    }

    #[test]
    fn stack_growth_quota_returns_resource_limit_without_mapping() {
        let (_region, mut allocator) = TestFrameRegion::allocator(80);
        let mut process = construct_test_process(&mut allocator).unwrap();
        process.limits.private_pages = process.usage().private_pages;
        let fault_address = process.layout().stack_initial_bottom - 8;
        let baseline_vmas = process.vmas().to_vec();
        let baseline_frames = allocator.allocated_count();

        assert_eq!(
            process.resolve_user_page_fault(
                fault_address,
                PAGE_FAULT_USER,
                fault_address,
                &mut allocator,
            ),
            UserPageFaultResolution::Fault(ProcessFault::at_address(
                ProcessFaultReason::ResourceLimit,
                PAGE_FAULT_USER,
                fault_address,
            ))
        );
        assert_eq!(process.vmas(), baseline_vmas);
        assert_eq!(allocator.allocated_count(), baseline_frames);
        process.retire().unwrap().reclaim(&mut allocator).unwrap();
    }

    #[test]
    fn stack_growth_physical_oom_is_attributed_to_faulting_process() {
        let (_region, mut allocator) = TestFrameRegion::allocator(64);
        let mut process = construct_test_process(&mut allocator).unwrap();
        let mut held = Vec::new();
        while let Some(frame) = allocator.allocate_frame().unwrap() {
            held.push(frame);
        }
        let fault_address = process.layout().stack_initial_bottom - 8;
        let baseline_vmas = process.vmas().to_vec();
        let baseline_private = process.usage().private_pages;

        assert_eq!(
            process.resolve_user_page_fault(
                fault_address,
                PAGE_FAULT_USER,
                fault_address,
                &mut allocator,
            ),
            UserPageFaultResolution::Fault(ProcessFault::at_address(
                ProcessFaultReason::OutOfMemory,
                PAGE_FAULT_USER,
                fault_address,
            ))
        );
        assert_eq!(process.state(), ProcessState::Ready);
        assert_eq!(process.vmas(), baseline_vmas);
        assert_eq!(process.usage().private_pages, baseline_private);
        allocator.reclaim_frames(&held).unwrap();
        process.retire().unwrap().reclaim(&mut allocator).unwrap();
    }

    #[test]
    fn partial_stack_growth_oom_rolls_back_pages_vma_and_accounting() {
        let (_region, mut allocator) = TestFrameRegion::allocator(80);
        let mut process = construct_test_process(&mut allocator).unwrap();
        let mut held = Vec::new();
        while let Some(frame) = allocator.allocate_frame().unwrap() {
            held.push(frame);
        }
        let available = held.pop().expect("one frame to release");
        allocator.deallocate_frame(available).unwrap();
        let old_bottom = process.layout().stack_initial_bottom;
        let fault_page = old_bottom - PAGE_SIZE * 2;
        let fault_address = fault_page + 8;
        let baseline_vmas = process.vmas().to_vec();
        let baseline_private = process.usage().private_pages;
        let baseline_frames = allocator.allocated_count();

        assert_eq!(
            process.resolve_user_page_fault(
                fault_address,
                PAGE_FAULT_USER,
                fault_address,
                &mut allocator,
            ),
            UserPageFaultResolution::Fault(ProcessFault::at_address(
                ProcessFaultReason::OutOfMemory,
                PAGE_FAULT_USER,
                fault_address,
            ))
        );
        assert_eq!(process.vmas(), baseline_vmas);
        assert_eq!(process.usage().private_pages, baseline_private);
        assert_eq!(allocator.allocated_count(), baseline_frames);
        for page in [fault_page, fault_page + PAGE_SIZE] {
            assert!(matches!(
                process.address_space().validate_user_range(
                    page,
                    PAGE_SIZE as usize,
                    UserAccess::Read,
                ),
                Err(AddressSpaceError::NotMapped(_))
            ));
        }
        allocator.reclaim_frames(&held).unwrap();
        process.retire().unwrap().reclaim(&mut allocator).unwrap();
    }

    #[test]
    fn stack_growth_planning_preserves_resource_failure_classification() {
        let address = USER_STACK_INITIAL_BOTTOM - 8;
        assert_eq!(
            stack_growth_planning_fault(SharedMappingError::OutOfMemory, PAGE_FAULT_USER, address,),
            UserPageFaultResolution::Fault(ProcessFault::at_address(
                ProcessFaultReason::OutOfMemory,
                PAGE_FAULT_USER,
                address,
            ))
        );
        assert_eq!(
            stack_growth_planning_fault(
                SharedMappingError::ResourceLimit,
                PAGE_FAULT_USER,
                address,
            ),
            UserPageFaultResolution::Fault(ProcessFault::at_address(
                ProcessFaultReason::ResourceLimit,
                PAGE_FAULT_USER,
                address,
            ))
        );
        assert_eq!(
            stack_growth_planning_fault(
                SharedMappingError::ExactMappingNotFound {
                    address,
                    length: PAGE_SIZE,
                },
                PAGE_FAULT_USER,
                address,
            ),
            UserPageFaultResolution::Fault(ProcessFault::at_address(
                ProcessFaultReason::Other(STACK_GROWTH_INVARIANT_REASON),
                STACK_GROWTH_INVARIANT_CODE,
                address,
            ))
        );
    }

    #[test]
    fn malformed_stack_vma_returns_other_process_fault_without_panicking() {
        let (_region, mut allocator) = TestFrameRegion::allocator(80);
        let mut process = construct_test_process(&mut allocator).unwrap();
        process.vmas.as_mut().unwrap().retain(|vma| {
            !matches!(
                vma.kind,
                VmAreaKind::Stack {
                    committed: true,
                    ..
                }
            )
        });
        let fault_address = process.layout().stack_initial_bottom - 8;
        assert_eq!(
            process.resolve_user_page_fault(
                fault_address,
                PAGE_FAULT_USER,
                fault_address,
                &mut allocator,
            ),
            UserPageFaultResolution::Fault(ProcessFault::at_address(
                ProcessFaultReason::Other(STACK_GROWTH_INVARIANT_REASON),
                STACK_GROWTH_INVARIANT_CODE,
                fault_address,
            ))
        );
        process.retire().unwrap().reclaim(&mut allocator).unwrap();
    }

    #[test]
    fn standard_layout_has_permanent_guard_reservation_and_initial_commit() {
        let layout = ProcessLayout::STANDARD;
        assert_eq!(layout.stack_size(), USER_STACK_MAX_SIZE);
        assert_eq!(layout.initial_stack_size(), USER_STACK_INITIAL_SIZE);
        assert_eq!(layout.stack_bottom - layout.stack_guard_start, PAGE_SIZE);
        assert_eq!(layout.stack_bottom % PAGE_SIZE, 0);
        assert_eq!(layout.stack_initial_bottom % PAGE_SIZE, 0);
        assert_eq!(layout.stack_top % 16, 0);
        assert!(layout.stack_top < USER_ADDRESS_END);
    }

    #[test]
    fn randomized_layout_stays_aligned_bounded_and_seed_dependent() {
        let first = ProcessLayout::randomized(1);
        let second = ProcessLayout::randomized(2);
        assert_ne!(first, second);
        for layout in [first, second] {
            assert_eq!(layout.stack_size(), USER_STACK_MAX_SIZE);
            assert_eq!(layout.initial_stack_size(), USER_STACK_INITIAL_SIZE);
            assert_eq!(layout.stack_top % 16, 0);
            assert_eq!(layout.stack_guard_start % PAGE_SIZE, 0);
            assert!(layout.stack_guard_start >= PAGE_SIZE);
            assert!(layout.stack_top < USER_ADDRESS_END);
        }
    }

    #[test]
    fn resource_accounting_enforces_memory_and_traffic_ceilings() {
        let mut process = test_process(ProcessState::Ready);
        assert!(process.can_allocate_shared_memory(PAGE_SIZE as usize));
        assert!(!process.can_allocate_shared_memory(1));
        process.record_shared_memory_allocation(PAGE_SIZE as usize);
        assert_eq!(process.usage.shared_memory_bytes, PAGE_SIZE);
        process.release_shared_memory_charge(PAGE_SIZE as usize);
        assert_eq!(process.usage.shared_memory_bytes, 0);
        process.usage.shared_memory_bytes = process.limits.shared_memory_bytes;
        assert!(!process.can_allocate_shared_memory(PAGE_SIZE as usize));
        assert!(process.can_send_channel_bytes(1));
        process.usage.channel_traffic_bytes = process.limits.channel_traffic_bytes;
        assert!(!process.can_send_channel_bytes(1));
        process.record_cpu_time(25);
        assert_eq!(process.usage.cpu_time_ns, 25);
    }

    #[test]
    fn start_arguments_set_abi_registers_without_changing_other_context() {
        let mut process = test_process(ProcessState::Ready);
        process.context_mut().rax = 4;
        process.context_mut().rbx = 5;
        let mut expected = *process.context();
        expected.rdi = 1;
        expected.rsi = 2;
        expected.rdx = 3;
        expected.rcx = 4;

        process.set_start_arguments([1, 2, 3, 4]);

        assert_eq!(*process.context(), expected);
    }

    #[test]
    fn mapping_range_accepts_partial_final_page_within_logical_length() {
        let request = validate_mapping_range(info(5000, 8192), 0, 5000).unwrap();
        assert_eq!(request.offset, 0);
        assert_eq!(request.mapped_len, 8192);

        let request = validate_mapping_range(info(8193, 12288), 4096, 4097).unwrap();
        assert_eq!(request.offset, 4096);
        assert_eq!(request.mapped_len, 8192);
    }

    #[test]
    fn mapping_range_rejects_unaligned_empty_overflow_and_out_of_bounds() {
        assert_eq!(
            validate_mapping_range(info(8192, 8192), 1, 1),
            Err(SharedMappingError::UnalignedOffset(1))
        );
        assert_eq!(
            validate_mapping_range(info(8192, 8192), 0, 0),
            Err(SharedMappingError::ZeroLength)
        );
        assert!(matches!(
            validate_mapping_range(info(8192, 8192), 4096, 4097),
            Err(SharedMappingError::RangeOutsideObject { .. })
        ));
        assert_eq!(
            validate_mapping_range(
                info(usize::MAX, usize::MAX & !(PAGE_SIZE as usize - 1)),
                0,
                u64::MAX,
            ),
            Err(SharedMappingError::RangeOverflow)
        );
    }

    #[test]
    fn protection_requires_read_forbids_execute_and_selects_write_lease() {
        assert_eq!(
            validate_protection(MapProtection::READ),
            Ok(SharedMemoryMappingAccess::ReadOnly)
        );
        assert_eq!(
            validate_protection(MapProtection::READ | MapProtection::WRITE),
            Ok(SharedMemoryMappingAccess::ReadWrite)
        );
        assert!(matches!(
            validate_protection(MapProtection::WRITE),
            Err(SharedMappingError::InvalidProtection(_))
        ));
        assert!(matches!(
            validate_protection(MapProtection::READ | MapProtection::EXECUTE),
            Err(SharedMappingError::InvalidProtection(_))
        ));
    }

    #[test]
    fn fixed_selection_is_exact_and_rejects_overlap() {
        let occupied = [VirtualRange::new(0x4000, 0x6000).unwrap()];
        assert_eq!(
            select_mapping_address(
                0x8000,
                true,
                4096,
                SHARED_MAPPING_BASE,
                USER_STACK_GUARD_START,
                &occupied,
            ),
            Ok(0x8000)
        );
        assert_eq!(
            select_mapping_address(
                0x5000,
                true,
                4096,
                SHARED_MAPPING_BASE,
                USER_STACK_GUARD_START,
                &occupied,
            ),
            Err(SharedMappingError::AlreadyMapped(0x5000))
        );
        assert_eq!(
            select_mapping_address(
                0x8001,
                true,
                4096,
                SHARED_MAPPING_BASE,
                USER_STACK_GUARD_START,
                &occupied,
            ),
            Err(SharedMappingError::UnalignedFixedAddress(0x8001))
        );
    }

    #[test]
    fn free_hint_is_aligned_and_occupied_hint_falls_back_to_cursor() {
        let occupied = [
            VirtualRange::new(0x8000, 0xa000).unwrap(),
            VirtualRange::new(SHARED_MAPPING_BASE, SHARED_MAPPING_BASE + PAGE_SIZE).unwrap(),
        ];
        assert_eq!(
            select_mapping_address(
                0xa001,
                false,
                4096,
                SHARED_MAPPING_BASE,
                USER_STACK_GUARD_START,
                &occupied,
            ),
            Ok(0xb000)
        );
        assert_eq!(
            select_mapping_address(
                0x8000,
                false,
                4096,
                SHARED_MAPPING_BASE,
                USER_STACK_GUARD_START,
                &occupied,
            ),
            Ok(SHARED_MAPPING_BASE + PAGE_SIZE)
        );
    }

    #[test]
    fn automatic_selection_stays_below_stack_guard() {
        let occupied =
            [VirtualRange::new(SHARED_MAPPING_BASE, USER_STACK_GUARD_START - PAGE_SIZE).unwrap()];
        assert_eq!(
            select_mapping_address(
                0,
                false,
                PAGE_SIZE as usize,
                SHARED_MAPPING_BASE,
                USER_STACK_GUARD_START,
                &occupied,
            ),
            Ok(USER_STACK_GUARD_START - PAGE_SIZE)
        );
        assert_eq!(
            select_mapping_address(
                0,
                false,
                (PAGE_SIZE * 2) as usize,
                SHARED_MAPPING_BASE,
                USER_STACK_GUARD_START,
                &occupied,
            ),
            Err(SharedMappingError::NoAddressSpace)
        );
    }

    #[test]
    fn writable_mapping_requires_write_right_in_lease_contract() {
        let requested = validate_protection(MapProtection::READ | MapProtection::WRITE).unwrap();
        assert_eq!(requested, SharedMemoryMappingAccess::ReadWrite);
        let required = Rights::MAP | Rights::READ | Rights::WRITE;
        assert!(required.contains(Rights::WRITE));
    }
}
