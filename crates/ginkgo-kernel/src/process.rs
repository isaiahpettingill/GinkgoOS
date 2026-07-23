//! User process ownership, ELF construction, and shared-memory mappings.

use alloc::vec::Vec;
use core::{fmt, mem, ptr};

use ginkgo_ipc::{
    Handle, HandleTable, IpcError, ProcessControl, SharedMemoryMappingAccess,
    SharedMemoryMappingInfo, SharedMemoryMappingLease, WaitItem,
};
#[cfg(test)]
use ginkgo_sysapi::Rights;
use ginkgo_sysapi::{
    MapFlags, MapProtection, ProcessFault as PublicProcessFault, SharedMemoryMapArgs, Status,
    PROCESS_MAX_ARGS, PROCESS_MAX_STARTUP_BYTES, PROCESS_MAX_STARTUP_HANDLES,
};
use x86_64::{
    structures::paging::{PhysFrame, Size4KiB},
    VirtAddr,
};

use crate::{
    arch::UserContext,
    elf::{self, ElfError, LoadError, SegmentPermissions},
    memory::{UsableFrameAllocator, PAGE_SIZE},
    paging::{
        address_space::{
            AddressSpace, AddressSpaceError, FrameReclaimStats, RetiredAddressSpace, UserAccess,
            UserPagePermissions,
        },
        ActivePageTable,
    },
};

pub const USER_STACK_INITIAL_SIZE: u64 = 64 * 1024;
pub const USER_STACK_MAX_SIZE: u64 = 8 * 1024 * 1024;
pub const USER_STACK_GROWTH_SLOP: u64 = 64 * 1024;
pub const USER_STACK_TOP: u64 = 0x0000_7fff_ffff_f000;
pub const USER_STACK_BOTTOM: u64 = USER_STACK_TOP - USER_STACK_MAX_SIZE;
pub const USER_STACK_INITIAL_BOTTOM: u64 = USER_STACK_TOP - USER_STACK_INITIAL_SIZE;
pub const USER_STACK_GUARD_START: u64 = USER_STACK_BOTTOM - PAGE_SIZE;
pub const SHARED_MAPPING_BASE: u64 = 0x0000_0001_0000_0000;
/// Hard ceiling for one process's sorted semantic virtual-memory areas.
pub const MAX_VMAS: usize = 256;
/// Stable internal fault reason/code used when page-table rollback cannot restore
/// a process to a coherent mapping state. Such a process is quarantined terminally.
const VM_ROLLBACK_FAILURE_REASON: u16 = 1;
const VM_ROLLBACK_FAILURE_CODE: u64 = 0x564d_0001;
const STACK_GROWTH_INVARIANT_REASON: u16 = 2;
const STACK_GROWTH_INVARIANT_CODE: u64 = 0x5354_0001;
const PAGE_FAULT_PRESENT: u64 = 1 << 0;
const PAGE_FAULT_USER: u64 = 1 << 2;

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
pub(crate) struct PendingWaitMany {
    pub(crate) items: Vec<WaitItem>,
    pub(crate) encoded_items: Vec<u8>,
    pub(crate) items_address: u64,
    pub(crate) output_address: u64,
    pub(crate) deadline: WaitDeadline,
    pub(crate) completion: Option<WaitManyCompletion>,
}

pub(crate) enum BlockedSyscall {
    WaitMany(PendingWaitMany),
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
    pub shared_memory_bytes: u64,
    pub mapped_shared_bytes: u64,
    pub channel_traffic_bytes: u64,
    /// Maximum uninterrupted execution before the scheduler rotates processes.
    pub cpu_quantum_ns: u64,
}

impl ProcessLimits {
    pub const STANDARD: Self = Self {
        private_pages: 262_144,
        shared_memory_bytes: 64 * 1024 * 1024,
        mapped_shared_bytes: 64 * 1024 * 1024,
        channel_traffic_bytes: 64 * 1024 * 1024,
        cpu_quantum_ns: 10_000_000,
    };
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProcessUsage {
    pub private_pages: u64,
    pub shared_memory_bytes: u64,
    pub mapped_shared_bytes: u64,
    pub channel_traffic_bytes: u64,
    pub cpu_time_ns: u64,
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
        committed: bool,
    },
    StackGuard,
    Shared,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AnonymousReservationRollback {
    start: u64,
    end: u64,
    reservation_id: u64,
    previous_cursor: u64,
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
    InvalidBackingAlignment(u64),
    InvalidBackingLength,
    OutOfMemory,
    ResourceLimit,
    InvalidKernelAddress(u64),
    KernelAddressNotMapped(u64),
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

/// All process-owned execution and capability state.
pub struct Process {
    address_space: Option<AddressSpace>,
    context: UserContext,
    layout: ProcessLayout,
    handles: Option<HandleTable>,
    application_data: Option<Handle>,
    control: Option<ProcessControl>,
    state: ProcessState,
    preemption_count: u64,
    blocked_syscall: Option<BlockedSyscall>,
    shared_mappings: Option<Vec<SharedMemoryMapping>>,
    vmas: Option<Vec<VmArea>>,
    // If a corrupt page table prevents rollback, retaining the lease is safer
    // than releasing backing which may still have a live userspace alias.
    retained_failed_mapping_leases: Option<Vec<SharedMemoryMappingLease>>,
    next_mapping_cursor: u64,
    next_anonymous_reservation_id: u64,
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
        Self::from_elf_with_randomness(file, kernel, allocator, None)
    }

    /// Builds a process with independently randomized PIE, stack, and mapping regions.
    pub fn from_elf_randomized(
        file: &[u8],
        kernel: &ActivePageTable,
        allocator: &mut UsableFrameAllocator<'_>,
        randomness: [u64; 3],
    ) -> Result<Self, ProcessCreateError> {
        Self::from_elf_with_randomness(file, kernel, allocator, Some(randomness))
    }

    fn from_elf_with_randomness(
        file: &[u8],
        kernel: &ActivePageTable,
        allocator: &mut UsableFrameAllocator<'_>,
        randomness: Option<[u64; 3]>,
    ) -> Result<Self, ProcessCreateError> {
        let parsed = match randomness {
            Some(values) => elf::parse_randomized(file, values[0]),
            None => elf::parse(file),
        }
        .map_err(ProcessCreateError::Elf)?;
        let layout = randomness
            .map(|values| ProcessLayout::randomized(values[1]))
            .unwrap_or(ProcessLayout::STANDARD);
        let limits = ProcessLimits::STANDARD;
        let initial_stack_pages = layout.initial_stack_size() / PAGE_SIZE;
        if parsed
            .total_load_pages()
            .saturating_add(initial_stack_pages)
            > limits.private_pages
        {
            return Err(ProcessCreateError::ResourceLimit);
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

        let hhdm_offset = kernel.hhdm_offset();
        let address_space =
            AddressSpace::new(kernel, allocator).map_err(ProcessCreateError::AddressSpace)?;
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

        let vmas = match initial_vmas(&image, layout) {
            Ok(vmas) => vmas,
            Err(error) => {
                return reclaim_failed_construction(address_space, allocator, error);
            }
        };
        let private_pages = image
            .segments
            .iter()
            .map(|segment| segment.page_count)
            .sum::<u64>()
            .saturating_add(layout.initial_stack_size() / PAGE_SIZE);
        let context = UserContext::new(image.entry, layout.stack_top);
        debug_assert_eq!(context.rsp & 0xf, 0);

        Ok(Self {
            address_space: Some(address_space),
            context,
            layout,
            handles: Some(HandleTable::new()),
            application_data: None,
            control: None,
            state: ProcessState::Ready,
            preemption_count: 0,
            blocked_syscall: None,
            shared_mappings: Some(Vec::new()),
            vmas: Some(vmas),
            retained_failed_mapping_leases: Some(Vec::new()),
            next_mapping_cursor: SHARED_MAPPING_BASE
                + randomness
                    .map(|values| values[2] % MAPPING_ASLR_SLOTS)
                    .unwrap_or(0)
                    * PAGE_SIZE,
            next_anonymous_reservation_id: 1,
            limits,
            usage: ProcessUsage {
                private_pages,
                ..ProcessUsage::default()
            },
        })
    }

    pub const fn layout(&self) -> ProcessLayout {
        self.layout
    }

    pub const fn state(&self) -> ProcessState {
        self.state
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

    pub fn termination_requested(&self) -> bool {
        self.control
            .as_ref()
            .is_some_and(ProcessControl::terminate_requested)
    }

    pub fn mark_terminated(&mut self) {
        self.blocked_syscall = None;
        self.state = ProcessState::Terminated;
        if let Some(control) = &self.control {
            control.mark_terminated();
        }
    }

    pub fn publish_terminal_status(&self) {
        let Some(control) = &self.control else {
            return;
        };
        match self.state {
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

    pub const fn is_runnable(&self) -> bool {
        self.state.is_runnable()
    }

    pub const fn limits(&self) -> ProcessLimits {
        self.limits
    }

    pub const fn usage(&self) -> ProcessUsage {
        self.usage
    }

    /// Resolves an eligible non-present userspace stack fault transactionally.
    ///
    /// The supplied `user_rsp` must be the context captured with this fault, not
    /// the process's previously saved scheduler context. Ineligible faults retain
    /// their original page-fault code and address. Resource exhaustion is attributed
    /// only to this process; allocator invariants and rollback failures quarantine it
    /// with a stable `Other` fault rather than panicking the kernel.
    pub fn resolve_user_page_fault(
        &mut self,
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
        let Some(committed_bottom) = self.stack_committed_bottom() else {
            return self.stack_growth_invariant_fault(fault_address);
        };
        if fault_page < self.layout.stack_bottom || fault_page >= committed_bottom {
            return page_fault();
        }

        let pages = (committed_bottom - fault_page) / PAGE_SIZE;
        let Some(new_private_pages) = self.usage.private_pages.checked_add(pages) else {
            return UserPageFaultResolution::Fault(ProcessFault::at_address(
                ProcessFaultReason::ResourceLimit,
                error_code,
                fault_address,
            ));
        };
        if new_private_pages > self.limits.private_pages {
            return UserPageFaultResolution::Fault(ProcessFault::at_address(
                ProcessFaultReason::ResourceLimit,
                error_code,
                fault_address,
            ));
        }
        let planned_vmas = match plan_stack_growth(self.vmas(), fault_page, committed_bottom) {
            Ok(planned) => planned,
            Err(error) => {
                return stack_growth_planning_fault(error, error_code, fault_address);
            }
        };

        let mut mapped = 0usize;
        let mapped_len = (committed_bottom - fault_page) as usize;
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
                    AddressSpaceError::OutOfFrames => {
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

    fn stack_committed_bottom(&self) -> Option<u64> {
        self.vmas()
            .iter()
            .filter_map(|vma| match vma.kind {
                VmAreaKind::Stack { committed: true } => Some(vma.start),
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

    pub fn can_allocate_shared_memory(&self, bytes: usize) -> bool {
        self.usage
            .shared_memory_bytes
            .checked_add(bytes as u64)
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
    }

    pub const fn preemption_count(&self) -> u64 {
        self.preemption_count
    }

    pub fn record_preemption(&mut self) {
        self.preemption_count = self.preemption_count.saturating_add(1);
    }

    pub(crate) fn block_wait_many(&mut self, wait: PendingWaitMany) {
        assert_eq!(
            self.state,
            ProcessState::Ready,
            "only a ready process can block"
        );
        assert!(
            self.blocked_syscall.is_none(),
            "ready process retained a blocked syscall"
        );
        self.blocked_syscall = Some(BlockedSyscall::WaitMany(wait));
        self.state = ProcessState::Blocked;
    }

    pub(crate) fn blocked_wait_many_parts(&mut self) -> (&HandleTable, &mut PendingWaitMany) {
        assert_eq!(self.state, ProcessState::Blocked, "process is not blocked");
        let handles = self
            .handles
            .as_ref()
            .expect("live process lost its handle table");
        let wait = match self
            .blocked_syscall
            .as_mut()
            .expect("blocked process lost its syscall continuation")
        {
            BlockedSyscall::WaitMany(wait) => wait,
        };
        (handles, wait)
    }

    pub(crate) fn take_blocked_wait_many(&mut self) -> PendingWaitMany {
        assert_eq!(self.state, ProcessState::Blocked, "process is not blocked");
        match self
            .blocked_syscall
            .take()
            .expect("blocked process lost its syscall continuation")
        {
            BlockedSyscall::WaitMany(wait) => wait,
        }
    }

    pub(crate) fn resume_from_block(&mut self) {
        assert_eq!(self.state, ProcessState::Blocked, "process is not blocked");
        assert!(
            self.blocked_syscall.is_none(),
            "blocked syscall must be consumed before resuming"
        );
        self.state = ProcessState::Ready;
    }

    pub fn mark_exited(&mut self, code: i32) {
        self.blocked_syscall = None;
        self.state = ProcessState::Exited(code);
        self.publish_terminal_status();
    }

    pub fn mark_faulted(&mut self, reason: ProcessFault) {
        self.blocked_syscall = None;
        self.state = ProcessState::Faulted(reason);
        self.publish_terminal_status();
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

    pub const fn context(&self) -> &UserContext {
        &self.context
    }

    /// Installs a prepared direct-process startup block in the active child stack.
    pub(crate) fn install_direct_startup(
        &mut self,
        startup: &DirectStartupBlock,
    ) -> Result<(), AddressSpaceError> {
        let block_address = self
            .layout
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
        self.context.rsp = block_address;
        self.set_start_arguments([block_address, startup.bytes.len() as u64, 0, 0]);
        Ok(())
    }

    /// Sets the first four System V AMD64 arguments for the initial user entry.
    pub fn set_start_arguments(&mut self, [rdi, rsi, rdx, rcx]: [u64; 4]) {
        self.context.rdi = rdi;
        self.context.rsi = rsi;
        self.context.rdx = rdx;
        self.context.rcx = rcx;
    }

    pub fn context_mut(&mut self) -> &mut UserContext {
        &mut self.context
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
            self.layout.stack_guard_start,
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
        *self.vmas.as_mut().expect("live process lost its VMA table") = planned;
        self.next_mapping_cursor = if end < self.layout.stack_guard_start {
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
            .expect("live process lost its VMA table")
            .remove(index);
        self.next_mapping_cursor = rollback.previous_cursor;
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
        let pages = mapped_len as u64 / PAGE_SIZE;
        let new_private_pages = self
            .usage
            .private_pages
            .checked_add(pages)
            .filter(|total| *total <= self.limits.private_pages)
            .ok_or(SharedMappingError::ResourceLimit)?;

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
        // The reservation removal is semantically complete even if physical-frame
        // reclamation is deferred; retired ownership and sticky allocator error remain.
        let _ = self
            .address_space_mut()
            .reclaim_retired_data_frames(allocator);
        Ok(())
    }

    /// Maps an exact logical range of a shared-memory handle.
    ///
    /// The offset must be page aligned. The logical range need not end on a page
    /// boundary; the installed span is rounded up and remains within the backing's
    /// page-rounded allocation. Every kernel virtual page is translated separately.
    ///
    /// `kernel` is used only as a read-only mapper for the stable kernel root which
    /// maps the shared-memory allocation. That root need not be the current CR3:
    /// syscall dispatch invokes this while this process's [`AddressSpace`] is active.
    /// Non-syscall callers may map an inactive process, but must arrange any required
    /// activation and TLB synchronization before exposing the mapping to userspace.
    pub fn map_shared_memory(
        &mut self,
        kernel: &ActivePageTable,
        handle: Handle,
        args: SharedMemoryMapArgs,
        allocator: &mut UsableFrameAllocator<'_>,
    ) -> Result<u64, SharedMappingError> {
        let access = validate_protection(args.protection)?;
        validate_flags(args.flags)?;

        let lease = self.handles().shared_memory_mapping_lease(handle, access)?;
        let request = validate_mapping_range(lease.info(), args.offset, args.length)?;
        let new_mapped_total = self
            .usage
            .mapped_shared_bytes
            .checked_add(request.mapped_len as u64)
            .filter(|total| *total <= self.limits.mapped_shared_bytes)
            .ok_or(SharedMappingError::ResourceLimit)?;

        let occupied = self.occupied_ranges()?;
        let address = select_mapping_address(
            args.address,
            args.flags.contains(MapFlags::FIXED),
            request.mapped_len,
            self.next_mapping_cursor,
            self.layout.stack_guard_start,
            &occupied,
        )?;

        let planned_vmas = plan_vma_insert(
            self.vmas(),
            VmArea {
                start: address,
                end: address
                    .checked_add(request.mapped_len as u64)
                    .ok_or(SharedMappingError::RangeOverflow)?,
                kind: VmAreaKind::Shared,
                protection: args.protection,
            },
        )?;
        let frames = translate_backing_pages(kernel, lease.info(), request)?;
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
        if !args.flags.contains(MapFlags::FIXED) {
            self.next_mapping_cursor = address
                .checked_add(request.mapped_len as u64)
                .filter(|next| *next < self.layout.stack_guard_start)
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
        let mapped_len = self.shared_mappings()[index].mapped_len;
        let end = address
            .checked_add(mapped_len as u64)
            .ok_or(SharedMappingError::RangeOverflow)?;
        let planned_vmas = plan_vma_remove_kind(self.vmas(), address, end, VmAreaKind::Shared)?;
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
            mappings_released: shared_mappings.len(),
            anonymous_mappings_released: count_anonymous_reservations(&vmas),
            retained_failed_mapping_leases_released: retained_failed_mapping_leases.len(),
        };
        let address_space = unsafe { address_space.retire() };
        drop(shared_mappings);
        drop(vmas);
        drop(retained_failed_mapping_leases);
        drop(handles);

        Ok(RetiredProcess {
            address_space,
            context: self.context,
            final_state: self.state,
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
        // Reclamation failure is a kernel ownership-invariant violation, not the
        // original malformed-image or exhaustion error. Preserve the exact owner
        // for postmortem safety before entering the kernel's fail-stop path.
        mem::forget(cleanup_error);
        panic!("failed to reclaim partial process construction");
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
) -> Result<Vec<VmArea>, ProcessCreateError> {
    let mut vmas = Vec::new();
    vmas.try_reserve_exact(MAX_VMAS)
        .map_err(|_| ProcessCreateError::ResourceLimit)?;
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
            kind: VmAreaKind::StackGuard,
            protection: MapProtection::empty(),
        },
    )
    .map_err(|_| ProcessCreateError::ResourceLimit)?;
    push_merged_vma(
        &mut vmas,
        VmArea {
            start: layout.stack_bottom,
            end: layout.stack_initial_bottom,
            kind: VmAreaKind::Stack { committed: false },
            protection: MapProtection::READ | MapProtection::WRITE,
        },
    )
    .map_err(|_| ProcessCreateError::ResourceLimit)?;
    push_merged_vma(
        &mut vmas,
        VmArea {
            start: layout.stack_initial_bottom,
            end: layout.stack_top,
            kind: VmAreaKind::Stack { committed: true },
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
            && vmas[write_index - 1].kind == area.kind
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

fn clone_vma_plan(vmas: &[VmArea]) -> Result<Vec<VmArea>, SharedMappingError> {
    let mut planned = Vec::new();
    planned
        .try_reserve_exact(MAX_VMAS)
        .map_err(|_| SharedMappingError::OutOfMemory)?;
    planned.extend_from_slice(vmas);
    Ok(planned)
}

fn push_merged_vma(vmas: &mut Vec<VmArea>, area: VmArea) -> Result<(), SharedMappingError> {
    if area.start >= area.end {
        return Err(SharedMappingError::RangeOverflow);
    }
    if let Some(previous) = vmas.last_mut() {
        if previous.end == area.start
            && previous.kind == area.kind
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
        .try_reserve_exact(MAX_VMAS)
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
        if area.start > covered || area.kind != (VmAreaKind::Stack { committed: false }) {
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
                kind: VmAreaKind::Stack { committed: true },
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
        .try_reserve_exact(MAX_VMAS)
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
        .try_reserve_exact(MAX_VMAS)
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
    let base = info.base as usize as u64;
    if base % PAGE_SIZE != 0 {
        return Err(SharedMappingError::InvalidBackingAlignment(base));
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

fn translate_backing_pages(
    kernel: &ActivePageTable,
    info: SharedMemoryMappingInfo,
    request: ValidatedMappingRange,
) -> Result<Vec<PhysFrame<Size4KiB>>, SharedMappingError> {
    let page_count = request.mapped_len / PAGE_SIZE as usize;
    let mut frames = Vec::new();
    frames
        .try_reserve_exact(page_count)
        .map_err(|_| SharedMappingError::OutOfMemory)?;
    let base = info.base as usize as u64;
    for page_index in 0..page_count {
        let page_offset = page_index
            .checked_mul(PAGE_SIZE as usize)
            .and_then(|offset| request.offset.checked_add(offset))
            .ok_or(SharedMappingError::RangeOverflow)?;
        let kernel_address = base
            .checked_add(page_offset as u64)
            .ok_or(SharedMappingError::RangeOverflow)?;
        let virtual_address = VirtAddr::try_new(kernel_address)
            .map_err(|_| SharedMappingError::InvalidKernelAddress(kernel_address))?;
        let physical_address = kernel
            .translate_addr(virtual_address)
            .ok_or(SharedMappingError::KernelAddressNotMapped(kernel_address))?;
        let frame = PhysFrame::from_start_address(physical_address).map_err(|_| {
            SharedMappingError::PhysicalAddressNotPageAligned(physical_address.as_u64())
        })?;
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

    /// Selects the next live process ID in deterministic round-robin slot order.
    ///
    /// Selection includes non-runnable processes so a permanent process-runner
    /// task can poll blocked syscalls and retire exited or faulted entries. Empty
    /// and retired slots are skipped. Reused slots are returned with their current generation,
    /// so an ID returned before removal never aliases its replacement.
    pub fn next_id(&mut self) -> Option<ProcessId> {
        self.inner.next_id()
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

    use super::*;

    static FRAME_RECLAIM_TEST_ELF: &[u8] =
        include_bytes!(concat!(env!("OUT_DIR"), "/ginkgo-frame-reclaim-exit.elf"));

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
            base: 0x1000usize as *const u8,
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
        Process {
            address_space: None,
            context: UserContext::new(0x1000, USER_STACK_TOP),
            layout: ProcessLayout::STANDARD,
            handles: None,
            application_data: None,
            control: None,
            state,
            preemption_count: 0,
            blocked_syscall: None,
            shared_mappings: None,
            vmas: None,
            retained_failed_mapping_leases: None,
            next_mapping_cursor: SHARED_MAPPING_BASE,
            next_anonymous_reservation_id: 1,
            limits: ProcessLimits::STANDARD,
            usage: ProcessUsage::default(),
        }
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

        process
            .commit_anonymous(address + PAGE_SIZE, PAGE_SIZE * 2, &mut allocator)
            .unwrap();
        assert_eq!(process.usage().private_pages, baseline_private + 2);
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
    #[should_panic(expected = "failed to reclaim partial process construction")]
    fn construction_cleanup_failure_is_fail_stop_not_the_original_error() {
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
        }
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
        process.preemption_count = u64::MAX;
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
        assert!(process.blocked_syscall.is_some());

        let wait = process.take_blocked_wait_many();
        assert_eq!(wait.deadline, WaitDeadline::At(25));
        assert!(process.blocked_syscall.is_none());
        process.resume_from_block();
        assert_eq!(process.state(), ProcessState::Ready);
    }

    #[test]
    fn terminal_transition_drops_blocked_wait_state() {
        let mut exited = test_process(ProcessState::Ready);
        exited.block_wait_many(pending_wait(WaitDeadline::Infinite));
        exited.mark_exited(7);
        assert_eq!(exited.state(), ProcessState::Exited(7));
        assert!(exited.blocked_syscall.is_none());

        let mut faulted = test_process(ProcessState::Ready);
        faulted.block_wait_many(pending_wait(WaitDeadline::Infinite));
        let fault = ProcessFault::new(ProcessFaultReason::InvalidOpcode, 6);
        faulted.mark_faulted(fault);
        assert_eq!(faulted.state(), ProcessState::Faulted(fault));
        assert!(faulted.blocked_syscall.is_none());
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
                && vma.kind == VmAreaKind::StackGuard
        }));
        assert!(process.vmas().iter().any(|vma| {
            vma.start == layout.stack_bottom
                && vma.end == layout.stack_initial_bottom
                && vma.kind == (VmAreaKind::Stack { committed: false })
        }));
        assert!(process.vmas().iter().any(|vma| {
            vma.start == layout.stack_initial_bottom
                && vma.end == layout.stack_top
                && vma.kind == (VmAreaKind::Stack { committed: true })
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
        assert_eq!(process.stack_committed_bottom(), Some(fault_page));
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
        process
            .vmas
            .as_mut()
            .unwrap()
            .retain(|vma| !matches!(vma.kind, VmAreaKind::Stack { committed: true }));
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
        assert!(process.can_allocate_shared_memory(1024));
        process.usage.shared_memory_bytes = process.limits.shared_memory_bytes;
        assert!(!process.can_allocate_shared_memory(1));
        assert!(process.can_send_channel_bytes(1));
        process.usage.channel_traffic_bytes = process.limits.channel_traffic_bytes;
        assert!(!process.can_send_channel_bytes(1));
        process.record_cpu_time(25);
        assert_eq!(process.usage.cpu_time_ns, 25);
    }

    #[test]
    fn start_arguments_set_abi_registers_without_changing_other_context() {
        let mut process = test_process(ProcessState::Ready);
        process.context.rax = 4;
        process.context.rbx = 5;
        let mut expected = process.context;
        expected.rdi = 1;
        expected.rsi = 2;
        expected.rdx = 3;
        expected.rcx = 4;

        process.set_start_arguments([1, 2, 3, 4]);

        assert_eq!(process.context, expected);
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
