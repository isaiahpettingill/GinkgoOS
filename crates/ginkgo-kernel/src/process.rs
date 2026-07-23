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

pub const USER_STACK_SIZE: u64 = 64 * 1024;
pub const USER_STACK_TOP: u64 = 0x0000_7fff_ffff_f000;
pub const USER_STACK_BOTTOM: u64 = USER_STACK_TOP - USER_STACK_SIZE;
pub const USER_STACK_GUARD_START: u64 = USER_STACK_BOTTOM - PAGE_SIZE;
pub const SHARED_MAPPING_BASE: u64 = 0x0000_0001_0000_0000;

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
        if total_size > USER_STACK_SIZE as usize {
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

/// Fixed initial userspace stack layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessLayout {
    pub stack_guard_start: u64,
    pub stack_bottom: u64,
    pub stack_top: u64,
}

impl ProcessLayout {
    pub const STANDARD: Self = Self {
        stack_guard_start: USER_STACK_GUARD_START,
        stack_bottom: USER_STACK_BOTTOM,
        stack_top: USER_STACK_TOP,
    };

    pub const fn stack_size(self) -> u64 {
        self.stack_top - self.stack_bottom
    }

    pub const fn randomized(random: u64) -> Self {
        let displacement = (random % STACK_ASLR_SLOTS) * STACK_ASLR_ALIGNMENT;
        let stack_top = USER_STACK_TOP - displacement;
        let stack_bottom = stack_top - USER_STACK_SIZE;
        Self {
            stack_guard_start: stack_bottom - PAGE_SIZE,
            stack_bottom,
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
        private_pages: 20_000,
        shared_memory_bytes: 64 * 1024 * 1024,
        mapped_shared_bytes: 64 * 1024 * 1024,
        channel_traffic_bytes: 64 * 1024 * 1024,
        cpu_quantum_ns: 10_000_000,
    };
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProcessUsage {
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

/// One exact application-visible shared-memory mapping.
///
/// `length` is the logical byte length supplied by the application, while
/// `mapped_len` is the page-rounded span installed in the address space.
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
    // If a corrupt page table prevents rollback, retaining the lease is safer
    // than releasing backing which may still have a live userspace alias.
    retained_failed_mapping_leases: Option<Vec<SharedMemoryMappingLease>>,
    next_mapping_cursor: u64,
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
        let stack_pages = layout.stack_size() / PAGE_SIZE;
        if parsed.total_load_pages().saturating_add(stack_pages) > limits.private_pages {
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

        let mut stack_page = layout.stack_bottom;
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
            layout.stack_bottom,
            layout.stack_size() as usize,
            UserAccess::Write,
        ) {
            return reclaim_failed_construction(
                address_space,
                allocator,
                ProcessCreateError::StackNotWritable(error),
            );
        }

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
            retained_failed_mapping_leases: Some(Vec::new()),
            next_mapping_cursor: SHARED_MAPPING_BASE
                + randomness
                    .map(|values| values[2] % MAPPING_ASLR_SLOTS)
                    .unwrap_or(0)
                    * PAGE_SIZE,
            limits,
            usage: ProcessUsage::default(),
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
            &occupied,
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
                        return Err(SharedMappingError::RollbackFailed {
                            mapping_error,
                            rollback_error,
                        });
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
        self.usage.mapped_shared_bytes = new_mapped_total;
        if !args.flags.contains(MapFlags::FIXED) {
            self.next_mapping_cursor = address
                .checked_add(request.mapped_len as u64)
                .filter(|next| *next < USER_STACK_GUARD_START)
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
        self.address_space_mut()
            .unmap_user_range(address, mapped_len)
            .map_err(SharedMappingError::AddressSpace)?;
        self.shared_mappings
            .as_mut()
            .expect("live process lost its mapping records")
            .swap_remove(index);
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
        let retained_failed_mapping_leases = self
            .retained_failed_mapping_leases
            .take()
            .expect("live process lost its retained leases");
        let teardown = ProcessTeardown {
            handles_closed: handles.len(),
            mappings_released: shared_mappings.len(),
            retained_failed_mapping_leases_released: retained_failed_mapping_leases.len(),
        };
        let address_space = unsafe { address_space.retire() };
        drop(shared_mappings);
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
        let mappings = self.address_space().mappings();
        let mut occupied = Vec::new();
        occupied
            .try_reserve_exact(mappings.len() + 1)
            .map_err(|_| SharedMappingError::OutOfMemory)?;
        occupied.push(
            VirtualRange::new(self.layout.stack_guard_start, self.layout.stack_top)
                .expect("static stack layout is valid"),
        );
        for mapping in mappings {
            occupied.push(
                VirtualRange::page(mapping.virtual_address)
                    .ok_or(SharedMappingError::RangeOverflow)?,
            );
        }
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
        retain_unretired_resource(&mut self.retained_failed_mapping_leases);
        retain_unretired_resource(&mut self.handles);
    }
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
    const fn new(start: u64, end: u64) -> Option<Self> {
        if start < end {
            Some(Self { start, end })
        } else {
            None
        }
    }

    fn page(address: u64) -> Option<Self> {
        address
            .checked_add(PAGE_SIZE)
            .and_then(|end| Self::new(address, end))
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
        .filter(|address| *address < USER_STACK_GUARD_START)
        .unwrap_or(SHARED_MAPPING_BASE);
    if let Some(address) = first_fit_mapping(start, USER_STACK_GUARD_START, mapped_len, occupied)? {
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
        let parsed = elf::parse(FRAME_RECLAIM_TEST_ELF).map_err(ProcessCreateError::Elf)?;
        let address_space =
            AddressSpace::new_for_test(allocator).map_err(ProcessCreateError::AddressSpace)?;
        Process::finish_construction(
            parsed,
            address_space,
            VirtAddr::zero(),
            ProcessLayout::STANDARD,
            ProcessLimits::STANDARD,
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
            retained_failed_mapping_leases: None,
            next_mapping_cursor: SHARED_MAPPING_BASE,
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
    fn standard_layout_has_guard_and_aligned_stack() {
        let layout = ProcessLayout::STANDARD;
        assert_eq!(layout.stack_size(), 64 * 1024);
        assert_eq!(layout.stack_bottom - layout.stack_guard_start, PAGE_SIZE);
        assert_eq!(layout.stack_bottom % PAGE_SIZE, 0);
        assert_eq!(layout.stack_top % 16, 0);
        assert!(layout.stack_top < USER_ADDRESS_END);
    }

    #[test]
    fn randomized_layout_stays_aligned_bounded_and_seed_dependent() {
        let first = ProcessLayout::randomized(1);
        let second = ProcessLayout::randomized(2);
        assert_ne!(first, second);
        for layout in [first, second] {
            assert_eq!(layout.stack_size(), USER_STACK_SIZE);
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
            select_mapping_address(0x8000, true, 4096, SHARED_MAPPING_BASE, &occupied),
            Ok(0x8000)
        );
        assert_eq!(
            select_mapping_address(0x5000, true, 4096, SHARED_MAPPING_BASE, &occupied),
            Err(SharedMappingError::AlreadyMapped(0x5000))
        );
        assert_eq!(
            select_mapping_address(0x8001, true, 4096, SHARED_MAPPING_BASE, &occupied),
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
            select_mapping_address(0xa001, false, 4096, SHARED_MAPPING_BASE, &occupied),
            Ok(0xb000)
        );
        assert_eq!(
            select_mapping_address(0x8000, false, 4096, SHARED_MAPPING_BASE, &occupied),
            Ok(SHARED_MAPPING_BASE + PAGE_SIZE)
        );
    }

    #[test]
    fn automatic_selection_stays_below_stack_guard() {
        let occupied =
            [VirtualRange::new(SHARED_MAPPING_BASE, USER_STACK_GUARD_START - PAGE_SIZE).unwrap()];
        assert_eq!(
            select_mapping_address(0, false, PAGE_SIZE as usize, SHARED_MAPPING_BASE, &occupied),
            Ok(USER_STACK_GUARD_START - PAGE_SIZE)
        );
        assert_eq!(
            select_mapping_address(
                0,
                false,
                (PAGE_SIZE * 2) as usize,
                SHARED_MAPPING_BASE,
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
