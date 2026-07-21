//! User process ownership, ELF construction, and shared-memory mappings.

use alloc::vec::Vec;
use core::{fmt, mem, ptr};

use ginkgo_ipc::{
    Handle, HandleTable, IpcError, SharedMemoryMappingAccess, SharedMemoryMappingInfo,
    SharedMemoryMappingLease,
};
#[cfg(test)]
use ginkgo_sysapi::Rights;
use ginkgo_sysapi::{MapFlags, MapProtection, SharedMemoryMapArgs};
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
            AddressSpace, AddressSpaceError, RetiredAddressSpace, UserAccess, UserPagePermissions,
        },
        ActivePageTable,
    },
};

pub const USER_STACK_SIZE: u64 = 64 * 1024;
pub const USER_STACK_TOP: u64 = 0x0000_7fff_ffff_f000;
pub const USER_STACK_BOTTOM: u64 = USER_STACK_TOP - USER_STACK_SIZE;
pub const USER_STACK_GUARD_START: u64 = USER_STACK_BOTTOM - PAGE_SIZE;
pub const SHARED_MAPPING_BASE: u64 = 0x0000_0001_0000_0000;
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
    Exited(i32),
    Faulted(ProcessFault),
}

impl ProcessState {
    pub const fn is_runnable(self) -> bool {
        matches!(self, Self::Ready)
    }
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
    handles: Option<HandleTable>,
    state: ProcessState,
    shared_mappings: Option<Vec<SharedMemoryMapping>>,
    // If a corrupt page table prevents rollback, retaining the lease is safer
    // than releasing backing which may still have a live userspace alias.
    retained_failed_mapping_leases: Option<Vec<SharedMemoryMappingLease>>,
    next_mapping_cursor: u64,
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
        let parsed = elf::parse(file).map_err(ProcessCreateError::Elf)?;
        if parsed
            .overlaps_reserved_range(
                USER_STACK_GUARD_START,
                USER_STACK_TOP - USER_STACK_GUARD_START,
            )
            .expect("static stack reservation is a valid user range")
        {
            return Err(ProcessCreateError::StackCollision);
        }

        let hhdm_offset = kernel.hhdm_offset();
        let mut address_space =
            AddressSpace::new(kernel, allocator).map_err(ProcessCreateError::AddressSpace)?;

        let loaded = parsed.load_with(|address, permissions, contents| {
            let permissions = user_permissions(permissions);
            let frame = address_space
                .map_zeroed_user_4k(address, permissions, allocator)
                .map_err(|error| ElfPageLoadError::AddressSpace { address, error })?;
            copy_page_through_hhdm(hhdm_offset, frame, contents)
        });
        let image = match loaded {
            Ok(image) => image,
            Err(LoadError::Elf(error)) => return Err(ProcessCreateError::Elf(error)),
            Err(LoadError::Page(error)) => return Err(ProcessCreateError::ElfPage(error)),
        };

        let mut stack_page = USER_STACK_BOTTOM;
        while stack_page < USER_STACK_TOP {
            address_space
                .map_zeroed_user_4k(stack_page, UserPagePermissions::READ_WRITE, allocator)
                .map_err(|error| ProcessCreateError::StackPage {
                    address: stack_page,
                    error,
                })?;
            stack_page += PAGE_SIZE;
        }

        address_space
            .validate_user_range(image.entry, 1, UserAccess::Execute)
            .map_err(ProcessCreateError::EntryNotExecutable)?;
        address_space
            .validate_user_range(
                USER_STACK_BOTTOM,
                USER_STACK_SIZE as usize,
                UserAccess::Write,
            )
            .map_err(ProcessCreateError::StackNotWritable)?;

        let context = UserContext::new(image.entry, USER_STACK_TOP);
        debug_assert_eq!(context.rsp & 0xf, 0);

        Ok(Self {
            address_space: Some(address_space),
            context,
            handles: Some(HandleTable::new()),
            state: ProcessState::Ready,
            shared_mappings: Some(Vec::new()),
            retained_failed_mapping_leases: Some(Vec::new()),
            next_mapping_cursor: SHARED_MAPPING_BASE,
        })
    }

    pub const fn layout(&self) -> ProcessLayout {
        ProcessLayout::STANDARD
    }

    pub const fn state(&self) -> ProcessState {
        self.state
    }

    pub const fn is_runnable(&self) -> bool {
        self.state.is_runnable()
    }

    pub fn mark_exited(&mut self, code: i32) {
        self.state = ProcessState::Exited(code);
    }

    pub fn mark_faulted(&mut self, reason: ProcessFault) {
        self.state = ProcessState::Faulted(reason);
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

    /// Sets the first three System V AMD64 arguments for the initial user entry.
    ///
    /// Call this after process creation and before the process is first entered.
    /// The arguments are installed in `rdi`, `rsi`, and `rdx`, respectively.
    pub fn set_start_arguments(&mut self, [rdi, rsi, rdx]: [u64; 3]) {
        self.context.rdi = rdi;
        self.context.rsi = rsi;
        self.context.rdx = rdx;
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
            VirtualRange::new(USER_STACK_GUARD_START, USER_STACK_TOP)
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
    len: usize,
}

impl<T> GenerationalSlots<T> {
    const fn new() -> Self {
        Self {
            slots: Vec::new(),
            len: 0,
        }
    }

    fn insert(&mut self, value: T) -> Result<ProcessId, ProcessTableError> {
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

    pub fn insert(&mut self, process: Process) -> Result<ProcessId, ProcessTableError> {
        self.inner.insert(process)
    }

    pub fn get(&self, id: ProcessId) -> Option<&Process> {
        self.inner.get(id)
    }

    pub fn get_mut(&mut self, id: ProcessId) -> Option<&mut Process> {
        self.inner.get_mut(id)
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
    use core::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

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
            len: 1,
        };
        let final_id = ProcessId::from_parts(0, u32::MAX);
        assert_eq!(table.remove(final_id), Some(7));
        assert_eq!(table.slots[0].generation, 0);

        let replacement = table.insert(8).unwrap();
        assert_eq!(replacement.slot(), 1);
        assert_eq!(table.get(final_id), None);
        assert_eq!(table.get(replacement), Some(&8));
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
    fn process_states_retain_completion_details_and_only_ready_is_runnable() {
        let fault = ProcessFault::at_address(ProcessFaultReason::PageFault, 0b101, 0xdead_beef);
        let ready = ProcessState::Ready;
        let exited = ProcessState::Exited(-17);
        let faulted = ProcessState::Faulted(fault);

        assert!(ready.is_runnable());
        assert!(!exited.is_runnable());
        assert!(!faulted.is_runnable());
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
    fn standard_layout_has_guard_and_aligned_stack() {
        let layout = ProcessLayout::STANDARD;
        assert_eq!(layout.stack_size(), 64 * 1024);
        assert_eq!(layout.stack_bottom - layout.stack_guard_start, PAGE_SIZE);
        assert_eq!(layout.stack_bottom % PAGE_SIZE, 0);
        assert_eq!(layout.stack_top % 16, 0);
        assert!(layout.stack_top < USER_ADDRESS_END);
    }

    #[test]
    fn start_arguments_set_abi_registers_without_changing_other_context() {
        let mut process = Process {
            address_space: None,
            context: UserContext::new(0x1000, USER_STACK_TOP),
            handles: None,
            state: ProcessState::Ready,
            shared_mappings: None,
            retained_failed_mapping_leases: None,
            next_mapping_cursor: SHARED_MAPPING_BASE,
        };
        process.context.rax = 4;
        process.context.rbx = 5;
        let mut expected = process.context;
        expected.rdi = 1;
        expected.rsi = 2;
        expected.rdx = 3;

        process.set_start_arguments([1, 2, 3]);

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
