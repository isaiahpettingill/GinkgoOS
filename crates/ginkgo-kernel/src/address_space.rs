//! Isolated four-level x86_64 user address spaces.
//!
//! User roots own their lower-half page-table tree and share only the kernel
//! half of the P4. Dropping an address space does not implicitly edit page tables
//! or return frames; inactive spaces must be explicitly retired and reclaimed.

use alloc::vec::Vec;
use core::ptr;

use x86_64::structures::paging::{
    mapper::{FlagUpdateError, MapToError, MapperFlush, UnmapError as X86UnmapError},
    FrameAllocator, Mapper, OffsetPageTable, Page, PageTable, PhysFrame, Size4KiB,
};
use x86_64::VirtAddr;

#[cfg(test)]
use x86_64::PhysAddr;

use crate::{
    arch,
    memory::{FrameAllocatorError, UsableFrameAllocator, PAGE_SIZE},
};

use super::{ActivePageTable, MapError, PageTableFlags};

const USER_P4_ENTRIES: usize = 256;
pub const USER_ADDRESS_MAX: u64 = 0x0000_7fff_ffff_ffff;
pub const KERNEL_ADDRESS_START: u64 = 0xffff_8000_0000_0000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserAccess {
    Read,
    Write,
    Execute,
}

/// Permissions for a readable user page.
///
/// Construction rejects writable-and-executable pages, so all mappings enforce
/// W^X. Readability is implicit because x86_64 has no independent read-disable
/// page-table bit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserPagePermissions {
    writable: bool,
    executable: bool,
}

impl UserPagePermissions {
    pub const READ_ONLY: Self = Self {
        writable: false,
        executable: false,
    };
    pub const READ_WRITE: Self = Self {
        writable: true,
        executable: false,
    };
    pub const READ_EXECUTE: Self = Self {
        writable: false,
        executable: true,
    };

    pub const fn new(writable: bool, executable: bool) -> Result<Self, AddressSpaceError> {
        if writable && executable {
            Err(AddressSpaceError::WritableExecutable)
        } else {
            Ok(Self {
                writable,
                executable,
            })
        }
    }

    pub const fn is_writable(self) -> bool {
        self.writable
    }

    pub const fn is_executable(self) -> bool {
        self.executable
    }

    fn page_table_flags(self) -> PageTableFlags {
        let mut flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
        if self.writable {
            flags |= PageTableFlags::WRITABLE;
        }
        if !self.executable {
            flags |= PageTableFlags::NO_EXECUTE;
        }
        flags
    }
}

impl Default for UserPagePermissions {
    fn default() -> Self {
        Self::READ_ONLY
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressSpaceError {
    /// Retained for exhaustive status translation. Safe address-space creation
    /// derives an already-validated offset from `ActivePageTable` and cannot emit it.
    InvalidHhdmOffset,
    AddressOverflow,
    NonCanonicalAddress(u64),
    HigherHalfAddress(u64),
    ZeroPage,
    UnalignedAddress(u64),
    WritableExecutable,
    AlreadyMapped(u64),
    NotMapped(u64),
    PermissionDenied {
        address: u64,
        access: UserAccess,
    },
    CorruptPageTable,
    HugePageConflict,
    FrameAlreadyOwned(PhysFrame<Size4KiB>),
    DuplicateSharedAlias(PhysFrame<Size4KiB>),
    MappedFrameNotOwned(PhysFrame<Size4KiB>),
    UntrackedMapping(u64),
    InvalidRangeLength(usize),
    ActiveAddressSpaceRequired,
    UserCopyFault,
    ActiveKernelPageTableRequired,
    /// Reserved for callers that require an already-hardened source root.
    /// `AddressSpace::new` instead clears this bit while copying kernel entries.
    UserAccessibleKernelP4Entry(usize),
    OutOfFrames,
    FrameAllocator(FrameAllocatorError),
    KernelPageTable(MapError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserMappingBacking {
    /// A uniquely owned private frame that retires when unmapped.
    OwnedPrivate,
    /// A non-owning alias of a frame whose lifetime is managed externally.
    SharedAlias,
}

/// Metadata for one tracked 4 KiB user mapping.
///
/// `frame` identifies the physical backing. For `SharedAlias`, it is never an
/// ownership token and must not be retired or returned to an allocator by this
/// address space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserPageMapping {
    pub virtual_address: u64,
    pub frame: PhysFrame<Size4KiB>,
    pub backing: UserMappingBacking,
    pub permissions: UserPagePermissions,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameAccounting {
    /// Currently mapped owned-private frames; shared aliases are excluded.
    pub mapped_data_frames: usize,
    /// Unmapped owned-private frames; shared aliases are never added here.
    pub retired_data_frames: usize,
    /// Non-owning mappings, deliberately excluded from owned frame counts.
    pub shared_alias_mappings: usize,
    /// Includes the P4 root and every allocated lower-half paging structure.
    pub page_table_frames: usize,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FrameReclaimStats {
    pub mapped_data_frames: usize,
    pub retired_data_frames: usize,
    pub page_table_frames: usize,
    pub shared_alias_mappings_excluded: usize,
}

impl FrameReclaimStats {
    pub const fn total_frames(self) -> usize {
        self.mapped_data_frames + self.retired_data_frames + self.page_table_frames
    }
}

/// A reclaim failure with exact ownership of every frame not yet reclaimed.
pub struct RetiredAddressSpaceReclaimError {
    address_space: RetiredAddressSpace,
    error: FrameAllocatorError,
    reclaimed: FrameReclaimStats,
}

impl RetiredAddressSpaceReclaimError {
    pub const fn error(&self) -> FrameAllocatorError {
        self.error
    }

    pub const fn reclaimed(&self) -> FrameReclaimStats {
        self.reclaimed
    }

    pub const fn address_space(&self) -> &RetiredAddressSpace {
        &self.address_space
    }

    pub fn into_address_space(self) -> RetiredAddressSpace {
        self.address_space
    }
}

impl core::fmt::Debug for RetiredAddressSpaceReclaimError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("RetiredAddressSpaceReclaimError")
            .field("error", &self.error)
            .field("reclaimed", &self.reclaimed)
            .field("remaining", &self.address_space.accounting())
            .finish()
    }
}

/// Owned physical frames and non-owning alias metadata retained after retirement.
///
/// Kernel higher-half paging structures are shared and therefore deliberately
/// absent. None of the owned frames have been returned to the allocator, and
/// `shared_alias_mappings` never conveys ownership of its physical frames.
pub struct RetiredAddressSpace {
    root: PhysFrame<Size4KiB>,
    mapped_data_frames: Vec<PhysFrame<Size4KiB>>,
    retired_data_frames: Vec<PhysFrame<Size4KiB>>,
    shared_alias_mappings: Vec<UserPageMapping>,
    page_table_frames: Vec<PhysFrame<Size4KiB>>,
}

impl RetiredAddressSpace {
    pub fn root_frame(&self) -> PhysFrame<Size4KiB> {
        self.root
    }

    pub fn mapped_data_frames(&self) -> &[PhysFrame<Size4KiB>] {
        &self.mapped_data_frames
    }

    pub fn retired_data_frames(&self) -> &[PhysFrame<Size4KiB>] {
        &self.retired_data_frames
    }

    pub fn shared_alias_mappings(&self) -> &[UserPageMapping] {
        &self.shared_alias_mappings
    }

    pub fn page_table_frames(&self) -> &[PhysFrame<Size4KiB>] {
        &self.page_table_frames
    }

    pub fn accounting(&self) -> FrameAccounting {
        FrameAccounting {
            mapped_data_frames: self.mapped_data_frames.len(),
            retired_data_frames: self.retired_data_frames.len(),
            shared_alias_mappings: self.shared_alias_mappings.len(),
            page_table_frames: self.page_table_frames.len(),
        }
    }

    /// Returns every owned frame to `allocator` exactly once.
    ///
    /// Shared aliases are never submitted. Each category is reclaimed atomically;
    /// if a later category fails, the returned owner contains only the categories
    /// that remain live and may be passed to `reclaim` again.
    pub fn reclaim(
        self,
        allocator: &mut UsableFrameAllocator<'_>,
    ) -> Result<FrameReclaimStats, RetiredAddressSpaceReclaimError> {
        self.reclaim_with(allocator)
    }

    fn reclaim_with<R: FrameReclaimer>(
        mut self,
        allocator: &mut R,
    ) -> Result<FrameReclaimStats, RetiredAddressSpaceReclaimError> {
        let mut reclaimed = FrameReclaimStats {
            shared_alias_mappings_excluded: self.shared_alias_mappings.len(),
            ..FrameReclaimStats::default()
        };

        for category in [
            ReclaimCategory::MappedData,
            ReclaimCategory::RetiredData,
            ReclaimCategory::PageTable,
        ] {
            if let Err(error) = reclaim_category(&mut self, allocator, category, &mut reclaimed) {
                return Err(RetiredAddressSpaceReclaimError {
                    address_space: self,
                    error,
                    reclaimed,
                });
            }
        }
        Ok(reclaimed)
    }
}

trait FrameReclaimer {
    fn reclaim(&mut self, frames: &[PhysFrame<Size4KiB>]) -> Result<(), FrameAllocatorError>;
}

impl FrameReclaimer for UsableFrameAllocator<'_> {
    fn reclaim(&mut self, frames: &[PhysFrame<Size4KiB>]) -> Result<(), FrameAllocatorError> {
        self.reclaim_frames(frames)
    }
}

#[derive(Clone, Copy)]
enum ReclaimCategory {
    MappedData,
    RetiredData,
    PageTable,
}

fn reclaim_category<R: FrameReclaimer>(
    address_space: &mut RetiredAddressSpace,
    allocator: &mut R,
    category: ReclaimCategory,
    reclaimed: &mut FrameReclaimStats,
) -> Result<(), FrameAllocatorError> {
    let frames = match category {
        ReclaimCategory::MappedData => &mut address_space.mapped_data_frames,
        ReclaimCategory::RetiredData => &mut address_space.retired_data_frames,
        ReclaimCategory::PageTable => &mut address_space.page_table_frames,
    };
    allocator.reclaim(frames)?;

    let count = frames.len();
    frames.clear();
    match category {
        ReclaimCategory::MappedData => reclaimed.mapped_data_frames += count,
        ReclaimCategory::RetiredData => reclaimed.retired_data_frames += count,
        ReclaimCategory::PageTable => reclaimed.page_table_frames += count,
    }
    Ok(())
}

/// Failure to clean up an address space that must no longer be active.
pub enum InactiveAddressSpaceCleanupError {
    Active(AddressSpace),
    Reclaim(RetiredAddressSpaceReclaimError),
}

impl core::fmt::Debug for InactiveAddressSpaceCleanupError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Active(address_space) => formatter
                .debug_tuple("Active")
                .field(&address_space.root_frame())
                .finish(),
            Self::Reclaim(error) => formatter.debug_tuple("Reclaim").field(error).finish(),
        }
    }
}

/// An isolated user address space with a shared kernel higher half.
///
/// The mapper and frame lists are intentionally private, preventing callers
/// from editing a kernel P4 entry or claiming that a physical frame was freed.
/// Kernel P4 entries are copied when this object is created; callers must keep
/// the kernel's higher-half P4 topology stable for this address space's life.
pub struct AddressSpace {
    root: PhysFrame<Size4KiB>,
    hhdm_offset: VirtAddr,
    mapper: OffsetPageTable<'static>,
    mappings: Vec<UserPageMapping>,
    owned_data_frames: Vec<PhysFrame<Size4KiB>>,
    retired_data_frames: Vec<PhysFrame<Size4KiB>>,
    owned_page_table_frames: Vec<PhysFrame<Size4KiB>>,
}

impl AddressSpace {
    /// Allocates and initializes a user P4 while the supplied kernel table is active.
    ///
    /// The active kernel paging structures are first reserved in `allocator`.
    /// The new root is then zeroed through the authoritative HHDM recorded by
    /// `kernel`, and only P4 entries 256–511 are cloned from the kernel root.
    /// `USER_ACCESSIBLE` is cleared on every cloned root entry, so the process
    /// cannot access higher-half mappings even if firmware or the bootloader set
    /// permissive flags in the source topology. Entries 0–255 remain empty.
    pub fn new(
        kernel: &ActivePageTable,
        allocator: &mut UsableFrameAllocator<'_>,
    ) -> Result<Self, AddressSpaceError> {
        if !kernel.is_active() {
            return Err(AddressSpaceError::ActiveKernelPageTableRequired);
        }
        let hhdm_offset = kernel.hhdm_offset();
        kernel
            .reserve_active_frames(allocator)
            .map_err(AddressSpaceError::KernelPageTable)?;

        let root = allocator
            .allocate_frame()
            .map_err(AddressSpaceError::FrameAllocator)?
            .ok_or(AddressSpaceError::OutOfFrames)?;
        let root_address = match frame_hhdm_address(hhdm_offset, root) {
            Ok(address) => address,
            Err(error) => {
                allocator
                    .deallocate_frame(root)
                    .map_err(AddressSpaceError::FrameAllocator)?;
                return Err(error);
            }
        };
        let root_table = unsafe { &mut *root_address.as_mut_ptr::<PageTable>() };
        copy_kernel_half(kernel.mapper.level_4_table(), root_table);
        let mapper = unsafe { OffsetPageTable::new(root_table, hhdm_offset) };

        Ok(Self {
            root,
            hhdm_offset,
            mapper,
            mappings: Vec::new(),
            owned_data_frames: Vec::new(),
            retired_data_frames: Vec::new(),
            owned_page_table_frames: alloc::vec![root],
        })
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(
        allocator: &mut UsableFrameAllocator<'_>,
    ) -> Result<Self, AddressSpaceError> {
        let root = allocator
            .allocate_frame()
            .map_err(AddressSpaceError::FrameAllocator)?
            .ok_or(AddressSpaceError::OutOfFrames)?;
        let root_table = unsafe { &mut *(root.start_address().as_u64() as *mut PageTable) };
        root_table.zero();
        let mapper = unsafe { OffsetPageTable::new(root_table, VirtAddr::zero()) };
        Ok(Self {
            root,
            hhdm_offset: VirtAddr::zero(),
            mapper,
            mappings: Vec::new(),
            owned_data_frames: Vec::new(),
            retired_data_frames: Vec::new(),
            owned_page_table_frames: alloc::vec![root],
        })
    }

    pub fn root_frame(&self) -> PhysFrame<Size4KiB> {
        self.root
    }

    pub fn accounting(&self) -> FrameAccounting {
        FrameAccounting {
            mapped_data_frames: self.owned_data_frames.len(),
            retired_data_frames: self.retired_data_frames.len(),
            shared_alias_mappings: self
                .mappings
                .iter()
                .filter(|mapping| mapping.backing == UserMappingBacking::SharedAlias)
                .count(),
            page_table_frames: self.owned_page_table_frames.len(),
        }
    }

    pub fn mappings(&self) -> &[UserPageMapping] {
        &self.mappings
    }

    #[cfg(ginkgo_memory_policy_smoke)]
    pub fn smoke_effective_mapping(
        &self,
        address: u64,
    ) -> Result<Option<UserPageMapping>, AddressSpaceError> {
        let tracked = self
            .mappings
            .iter()
            .find(|mapping| mapping.virtual_address == address)
            .copied();
        let walked = match self.walk_user_page(address)? {
            WalkResult::Unmapped if tracked.is_none() => return Ok(None),
            WalkResult::Unmapped => return Err(AddressSpaceError::CorruptPageTable),
            WalkResult::Mapped(_) if tracked.is_none() => {
                return Err(AddressSpaceError::UntrackedMapping(address))
            }
            WalkResult::Mapped(mapping) => mapping,
        };
        let tracked = tracked.expect("mapped page had tracked smoke metadata");
        if walked.frame != tracked.frame {
            return Err(AddressSpaceError::CorruptPageTable);
        }
        self.validate_user_range(address, 1, UserAccess::Read)?;
        let write_result = self.validate_user_range(address, 1, UserAccess::Write);
        match tracked.permissions {
            UserPagePermissions::READ_WRITE if write_result.is_err() => {
                return Err(AddressSpaceError::CorruptPageTable)
            }
            UserPagePermissions::READ_ONLY | UserPagePermissions::READ_EXECUTE
                if !matches!(
                    write_result,
                    Err(AddressSpaceError::PermissionDenied {
                        address: denied,
                        access: UserAccess::Write,
                    }) if denied == address
                ) =>
            {
                return Err(AddressSpaceError::CorruptPageTable)
            }
            _ => {}
        }
        Ok(Some(tracked))
    }

    pub fn owned_data_frames(&self) -> &[PhysFrame<Size4KiB>] {
        &self.owned_data_frames
    }

    pub fn retired_data_frames(&self) -> &[PhysFrame<Size4KiB>] {
        &self.retired_data_frames
    }

    pub fn owned_page_table_frames(&self) -> &[PhysFrame<Size4KiB>] {
        &self.owned_page_table_frames
    }

    pub fn is_active(&self) -> bool {
        active_root_is(self.root)
    }

    /// Activates this address space and flushes the non-global TLB through CR3.
    ///
    /// The caller must ensure that the copied kernel half maps the current code,
    /// stack, interrupt path, and HHDM, and that no references into a different
    /// user address space remain live across the switch.
    pub unsafe fn activate(&self) {
        let (_, flags) = x86_64::registers::control::Cr3::read();
        unsafe { x86_64::registers::control::Cr3::write(self.root, flags) };
    }

    /// Maps `frame` at one 4 KiB user page and transfers frame ownership on success.
    ///
    /// `address` must be page-aligned and outside the zero page. The frame must
    /// be uniquely owned, suitably initialized for user visibility, and not be
    /// aliased by another writable mapping. On error, ownership remains with the
    /// caller. Lower-level page-table frames allocated before an out-of-memory
    /// error remain owned and recorded by this address space.
    pub unsafe fn map_user_4k(
        &mut self,
        address: u64,
        frame: PhysFrame<Size4KiB>,
        permissions: UserPagePermissions,
        allocator: &mut UsableFrameAllocator<'_>,
    ) -> Result<(), AddressSpaceError> {
        let result = unsafe {
            self.map_user_4k_with_allocator(
                address,
                frame,
                permissions,
                UserMappingBacking::OwnedPrivate,
                allocator,
            )
        };
        if result == Err(AddressSpaceError::OutOfFrames) {
            if let Some(error) = allocator.error() {
                return Err(AddressSpaceError::FrameAllocator(error));
            }
        }
        result
    }

    /// Maps a non-owning alias of a shared physical frame.
    ///
    /// The external owner must keep `frame` alive until this mapping is removed
    /// from every address space. The caller is also responsible for synchronization
    /// when aliases are writable. This address space records only alias metadata:
    /// the frame is never counted as owned, retired, or returned to an allocator.
    pub unsafe fn map_shared_user_4k(
        &mut self,
        address: u64,
        frame: PhysFrame<Size4KiB>,
        permissions: UserPagePermissions,
        allocator: &mut UsableFrameAllocator<'_>,
    ) -> Result<(), AddressSpaceError> {
        let result = unsafe {
            self.map_user_4k_with_allocator(
                address,
                frame,
                permissions,
                UserMappingBacking::SharedAlias,
                allocator,
            )
        };
        if result == Err(AddressSpaceError::OutOfFrames) {
            if let Some(error) = allocator.error() {
                return Err(AddressSpaceError::FrameAllocator(error));
            }
        }
        result
    }

    /// Allocates, HHDM-zeroes, and maps one uniquely owned user data frame.
    pub fn map_zeroed_user_4k(
        &mut self,
        address: u64,
        permissions: UserPagePermissions,
        allocator: &mut UsableFrameAllocator<'_>,
    ) -> Result<PhysFrame<Size4KiB>, AddressSpaceError> {
        validate_user_page(address)?;
        self.ensure_unmapped(address)?;

        let frame = allocator
            .allocate_frame()
            .map_err(AddressSpaceError::FrameAllocator)?
            .ok_or(AddressSpaceError::OutOfFrames)?;
        if let Err(error) = self.zero_frame(frame) {
            self.retired_data_frames.push(frame);
            return Err(error);
        }

        let result = unsafe { self.map_user_4k(address, frame, permissions, allocator) };
        match result {
            Ok(()) => Ok(frame),
            Err(error) => {
                self.retired_data_frames.push(frame);
                Err(error)
            }
        }
    }

    /// Removes one tracked user mapping and returns non-owning backing metadata.
    ///
    /// Owned private frames move to retirement accounting. Shared aliases simply
    /// disappear from this address space; their physical frames remain entirely
    /// under the external owner's control.
    pub fn unmap_user_4k(&mut self, address: u64) -> Result<UserPageMapping, AddressSpaceError> {
        let mut mappings = self.unmap_user_range(address, PAGE_SIZE as usize)?;
        Ok(mappings.pop().expect("one-page unmap returned no metadata"))
    }

    /// Preflights several discontiguous mapped ranges before a compound operation.
    ///
    /// Every range is validated before the caller changes any PTE, preventing a
    /// later hole or untracked mapping from turning a semantic multi-range update
    /// into a partial operation.
    pub fn preflight_mapped_user_ranges(
        &self,
        ranges: &[(u64, usize)],
    ) -> Result<(), AddressSpaceError> {
        let mut previous_end = None;
        for &(address, length) in ranges {
            let (_, end) = validate_exact_user_page_range(address, length)?;
            if previous_end.is_some_and(|previous_end| address <= previous_end) {
                return Err(AddressSpaceError::InvalidRangeLength(length));
            }
            previous_end = Some(end);
            let mut page_address = address;
            loop {
                let walked = match self.walk_user_page(page_address)? {
                    WalkResult::Unmapped => return Err(AddressSpaceError::NotMapped(page_address)),
                    WalkResult::Mapped(mapping) => mapping,
                };
                let tracked = self
                    .mappings
                    .iter()
                    .find(|mapping| mapping.virtual_address == page_address)
                    .ok_or(AddressSpaceError::UntrackedMapping(page_address))?;
                if tracked.frame != walked.frame {
                    return Err(AddressSpaceError::CorruptPageTable);
                }
                match tracked.backing {
                    UserMappingBacking::OwnedPrivate => {
                        if !self.owned_data_frames.contains(&tracked.frame) {
                            return Err(AddressSpaceError::MappedFrameNotOwned(tracked.frame));
                        }
                    }
                    UserMappingBacking::SharedAlias => {
                        if self.owned_data_frames.contains(&tracked.frame)
                            || self.retired_data_frames.contains(&tracked.frame)
                        {
                            return Err(AddressSpaceError::CorruptPageTable);
                        }
                    }
                }
                if page_address == end {
                    break;
                }
                page_address = page_address
                    .checked_add(PAGE_SIZE)
                    .ok_or(AddressSpaceError::AddressOverflow)?;
            }
        }
        Ok(())
    }

    /// Unmaps several discontiguous ranges after preflighting the complete set.
    pub fn unmap_user_ranges(
        &mut self,
        ranges: &[(u64, usize)],
    ) -> Result<Vec<UserPageMapping>, AddressSpaceError> {
        self.preflight_mapped_user_ranges(ranges)?;
        let mapping_count = ranges
            .iter()
            .try_fold(0usize, |total, (_, length)| {
                total.checked_add(length / PAGE_SIZE as usize)
            })
            .ok_or(AddressSpaceError::AddressOverflow)?;
        let mut removed = Vec::new();
        removed
            .try_reserve_exact(mapping_count)
            .map_err(|_| AddressSpaceError::OutOfFrames)?;
        for &(address, length) in ranges {
            removed.extend(self.unmap_user_range(address, length)?);
        }
        Ok(removed)
    }

    /// Unmaps exactly `length` bytes of page-aligned user mappings.
    ///
    /// Both the start and length must be 4 KiB aligned and `length` must be
    /// nonzero. The complete range is checked before any PTE is changed, so a
    /// missing or untracked page cannot produce a partial unmap. Returned shared
    /// alias frames are identities only, never ownership tokens.
    pub fn unmap_user_range(
        &mut self,
        address: u64,
        length: usize,
    ) -> Result<Vec<UserPageMapping>, AddressSpaceError> {
        let (_, end) = validate_exact_user_page_range(address, length)?;
        let mut planned = Vec::with_capacity(length / PAGE_SIZE as usize);
        let mut page_address = address;

        loop {
            let walked = match self.walk_user_page(page_address)? {
                WalkResult::Unmapped => return Err(AddressSpaceError::NotMapped(page_address)),
                WalkResult::Mapped(mapping) => mapping,
            };
            let tracked = self
                .mappings
                .iter()
                .find(|mapping| mapping.virtual_address == page_address)
                .copied()
                .ok_or(AddressSpaceError::UntrackedMapping(page_address))?;
            if tracked.frame != walked.frame {
                return Err(AddressSpaceError::CorruptPageTable);
            }
            match tracked.backing {
                UserMappingBacking::OwnedPrivate => {
                    if !self.owned_data_frames.contains(&tracked.frame) {
                        return Err(AddressSpaceError::MappedFrameNotOwned(tracked.frame));
                    }
                }
                UserMappingBacking::SharedAlias => {
                    if self.owned_data_frames.contains(&tracked.frame)
                        || self.retired_data_frames.contains(&tracked.frame)
                    {
                        return Err(AddressSpaceError::CorruptPageTable);
                    }
                }
            }
            planned.push(tracked);
            if page_address == end {
                break;
            }
            page_address = page_address
                .checked_add(PAGE_SIZE)
                .ok_or(AddressSpaceError::AddressOverflow)?;
        }

        for tracked in &planned {
            let page = x86_64::structures::paging::Page::from_start_address(VirtAddr::new(
                tracked.virtual_address,
            ))
            .map_err(|_| AddressSpaceError::UnalignedAddress(tracked.virtual_address))?;
            let (frame, flush) = match self.mapper.unmap(page) {
                Ok(result) => result,
                Err(X86UnmapError::PageNotMapped) => {
                    return Err(AddressSpaceError::NotMapped(tracked.virtual_address))
                }
                Err(X86UnmapError::ParentEntryHugePage) => {
                    return Err(AddressSpaceError::HugePageConflict)
                }
                Err(X86UnmapError::InvalidFrameAddress(_)) => {
                    return Err(AddressSpaceError::CorruptPageTable)
                }
            };
            finish_flush(self.root, flush);
            if frame != tracked.frame {
                return Err(AddressSpaceError::CorruptPageTable);
            }

            let mapping_index = self
                .mappings
                .iter()
                .position(|mapping| mapping.virtual_address == tracked.virtual_address)
                .ok_or(AddressSpaceError::UntrackedMapping(tracked.virtual_address))?;
            self.mappings.swap_remove(mapping_index);
            if tracked.backing == UserMappingBacking::OwnedPrivate {
                let owned_index = self
                    .owned_data_frames
                    .iter()
                    .position(|owned| *owned == frame)
                    .ok_or(AddressSpaceError::MappedFrameNotOwned(frame))?;
                self.owned_data_frames.swap_remove(owned_index);
                self.retired_data_frames.push(frame);
            }
        }
        Ok(planned)
    }

    /// Applies one permission set to several mapped ranges after complete preflight.
    pub fn protect_user_ranges(
        &mut self,
        ranges: &[(u64, usize)],
        permissions: UserPagePermissions,
    ) -> Result<(), AddressSpaceError> {
        self.preflight_mapped_user_ranges(ranges)?;
        for &(address, length) in ranges {
            self.protect_user_range(address, length, permissions)?;
        }
        Ok(())
    }

    /// Returns all private frames retired by successful unmaps or failed mappings.
    /// The complete batch remains owned by this address space if reclamation fails.
    pub fn protect_user_range(
        &mut self,
        address: u64,
        length: usize,
        permissions: UserPagePermissions,
    ) -> Result<(), AddressSpaceError> {
        let (_, end) = validate_exact_user_page_range(address, length)?;
        let mut page_address = address;
        loop {
            if matches!(self.walk_user_page(page_address)?, WalkResult::Unmapped) {
                return Err(AddressSpaceError::NotMapped(page_address));
            }
            if !self
                .mappings
                .iter()
                .any(|mapping| mapping.virtual_address == page_address)
            {
                return Err(AddressSpaceError::UntrackedMapping(page_address));
            }
            if page_address == end {
                break;
            }
            page_address += PAGE_SIZE;
        }

        let flags = permissions.page_table_flags();
        page_address = address;
        loop {
            let page = Page::from_start_address(VirtAddr::new(page_address))
                .map_err(|_| AddressSpaceError::UnalignedAddress(page_address))?;
            let flush =
                unsafe { self.mapper.update_flags(page, flags) }.map_err(|error| match error {
                    FlagUpdateError::PageNotMapped => AddressSpaceError::NotMapped(page_address),
                    FlagUpdateError::ParentEntryHugePage => AddressSpaceError::HugePageConflict,
                })?;
            finish_flush(self.root, flush);
            self.mappings
                .iter_mut()
                .find(|mapping| mapping.virtual_address == page_address)
                .expect("protection range was completely preflighted")
                .permissions = permissions;
            if page_address == end {
                break;
            }
            page_address += PAGE_SIZE;
        }
        Ok(())
    }

    pub fn reclaim_retired_data_frames(
        &mut self,
        allocator: &mut UsableFrameAllocator<'_>,
    ) -> Result<usize, FrameAllocatorError> {
        let count = self.retired_data_frames.len();
        allocator.deallocate_frames(&self.retired_data_frames)?;
        self.retired_data_frames.clear();
        Ok(count)
    }

    /// Validates every 4 KiB page touched by a user byte range.
    ///
    /// Empty ranges are accepted without inspecting `address`. Non-empty ranges
    /// reject overflow, noncanonical addresses, the higher half, and any byte in
    /// the zero page. Permissions are effective permissions across all four
    /// paging levels, not just leaf flags.
    pub fn validate_user_range(
        &self,
        address: u64,
        length: usize,
        access: UserAccess,
    ) -> Result<(), AddressSpaceError> {
        let Some((start, end)) = checked_user_range(address, length)? else {
            return Ok(());
        };
        let mut page_address = start & !(PAGE_SIZE - 1);
        let final_page = end & !(PAGE_SIZE - 1);

        loop {
            let mapping = match self.walk_user_page(page_address)? {
                WalkResult::Unmapped => return Err(AddressSpaceError::NotMapped(page_address)),
                WalkResult::Mapped(mapping) => mapping,
            };
            let permitted = mapping.user_accessible
                && match access {
                    UserAccess::Read => true,
                    UserAccess::Write => mapping.writable,
                    UserAccess::Execute => mapping.executable,
                };
            if !permitted {
                return Err(AddressSpaceError::PermissionDenied {
                    address: page_address,
                    access,
                });
            }
            if page_address == final_page {
                break;
            }
            page_address = page_address
                .checked_add(PAGE_SIZE)
                .ok_or(AddressSpaceError::AddressOverflow)?;
        }
        Ok(())
    }

    /// Copies bytes from the currently active user address space after checking
    /// every source page for user-readable access.
    pub fn copy_from_user(
        &self,
        destination: &mut [u8],
        user_source: u64,
    ) -> Result<(), AddressSpaceError> {
        self.validate_user_range(user_source, destination.len(), UserAccess::Read)?;
        if destination.is_empty() {
            return Ok(());
        }
        if !self.is_active() {
            return Err(AddressSpaceError::ActiveAddressSpaceRequired);
        }
        let source = VirtAddr::try_new(user_source)
            .map_err(|_| AddressSpaceError::NonCanonicalAddress(user_source))?;
        if unsafe {
            arch::copy_user_bytes(
                destination.as_mut_ptr(),
                source.as_ptr::<u8>(),
                destination.len(),
            )
        } {
            Ok(())
        } else {
            Err(AddressSpaceError::UserCopyFault)
        }
    }

    /// Copies bytes into the currently active user address space after checking
    /// every destination page for user-writable access.
    pub fn copy_to_user(
        &self,
        user_destination: u64,
        source: &[u8],
    ) -> Result<(), AddressSpaceError> {
        self.validate_user_range(user_destination, source.len(), UserAccess::Write)?;
        if source.is_empty() {
            return Ok(());
        }
        if !self.is_active() {
            return Err(AddressSpaceError::ActiveAddressSpaceRequired);
        }
        let destination = VirtAddr::try_new(user_destination)
            .map_err(|_| AddressSpaceError::NonCanonicalAddress(user_destination))?;
        if unsafe {
            arch::copy_user_bytes(
                destination.as_mut_ptr::<u8>(),
                source.as_ptr(),
                source.len(),
            )
        } {
            Ok(())
        } else {
            Err(AddressSpaceError::UserCopyFault)
        }
    }

    /// Retires and reclaims an address space after verifying it is not the
    /// current CPU's active root.
    ///
    /// Callers must still ensure no other CPU can use this root. On any failure,
    /// exact ownership is returned in the error for retry or deliberate retention.
    pub fn cleanup_inactive(
        self,
        allocator: &mut UsableFrameAllocator<'_>,
    ) -> Result<FrameReclaimStats, InactiveAddressSpaceCleanupError> {
        if self.is_active() {
            return Err(InactiveAddressSpaceCleanupError::Active(self));
        }
        let retired = unsafe { self.retire() };
        retired
            .reclaim(allocator)
            .map_err(InactiveAddressSpaceCleanupError::Reclaim)
    }

    /// Converts this inactive address space into explicit ownership records.
    ///
    /// The caller must first switch CR3 away from this root on every CPU and
    /// ensure no other CPU can use it. Reclamation is then performed by
    /// [`RetiredAddressSpace::reclaim`].
    pub unsafe fn retire(self) -> RetiredAddressSpace {
        let shared_alias_mappings = self
            .mappings
            .iter()
            .filter(|mapping| mapping.backing == UserMappingBacking::SharedAlias)
            .copied()
            .collect();
        RetiredAddressSpace {
            root: self.root,
            mapped_data_frames: self.owned_data_frames,
            retired_data_frames: self.retired_data_frames,
            shared_alias_mappings,
            page_table_frames: self.owned_page_table_frames,
        }
    }

    unsafe fn map_user_4k_with_allocator<A>(
        &mut self,
        address: u64,
        frame: PhysFrame<Size4KiB>,
        permissions: UserPagePermissions,
        backing: UserMappingBacking,
        allocator: &mut A,
    ) -> Result<(), AddressSpaceError>
    where
        A: FrameAllocator<Size4KiB> + ?Sized,
    {
        validate_user_page(address)?;
        self.ensure_unmapped(address)?;
        if self.mappings.iter().any(|mapping| mapping.frame == frame) {
            return match backing {
                UserMappingBacking::OwnedPrivate => {
                    Err(AddressSpaceError::FrameAlreadyOwned(frame))
                }
                UserMappingBacking::SharedAlias => {
                    Err(AddressSpaceError::DuplicateSharedAlias(frame))
                }
            };
        }
        if self.frame_is_owned(frame) {
            return Err(AddressSpaceError::FrameAlreadyOwned(frame));
        }
        let page = x86_64::structures::paging::Page::from_start_address(VirtAddr::new(address))
            .map_err(|_| AddressSpaceError::UnalignedAddress(address))?;
        let flags = permissions.page_table_flags();
        let mut recording_allocator = RecordingFrameAllocator {
            inner: allocator,
            recorded: &mut self.owned_page_table_frames,
        };
        let result = unsafe {
            self.mapper
                .map_to(page, frame, flags, &mut recording_allocator)
        };

        match result {
            Ok(flush) => {
                finish_flush(self.root, flush);
                if backing == UserMappingBacking::OwnedPrivate {
                    self.owned_data_frames.push(frame);
                }
                self.mappings.push(UserPageMapping {
                    virtual_address: address,
                    frame,
                    backing,
                    permissions,
                });
                Ok(())
            }
            Err(MapToError::PageAlreadyMapped(_)) => Err(AddressSpaceError::AlreadyMapped(address)),
            Err(MapToError::ParentEntryHugePage) => Err(AddressSpaceError::HugePageConflict),
            Err(MapToError::FrameAllocationFailed) => Err(AddressSpaceError::OutOfFrames),
        }
    }

    fn ensure_unmapped(&self, address: u64) -> Result<(), AddressSpaceError> {
        match self.walk_user_page(address)? {
            WalkResult::Unmapped => Ok(()),
            WalkResult::Mapped(_) => Err(AddressSpaceError::AlreadyMapped(address)),
        }
    }

    fn frame_is_owned(&self, frame: PhysFrame<Size4KiB>) -> bool {
        self.owned_data_frames.contains(&frame)
            || self.retired_data_frames.contains(&frame)
            || self.owned_page_table_frames.contains(&frame)
    }

    fn zero_frame(&self, frame: PhysFrame<Size4KiB>) -> Result<(), AddressSpaceError> {
        let address = frame_hhdm_address(self.hhdm_offset, frame)?;
        unsafe { ptr::write_bytes(address.as_mut_ptr::<u8>(), 0, PAGE_SIZE as usize) };
        Ok(())
    }

    fn walk_user_page(&self, address: u64) -> Result<WalkResult, AddressSpaceError> {
        classify_user_address(address)?;
        let address = VirtAddr::new(address);
        if usize::from(address.p4_index()) >= USER_P4_ENTRIES {
            return Err(AddressSpaceError::HigherHalfAddress(address.as_u64()));
        }
        let indexes = [
            usize::from(address.p4_index()),
            usize::from(address.p3_index()),
            usize::from(address.p2_index()),
        ];
        let mut table = self.mapper.level_4_table();
        let mut effective = EffectivePermissions::new();

        for (level, index) in indexes.into_iter().enumerate() {
            let entry = &table[index];
            if entry.is_unused() {
                return Ok(WalkResult::Unmapped);
            }
            let flags = entry.flags();
            if !flags.contains(PageTableFlags::PRESENT) {
                return Err(AddressSpaceError::CorruptPageTable);
            }
            if flags.contains(PageTableFlags::HUGE_PAGE) {
                return if level == 0 {
                    Err(AddressSpaceError::CorruptPageTable)
                } else {
                    Err(AddressSpaceError::HugePageConflict)
                };
            }
            effective.include(flags);
            let frame = entry
                .frame()
                .map_err(|_| AddressSpaceError::CorruptPageTable)?;
            table = self.table(frame)?;
        }

        let entry = &table[usize::from(address.p1_index())];
        if entry.is_unused() {
            return Ok(WalkResult::Unmapped);
        }
        let flags = entry.flags();
        if !flags.contains(PageTableFlags::PRESENT) || flags.contains(PageTableFlags::HUGE_PAGE) {
            return Err(AddressSpaceError::CorruptPageTable);
        }
        effective.include(flags);
        let frame = entry
            .frame()
            .map_err(|_| AddressSpaceError::CorruptPageTable)?;
        Ok(WalkResult::Mapped(PageMapping {
            frame,
            user_accessible: effective.user_accessible,
            writable: effective.writable,
            executable: effective.executable,
        }))
    }

    fn table(&self, frame: PhysFrame<Size4KiB>) -> Result<&PageTable, AddressSpaceError> {
        let address = frame_hhdm_address(self.hhdm_offset, frame)?;
        Ok(unsafe { &*address.as_ptr::<PageTable>() })
    }
}

struct RecordingFrameAllocator<'a, 'b, A: ?Sized> {
    inner: &'a mut A,
    recorded: &'b mut Vec<PhysFrame<Size4KiB>>,
}

unsafe impl<A> FrameAllocator<Size4KiB> for RecordingFrameAllocator<'_, '_, A>
where
    A: FrameAllocator<Size4KiB> + ?Sized,
{
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        let frame = self.inner.allocate_frame()?;
        self.recorded.push(frame);
        Some(frame)
    }
}

#[derive(Clone, Copy)]
struct EffectivePermissions {
    user_accessible: bool,
    writable: bool,
    executable: bool,
}

impl EffectivePermissions {
    const fn new() -> Self {
        Self {
            user_accessible: true,
            writable: true,
            executable: true,
        }
    }

    fn include(&mut self, flags: PageTableFlags) {
        self.user_accessible &= flags.contains(PageTableFlags::USER_ACCESSIBLE);
        self.writable &= flags.contains(PageTableFlags::WRITABLE);
        self.executable &= !flags.contains(PageTableFlags::NO_EXECUTE);
    }
}

#[derive(Clone, Copy)]
struct PageMapping {
    frame: PhysFrame<Size4KiB>,
    user_accessible: bool,
    writable: bool,
    executable: bool,
}

enum WalkResult {
    Unmapped,
    Mapped(PageMapping),
}

fn frame_hhdm_address(
    hhdm_offset: VirtAddr,
    frame: PhysFrame<Size4KiB>,
) -> Result<VirtAddr, AddressSpaceError> {
    hhdm_offset
        .as_u64()
        .checked_add(frame.start_address().as_u64())
        .and_then(|address| VirtAddr::try_new(address).ok())
        .ok_or(AddressSpaceError::AddressOverflow)
}

fn copy_kernel_half(source: &PageTable, destination: &mut PageTable) {
    destination.zero();
    for index in USER_P4_ENTRIES..512 {
        destination[index] = source[index].clone();
        let supervisor_flags = destination[index].flags() & !PageTableFlags::USER_ACCESSIBLE;
        destination[index].set_flags(supervisor_flags);
    }
}

fn classify_user_address(address: u64) -> Result<(), AddressSpaceError> {
    if address <= USER_ADDRESS_MAX {
        Ok(())
    } else if address >= KERNEL_ADDRESS_START {
        Err(AddressSpaceError::HigherHalfAddress(address))
    } else {
        Err(AddressSpaceError::NonCanonicalAddress(address))
    }
}

fn checked_user_range(
    address: u64,
    length: usize,
) -> Result<Option<(u64, u64)>, AddressSpaceError> {
    if length == 0 {
        return Ok(None);
    }
    let length = u64::try_from(length).map_err(|_| AddressSpaceError::AddressOverflow)?;
    let end = address
        .checked_add(length - 1)
        .ok_or(AddressSpaceError::AddressOverflow)?;
    classify_user_address(address)?;
    classify_user_address(end)?;
    if address < PAGE_SIZE {
        return Err(AddressSpaceError::ZeroPage);
    }
    Ok(Some((address, end)))
}

fn validate_exact_user_page_range(
    address: u64,
    length: usize,
) -> Result<(u64, u64), AddressSpaceError> {
    if address % PAGE_SIZE != 0 {
        return Err(AddressSpaceError::UnalignedAddress(address));
    }
    if length == 0 || length % PAGE_SIZE as usize != 0 {
        return Err(AddressSpaceError::InvalidRangeLength(length));
    }
    let (_, end) = checked_user_range(address, length)?
        .expect("nonzero exact page range unexpectedly became empty");
    Ok((address, end & !(PAGE_SIZE - 1)))
}

fn validate_user_page(address: u64) -> Result<(), AddressSpaceError> {
    validate_exact_user_page_range(address, PAGE_SIZE as usize).map(|_| ())
}

fn finish_flush(flush_root: PhysFrame<Size4KiB>, flush: MapperFlush<Size4KiB>) {
    #[cfg(target_os = "none")]
    {
        if active_root_is(flush_root) {
            flush.flush();
        } else {
            flush.ignore();
        }
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = flush_root;
        flush.ignore();
    }
}

fn active_root_is(root: PhysFrame<Size4KiB>) -> bool {
    #[cfg(target_os = "none")]
    {
        x86_64::registers::control::Cr3::read().0 == root
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = root;
        false
    }
}

#[cfg(test)]
mod tests {
    use alloc::boxed::Box;

    use super::*;

    struct FakeFrameAllocator {
        tables: Vec<Box<PageTable>>,
    }

    #[derive(Default)]
    struct TrackingReclaimer {
        calls: usize,
        fail_call: Option<usize>,
        reclaimed: Vec<PhysFrame<Size4KiB>>,
    }

    impl FrameReclaimer for TrackingReclaimer {
        fn reclaim(&mut self, frames: &[PhysFrame<Size4KiB>]) -> Result<(), FrameAllocatorError> {
            self.calls += 1;
            if self.fail_call == Some(self.calls) {
                return Err(FrameAllocatorError::OwnershipTrackingAllocationFailed);
            }
            for frame in frames {
                if self.reclaimed.contains(frame) {
                    return Err(FrameAllocatorError::DoubleFree {
                        address: frame.start_address().as_u64(),
                    });
                }
            }
            self.reclaimed.extend_from_slice(frames);
            Ok(())
        }
    }

    fn frame(address: u64) -> PhysFrame<Size4KiB> {
        PhysFrame::from_start_address(PhysAddr::new(address)).unwrap()
    }

    fn retired_with_all_backing_kinds() -> RetiredAddressSpace {
        let root = frame(0x5000);
        RetiredAddressSpace {
            root,
            mapped_data_frames: alloc::vec![frame(0x1000)],
            retired_data_frames: alloc::vec![frame(0x2000)],
            shared_alias_mappings: alloc::vec![UserPageMapping {
                virtual_address: 0x8000,
                frame: frame(0x3000),
                backing: UserMappingBacking::SharedAlias,
                permissions: UserPagePermissions::READ_WRITE,
            }],
            page_table_frames: alloc::vec![root, frame(0x6000)],
        }
    }

    impl FakeFrameAllocator {
        fn new() -> Self {
            Self { tables: Vec::new() }
        }
    }

    unsafe impl FrameAllocator<Size4KiB> for FakeFrameAllocator {
        fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
            let mut table = Box::new(PageTable::new());
            let address = table.as_mut() as *mut PageTable as u64;
            let frame = PhysFrame::from_start_address(PhysAddr::try_new(address).ok()?).ok()?;
            self.tables.push(table);
            Some(frame)
        }
    }

    fn fake_address_space() -> AddressSpace {
        let root_table = Box::leak(Box::new(PageTable::new()));
        let root_address = root_table as *mut PageTable as u64;
        let root = PhysFrame::from_start_address(PhysAddr::try_new(root_address).unwrap()).unwrap();
        let mapper = unsafe { OffsetPageTable::new(root_table, VirtAddr::zero()) };
        AddressSpace {
            root,
            hhdm_offset: VirtAddr::zero(),
            mapper,
            mappings: Vec::new(),
            owned_data_frames: Vec::new(),
            retired_data_frames: Vec::new(),
            owned_page_table_frames: alloc::vec![root],
        }
    }

    #[test]
    fn permission_constructor_enforces_w_xor_x() {
        assert_eq!(
            UserPagePermissions::new(true, true),
            Err(AddressSpaceError::WritableExecutable)
        );
        assert_eq!(
            UserPagePermissions::new(true, false).unwrap(),
            UserPagePermissions::READ_WRITE
        );
    }

    #[test]
    fn range_checks_reject_zero_noncanonical_higher_half_and_overflow() {
        assert_eq!(
            checked_user_range(0x800, 0x1000),
            Err(AddressSpaceError::ZeroPage)
        );
        assert_eq!(
            checked_user_range(0x0000_8000_0000_0000, 1),
            Err(AddressSpaceError::NonCanonicalAddress(
                0x0000_8000_0000_0000
            ))
        );
        assert_eq!(
            checked_user_range(KERNEL_ADDRESS_START, 1),
            Err(AddressSpaceError::HigherHalfAddress(KERNEL_ADDRESS_START))
        );
        assert_eq!(
            checked_user_range(u64::MAX, 2),
            Err(AddressSpaceError::AddressOverflow)
        );
        assert_eq!(checked_user_range(0, 0), Ok(None));
    }

    #[test]
    fn range_checks_reject_crossing_the_user_limit() {
        assert_eq!(
            checked_user_range(USER_ADDRESS_MAX, 2),
            Err(AddressSpaceError::NonCanonicalAddress(USER_ADDRESS_MAX + 1))
        );
    }

    #[test]
    fn kernel_half_copy_leaves_the_user_half_empty() {
        let mut source = PageTable::new();
        let frame = PhysFrame::from_start_address(PhysAddr::new(0x2000)).unwrap();
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
        source[3].set_frame(frame, flags);
        source[300].set_frame(frame, flags);
        let mut destination = PageTable::new();
        destination[4].set_frame(frame, flags);

        copy_kernel_half(&source, &mut destination);

        assert!(destination
            .iter()
            .take(USER_P4_ENTRIES)
            .all(|entry| entry.is_unused()));
        assert_eq!(destination[300].addr(), source[300].addr());
        assert_eq!(destination[300].flags(), source[300].flags());
    }

    #[test]
    fn kernel_half_copy_forces_root_entries_to_supervisor_only() {
        let mut source = PageTable::new();
        let frame = PhysFrame::from_start_address(PhysAddr::new(0x2000)).unwrap();
        source[400].set_frame(
            frame,
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE,
        );
        let mut destination = PageTable::new();

        copy_kernel_half(&source, &mut destination);

        assert_eq!(destination[400].addr(), source[400].addr());
        assert!(destination[400].flags().contains(PageTableFlags::PRESENT));
        assert!(destination[400].flags().contains(PageTableFlags::WRITABLE));
        assert!(!destination[400]
            .flags()
            .contains(PageTableFlags::USER_ACCESSIBLE));
    }

    #[test]
    fn fake_tables_map_validate_overlap_and_unmap() {
        let mut address_space = fake_address_space();
        let mut allocator = FakeFrameAllocator::new();
        let read_only = allocator.allocate_frame().unwrap();
        let writable = allocator.allocate_frame().unwrap();
        let executable = allocator.allocate_frame().unwrap();

        unsafe {
            address_space
                .map_user_4k_with_allocator(
                    0x1000,
                    read_only,
                    UserPagePermissions::READ_ONLY,
                    UserMappingBacking::OwnedPrivate,
                    &mut allocator,
                )
                .unwrap();
            address_space
                .map_user_4k_with_allocator(
                    0x2000,
                    writable,
                    UserPagePermissions::READ_WRITE,
                    UserMappingBacking::OwnedPrivate,
                    &mut allocator,
                )
                .unwrap();
            address_space
                .map_user_4k_with_allocator(
                    0x3000,
                    executable,
                    UserPagePermissions::READ_EXECUTE,
                    UserMappingBacking::OwnedPrivate,
                    &mut allocator,
                )
                .unwrap();
        }

        assert_eq!(
            address_space.validate_user_range(0x1fff, 2, UserAccess::Read),
            Ok(())
        );
        assert_eq!(
            address_space.validate_user_range(0x1000, 1, UserAccess::Write),
            Err(AddressSpaceError::PermissionDenied {
                address: 0x1000,
                access: UserAccess::Write,
            })
        );
        assert_eq!(
            address_space.validate_user_range(0x2000, 1, UserAccess::Execute),
            Err(AddressSpaceError::PermissionDenied {
                address: 0x2000,
                access: UserAccess::Execute,
            })
        );
        assert_eq!(
            address_space.validate_user_range(0x3000, 1, UserAccess::Execute),
            Ok(())
        );

        let original_p4_flags = address_space.mapper.level_4_table()[0].flags();
        address_space.mapper.level_4_table_mut()[0]
            .set_flags(original_p4_flags & !PageTableFlags::USER_ACCESSIBLE);
        assert_eq!(
            address_space.validate_user_range(0x3000, 1, UserAccess::Read),
            Err(AddressSpaceError::PermissionDenied {
                address: 0x3000,
                access: UserAccess::Read,
            })
        );
        address_space.mapper.level_4_table_mut()[0]
            .set_flags(original_p4_flags | PageTableFlags::NO_EXECUTE);
        assert_eq!(
            address_space.validate_user_range(0x3000, 1, UserAccess::Execute),
            Err(AddressSpaceError::PermissionDenied {
                address: 0x3000,
                access: UserAccess::Execute,
            })
        );
        address_space.mapper.level_4_table_mut()[0].set_flags(original_p4_flags);

        let mut copy_buffer = [0_u8; 1];
        assert_eq!(
            address_space.copy_from_user(&mut copy_buffer, 0x1000),
            Err(AddressSpaceError::ActiveAddressSpaceRequired)
        );

        let overlap = allocator.allocate_frame().unwrap();
        assert_eq!(
            unsafe {
                address_space.map_user_4k_with_allocator(
                    0x1000,
                    overlap,
                    UserPagePermissions::READ_ONLY,
                    UserMappingBacking::OwnedPrivate,
                    &mut allocator,
                )
            },
            Err(AddressSpaceError::AlreadyMapped(0x1000))
        );

        assert_eq!(
            address_space.unmap_user_4k(0x2000),
            Ok(UserPageMapping {
                virtual_address: 0x2000,
                frame: writable,
                backing: UserMappingBacking::OwnedPrivate,
                permissions: UserPagePermissions::READ_WRITE,
            })
        );
        assert_eq!(
            address_space.validate_user_range(0x2000, 1, UserAccess::Read),
            Err(AddressSpaceError::NotMapped(0x2000))
        );
        assert_eq!(address_space.accounting().mapped_data_frames, 2);
        assert_eq!(address_space.accounting().retired_data_frames, 1);
        assert!(address_space.accounting().page_table_frames >= 4);
    }

    #[test]
    fn exact_range_unmap_preflights_every_page() {
        let mut address_space = fake_address_space();
        let mut allocator = FakeFrameAllocator::new();
        let frame = allocator.allocate_frame().unwrap();
        unsafe {
            address_space
                .map_user_4k_with_allocator(
                    0x7000,
                    frame,
                    UserPagePermissions::READ_ONLY,
                    UserMappingBacking::OwnedPrivate,
                    &mut allocator,
                )
                .unwrap();
        }

        assert_eq!(
            address_space.unmap_user_range(0x7000, (PAGE_SIZE * 2) as usize),
            Err(AddressSpaceError::NotMapped(0x8000))
        );
        assert_eq!(
            address_space.validate_user_range(0x7000, 1, UserAccess::Read),
            Ok(())
        );
        assert!(address_space.retired_data_frames().is_empty());
        assert_eq!(
            address_space.unmap_user_range(0x7000, 1),
            Err(AddressSpaceError::InvalidRangeLength(1))
        );
    }

    #[test]
    fn multi_range_protect_later_failure_leaves_earlier_permissions_unchanged() {
        let mut address_space = fake_address_space();
        let mut allocator = FakeFrameAllocator::new();
        let frame = allocator.allocate_frame().unwrap();
        unsafe {
            address_space
                .map_user_4k_with_allocator(
                    0x7000,
                    frame,
                    UserPagePermissions::READ_WRITE,
                    UserMappingBacking::OwnedPrivate,
                    &mut allocator,
                )
                .unwrap();
        }

        assert_eq!(
            address_space.protect_user_ranges(
                &[(0x7000, PAGE_SIZE as usize), (0x9000, PAGE_SIZE as usize),],
                UserPagePermissions::READ_ONLY,
            ),
            Err(AddressSpaceError::NotMapped(0x9000))
        );
        assert_eq!(
            address_space.validate_user_range(0x7000, 1, UserAccess::Write),
            Ok(())
        );
        assert_eq!(
            address_space
                .mappings()
                .iter()
                .find(|mapping| mapping.virtual_address == 0x7000)
                .unwrap()
                .permissions,
            UserPagePermissions::READ_WRITE
        );
    }

    #[test]
    fn multi_range_unmap_later_failure_leaves_earlier_mapping_unchanged() {
        let mut address_space = fake_address_space();
        let mut allocator = FakeFrameAllocator::new();
        let frame = allocator.allocate_frame().unwrap();
        unsafe {
            address_space
                .map_user_4k_with_allocator(
                    0x7000,
                    frame,
                    UserPagePermissions::READ_ONLY,
                    UserMappingBacking::OwnedPrivate,
                    &mut allocator,
                )
                .unwrap();
        }

        assert_eq!(
            address_space
                .unmap_user_ranges(&[(0x7000, PAGE_SIZE as usize), (0x9000, PAGE_SIZE as usize),]),
            Err(AddressSpaceError::NotMapped(0x9000))
        );
        assert_eq!(
            address_space.validate_user_range(0x7000, 1, UserAccess::Read),
            Ok(())
        );
        assert!(address_space.retired_data_frames().is_empty());
        assert_eq!(address_space.accounting().mapped_data_frames, 1);
    }

    #[test]
    fn shared_aliases_are_non_owning_across_address_spaces() {
        let mut first = fake_address_space();
        let mut second = fake_address_space();
        let mut first_allocator = FakeFrameAllocator::new();
        let mut second_allocator = FakeFrameAllocator::new();
        let mut backing_allocator = FakeFrameAllocator::new();
        let private = first_allocator.allocate_frame().unwrap();
        let shared = backing_allocator.allocate_frame().unwrap();

        unsafe {
            first
                .map_user_4k_with_allocator(
                    0x3000,
                    private,
                    UserPagePermissions::READ_WRITE,
                    UserMappingBacking::OwnedPrivate,
                    &mut first_allocator,
                )
                .unwrap();
            first
                .map_user_4k_with_allocator(
                    0x4000,
                    shared,
                    UserPagePermissions::READ_WRITE,
                    UserMappingBacking::SharedAlias,
                    &mut first_allocator,
                )
                .unwrap();
            second
                .map_user_4k_with_allocator(
                    0x5000,
                    shared,
                    UserPagePermissions::READ_EXECUTE,
                    UserMappingBacking::SharedAlias,
                    &mut second_allocator,
                )
                .unwrap();
        }

        assert_eq!(
            first.validate_user_range(0x4000, 1, UserAccess::Write),
            Ok(())
        );
        assert_eq!(
            second.validate_user_range(0x5000, 1, UserAccess::Execute),
            Ok(())
        );
        assert_eq!(
            second.validate_user_range(0x5000, 1, UserAccess::Write),
            Err(AddressSpaceError::PermissionDenied {
                address: 0x5000,
                access: UserAccess::Write,
            })
        );
        assert_eq!(first.accounting().mapped_data_frames, 1);
        assert_eq!(first.accounting().shared_alias_mappings, 1);
        assert_eq!(second.accounting().mapped_data_frames, 0);
        assert_eq!(second.accounting().shared_alias_mappings, 1);

        assert_eq!(
            unsafe {
                first.map_user_4k_with_allocator(
                    0x6000,
                    shared,
                    UserPagePermissions::READ_ONLY,
                    UserMappingBacking::SharedAlias,
                    &mut first_allocator,
                )
            },
            Err(AddressSpaceError::DuplicateSharedAlias(shared))
        );

        assert_eq!(
            first.unmap_user_range(0x3000, (PAGE_SIZE * 2) as usize),
            Ok(alloc::vec![
                UserPageMapping {
                    virtual_address: 0x3000,
                    frame: private,
                    backing: UserMappingBacking::OwnedPrivate,
                    permissions: UserPagePermissions::READ_WRITE,
                },
                UserPageMapping {
                    virtual_address: 0x4000,
                    frame: shared,
                    backing: UserMappingBacking::SharedAlias,
                    permissions: UserPagePermissions::READ_WRITE,
                },
            ])
        );
        assert_eq!(first.owned_data_frames(), &[]);
        assert_eq!(first.retired_data_frames(), &[private]);
        assert!(!first.retired_data_frames().contains(&shared));
        assert_eq!(first.accounting().shared_alias_mappings, 0);

        assert_eq!(
            second.validate_user_range(0x5000, 1, UserAccess::Execute),
            Ok(())
        );
        assert_eq!(
            second.unmap_user_4k(0x5000),
            Ok(UserPageMapping {
                virtual_address: 0x5000,
                frame: shared,
                backing: UserMappingBacking::SharedAlias,
                permissions: UserPagePermissions::READ_EXECUTE,
            })
        );
        assert!(second.retired_data_frames().is_empty());
        assert_eq!(second.accounting().mapped_data_frames, 0);
        assert_eq!(second.accounting().shared_alias_mappings, 0);
    }

    #[test]
    fn retired_reclaim_submits_exact_ownership_and_excludes_shared_aliases() {
        let retired = retired_with_all_backing_kinds();
        let mut allocator = TrackingReclaimer::default();

        let stats = retired.reclaim_with(&mut allocator).unwrap();

        assert_eq!(
            stats,
            FrameReclaimStats {
                mapped_data_frames: 1,
                retired_data_frames: 1,
                page_table_frames: 2,
                shared_alias_mappings_excluded: 1,
            }
        );
        assert_eq!(stats.total_frames(), 4);
        assert_eq!(allocator.reclaimed.len(), 4);
        assert!(allocator.reclaimed.contains(&frame(0x1000)));
        assert!(allocator.reclaimed.contains(&frame(0x2000)));
        assert!(allocator.reclaimed.contains(&frame(0x5000)));
        assert!(allocator.reclaimed.contains(&frame(0x6000)));
        assert!(!allocator.reclaimed.contains(&frame(0x3000)));
        assert_eq!(
            allocator
                .reclaimed
                .iter()
                .filter(|candidate| **candidate == frame(0x5000))
                .count(),
            1,
            "the root is reclaimed only through the page-table ownership list"
        );
        // `retired` was consumed and success returns only stats, so a second
        // reclaim is structurally impossible.
    }

    #[test]
    fn failed_reclaim_retains_only_unreclaimed_ownership_for_exact_retry() {
        let retired = retired_with_all_backing_kinds();
        let mut allocator = TrackingReclaimer {
            fail_call: Some(2),
            ..TrackingReclaimer::default()
        };

        let failure = retired.reclaim_with(&mut allocator).unwrap_err();
        assert_eq!(
            failure.error(),
            FrameAllocatorError::OwnershipTrackingAllocationFailed
        );
        assert_eq!(failure.reclaimed().mapped_data_frames, 1);
        assert_eq!(failure.address_space().mapped_data_frames(), &[]);
        assert_eq!(
            failure.address_space().retired_data_frames(),
            &[frame(0x2000)]
        );
        assert_eq!(failure.address_space().page_table_frames().len(), 2);

        allocator.fail_call = None;
        let retry = failure
            .into_address_space()
            .reclaim_with(&mut allocator)
            .unwrap();
        assert_eq!(retry.mapped_data_frames, 0);
        assert_eq!(retry.retired_data_frames, 1);
        assert_eq!(retry.page_table_frames, 2);
        assert_eq!(allocator.reclaimed.len(), 4);
    }

    #[test]
    fn duplicate_owned_frame_is_rejected_without_losing_the_owner() {
        let root = frame(0x5000);
        let retired = RetiredAddressSpace {
            root,
            mapped_data_frames: alloc::vec![frame(0x1000)],
            retired_data_frames: alloc::vec![frame(0x1000)],
            shared_alias_mappings: Vec::new(),
            page_table_frames: alloc::vec![root],
        };
        let mut allocator = TrackingReclaimer::default();

        let failure = retired.reclaim_with(&mut allocator).unwrap_err();
        assert!(matches!(
            failure.error(),
            FrameAllocatorError::DoubleFree { address: 0x1000 }
        ));
        assert!(failure.address_space().mapped_data_frames().is_empty());
        assert_eq!(
            failure.address_space().retired_data_frames(),
            &[frame(0x1000)]
        );
        assert_eq!(allocator.reclaimed, alloc::vec![frame(0x1000)]);
    }

    #[test]
    fn mapper_rejects_kernel_and_zero_pages_before_editing_tables() {
        let mut address_space = fake_address_space();
        let mut allocator = FakeFrameAllocator::new();
        let zero_frame = allocator.allocate_frame().unwrap();
        let high_frame = allocator.allocate_frame().unwrap();

        assert_eq!(
            unsafe {
                address_space.map_user_4k_with_allocator(
                    0,
                    zero_frame,
                    UserPagePermissions::READ_ONLY,
                    UserMappingBacking::OwnedPrivate,
                    &mut allocator,
                )
            },
            Err(AddressSpaceError::ZeroPage)
        );
        assert_eq!(
            unsafe {
                address_space.map_user_4k_with_allocator(
                    KERNEL_ADDRESS_START,
                    high_frame,
                    UserPagePermissions::READ_ONLY,
                    UserMappingBacking::OwnedPrivate,
                    &mut allocator,
                )
            },
            Err(AddressSpaceError::HigherHalfAddress(KERNEL_ADDRESS_START))
        );
        assert!(address_space.mapper.level_4_table()[0].is_unused());
        assert!(address_space.mapper.level_4_table()[USER_P4_ENTRIES].is_unused());
    }
}
