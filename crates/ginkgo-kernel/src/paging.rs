//! Active x86_64 page-table access built on the `x86_64` crate.

#[path = "address_space.rs"]
pub mod address_space;

use x86_64::{
    registers::control::Cr3,
    structures::paging::{
        mapper::{MapToError, Translate, UnmapError as X86UnmapError},
        Mapper, OffsetPageTable, PageTable, PhysFrame, Size4KiB,
    },
};

use crate::memory::{FrameAllocatorError, UsableFrameAllocator, VirtAddr, VirtPage, PAGE_SIZE};

pub use x86_64::structures::paging::PageTableFlags;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapError {
    InvalidHhdmOffset,
    AddressOverflow,
    CorruptPageTable,
    AlreadyMapped,
    ParentPermissionConflict,
    HugePageConflict,
    OutOfFrames,
    FrameAllocator(FrameAllocatorError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnmapError {
    CorruptPageTable,
    NotMapped,
    HugePageConflict,
}

pub struct ActivePageTable {
    root: PhysFrame<Size4KiB>,
    hhdm_offset: VirtAddr,
    mapper: OffsetPageTable<'static>,
}

impl ActivePageTable {
    /// Creates exclusive access to the active four-level page tables.
    ///
    /// The caller must ensure that four-level paging is active, the supplied
    /// HHDM maps all page-table frames, and no other code mutates the active
    /// page tables while this handle exists.
    pub unsafe fn from_current(hhdm_offset: u64) -> Result<Self, MapError> {
        let hhdm_offset =
            VirtAddr::try_new(hhdm_offset).map_err(|_| MapError::InvalidHhdmOffset)?;
        if !hhdm_offset.is_aligned(PAGE_SIZE) {
            return Err(MapError::InvalidHhdmOffset);
        }

        let (root, _) = Cr3::read();
        let root_virtual = hhdm_offset
            .as_u64()
            .checked_add(root.start_address().as_u64())
            .and_then(|address| VirtAddr::try_new(address).ok())
            .ok_or(MapError::AddressOverflow)?;
        let root_table = unsafe { &mut *root_virtual.as_mut_ptr::<PageTable>() };
        let mapper = unsafe { OffsetPageTable::new(root_table, hhdm_offset) };

        Ok(Self {
            root,
            hhdm_offset,
            mapper,
        })
    }

    pub fn root_frame(&self) -> PhysFrame<Size4KiB> {
        self.root
    }

    /// Returns the HHDM offset validated when this active-root capability was built.
    ///
    /// Safe paging consumers must derive HHDM access from this value rather than
    /// accepting an independent raw offset which could disagree with the mapper.
    pub const fn hhdm_offset(&self) -> VirtAddr {
        self.hhdm_offset
    }

    /// Switches to this page-table root while preserving the current CR3 flags.
    ///
    /// The caller must ensure that this root maps the current instruction, stack,
    /// and all other memory needed immediately after the switch.
    pub unsafe fn activate(&self) {
        let (_, flags) = Cr3::read();
        unsafe { Cr3::write(self.root, flags) };
    }

    pub fn is_active(&self) -> bool {
        Cr3::read().0 == self.root
    }

    /// Reserves every page-table frame reachable from the active root so the
    /// physical allocator cannot return live paging structures to DMA users.
    pub fn reserve_active_frames(
        &self,
        allocator: &mut UsableFrameAllocator<'_>,
    ) -> Result<usize, MapError> {
        let mut reserved = usize::from(
            allocator
                .reserve_frame(self.root)
                .map_err(MapError::FrameAllocator)?,
        );

        for p4_entry in self.mapper.level_4_table().iter() {
            if !p4_entry.flags().contains(PageTableFlags::PRESENT) {
                continue;
            }
            if p4_entry.flags().contains(PageTableFlags::HUGE_PAGE) {
                return Err(MapError::CorruptPageTable);
            }
            let p3_frame = p4_entry.frame().map_err(|_| MapError::CorruptPageTable)?;
            let newly_reserved = allocator
                .reserve_frame(p3_frame)
                .map_err(MapError::FrameAllocator)?;
            reserved += usize::from(newly_reserved);
            if !newly_reserved {
                continue;
            }

            for p3_entry in self.table(p3_frame)?.iter() {
                let flags = p3_entry.flags();
                if !flags.contains(PageTableFlags::PRESENT)
                    || flags.contains(PageTableFlags::HUGE_PAGE)
                {
                    continue;
                }
                let p2_frame = p3_entry.frame().map_err(|_| MapError::CorruptPageTable)?;
                let newly_reserved = allocator
                    .reserve_frame(p2_frame)
                    .map_err(MapError::FrameAllocator)?;
                reserved += usize::from(newly_reserved);
                if !newly_reserved {
                    continue;
                }

                for p2_entry in self.table(p2_frame)?.iter() {
                    let flags = p2_entry.flags();
                    if !flags.contains(PageTableFlags::PRESENT)
                        || flags.contains(PageTableFlags::HUGE_PAGE)
                    {
                        continue;
                    }
                    let p1_frame = p2_entry.frame().map_err(|_| MapError::CorruptPageTable)?;
                    reserved += usize::from(
                        allocator
                            .reserve_frame(p1_frame)
                            .map_err(MapError::FrameAllocator)?,
                    );
                }
            }
        }
        Ok(reserved)
    }

    pub fn translate_addr(&self, address: VirtAddr) -> Option<crate::memory::PhysAddr> {
        self.mapper.translate_addr(address)
    }

    /// Adds a 4 KiB mapping to the active address space.
    ///
    /// The caller must ensure that creating this alias does not violate any
    /// live Rust references and that `NO_EXECUTE` is used only when supported.
    pub unsafe fn map_4k(
        &mut self,
        page: VirtPage,
        frame: PhysFrame<Size4KiB>,
        flags: PageTableFlags,
        allocator: &mut UsableFrameAllocator<'_>,
    ) -> Result<(), MapError> {
        let flags = flags | PageTableFlags::PRESENT;
        self.validate_parent_permissions(page, flags)?;
        let result = unsafe { self.mapper.map_to(page, frame, flags, allocator) };
        match result {
            Ok(flush) => {
                flush.flush();
                Ok(())
            }
            Err(MapToError::PageAlreadyMapped(_)) => Err(MapError::AlreadyMapped),
            Err(MapToError::ParentEntryHugePage) => Err(MapError::HugePageConflict),
            Err(MapToError::FrameAllocationFailed) => Err(allocator
                .error()
                .map(MapError::FrameAllocator)
                .unwrap_or(MapError::OutOfFrames)),
        }
    }

    /// Removes a 4 KiB mapping from the active address space.
    ///
    /// The caller must ensure that no references, instruction pointers, or
    /// stack pointers continue to use the page. Empty parent tables remain.
    pub unsafe fn unmap_4k(&mut self, page: VirtPage) -> Result<PhysFrame<Size4KiB>, UnmapError> {
        match self.mapper.unmap(page) {
            Ok((frame, flush)) => {
                flush.flush();
                Ok(frame)
            }
            Err(X86UnmapError::PageNotMapped) => Err(UnmapError::NotMapped),
            Err(X86UnmapError::ParentEntryHugePage) => Err(UnmapError::HugePageConflict),
            Err(X86UnmapError::InvalidFrameAddress(_)) => Err(UnmapError::CorruptPageTable),
        }
    }

    fn validate_parent_permissions(
        &self,
        page: VirtPage,
        requested: PageTableFlags,
    ) -> Result<(), MapError> {
        let address = page.start_address();
        let indexes = [
            usize::from(address.p4_index()),
            usize::from(address.p3_index()),
            usize::from(address.p2_index()),
        ];
        let mut table = self.mapper.level_4_table();

        for (level, index) in indexes.into_iter().enumerate() {
            let entry = &table[index];
            let flags = entry.flags();
            if !flags.contains(PageTableFlags::PRESENT) {
                return Ok(());
            }
            if flags.contains(PageTableFlags::HUGE_PAGE) {
                return if level == 0 {
                    Err(MapError::CorruptPageTable)
                } else {
                    Err(MapError::HugePageConflict)
                };
            }
            if (requested.contains(PageTableFlags::WRITABLE)
                && !flags.contains(PageTableFlags::WRITABLE))
                || (requested.contains(PageTableFlags::USER_ACCESSIBLE)
                    && !flags.contains(PageTableFlags::USER_ACCESSIBLE))
                || (!requested.contains(PageTableFlags::NO_EXECUTE)
                    && flags.contains(PageTableFlags::NO_EXECUTE))
            {
                return Err(MapError::ParentPermissionConflict);
            }
            let frame = entry.frame().map_err(|_| MapError::CorruptPageTable)?;
            table = self.table(frame)?;
        }
        Ok(())
    }

    fn table(&self, frame: PhysFrame<Size4KiB>) -> Result<&PageTable, MapError> {
        let address = self
            .mapper
            .phys_offset()
            .as_u64()
            .checked_add(frame.start_address().as_u64())
            .and_then(|address| VirtAddr::try_new(address).ok())
            .ok_or(MapError::AddressOverflow)?;
        Ok(unsafe { &*address.as_ptr::<PageTable>() })
    }
}
