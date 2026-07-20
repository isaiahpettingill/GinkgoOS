//! Minimal active x86_64 four-level page-table primitives.

use core::{
    arch::asm,
    ptr,
    sync::atomic::{compiler_fence, Ordering},
};

use crate::memory::{
    FrameAllocator, FrameAllocatorError, PhysAddr, PhysFrame, VirtAddr, VirtPage, PAGE_SIZE,
};

const ENTRY_COUNT: usize = 512;
const ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
const PRESENT: u64 = 1 << 0;
const WRITABLE: u64 = 1 << 1;
const WRITE_THROUGH: u64 = 1 << 3;
const CACHE_DISABLE: u64 = 1 << 4;
const HUGE_PAGE: u64 = 1 << 7;
const GLOBAL: u64 = 1 << 8;
const NO_EXECUTE: u64 = 1 << 63;

#[repr(transparent)]
#[derive(Clone, Copy)]
struct PageTableEntry(u64);

#[repr(C, align(4096))]
struct PageTable {
    entries: [PageTableEntry; ENTRY_COUNT],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageFlags(u64);

impl PageFlags {
    pub const READ_ONLY: Self = Self(0);
    pub const WRITABLE: Self = Self(WRITABLE);
    pub const WRITE_THROUGH: Self = Self(WRITE_THROUGH);
    pub const CACHE_DISABLE: Self = Self(CACHE_DISABLE);
    pub const GLOBAL: Self = Self(GLOBAL);
    pub const NO_EXECUTE: Self = Self(NO_EXECUTE);

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    const fn bits(self) -> u64 {
        self.0
    }
}

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
    AddressOverflow,
    CorruptPageTable,
    NotMapped,
    HugePageConflict,
}

pub struct ActivePageTable {
    root: PhysFrame,
    hhdm_offset: VirtAddr,
}

impl ActivePageTable {
    /// Creates a handle to the active four-level page tables.
    ///
    /// The caller must ensure that four-level paging is active, the supplied
    /// HHDM maps all page-table frames, and no other code can mutate the active
    /// page tables while this handle exists.
    pub unsafe fn from_current(hhdm_offset: u64) -> Result<Self, MapError> {
        let hhdm_offset = VirtAddr::new(hhdm_offset).ok_or(MapError::InvalidHhdmOffset)?;
        if hhdm_offset.as_u64() % PAGE_SIZE != 0 {
            return Err(MapError::InvalidHhdmOffset);
        }

        let mut cr3 = 0_u64;
        asm!(
            "mov {}, cr3",
            out(reg) cr3,
            options(nomem, nostack, preserves_flags),
        );

        let root_address = PhysAddr::new(cr3 & ADDRESS_MASK).ok_or(MapError::CorruptPageTable)?;
        let root = PhysFrame::from_start_address(root_address).ok_or(MapError::CorruptPageTable)?;

        Ok(Self { root, hhdm_offset })
    }

    pub fn root_frame(&self) -> PhysFrame {
        self.root
    }

    pub fn translate_addr(&self, address: VirtAddr) -> Option<PhysAddr> {
        let indexes = page_table_indexes(address);
        let mut table = self.table_pointer(self.root)?;

        let pml4_entry = unsafe { read_entry(table, indexes[0]) };
        if pml4_entry & PRESENT == 0 || pml4_entry & HUGE_PAGE != 0 {
            return None;
        }
        table = self.table_pointer(frame_from_entry(pml4_entry)?)?;

        let pdpt_entry = unsafe { read_entry(table, indexes[1]) };
        if pdpt_entry & PRESENT == 0 {
            return None;
        }
        if pdpt_entry & HUGE_PAGE != 0 {
            return translate_huge(pdpt_entry, address, 1_u64 << 30);
        }
        table = self.table_pointer(frame_from_entry(pdpt_entry)?)?;

        let page_directory_entry = unsafe { read_entry(table, indexes[2]) };
        if page_directory_entry & PRESENT == 0 {
            return None;
        }
        if page_directory_entry & HUGE_PAGE != 0 {
            return translate_huge(page_directory_entry, address, 1_u64 << 21);
        }
        table = self.table_pointer(frame_from_entry(page_directory_entry)?)?;

        let page_table_entry = unsafe { read_entry(table, indexes[3]) };
        if page_table_entry & PRESENT == 0 {
            return None;
        }

        let base = page_table_entry & ADDRESS_MASK;
        PhysAddr::new(base.checked_add(address.as_u64() & (PAGE_SIZE - 1))?)
    }

    /// Adds a 4 KiB mapping to the active address space.
    ///
    /// The caller must ensure that creating this alias does not violate any
    /// live Rust references and that `NO_EXECUTE` is used only when NX is
    /// supported. Existing huge mappings are not split.
    pub unsafe fn map_4k(
        &mut self,
        page: VirtPage,
        frame: PhysFrame,
        flags: PageFlags,
        allocator: &mut impl FrameAllocator,
    ) -> Result<(), MapError> {
        let indexes = page_table_indexes(page.start_address());
        let mut table = self
            .table_pointer(self.root)
            .ok_or(MapError::AddressOverflow)?;

        table =
            self.next_table_or_create(table, indexes[0], Level::Pml4, flags, allocator)?;
        table =
            self.next_table_or_create(table, indexes[1], Level::Pdpt, flags, allocator)?;
        table = self.next_table_or_create(
            table,
            indexes[2],
            Level::PageDirectory,
            flags,
            allocator,
        )?;

        let entry = read_entry(table, indexes[3]);
        if entry & PRESENT != 0 {
            return Err(MapError::AlreadyMapped);
        }

        write_entry(
            table,
            indexes[3],
            frame.start_address().as_u64() | PRESENT | flags.bits(),
        );
        compiler_fence(Ordering::SeqCst);
        invalidate_page(page.start_address());
        Ok(())
    }

    /// Removes a 4 KiB mapping from the active address space.
    ///
    /// The caller must ensure that no references, instruction pointers, or
    /// stack pointers continue to use the page. Empty intermediate tables are
    /// deliberately retained.
    pub unsafe fn unmap_4k(&mut self, page: VirtPage) -> Result<PhysFrame, UnmapError> {
        let indexes = page_table_indexes(page.start_address());
        let mut table = self
            .table_pointer(self.root)
            .ok_or(UnmapError::AddressOverflow)?;

        table = self.next_existing_table(table, indexes[0], Level::Pml4)?;
        table = self.next_existing_table(table, indexes[1], Level::Pdpt)?;
        table = self.next_existing_table(table, indexes[2], Level::PageDirectory)?;

        let entry = read_entry(table, indexes[3]);
        if entry & PRESENT == 0 {
            return Err(UnmapError::NotMapped);
        }
        let frame = frame_from_entry(entry).ok_or(UnmapError::CorruptPageTable)?;

        write_entry(table, indexes[3], 0);
        compiler_fence(Ordering::SeqCst);
        invalidate_page(page.start_address());
        Ok(frame)
    }

    unsafe fn next_table_or_create(
        &self,
        table: *mut PageTable,
        index: usize,
        level: Level,
        leaf_flags: PageFlags,
        allocator: &mut impl FrameAllocator,
    ) -> Result<*mut PageTable, MapError> {
        let entry = read_entry(table, index);
        if entry & PRESENT != 0 {
            if entry & HUGE_PAGE != 0 {
                return match level {
                    Level::Pml4 => Err(MapError::CorruptPageTable),
                    Level::Pdpt | Level::PageDirectory => Err(MapError::HugePageConflict),
                };
            }
            if (leaf_flags.bits() & WRITABLE != 0 && entry & WRITABLE == 0)
                || (leaf_flags.bits() & NO_EXECUTE == 0 && entry & NO_EXECUTE != 0)
            {
                return Err(MapError::ParentPermissionConflict);
            }

            let frame = frame_from_entry(entry).ok_or(MapError::CorruptPageTable)?;
            return self.table_pointer(frame).ok_or(MapError::AddressOverflow);
        }

        let frame = allocator
            .allocate_frame()
            .map_err(MapError::FrameAllocator)?
            .ok_or(MapError::OutOfFrames)?;
        let next_table = self
            .table_pointer(frame)
            .ok_or(MapError::AddressOverflow)?;
        ptr::write_bytes(next_table.cast::<u8>(), 0, PAGE_SIZE as usize);
        compiler_fence(Ordering::Release);
        write_entry(
            table,
            index,
            frame.start_address().as_u64() | PRESENT | WRITABLE,
        );
        Ok(next_table)
    }

    unsafe fn next_existing_table(
        &self,
        table: *mut PageTable,
        index: usize,
        level: Level,
    ) -> Result<*mut PageTable, UnmapError> {
        let entry = read_entry(table, index);
        if entry & PRESENT == 0 {
            return Err(UnmapError::NotMapped);
        }
        if entry & HUGE_PAGE != 0 {
            return match level {
                Level::Pml4 => Err(UnmapError::CorruptPageTable),
                Level::Pdpt | Level::PageDirectory => Err(UnmapError::HugePageConflict),
            };
        }

        let frame = frame_from_entry(entry).ok_or(UnmapError::CorruptPageTable)?;
        self.table_pointer(frame).ok_or(UnmapError::AddressOverflow)
    }

    fn table_pointer(&self, frame: PhysFrame) -> Option<*mut PageTable> {
        let address = self
            .hhdm_offset
            .checked_add(frame.start_address().as_u64())?;
        Some(address.as_u64() as usize as *mut PageTable)
    }
}

#[derive(Clone, Copy)]
enum Level {
    Pml4,
    Pdpt,
    PageDirectory,
}

fn page_table_indexes(address: VirtAddr) -> [usize; 4] {
    let address = address.as_u64();
    [
        ((address >> 39) & 0x1ff) as usize,
        ((address >> 30) & 0x1ff) as usize,
        ((address >> 21) & 0x1ff) as usize,
        ((address >> 12) & 0x1ff) as usize,
    ]
}

fn frame_from_entry(entry: u64) -> Option<PhysFrame> {
    let address = PhysAddr::new(entry & ADDRESS_MASK)?;
    PhysFrame::from_start_address(address)
}

fn translate_huge(entry: u64, address: VirtAddr, page_size: u64) -> Option<PhysAddr> {
    let base = entry & ADDRESS_MASK & !(page_size - 1);
    let offset = address.as_u64() & (page_size - 1);
    PhysAddr::new(base.checked_add(offset)?)
}

unsafe fn read_entry(table: *const PageTable, index: usize) -> u64 {
    ptr::read_volatile(table.cast::<PageTableEntry>().add(index)).0
}

unsafe fn write_entry(table: *mut PageTable, index: usize, value: u64) {
    ptr::write_volatile(
        table.cast::<PageTableEntry>().add(index),
        PageTableEntry(value),
    );
}

unsafe fn invalidate_page(address: VirtAddr) {
    asm!(
        "invlpg [{}]",
        in(reg) address.as_u64(),
        options(nostack, preserves_flags),
    );
}
