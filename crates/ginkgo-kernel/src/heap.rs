//! Bootstrap and page-backed kernel heap management.

use alloc::vec::Vec;
use core::ptr::NonNull;

use ginkgo_kernel::{
    memory::{FrameAllocatorError, PhysFrame, UsableFrameAllocator, VirtAddr, VirtPage, PAGE_SIZE},
    paging::{ActivePageTable, MapError, PageTableFlags},
};
use spinning_top::RawSpinlock;
use talc::{source::Claim, TalcLock};

pub const BOOTSTRAP_HEAP_SIZE: usize = 32 * 1024 * 1024;
pub const INITIAL_PAGE_BACKED_BYTES: usize = 16 * 1024 * 1024;
pub const PAGE_BACKED_GROWTH_BYTES: usize = 16 * 1024 * 1024;
pub const MINIMUM_HEAP_HEADROOM: usize = 8 * 1024 * 1024;
const PAGE_BACKED_HEAP_BASE: u64 = 0xffff_b000_0000_0000;
const PAGE_BACKED_HEAP_LIMIT: u64 = 0xffff_b010_0000_0000;

#[global_allocator]
static ALLOCATOR: TalcLock<RawSpinlock, Claim> = TalcLock::new(unsafe {
    #[link_section = ".bootstrap_heap"]
    static mut HEAP: [u8; BOOTSTRAP_HEAP_SIZE] = [0xa5; BOOTSTRAP_HEAP_SIZE];
    Claim::array(&raw mut HEAP)
});

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeapGrowError {
    AddressOverflow,
    VirtualLimit,
    AlreadyMapped(u64),
    OutOfFrames,
    FrameAllocator(FrameAllocatorError),
    Mapping(MapError),
    TalcRejected,
}

pub struct PageBackedHeap {
    mapped_end: u64,
    talc_end: NonNull<u8>,
    growth_count: u64,
    failed_growth_count: u64,
}

impl PageBackedHeap {
    pub fn initialize(
        page_table: &mut ActivePageTable,
        frames: &mut UsableFrameAllocator<'_>,
    ) -> Result<Self, HeapGrowError> {
        let mapped_end = PAGE_BACKED_HEAP_BASE
            .checked_add(INITIAL_PAGE_BACKED_BYTES as u64)
            .ok_or(HeapGrowError::AddressOverflow)?;
        map_heap_pages(
            page_table,
            frames,
            PAGE_BACKED_HEAP_BASE,
            INITIAL_PAGE_BACKED_BYTES,
        )?;

        let talc_end = {
            let mut talc = ALLOCATOR.lock();
            unsafe { talc.claim(PAGE_BACKED_HEAP_BASE as *mut u8, INITIAL_PAGE_BACKED_BYTES) }
        };
        let Some(talc_end) = talc_end else {
            rollback_heap_pages(
                page_table,
                frames,
                PAGE_BACKED_HEAP_BASE,
                INITIAL_PAGE_BACKED_BYTES,
            );
            return Err(HeapGrowError::TalcRejected);
        };
        if talc_end.as_ptr() as u64 != mapped_end {
            panic!("page-backed heap claim did not consume the complete mapped range");
        }

        Ok(Self {
            mapped_end,
            talc_end,
            growth_count: 1,
            failed_growth_count: 0,
        })
    }

    pub fn available_bytes(&self) -> usize {
        ALLOCATOR.lock().counters().available_bytes
    }

    /// Total allocator capacity supplied by the bootstrap arena and page-backed heap.
    pub const fn committed_bytes(&self) -> u64 {
        total_committed_bytes(self.mapped_end - PAGE_BACKED_HEAP_BASE)
    }

    pub const fn growth_count(&self) -> u64 {
        self.growth_count
    }

    pub const fn failed_growth_count(&self) -> u64 {
        self.failed_growth_count
    }

    pub fn ensure_headroom(
        &mut self,
        minimum_available: usize,
        page_table: &mut ActivePageTable,
        frames: &mut UsableFrameAllocator<'_>,
    ) -> Result<(), HeapGrowError> {
        while self.available_bytes() < minimum_available {
            if let Err(error) = self.grow(page_table, frames, PAGE_BACKED_GROWTH_BYTES) {
                return Err(error);
            }
        }
        Ok(())
    }

    pub fn grow(
        &mut self,
        page_table: &mut ActivePageTable,
        frames: &mut UsableFrameAllocator<'_>,
        bytes: usize,
    ) -> Result<(), HeapGrowError> {
        let result = self.grow_inner(page_table, frames, bytes);
        if result.is_err() {
            self.failed_growth_count = self.failed_growth_count.saturating_add(1);
        }
        result
    }

    fn grow_inner(
        &mut self,
        page_table: &mut ActivePageTable,
        frames: &mut UsableFrameAllocator<'_>,
        bytes: usize,
    ) -> Result<(), HeapGrowError> {
        let bytes = page_rounded_bytes(bytes)?;
        let new_end = self
            .mapped_end
            .checked_add(bytes as u64)
            .ok_or(HeapGrowError::AddressOverflow)?;
        if new_end > PAGE_BACKED_HEAP_LIMIT {
            return Err(HeapGrowError::VirtualLimit);
        }

        map_heap_pages(page_table, frames, self.mapped_end, bytes)?;
        let talc_end = unsafe { ALLOCATOR.lock().extend(self.talc_end, new_end as *mut u8) };
        if talc_end.as_ptr() as u64 != new_end {
            panic!("page-backed heap extension did not consume the complete mapped range");
        }
        self.talc_end = talc_end;
        self.mapped_end = new_end;
        self.growth_count = self.growth_count.saturating_add(1);
        Ok(())
    }
}

const fn total_committed_bytes(page_backed_bytes: u64) -> u64 {
    (BOOTSTRAP_HEAP_SIZE as u64).saturating_add(page_backed_bytes)
}

fn page_rounded_bytes(bytes: usize) -> Result<usize, HeapGrowError> {
    if bytes == 0 {
        return Err(HeapGrowError::AddressOverflow);
    }
    bytes
        .checked_add(PAGE_SIZE as usize - 1)
        .map(|value| value / PAGE_SIZE as usize * PAGE_SIZE as usize)
        .ok_or(HeapGrowError::AddressOverflow)
}

fn map_heap_pages(
    page_table: &mut ActivePageTable,
    frames: &mut UsableFrameAllocator<'_>,
    start: u64,
    bytes: usize,
) -> Result<(), HeapGrowError> {
    let pages = page_rounded_bytes(bytes)? / PAGE_SIZE as usize;
    let end = start
        .checked_add(bytes as u64)
        .ok_or(HeapGrowError::AddressOverflow)?;
    VirtAddr::try_new(start).map_err(|_| HeapGrowError::AddressOverflow)?;
    VirtAddr::try_new(end - 1).map_err(|_| HeapGrowError::AddressOverflow)?;

    for index in 0..pages {
        let address = start + index as u64 * PAGE_SIZE;
        let virtual_address = VirtAddr::new(address);
        if page_table.translate_addr(virtual_address).is_some() {
            return Err(HeapGrowError::AlreadyMapped(address));
        }
    }

    let mut allocated = Vec::<PhysFrame>::new();
    allocated.try_reserve_exact(pages).map_err(|_| {
        HeapGrowError::FrameAllocator(FrameAllocatorError::OwnershipTrackingAllocationFailed)
    })?;
    let mut mapped = 0_usize;
    for index in 0..pages {
        let frame = match frames.allocate_frame() {
            Ok(Some(frame)) => frame,
            Ok(None) => {
                rollback_partial(page_table, frames, start, mapped, &allocated);
                return Err(HeapGrowError::OutOfFrames);
            }
            Err(error) => {
                rollback_partial(page_table, frames, start, mapped, &allocated);
                return Err(HeapGrowError::FrameAllocator(error));
            }
        };
        allocated.push(frame);
        let page = VirtPage::from_start_address(VirtAddr::new(start + index as u64 * PAGE_SIZE))
            .map_err(|_| HeapGrowError::AddressOverflow)?;
        if let Err(error) = unsafe {
            page_table.map_4k(
                page,
                frame,
                PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE,
                frames,
            )
        } {
            rollback_partial(page_table, frames, start, mapped, &allocated);
            return Err(HeapGrowError::Mapping(error));
        }
        mapped += 1;
    }
    Ok(())
}

fn rollback_heap_pages(
    page_table: &mut ActivePageTable,
    frames: &mut UsableFrameAllocator<'_>,
    start: u64,
    bytes: usize,
) {
    let pages = bytes / PAGE_SIZE as usize;
    let mut allocated = Vec::new();
    allocated
        .try_reserve_exact(pages)
        .expect("heap rollback metadata allocation failed");
    for index in 0..pages {
        let page = VirtPage::from_start_address(VirtAddr::new(start + index as u64 * PAGE_SIZE))
            .expect("heap rollback page must remain aligned");
        allocated.push(unsafe {
            page_table
                .unmap_4k(page)
                .expect("heap rollback mapping must remain present")
        });
    }
    frames
        .deallocate_frames(&allocated)
        .expect("heap rollback frames must remain allocator-owned");
}

fn rollback_partial(
    page_table: &mut ActivePageTable,
    frames: &mut UsableFrameAllocator<'_>,
    start: u64,
    mapped: usize,
    allocated: &[PhysFrame],
) {
    for index in (0..mapped).rev() {
        let page = VirtPage::from_start_address(VirtAddr::new(start + index as u64 * PAGE_SIZE))
            .expect("heap rollback page must remain aligned");
        let unmapped = unsafe {
            page_table
                .unmap_4k(page)
                .expect("heap rollback mapping must remain present")
        };
        assert_eq!(unmapped, allocated[index]);
    }
    if !allocated.is_empty() {
        frames
            .deallocate_frames(allocated)
            .expect("heap rollback frames must remain allocator-owned");
    }
}

#[cfg(test)]
mod tests {
    use super::{total_committed_bytes, BOOTSTRAP_HEAP_SIZE, INITIAL_PAGE_BACKED_BYTES};

    #[test]
    fn committed_capacity_includes_bootstrap_and_page_backed_arenas() {
        assert_eq!(
            total_committed_bytes(INITIAL_PAGE_BACKED_BYTES as u64),
            (BOOTSTRAP_HEAP_SIZE + INITIAL_PAGE_BACKED_BYTES) as u64,
        );
    }
}
