//! Host-testable policy and transaction helpers for the page-backed kernel heap.

use alloc::vec::Vec;

use crate::{
    memory::{FrameAllocatorError, PhysFrame, VirtAddr, VirtPage, PAGE_SIZE},
    paging::UnmapError,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeapRollbackError {
    AddressOverflow,
    Unmap(UnmapError),
    FrameMismatch {
        expected: PhysFrame,
        actual: PhysFrame,
    },
    FrameAllocator(FrameAllocatorError),
}

pub fn planned_heap_growth_bytes(
    current_available: usize,
    minimum_available: usize,
    available_frames: u64,
    growth_quantum: usize,
    frame_reserve: u64,
    frame_cost: u64,
) -> Option<usize> {
    let shortage = minimum_available.saturating_sub(current_available);
    if shortage == 0 {
        return Some(0);
    }
    let page_size = PAGE_SIZE as usize;
    let shortage_pages = shortage.checked_add(page_size - 1)? / page_size;
    let quantum_pages = growth_quantum / page_size;
    let safe_pages = available_frames.saturating_sub(frame_reserve) / frame_cost.max(1);
    let selected_pages = (shortage_pages as u64)
        .min(quantum_pages as u64)
        .min(safe_pages);
    usize::try_from(selected_pages).ok()?.checked_mul(page_size)
}

pub const fn adaptive_heap_headroom(
    available_ram_bytes: u64,
    minimum: usize,
    maximum: usize,
) -> usize {
    let scaled = available_ram_bytes / 64;
    let bounded = if scaled < minimum as u64 {
        minimum as u64
    } else if scaled > maximum as u64 {
        maximum as u64
    } else {
        scaled
    };
    bounded as usize
}

pub fn rollback_heap_frames(
    start: u64,
    mapped: usize,
    allocated: &[PhysFrame],
    mut unmap: impl FnMut(VirtPage) -> Result<PhysFrame, UnmapError>,
    reclaim: impl FnOnce(&[PhysFrame]) -> Result<(), FrameAllocatorError>,
) -> Result<(), HeapRollbackError> {
    if mapped > allocated.len() {
        return Err(HeapRollbackError::AddressOverflow);
    }
    for index in (0..mapped).rev() {
        let offset = (index as u64)
            .checked_mul(PAGE_SIZE)
            .ok_or(HeapRollbackError::AddressOverflow)?;
        let address = start
            .checked_add(offset)
            .ok_or(HeapRollbackError::AddressOverflow)?;
        let page = VirtPage::from_start_address(VirtAddr::new(address))
            .map_err(|_| HeapRollbackError::AddressOverflow)?;
        let actual = unmap(page).map_err(HeapRollbackError::Unmap)?;
        let expected = allocated[index];
        if actual != expected {
            return Err(HeapRollbackError::FrameMismatch { expected, actual });
        }
    }
    if !allocated.is_empty() {
        reclaim(allocated).map_err(HeapRollbackError::FrameAllocator)?;
    }
    Ok(())
}

pub fn fail_stop_heap_rollback(allocated: Vec<PhysFrame>, error: HeapRollbackError) -> ! {
    // The frame allocator still records these frames as live. Keep the exact list
    // allocated too, then halt through the kernel's panic path.
    core::mem::forget(allocated);
    panic!("kernel heap rollback invariant failed: {error:?}");
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use super::*;
    use crate::memory::PhysAddr;

    const MIB: usize = 1024 * 1024;
    const GROWTH_QUANTUM: usize = 16 * MIB;
    const FRAME_RESERVE: u64 = 64;
    const FRAME_COST: u64 = 2;

    fn plan(current: usize, minimum: usize, frames: u64) -> Option<usize> {
        planned_heap_growth_bytes(
            current,
            minimum,
            frames,
            GROWTH_QUANTUM,
            FRAME_RESERVE,
            FRAME_COST,
        )
    }

    fn frame(address: u64) -> PhysFrame {
        PhysFrame::from_start_address(PhysAddr::new(address)).unwrap()
    }

    #[test]
    fn growth_plan_is_page_rounded_and_bounded_by_shortage_and_quantum() {
        assert_eq!(plan(0, 1, u64::MAX), Some(PAGE_SIZE as usize));
        assert_eq!(plan(0, usize::MAX / 2, u64::MAX), Some(GROWTH_QUANTUM));
    }

    #[test]
    fn low_memory_growth_backs_off_cheaply_and_recovers_after_frames_return() {
        for _ in 0..3 {
            assert_eq!(plan(0, 8 * MIB, FRAME_RESERVE), Some(0));
        }
        assert_eq!(
            plan(0, 8 * MIB, FRAME_RESERVE + 4),
            Some(PAGE_SIZE as usize * 2),
        );
    }

    #[test]
    fn adaptive_headroom_scales_and_stays_bounded() {
        assert_eq!(adaptive_heap_headroom(0, 8 * MIB, 256 * MIB), 8 * MIB);
        assert_eq!(
            adaptive_heap_headroom(8 * 1024 * MIB as u64, 8 * MIB, 256 * MIB),
            128 * MIB,
        );
        assert_eq!(
            adaptive_heap_headroom(u64::MAX, 8 * MIB, 256 * MIB),
            256 * MIB,
        );
    }

    #[test]
    fn ordinary_out_of_frames_rollback_unmaps_in_reverse_and_reclaims_once() {
        let allocated = vec![frame(0x1000), frame(0x2000), frame(0x3000)];
        let mut unmapped = Vec::new();
        let mut reclaimed = Vec::new();

        assert_eq!(
            rollback_heap_frames(
                0x4000,
                allocated.len(),
                &allocated,
                |page| {
                    let index = ((page.start_address().as_u64() - 0x4000) / PAGE_SIZE) as usize;
                    unmapped.push(index);
                    Ok(allocated[index])
                },
                |frames| {
                    reclaimed.extend_from_slice(frames);
                    Ok(())
                },
            ),
            Ok(()),
        );
        assert_eq!(unmapped, vec![2, 1, 0]);
        assert_eq!(reclaimed, allocated);
    }

    #[test]
    fn rollback_reports_unmap_mismatch_and_reclaim_invariants() {
        let allocated = vec![frame(0x1000)];
        assert_eq!(
            rollback_heap_frames(
                0x4000,
                1,
                &allocated,
                |_| Err(UnmapError::NotMapped),
                |_| Ok(()),
            ),
            Err(HeapRollbackError::Unmap(UnmapError::NotMapped)),
        );
        assert_eq!(
            rollback_heap_frames(0x4000, 1, &allocated, |_| Ok(frame(0x2000)), |_| Ok(()),),
            Err(HeapRollbackError::FrameMismatch {
                expected: frame(0x1000),
                actual: frame(0x2000),
            }),
        );
        assert_eq!(
            rollback_heap_frames(
                0x4000,
                1,
                &allocated,
                |_| Ok(frame(0x1000)),
                |_| Err(FrameAllocatorError::NeverAllocatedFrame { address: 0x1000 }),
            ),
            Err(HeapRollbackError::FrameAllocator(
                FrameAllocatorError::NeverAllocatedFrame { address: 0x1000 },
            )),
        );
    }

    #[test]
    #[should_panic(expected = "kernel heap rollback invariant failed")]
    fn rollback_invariant_error_is_fail_stop() {
        fail_stop_heap_rollback(vec![frame(0x1000)], HeapRollbackError::AddressOverflow);
    }
}
