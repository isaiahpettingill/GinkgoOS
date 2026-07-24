//! Physical frame allocation backed by the Limine memory map.

use alloc::vec::Vec;
use core::marker::PhantomData;

use x86_64::structures::paging::{FrameAllocator, Page, PhysFrame as GenericPhysFrame, Size4KiB};

use crate::{
    arch::MAX_PHYSICAL_ADDRESS_BITS,
    limine::{MemoryMapError, MemoryMapResponse, MEMORY_MAP_USABLE},
};

pub use x86_64::{PhysAddr, VirtAddr};

pub type PhysFrame = GenericPhysFrame<Size4KiB>;
pub type VirtPage = Page<Size4KiB>;
pub const PAGE_SIZE: u64 = 4096;
pub const DMA_32BIT_ADDRESS_LIMIT: u64 = 1_u64 << 32;

const fn physical_address_space_size(bits: u8) -> Option<u64> {
    if bits < 12 || bits > MAX_PHYSICAL_ADDRESS_BITS {
        None
    } else {
        Some(1_u64 << bits)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameAllocatorError {
    InvalidMemoryMap(MemoryMapError),
    InvalidPhysicalAddressBits { bits: u8 },
    InvalidUsableRegion { base: u64, length: u64 },
    UsableRegionOverflow { base: u64, length: u64 },
    PhysicalAddressTooLarge { base: u64, length: u64 },
    ReservedFrame { address: u64 },
    NeverAllocatedFrame { address: u64 },
    DuplicateFrameInBatch { address: u64 },
    DoubleFree { address: u64 },
    OwnershipTrackingAllocationFailed,
    UsableFrameCountOverflow,
    OverlappingMemoryMapRegions { usable_base: u64, other_base: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OwnershipState {
    Allocated,
    Free,
    Reserved,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct OwnershipRecord {
    address: u64,
    state: OwnershipState,
    dma_low: bool,
}

/// Exact ownership state for every frame issued or explicitly reserved.
///
/// Addresses are used instead of `PhysFrame` so this state machine can be
/// exhaustively tested on a host without constructing a Limine memory map.
struct OwnershipLedger {
    records: Vec<OwnershipRecord>,
    free: Vec<u64>,
    live_allocated: u64,
    fresh_issued: u64,
    dma_low_live: u64,
    above_4g_live: u64,
}

impl OwnershipLedger {
    const fn new() -> Self {
        Self {
            records: Vec::new(),
            free: Vec::new(),
            live_allocated: 0,
            fresh_issued: 0,
            dma_low_live: 0,
            above_4g_live: 0,
        }
    }

    fn live_allocated_count(&self) -> u64 {
        self.live_allocated
    }

    fn fresh_issued_count(&self) -> u64 {
        self.fresh_issued
    }

    fn free_count(&self) -> usize {
        self.free.len()
    }

    fn reserved_count(&self) -> usize {
        self.records
            .iter()
            .filter(|record| record.state == OwnershipState::Reserved)
            .count()
    }

    fn find(&self, address: u64) -> Option<usize> {
        self.records
            .iter()
            .position(|record| record.address == address)
    }

    /// Claims an address that has not previously been issued. Returns `false`
    /// when the address is already tracked, including when it is reserved.
    fn claim_fresh(&mut self, address: u64) -> Result<bool, FrameAllocatorError> {
        if self.find(address).is_some() {
            return Ok(false);
        }

        self.records
            .try_reserve(1)
            .map_err(|_| FrameAllocatorError::OwnershipTrackingAllocationFailed)?;
        self.records.push(OwnershipRecord {
            address,
            state: OwnershipState::Allocated,
            dma_low: false,
        });
        self.live_allocated = self.live_allocated.saturating_add(1);
        self.fresh_issued = self.fresh_issued.saturating_add(1);
        if address >= DMA_32BIT_ADDRESS_LIMIT {
            self.above_4g_live = self.above_4g_live.saturating_add(1);
        }
        Ok(true)
    }

    /// Reclaimed addresses are always preferred over fresh addresses.
    #[cfg(test)]
    fn claim_reclaimed(&mut self) -> Option<u64> {
        self.claim_reclaimed_below(u64::MAX)
    }

    fn claim_reclaimed_below(&mut self, max_address_exclusive: u64) -> Option<u64> {
        let free_index = self.free.iter().rposition(|address| {
            address
                .checked_add(PAGE_SIZE)
                .is_some_and(|end| end <= max_address_exclusive)
        })?;
        let address = self.free.swap_remove(free_index);
        self.mark_reclaimed_allocated(address);
        Some(address)
    }

    fn claim_reclaimed_at_or_above(&mut self, min_address: u64) -> Option<u64> {
        let free_index = self
            .free
            .iter()
            .rposition(|address| *address >= min_address)?;
        let address = self.free.swap_remove(free_index);
        self.mark_reclaimed_allocated(address);
        Some(address)
    }

    fn claim_reclaimed_range_below(
        &mut self,
        pages: usize,
        max_address_exclusive: u64,
    ) -> Option<u64> {
        let byte_len = u64::try_from(pages).ok()?.checked_mul(PAGE_SIZE)?;
        let start = self.free.iter().copied().find(|start| {
            start
                .checked_add(byte_len)
                .is_some_and(|end| end <= max_address_exclusive)
                && (0..pages).all(|index| {
                    let address = *start + index as u64 * PAGE_SIZE;
                    self.free.contains(&address)
                })
        })?;
        for index in 0..pages {
            let address = start + index as u64 * PAGE_SIZE;
            let free_index = self
                .free
                .iter()
                .position(|candidate| *candidate == address)
                .expect("reclaimed range was completely preflighted");
            self.free.swap_remove(free_index);
            self.mark_reclaimed_allocated(address);
        }
        Some(start)
    }

    fn mark_reclaimed_allocated(&mut self, address: u64) {
        let index = self
            .find(address)
            .expect("free-list address must have an ownership record");
        debug_assert_eq!(self.records[index].state, OwnershipState::Free);
        self.records[index].state = OwnershipState::Allocated;
        self.records[index].dma_low = false;
        self.live_allocated = self.live_allocated.saturating_add(1);
        if address >= DMA_32BIT_ADDRESS_LIMIT {
            self.above_4g_live = self.above_4g_live.saturating_add(1);
        }
    }

    fn reserve(&mut self, address: u64) -> Result<bool, FrameAllocatorError> {
        if let Some(index) = self.find(address) {
            match self.records[index].state {
                OwnershipState::Reserved => return Ok(false),
                OwnershipState::Allocated => {
                    self.live_allocated = self.live_allocated.saturating_sub(1);
                    if address >= DMA_32BIT_ADDRESS_LIMIT {
                        self.above_4g_live = self.above_4g_live.saturating_sub(1);
                    }
                    if self.records[index].dma_low {
                        self.dma_low_live = self.dma_low_live.saturating_sub(1);
                    }
                }
                OwnershipState::Free => {
                    let free_index = self
                        .free
                        .iter()
                        .position(|free_address| *free_address == address)
                        .expect("free ownership record must be present in free list");
                    self.free.swap_remove(free_index);
                }
            }
            self.records[index].state = OwnershipState::Reserved;
            self.records[index].dma_low = false;
            return Ok(true);
        }

        self.records
            .try_reserve(1)
            .map_err(|_| FrameAllocatorError::OwnershipTrackingAllocationFailed)?;
        self.records.push(OwnershipRecord {
            address,
            state: OwnershipState::Reserved,
            dma_low: false,
        });
        Ok(true)
    }

    #[cfg(test)]
    fn reclaim(&mut self, addresses: &[u64]) -> Result<(), FrameAllocatorError> {
        self.reclaim_with(addresses.len(), |index| addresses[index])
    }

    fn reclaim_with(
        &mut self,
        count: usize,
        address_at: impl Fn(usize) -> u64,
    ) -> Result<(), FrameAllocatorError> {
        for index in 0..count {
            let address = address_at(index);
            if (0..index).any(|prior| address_at(prior) == address) {
                return Err(FrameAllocatorError::DuplicateFrameInBatch { address });
            }
        }

        for index in 0..count {
            let address = address_at(index);
            let Some(record_index) = self.find(address) else {
                return Err(FrameAllocatorError::NeverAllocatedFrame { address });
            };
            match self.records[record_index].state {
                OwnershipState::Allocated => {}
                OwnershipState::Free => return Err(FrameAllocatorError::DoubleFree { address }),
                OwnershipState::Reserved => {
                    return Err(FrameAllocatorError::ReservedFrame { address })
                }
            }
        }

        self.free
            .try_reserve(count)
            .map_err(|_| FrameAllocatorError::OwnershipTrackingAllocationFailed)?;
        let mut dma_low_reclaimed = 0u64;
        let mut above_4g_reclaimed = 0u64;
        for index in 0..count {
            let address = address_at(index);
            let record_index = self
                .find(address)
                .expect("reclamation was preflighted against ownership records");
            if self.records[record_index].dma_low {
                dma_low_reclaimed = dma_low_reclaimed.saturating_add(1);
            }
            if address >= DMA_32BIT_ADDRESS_LIMIT {
                above_4g_reclaimed = above_4g_reclaimed.saturating_add(1);
            }
            self.records[record_index].state = OwnershipState::Free;
            self.records[record_index].dma_low = false;
            self.free.push(address);
        }
        self.live_allocated = self.live_allocated.saturating_sub(count as u64);
        self.dma_low_live = self.dma_low_live.saturating_sub(dma_low_reclaimed);
        self.above_4g_live = self.above_4g_live.saturating_sub(above_4g_reclaimed);
        Ok(())
    }

    fn mark_dma_low(&mut self, address: u64) {
        if let Some(record) = self
            .records
            .iter_mut()
            .find(|record| record.address == address)
        {
            debug_assert_eq!(record.state, OwnershipState::Allocated);
            if !record.dma_low {
                record.dma_low = true;
                self.dma_low_live = self.dma_low_live.saturating_add(1);
            }
        }
    }

    const fn dma_low_live_count(&self) -> u64 {
        self.dma_low_live
    }

    const fn above_4g_live_count(&self) -> u64 {
        self.above_4g_live
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct UsableRegion {
    base: u64,
    end: u64,
    next: u64,
    high_next: u64,
    at_or_above_next: u64,
}

impl UsableRegion {
    const fn contains(self, address: u64) -> bool {
        address >= self.base && address < self.end
    }
}

/// Coherent physical-frame allocator checkpoint. Counts and byte values are u64
/// and therefore do not truncate systems with usable RAM above 4 GiB.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FrameAllocatorStats {
    pub total_eligible_frames: u64,
    pub total_eligible_bytes: u64,
    pub below_4g_frames: u64,
    pub above_4g_frames: u64,
    pub highest_usable_address: u64,
    pub highest_issued_address: u64,
    pub fresh_issued_frames: u64,
    pub fresh_remaining_frames: u64,
    pub available_frames: u64,
    pub available_bytes: u64,
    pub live_allocated_frames: u64,
    pub above_4g_live_frames: u64,
    pub reclaimed_free_frames: u64,
    pub reserved_eligible_frames: u64,
    pub dma_low_allocations: u64,
    pub dma_low_live_frames: u64,
    pub dma_low_failures: u64,
    pub allocation_failures: u64,
}

fn frames_below_limit(base: u64, end: u64, limit: u64) -> u64 {
    end.min(limit).saturating_sub(base) / PAGE_SIZE
}

#[derive(Clone, Copy)]
struct MemoryMapRange {
    base: u64,
    end: u64,
    usable: bool,
}

fn validate_usable_regions(
    memory_map: &MemoryMapResponse,
    physical_address_space_size: u64,
) -> Result<(Vec<UsableRegion>, u64, u64, u64, u64), FrameAllocatorError> {
    let mut regions = Vec::new();
    let mut all_ranges = Vec::new();
    for entry in memory_map
        .entries()
        .map_err(FrameAllocatorError::InvalidMemoryMap)?
    {
        let entry = entry.map_err(FrameAllocatorError::InvalidMemoryMap)?;
        if entry.length == 0 {
            continue;
        }
        let end = entry.base.checked_add(entry.length).ok_or(
            FrameAllocatorError::UsableRegionOverflow {
                base: entry.base,
                length: entry.length,
            },
        )?;
        all_ranges
            .try_reserve(1)
            .map_err(|_| FrameAllocatorError::OwnershipTrackingAllocationFailed)?;
        all_ranges.push(MemoryMapRange {
            base: entry.base,
            end,
            usable: entry.entry_type == MEMORY_MAP_USABLE,
        });
        if entry.entry_type != MEMORY_MAP_USABLE {
            continue;
        }
        if entry.base % PAGE_SIZE != 0 || entry.length % PAGE_SIZE != 0 {
            return Err(FrameAllocatorError::InvalidUsableRegion {
                base: entry.base,
                length: entry.length,
            });
        }
        if end > physical_address_space_size {
            return Err(FrameAllocatorError::PhysicalAddressTooLarge {
                base: entry.base,
                length: entry.length,
            });
        }
        regions
            .try_reserve(1)
            .map_err(|_| FrameAllocatorError::OwnershipTrackingAllocationFailed)?;
        regions.push(UsableRegion {
            base: entry.base,
            end,
            next: entry.base,
            high_next: entry.base.max(DMA_32BIT_ADDRESS_LIMIT),
            at_or_above_next: entry.base,
        });
    }
    all_ranges.sort_unstable_by_key(|range| range.base);
    for first in 0..all_ranges.len() {
        for second in first + 1..all_ranges.len() {
            if all_ranges[second].base >= all_ranges[first].end {
                break;
            }
            if all_ranges[first].usable || all_ranges[second].usable {
                let (usable, other) = if all_ranges[first].usable {
                    (all_ranges[first], all_ranges[second])
                } else {
                    (all_ranges[second], all_ranges[first])
                };
                return Err(FrameAllocatorError::OverlappingMemoryMapRegions {
                    usable_base: usable.base,
                    other_base: other.base,
                });
            }
        }
    }
    regions.sort_unstable_by_key(|region| region.base);

    let mut total = 0u64;
    let mut below = 0u64;
    let mut highest = 0u64;
    for region in &regions {
        let frames = (region.end - region.base) / PAGE_SIZE;
        total = total
            .checked_add(frames)
            .ok_or(FrameAllocatorError::UsableFrameCountOverflow)?;
        below = below
            .checked_add(frames_below_limit(
                region.base,
                region.end,
                DMA_32BIT_ADDRESS_LIMIT,
            ))
            .ok_or(FrameAllocatorError::UsableFrameCountOverflow)?;
        highest = highest.max(region.end - PAGE_SIZE);
    }
    Ok((regions, total, below, total - below, highest))
}

pub struct UsableFrameAllocator<'a> {
    memory_map: PhantomData<&'a MemoryMapResponse>,
    physical_address_space_size: u64,
    usable_regions: Vec<UsableRegion>,
    total_eligible_frames: u64,
    below_4g_frames: u64,
    above_4g_frames: u64,
    highest_usable_address: u64,
    highest_issued_address: u64,
    fresh_remaining_frames: u64,
    reserved_eligible_frames: u64,
    dma_low_allocations: u64,
    dma_low_failures: u64,
    allocation_failures: u64,
    ownership: OwnershipLedger,
    error: Option<FrameAllocatorError>,
    #[cfg(ginkgo_memory_policy_smoke)]
    smoke_fail_next_unrestricted_allocation: bool,
    #[cfg(ginkgo_memory_policy_smoke)]
    smoke_high_policy_enabled: bool,
}

impl<'a> UsableFrameAllocator<'a> {
    /// Builds an allocator over Limine's usable regions, constrained by the
    /// physical-address width reported by CPUID.
    pub fn new(
        memory_map: &'a MemoryMapResponse,
        physical_address_bits: u8,
    ) -> Result<Self, FrameAllocatorError> {
        let physical_address_space_size = physical_address_space_size(physical_address_bits)
            .ok_or(FrameAllocatorError::InvalidPhysicalAddressBits {
                bits: physical_address_bits,
            })?;
        let (
            usable_regions,
            total_eligible_frames,
            below_4g_frames,
            above_4g_frames,
            highest_usable_address,
        ) = validate_usable_regions(memory_map, physical_address_space_size)?;
        Ok(Self {
            memory_map: PhantomData,
            physical_address_space_size,
            usable_regions,
            total_eligible_frames,
            below_4g_frames,
            above_4g_frames,
            highest_usable_address,
            highest_issued_address: 0,
            fresh_remaining_frames: total_eligible_frames,
            reserved_eligible_frames: 0,
            dma_low_allocations: 0,
            dma_low_failures: 0,
            allocation_failures: 0,
            ownership: OwnershipLedger::new(),
            error: None,
            #[cfg(ginkgo_memory_policy_smoke)]
            smoke_fail_next_unrestricted_allocation: false,
            #[cfg(ginkgo_memory_policy_smoke)]
            smoke_high_policy_enabled: false,
        })
    }

    #[cfg(test)]
    pub(crate) unsafe fn from_test_region(
        base: u64,
        length: u64,
        physical_address_bits: u8,
    ) -> Self {
        let physical_address_space_size = physical_address_space_size(physical_address_bits)
            .expect("test physical address width must be valid");
        assert_eq!(base % PAGE_SIZE, 0);
        assert_eq!(length % PAGE_SIZE, 0);
        assert!(base
            .checked_add(length)
            .is_some_and(|end| end <= physical_address_space_size));
        Self {
            memory_map: PhantomData,
            physical_address_space_size,
            usable_regions: alloc::vec![UsableRegion {
                base,
                end: base + length,
                next: base,
                high_next: base.max(DMA_32BIT_ADDRESS_LIMIT),
                at_or_above_next: base,
            }],
            total_eligible_frames: length / PAGE_SIZE,
            below_4g_frames: frames_below_limit(base, base + length, DMA_32BIT_ADDRESS_LIMIT),
            above_4g_frames: length / PAGE_SIZE
                - frames_below_limit(base, base + length, DMA_32BIT_ADDRESS_LIMIT),
            highest_usable_address: base + length - PAGE_SIZE,
            highest_issued_address: 0,
            fresh_remaining_frames: length / PAGE_SIZE,
            reserved_eligible_frames: 0,
            dma_low_allocations: 0,
            dma_low_failures: 0,
            allocation_failures: 0,
            ownership: OwnershipLedger::new(),
            error: None,
            #[cfg(ginkgo_memory_policy_smoke)]
            smoke_fail_next_unrestricted_allocation: false,
            #[cfg(ginkgo_memory_policy_smoke)]
            smoke_high_policy_enabled: true,
        }
    }

    /// Number of currently live, allocator-owned frames that may be reclaimed.
    pub fn allocated_count(&self) -> u64 {
        self.ownership.live_allocated_count()
    }

    /// Alias for [`Self::allocated_count`] emphasizing reclaimable ownership.
    pub fn reclaimable_count(&self) -> u64 {
        self.allocated_count()
    }

    /// Total number of fresh memory-map frames ever issued.
    ///
    /// Reissuing reclaimed frames does not increase this high-water mark.
    pub fn fresh_issued_count(&self) -> u64 {
        self.ownership.fresh_issued_count()
    }

    /// Alias for [`Self::fresh_issued_count`].
    pub fn high_water_mark(&self) -> u64 {
        self.fresh_issued_count()
    }

    /// Number of reclaimed frames currently available for reuse.
    pub fn free_count(&self) -> usize {
        self.ownership.free_count()
    }

    /// Alias for [`Self::free_count`].
    pub fn reclaimed_count(&self) -> usize {
        self.free_count()
    }

    pub fn error(&self) -> Option<FrameAllocatorError> {
        self.error
    }

    /// Returns one internally coherent constant-time allocator checkpoint.
    /// Historical ownership records are not scanned.
    pub fn stats(&self) -> FrameAllocatorStats {
        let reclaimed_free_frames = self.ownership.free_count() as u64;
        let available_frames = self
            .fresh_remaining_frames
            .saturating_add(reclaimed_free_frames);
        FrameAllocatorStats {
            total_eligible_frames: self.total_eligible_frames,
            total_eligible_bytes: self.total_eligible_frames.saturating_mul(PAGE_SIZE),
            below_4g_frames: self.below_4g_frames,
            above_4g_frames: self.above_4g_frames,
            highest_usable_address: self.highest_usable_address,
            highest_issued_address: self.highest_issued_address,
            fresh_issued_frames: self.ownership.fresh_issued_count(),
            fresh_remaining_frames: self.fresh_remaining_frames,
            available_frames,
            available_bytes: available_frames.saturating_mul(PAGE_SIZE),
            live_allocated_frames: self.ownership.live_allocated_count(),
            above_4g_live_frames: self.ownership.above_4g_live_count(),
            reclaimed_free_frames,
            reserved_eligible_frames: self.reserved_eligible_frames,
            dma_low_allocations: self.dma_low_allocations,
            dma_low_live_frames: self.ownership.dma_low_live_count(),
            dma_low_failures: self.dma_low_failures,
            allocation_failures: self.allocation_failures,
        }
    }

    pub const fn total_eligible_bytes(&self) -> u64 {
        self.total_eligible_frames.saturating_mul(PAGE_SIZE)
    }

    /// Frames immediately allocatable from untouched regions or the reclaim list.
    pub fn available_frames(&self) -> u64 {
        self.fresh_remaining_frames
            .saturating_add(self.ownership.free_count() as u64)
    }

    pub fn available_bytes(&self) -> u64 {
        self.available_frames().saturating_mul(PAGE_SIZE)
    }

    fn eligible_region(&self, address: u64) -> Option<&UsableRegion> {
        self.usable_regions
            .iter()
            .find(|region| region.contains(address))
    }

    /// Permanently prevents a physical frame from being returned by future
    /// allocations. Reserving an allocated or free frame transfers it out of
    /// allocator ownership and removes it from the reclaimable free list.
    pub fn reserve_frame(&mut self, frame: PhysFrame) -> Result<bool, FrameAllocatorError> {
        let address = frame.start_address().as_u64();
        let was_tracked = self.ownership.find(address).is_some();
        let was_fresh = self
            .eligible_region(address)
            .is_some_and(|region| address >= region.next);
        let eligible = self.eligible_region(address).is_some();
        let changed = self.ownership.reserve(address)?;
        if changed && eligible {
            self.reserved_eligible_frames = self.reserved_eligible_frames.saturating_add(1);
            if !was_tracked && was_fresh {
                self.fresh_remaining_frames = self.fresh_remaining_frames.saturating_sub(1);
            }
        }
        Ok(changed)
    }

    pub fn reserved_count(&self) -> usize {
        self.ownership.reserved_count()
    }

    /// Reclaims one live frame owned by this allocator.
    ///
    /// This safe API rejects reserved, never-issued, and already-free frames.
    pub fn deallocate_frame(&mut self, frame: PhysFrame) -> Result<(), FrameAllocatorError> {
        self.deallocate_frames(core::slice::from_ref(&frame))
    }

    /// Atomically reclaims a batch of live frames owned by this allocator.
    ///
    /// The complete batch is preflighted before mutation. Reserved,
    /// never-issued, duplicate-in-batch, or already-free frames reject the
    /// entire batch without reclaiming any frame.
    pub fn deallocate_frames(&mut self, frames: &[PhysFrame]) -> Result<(), FrameAllocatorError> {
        self.ownership
            .reclaim_with(frames.len(), |index| frames[index].start_address().as_u64())
    }

    /// Alias for [`Self::deallocate_frames`].
    pub fn reclaim_frames(&mut self, frames: &[PhysFrame]) -> Result<(), FrameAllocatorError> {
        self.deallocate_frames(frames)
    }

    pub fn allocate_frame(&mut self) -> Result<Option<PhysFrame>, FrameAllocatorError> {
        #[cfg(ginkgo_memory_policy_smoke)]
        if core::mem::take(&mut self.smoke_fail_next_unrestricted_allocation) {
            self.allocation_failures = self.allocation_failures.saturating_add(1);
            return Ok(None);
        }

        let prefer_high = self.above_4g_frames != 0;
        #[cfg(ginkgo_memory_policy_smoke)]
        let prefer_high = prefer_high && self.smoke_high_policy_enabled;
        let result = if prefer_high {
            self.allocate_frame_at_or_above_inner(DMA_32BIT_ADDRESS_LIMIT, true)
                .and_then(|frame| match frame {
                    Some(frame) => Ok(Some(frame)),
                    None => self.allocate_frame_below_inner(DMA_32BIT_ADDRESS_LIMIT, true),
                })
        } else {
            self.allocate_frame_below_inner(self.physical_address_space_size, true)
        };
        if !matches!(result, Ok(Some(_))) {
            self.allocation_failures = self.allocation_failures.saturating_add(1);
        }
        result
    }

    #[cfg(ginkgo_memory_policy_smoke)]
    pub fn smoke_enable_high_policy(&mut self) {
        self.smoke_high_policy_enabled = true;
    }

    #[cfg(ginkgo_memory_policy_smoke)]
    pub fn smoke_fail_next_unrestricted_allocation(&mut self) {
        self.smoke_fail_next_unrestricted_allocation = true;
    }

    /// Allocates one frame at or above `min_address` without consuming lower frames.
    ///
    /// The lower bound is rounded up to a frame boundary. If no eligible frame exists,
    /// the allocator returns `None` without changing region cursors, ownership, or
    /// accounting, so callers can safely fall back to another policy.
    pub fn allocate_frame_at_or_above(
        &mut self,
        min_address: u64,
    ) -> Result<Option<PhysFrame>, FrameAllocatorError> {
        let result = self.allocate_frame_at_or_above_inner(min_address, true);
        if !matches!(result, Ok(Some(_))) {
            self.allocation_failures = self.allocation_failures.saturating_add(1);
        }
        result
    }

    fn allocate_frame_at_or_above_inner(
        &mut self,
        min_address: u64,
        allow_reclaimed: bool,
    ) -> Result<Option<PhysFrame>, FrameAllocatorError> {
        if let Some(error) = self.error {
            return Err(error);
        }
        let Some(min_address) = min_address.checked_add(PAGE_SIZE - 1) else {
            return Ok(None);
        };
        let min_address = min_address & !(PAGE_SIZE - 1);
        if min_address >= self.physical_address_space_size {
            return Ok(None);
        }

        if allow_reclaimed {
            if let Some(address) = self.ownership.claim_reclaimed_at_or_above(min_address) {
                let frame = Self::frame_from_address(address)?;
                self.advance_at_or_above_cursor(address);
                return Ok(Some(frame));
            }
        }

        let candidate = self.usable_regions.iter().find_map(|region| {
            let lower = region.base.max(min_address);
            if lower >= region.end {
                return None;
            }
            let ordinary_hint = if min_address == DMA_32BIT_ADDRESS_LIMIT {
                region.high_next
            } else {
                lower
            };
            let hint = region
                .at_or_above_next
                .max(ordinary_hint)
                .max(lower)
                .min(region.end);
            let find_unowned = |start: u64, end: u64| {
                let mut address = start;
                while address < end {
                    if self.ownership.find(address).is_none() {
                        return Some(address);
                    }
                    address = address.checked_add(PAGE_SIZE)?;
                }
                None
            };
            find_unowned(hint, region.end).or_else(|| find_unowned(lower, hint))
        });
        let Some(address) = candidate else {
            return Ok(None);
        };
        let frame = Self::frame_from_address(address)?;
        match self.ownership.claim_fresh(address) {
            Ok(true) => {}
            Ok(false) => unreachable!("at-or-above candidate was preflighted as unowned"),
            Err(error) => return self.fail(error),
        }
        self.fresh_remaining_frames = self.fresh_remaining_frames.saturating_sub(1);
        self.advance_at_or_above_cursor(address);
        self.highest_issued_address = self.highest_issued_address.max(address);
        Ok(Some(frame))
    }

    fn advance_at_or_above_cursor(&mut self, address: u64) {
        if let Some(region) = self
            .usable_regions
            .iter_mut()
            .find(|region| region.contains(address))
        {
            region.at_or_above_next = address + PAGE_SIZE;
            if region.high_next == address {
                region.high_next = address + PAGE_SIZE;
            }
        }
    }

    /// Allocates one frame whose complete byte range is below the exclusive limit.
    ///
    /// A bounded request never consumes a frame that the device cannot address.
    /// If the current Limine range begins above the limit it is retained for a
    /// later unrestricted request.
    pub fn allocate_frame_below(
        &mut self,
        max_address_exclusive: u64,
    ) -> Result<Option<PhysFrame>, FrameAllocatorError> {
        let dma_low = max_address_exclusive <= DMA_32BIT_ADDRESS_LIMIT;
        let result = self.allocate_frame_below_inner(max_address_exclusive, true);
        match result {
            Ok(Some(frame)) if dma_low => {
                self.ownership.mark_dma_low(frame.start_address().as_u64());
                self.dma_low_allocations = self.dma_low_allocations.saturating_add(1);
            }
            Ok(Some(_)) => {}
            _ if dma_low => {
                self.dma_low_failures = self.dma_low_failures.saturating_add(1);
                self.allocation_failures = self.allocation_failures.saturating_add(1);
            }
            _ => self.allocation_failures = self.allocation_failures.saturating_add(1),
        }
        result
    }

    fn allocate_frame_below_inner(
        &mut self,
        max_address_exclusive: u64,
        allow_reclaimed: bool,
    ) -> Result<Option<PhysFrame>, FrameAllocatorError> {
        if let Some(error) = self.error {
            return Err(error);
        }
        if max_address_exclusive == 0 {
            return Err(FrameAllocatorError::PhysicalAddressTooLarge {
                base: max_address_exclusive,
                length: 0,
            });
        }
        let max_address_exclusive = max_address_exclusive.min(self.physical_address_space_size);

        if allow_reclaimed {
            if let Some(address) = self.ownership.claim_reclaimed_below(max_address_exclusive) {
                return Ok(Some(Self::frame_from_address(address)?));
            }
        }

        loop {
            let Some(region) = self.usable_regions.iter_mut().find(|region| {
                region.next < region.end
                    && region
                        .next
                        .checked_add(PAGE_SIZE)
                        .is_some_and(|end| end <= max_address_exclusive)
            }) else {
                return Ok(None);
            };
            let address = region.next;
            region.next += PAGE_SIZE;
            match self.ownership.claim_fresh(address) {
                Ok(true) => {
                    self.fresh_remaining_frames = self.fresh_remaining_frames.saturating_sub(1);
                }
                Ok(false) => continue,
                Err(error) => return self.fail(error),
            }

            self.highest_issued_address = self.highest_issued_address.max(address);
            return match Self::frame_from_address(address) {
                Ok(frame) => Ok(Some(frame)),
                Err(error) => self.fail(error),
            };
        }
    }

    pub fn allocate_contiguous_frames(
        &mut self,
        pages: usize,
    ) -> Result<Option<Vec<PhysFrame>>, FrameAllocatorError> {
        let result = self.allocate_contiguous_frames_below_inner(
            pages,
            self.physical_address_space_size,
            false,
        );
        if !matches!(result, Ok(Some(_))) {
            self.allocation_failures = self.allocation_failures.saturating_add(1);
        }
        result
    }

    /// Attempts one atomic contiguous allocation below an exclusive address limit.
    /// Partial, exhausted, or fragmented runs are returned to the allocator.
    pub fn allocate_contiguous_frames_below(
        &mut self,
        pages: usize,
        max_address_exclusive: u64,
    ) -> Result<Option<Vec<PhysFrame>>, FrameAllocatorError> {
        let dma_low = max_address_exclusive <= DMA_32BIT_ADDRESS_LIMIT;
        let result =
            self.allocate_contiguous_frames_below_inner(pages, max_address_exclusive, dma_low);
        if !matches!(result, Ok(Some(_))) {
            self.allocation_failures = self.allocation_failures.saturating_add(1);
            if dma_low {
                self.dma_low_failures = self.dma_low_failures.saturating_add(1);
            }
        }
        result
    }

    fn allocate_contiguous_frames_below_inner(
        &mut self,
        pages: usize,
        max_address_exclusive: u64,
        dma_low: bool,
    ) -> Result<Option<Vec<PhysFrame>>, FrameAllocatorError> {
        if pages == 0 {
            return Ok(None);
        }
        let mut frames = Vec::new();
        frames
            .try_reserve_exact(pages)
            .map_err(|_| FrameAllocatorError::OwnershipTrackingAllocationFailed)?;
        if let Some(start) = self
            .ownership
            .claim_reclaimed_range_below(pages, max_address_exclusive)
        {
            for index in 0..pages {
                let address = start + index as u64 * PAGE_SIZE;
                if dma_low {
                    self.ownership.mark_dma_low(address);
                }
                frames.push(Self::frame_from_address(address)?);
            }
            if dma_low {
                self.dma_low_allocations = self.dma_low_allocations.saturating_add(pages as u64);
            }
            return Ok(Some(frames));
        }
        let mut expected = None;
        for _ in 0..pages {
            let frame = match self.allocate_frame_below_inner(max_address_exclusive, false) {
                Ok(Some(frame)) => frame,
                Ok(None) => {
                    self.deallocate_frames(&frames)?;
                    return Ok(None);
                }
                Err(error) => {
                    if !frames.is_empty() {
                        self.deallocate_frames(&frames)?;
                    }
                    return Err(error);
                }
            };
            let address = frame.start_address().as_u64();
            if expected.is_some_and(|expected| expected != address) {
                frames.push(frame);
                self.deallocate_frames(&frames)?;
                return Ok(None);
            }
            expected = address.checked_add(PAGE_SIZE);
            if expected.is_none() {
                frames.push(frame);
                self.deallocate_frames(&frames)?;
                return Err(FrameAllocatorError::UsableRegionOverflow {
                    base: address,
                    length: PAGE_SIZE,
                });
            }
            frames.push(frame);
        }
        if dma_low {
            for frame in &frames {
                self.ownership.mark_dma_low(frame.start_address().as_u64());
            }
            self.dma_low_allocations = self.dma_low_allocations.saturating_add(frames.len() as u64);
        }
        Ok(Some(frames))
    }

    #[cfg(ginkgo_memory_policy_smoke)]
    pub fn smoke_frame_is_live(&self, address: u64) -> bool {
        self.ownership
            .find(address)
            .is_some_and(|index| self.ownership.records[index].state == OwnershipState::Allocated)
    }

    #[cfg(ginkgo_memory_policy_smoke)]
    pub fn smoke_frame_is_reclaimed(&self, address: u64) -> bool {
        self.ownership
            .find(address)
            .is_some_and(|index| self.ownership.records[index].state == OwnershipState::Free)
    }

    #[cfg(test)]
    fn set_failure_counters_for_test(&mut self, dma_low_failures: u64, allocation_failures: u64) {
        self.dma_low_failures = dma_low_failures;
        self.allocation_failures = allocation_failures;
    }

    fn frame_from_address(address: u64) -> Result<PhysFrame, FrameAllocatorError> {
        let address = PhysAddr::try_new(address).map_err(|_| {
            FrameAllocatorError::PhysicalAddressTooLarge {
                base: address,
                length: PAGE_SIZE,
            }
        })?;
        PhysFrame::from_start_address(address).map_err(|_| {
            FrameAllocatorError::InvalidUsableRegion {
                base: address.as_u64(),
                length: PAGE_SIZE,
            }
        })
    }

    fn fail<T>(&mut self, error: FrameAllocatorError) -> Result<T, FrameAllocatorError> {
        self.error = Some(error);
        Err(error)
    }
}

// SAFETY: Limine marks fresh source regions usable, exact ownership tracking
// prevents live or reserved frames from entering the free list, and allocation
// prefers only successfully reclaimed frames before advancing monotonically.
unsafe impl FrameAllocator<Size4KiB> for UsableFrameAllocator<'_> {
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        UsableFrameAllocator::allocate_frame(self).ok().flatten()
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::{
        physical_address_space_size, FrameAllocatorError, OwnershipLedger, UsableFrameAllocator,
        DMA_32BIT_ADDRESS_LIMIT, PAGE_SIZE,
    };
    use crate::limine::{
        MemoryMapEntry, MemoryMapResponse, MEMORY_MAP_RESERVED, MEMORY_MAP_USABLE,
    };

    const A: u64 = 0x1000;
    const B: u64 = 0x2000;
    const C: u64 = 0x3000;

    fn memory_map_response(
        entries: &mut [MemoryMapEntry],
    ) -> (Vec<*mut MemoryMapEntry>, MemoryMapResponse) {
        let mut pointers = entries
            .iter_mut()
            .map(|entry| entry as *mut MemoryMapEntry)
            .collect::<Vec<_>>();
        let response = MemoryMapResponse {
            revision: 0,
            entry_count: pointers.len() as u64,
            entries: pointers.as_mut_ptr(),
        };
        (pointers, response)
    }

    fn ledger_with_three_allocations() -> OwnershipLedger {
        let mut ledger = OwnershipLedger::new();
        assert_eq!(ledger.claim_fresh(A), Ok(true));
        assert_eq!(ledger.claim_fresh(B), Ok(true));
        assert_eq!(ledger.claim_fresh(C), Ok(true));
        ledger
    }

    #[test]
    fn physical_address_width_limits_are_checked() {
        assert_eq!(physical_address_space_size(11), None);
        assert_eq!(physical_address_space_size(52), Some(1_u64 << 52));
        assert_eq!(physical_address_space_size(53), None);
    }

    #[test]
    fn allocator_issues_frames_above_four_gib_when_supported() {
        let base = 0x1_0000_0000;
        let mut allocator = unsafe { UsableFrameAllocator::from_test_region(base, PAGE_SIZE, 52) };
        let frame = allocator.allocate_frame().unwrap().unwrap();
        assert_eq!(frame.start_address().as_u64(), base);
        assert_eq!(allocator.allocate_frame(), Ok(None));
    }

    #[test]
    fn bounded_allocation_preserves_high_frame_for_unrestricted_use() {
        let base = DMA_32BIT_ADDRESS_LIMIT;
        let mut allocator = unsafe { UsableFrameAllocator::from_test_region(base, PAGE_SIZE, 52) };
        assert_eq!(
            allocator.allocate_frame_below(DMA_32BIT_ADDRESS_LIMIT),
            Ok(None)
        );
        assert_eq!(
            allocator
                .allocate_frame()
                .unwrap()
                .unwrap()
                .start_address()
                .as_u64(),
            base
        );
    }

    #[test]
    fn unrestricted_allocation_prefers_high_memory_and_preserves_dma32() {
        let mut entries = [
            MemoryMapEntry {
                base: 0x20_0000,
                length: PAGE_SIZE * 2,
                entry_type: MEMORY_MAP_USABLE,
            },
            MemoryMapEntry {
                base: DMA_32BIT_ADDRESS_LIMIT,
                length: PAGE_SIZE * 2,
                entry_type: MEMORY_MAP_USABLE,
            },
        ];
        let (_pointers, response) = memory_map_response(&mut entries);
        let mut allocator = UsableFrameAllocator::new(&response, 52).unwrap();

        let unrestricted = allocator.allocate_frame().unwrap().unwrap();
        assert_eq!(
            unrestricted.start_address().as_u64(),
            DMA_32BIT_ADDRESS_LIMIT
        );
        let dma = allocator
            .allocate_frame_below(DMA_32BIT_ADDRESS_LIMIT)
            .unwrap()
            .unwrap();
        assert_eq!(dma.start_address().as_u64(), 0x20_0000);
        assert_eq!(allocator.stats().above_4g_live_frames, 1);
        assert_eq!(allocator.stats().dma_low_live_frames, 1);
    }

    #[test]
    fn at_or_above_failure_is_transactional_and_fallback_keeps_low_frame() {
        let mut allocator =
            unsafe { UsableFrameAllocator::from_test_region(0x20_0000, PAGE_SIZE, 52) };
        let before = allocator.stats();
        assert_eq!(
            allocator.allocate_frame_at_or_above(DMA_32BIT_ADDRESS_LIMIT),
            Ok(None)
        );
        let after = allocator.stats();
        assert_eq!(after.fresh_issued_frames, before.fresh_issued_frames);
        assert_eq!(after.fresh_remaining_frames, before.fresh_remaining_frames);
        assert_eq!(after.live_allocated_frames, before.live_allocated_frames);
        assert_eq!(after.reclaimed_free_frames, before.reclaimed_free_frames);
        assert_eq!(
            allocator
                .allocate_frame_below(DMA_32BIT_ADDRESS_LIMIT)
                .unwrap()
                .unwrap()
                .start_address()
                .as_u64(),
            0x20_0000
        );
    }

    #[test]
    fn at_or_above_rounds_up_and_reuses_only_eligible_reclaimed_frames() {
        let base = DMA_32BIT_ADDRESS_LIMIT - PAGE_SIZE;
        let mut allocator =
            unsafe { UsableFrameAllocator::from_test_region(base, PAGE_SIZE * 3, 52) };
        let high0 = allocator.allocate_frame().unwrap().unwrap();
        let high1 = allocator.allocate_frame().unwrap().unwrap();
        let low = allocator.allocate_frame().unwrap().unwrap();
        allocator.deallocate_frames(&[low, high0, high1]).unwrap();

        let selected = allocator
            .allocate_frame_at_or_above(DMA_32BIT_ADDRESS_LIMIT + 1)
            .unwrap()
            .unwrap();
        assert_eq!(
            selected.start_address().as_u64(),
            DMA_32BIT_ADDRESS_LIMIT + PAGE_SIZE
        );
        assert_eq!(allocator.stats().above_4g_live_frames, 1);
    }

    #[test]
    fn at_or_above_cursor_progresses_across_jumps_without_skipping_bounded_frames() {
        let base = 0x20_0000;
        let mut allocator =
            unsafe { UsableFrameAllocator::from_test_region(base, PAGE_SIZE * 16, 52) };

        let jumped = allocator
            .allocate_frame_at_or_above(base + PAGE_SIZE * 8 + 1)
            .unwrap()
            .unwrap();
        let after_jump = allocator
            .allocate_frame_at_or_above(base + PAGE_SIZE * 8)
            .unwrap()
            .unwrap();
        assert_eq!(jumped.start_address().as_u64(), base + PAGE_SIZE * 9);
        assert_eq!(after_jump.start_address().as_u64(), base + PAGE_SIZE * 10);

        for index in 0..4 {
            let bounded = allocator
                .allocate_frame_below(base + PAGE_SIZE * 8)
                .unwrap()
                .unwrap();
            assert_eq!(bounded.start_address().as_u64(), base + PAGE_SIZE * index);
        }

        let repeated = allocator
            .allocate_frame_at_or_above(base + PAGE_SIZE * 2)
            .unwrap()
            .unwrap();
        assert_eq!(repeated.start_address().as_u64(), base + PAGE_SIZE * 11);
        for index in 4..8 {
            let bounded = allocator
                .allocate_frame_below(base + PAGE_SIZE * 8)
                .unwrap()
                .unwrap();
            assert_eq!(bounded.start_address().as_u64(), base + PAGE_SIZE * index);
        }
    }

    #[test]
    fn address_limit_above_cpu_width_is_clamped_to_supported_memory() {
        let mut allocator =
            unsafe { UsableFrameAllocator::from_test_region(0x1000, PAGE_SIZE, 36) };
        assert!(allocator
            .allocate_frame_below(1_u64 << 44)
            .unwrap()
            .is_some());
    }

    #[test]
    fn bounded_allocation_can_reuse_an_eligible_reclaimed_frame() {
        let mut allocator = unsafe {
            UsableFrameAllocator::from_test_region(
                DMA_32BIT_ADDRESS_LIMIT - PAGE_SIZE,
                PAGE_SIZE * 2,
                52,
            )
        };
        let high = allocator.allocate_frame().unwrap().unwrap();
        let low = allocator.allocate_frame().unwrap().unwrap();
        allocator.deallocate_frames(&[high, low]).unwrap();
        assert_eq!(
            allocator
                .allocate_frame_below(DMA_32BIT_ADDRESS_LIMIT)
                .unwrap()
                .unwrap(),
            low
        );
    }

    #[test]
    fn stats_preserve_above_four_gib_counts_without_truncation() {
        let base = DMA_32BIT_ADDRESS_LIMIT - PAGE_SIZE;
        let mut allocator =
            unsafe { UsableFrameAllocator::from_test_region(base, PAGE_SIZE * 3, 52) };
        let initial = allocator.stats();
        assert_eq!(initial.total_eligible_frames, 3);
        assert_eq!(initial.total_eligible_bytes, PAGE_SIZE * 3);
        assert_eq!(initial.available_frames, 3);
        assert_eq!(initial.available_bytes, PAGE_SIZE * 3);
        assert_eq!(initial.below_4g_frames, 1);
        assert_eq!(initial.above_4g_frames, 2);
        assert_eq!(
            initial.highest_usable_address,
            DMA_32BIT_ADDRESS_LIMIT + PAGE_SIZE
        );

        let frame = allocator.allocate_frame().unwrap().unwrap();
        assert_eq!(frame.start_address().as_u64(), DMA_32BIT_ADDRESS_LIMIT);
        let issued = allocator.stats();
        assert_eq!(issued.highest_issued_address, DMA_32BIT_ADDRESS_LIMIT);
        assert_eq!(issued.live_allocated_frames, 1);
        assert_eq!(issued.above_4g_live_frames, 1);
        assert_eq!(issued.fresh_remaining_frames, 2);
        assert_eq!(issued.available_frames, 2);
        assert_eq!(issued.available_bytes, PAGE_SIZE * 2);
    }

    #[test]
    fn usable_ranges_reject_overlap_with_reserved_ranges_but_allow_adjacency() {
        let mut overlapping = [
            MemoryMapEntry {
                base: 0x1000,
                length: PAGE_SIZE * 2,
                entry_type: MEMORY_MAP_USABLE,
            },
            MemoryMapEntry {
                base: 0x2000,
                length: PAGE_SIZE,
                entry_type: MEMORY_MAP_RESERVED,
            },
        ];
        let (_pointers, response) = memory_map_response(&mut overlapping);
        assert_eq!(
            UsableFrameAllocator::new(&response, 52).err(),
            Some(FrameAllocatorError::OverlappingMemoryMapRegions {
                usable_base: 0x1000,
                other_base: 0x2000,
            })
        );

        let mut adjacent = [
            MemoryMapEntry {
                base: 0x1000,
                length: PAGE_SIZE,
                entry_type: MEMORY_MAP_RESERVED,
            },
            MemoryMapEntry {
                base: 0x2000,
                length: PAGE_SIZE * 2,
                entry_type: MEMORY_MAP_USABLE,
            },
        ];
        let (_pointers, response) = memory_map_response(&mut adjacent);
        let allocator = UsableFrameAllocator::new(&response, 52).unwrap();
        assert_eq!(allocator.stats().total_eligible_frames, 2);
    }

    #[test]
    fn stats_counters_remain_exact_after_large_ownership_history() {
        let mut allocator =
            unsafe { UsableFrameAllocator::from_test_region(0x1000, PAGE_SIZE * 256, 52) };
        let mut frames = Vec::new();
        while let Some(frame) = allocator.allocate_frame().unwrap() {
            frames.push(frame);
        }
        allocator.deallocate_frames(&frames).unwrap();
        let mut dma = Vec::new();
        for _ in 0..64 {
            dma.push(
                allocator
                    .allocate_frame_below(DMA_32BIT_ADDRESS_LIMIT)
                    .unwrap()
                    .unwrap(),
            );
        }
        assert!(allocator.reserve_frame(dma.pop().unwrap()).unwrap());

        for _ in 0..1024 {
            let stats = allocator.stats();
            assert_eq!(stats.fresh_remaining_frames, 0);
            assert_eq!(stats.reclaimed_free_frames, 192);
            assert_eq!(stats.available_frames, 192);
            assert_eq!(stats.available_bytes, PAGE_SIZE * 192);
            assert_eq!(stats.live_allocated_frames, 63);
            assert_eq!(stats.reserved_eligible_frames, 1);
            assert_eq!(stats.dma_low_live_frames, 63);
        }
    }

    #[test]
    fn bounded_dma_failures_and_counters_saturate() {
        let mut allocator = unsafe {
            UsableFrameAllocator::from_test_region(DMA_32BIT_ADDRESS_LIMIT, PAGE_SIZE, 52)
        };
        allocator.set_failure_counters_for_test(u64::MAX, u64::MAX);
        assert_eq!(
            allocator.allocate_frame_below(DMA_32BIT_ADDRESS_LIMIT),
            Ok(None)
        );
        let stats = allocator.stats();
        assert_eq!(stats.dma_low_failures, u64::MAX);
        assert_eq!(stats.allocation_failures, u64::MAX);
        assert_eq!(stats.dma_low_live_frames, 0);
    }

    #[test]
    fn bounded_dma_live_use_is_released_on_reclaim() {
        let mut allocator =
            unsafe { UsableFrameAllocator::from_test_region(0x1000, PAGE_SIZE, 52) };
        let frame = allocator
            .allocate_frame_below(DMA_32BIT_ADDRESS_LIMIT)
            .unwrap()
            .unwrap();
        assert_eq!(allocator.stats().dma_low_allocations, 1);
        assert_eq!(allocator.stats().dma_low_live_frames, 1);
        allocator.deallocate_frame(frame).unwrap();
        assert_eq!(allocator.stats().dma_low_live_frames, 0);
    }

    #[test]
    fn failed_contiguous_allocation_rolls_back_every_partial_frame() {
        let mut allocator =
            unsafe { UsableFrameAllocator::from_test_region(0x1000, PAGE_SIZE * 2, 52) };
        assert_eq!(allocator.allocate_contiguous_frames(3), Ok(None));
        assert_eq!(allocator.allocated_count(), 0);
        assert_eq!(allocator.free_count(), 2);
        assert!(allocator.allocate_contiguous_frames(2).unwrap().is_some());
        assert_eq!(allocator.allocated_count(), 2);
    }

    #[test]
    fn fresh_claims_track_live_and_high_water_counts() {
        let mut ledger = OwnershipLedger::new();
        assert_eq!(ledger.claim_fresh(A), Ok(true));
        assert_eq!(ledger.claim_fresh(B), Ok(true));
        assert_eq!(ledger.live_allocated_count(), 2);
        assert_eq!(ledger.fresh_issued_count(), 2);
        assert_eq!(ledger.free_count(), 0);
        assert_eq!(ledger.reserved_count(), 0);
    }

    #[test]
    fn reclaimed_frames_are_reissued_without_raising_high_water_mark() {
        let mut ledger = ledger_with_three_allocations();
        assert_eq!(ledger.reclaim(&[A, C]), Ok(()));
        assert_eq!(ledger.live_allocated_count(), 1);
        assert_eq!(ledger.free_count(), 2);

        assert_eq!(ledger.claim_reclaimed(), Some(C));
        assert_eq!(ledger.claim_reclaimed(), Some(A));
        assert_eq!(ledger.claim_reclaimed(), None);
        assert_eq!(ledger.live_allocated_count(), 3);
        assert_eq!(ledger.fresh_issued_count(), 3);
        assert_eq!(ledger.free_count(), 0);
    }

    #[test]
    fn reclaim_rejects_never_allocated_frame_without_mutation() {
        let mut ledger = ledger_with_three_allocations();
        assert_eq!(
            ledger.reclaim(&[A, 0x9000, B]),
            Err(FrameAllocatorError::NeverAllocatedFrame { address: 0x9000 })
        );
        assert_eq!(ledger.live_allocated_count(), 3);
        assert_eq!(ledger.free_count(), 0);
    }

    #[test]
    fn reclaim_rejects_duplicate_batch_without_mutation() {
        let mut ledger = ledger_with_three_allocations();
        assert_eq!(
            ledger.reclaim(&[A, B, A]),
            Err(FrameAllocatorError::DuplicateFrameInBatch { address: A })
        );
        assert_eq!(ledger.live_allocated_count(), 3);
        assert_eq!(ledger.free_count(), 0);
    }

    #[test]
    fn reclaim_rejects_double_free_without_partial_mutation() {
        let mut ledger = ledger_with_three_allocations();
        assert_eq!(ledger.reclaim(&[B]), Ok(()));
        assert_eq!(
            ledger.reclaim(&[A, B, C]),
            Err(FrameAllocatorError::DoubleFree { address: B })
        );
        assert_eq!(ledger.live_allocated_count(), 2);
        assert_eq!(ledger.free_count(), 1);
        assert_eq!(ledger.claim_reclaimed(), Some(B));
    }

    #[test]
    fn reclaim_rejects_reserved_frame_without_partial_mutation() {
        let mut ledger = ledger_with_three_allocations();
        assert_eq!(ledger.reserve(B), Ok(true));
        assert_eq!(
            ledger.reclaim(&[A, B, C]),
            Err(FrameAllocatorError::ReservedFrame { address: B })
        );
        assert_eq!(ledger.live_allocated_count(), 2);
        assert_eq!(ledger.free_count(), 0);
        assert_eq!(ledger.reserved_count(), 1);
    }

    #[test]
    fn reserving_allocated_frame_transfers_it_out_of_live_ownership() {
        let mut ledger = ledger_with_three_allocations();
        assert_eq!(ledger.reserve(B), Ok(true));
        assert_eq!(ledger.reserve(B), Ok(false));
        assert_eq!(ledger.live_allocated_count(), 2);
        assert_eq!(ledger.fresh_issued_count(), 3);
        assert_eq!(ledger.reserved_count(), 1);
        assert_eq!(ledger.claim_fresh(B), Ok(false));
    }

    #[test]
    fn reserving_free_frame_removes_it_from_reclaimed_list() {
        let mut ledger = ledger_with_three_allocations();
        assert_eq!(ledger.reclaim(&[A, B]), Ok(()));
        assert_eq!(ledger.reserve(A), Ok(true));
        assert_eq!(ledger.free_count(), 1);
        assert_eq!(ledger.reserved_count(), 1);
        assert_eq!(ledger.claim_reclaimed(), Some(B));
        assert_eq!(ledger.claim_reclaimed(), None);
        assert_eq!(ledger.claim_fresh(A), Ok(false));
    }

    #[test]
    fn reserving_unseen_frame_blocks_fresh_issue() {
        let mut ledger = OwnershipLedger::new();
        assert_eq!(ledger.reserve(A), Ok(true));
        assert_eq!(ledger.reserve(A), Ok(false));
        assert_eq!(ledger.claim_fresh(A), Ok(false));
        assert_eq!(ledger.live_allocated_count(), 0);
        assert_eq!(ledger.fresh_issued_count(), 0);
        assert_eq!(ledger.free_count(), 0);
        assert_eq!(ledger.reserved_count(), 1);
    }

    #[test]
    fn empty_reclaim_is_a_noop() {
        let mut ledger = ledger_with_three_allocations();
        assert_eq!(ledger.reclaim(&[]), Ok(()));
        assert_eq!(ledger.live_allocated_count(), 3);
        assert_eq!(ledger.free_count(), 0);
    }
}
