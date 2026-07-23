//! Physical frame allocation backed by the Limine memory map.

use alloc::vec::Vec;

use x86_64::structures::paging::{FrameAllocator, Page, PhysFrame as GenericPhysFrame, Size4KiB};

use crate::{
    arch::MAX_PHYSICAL_ADDRESS_BITS,
    limine::{MemoryMapEntries, MemoryMapError, MemoryMapResponse, MEMORY_MAP_USABLE},
};

pub use x86_64::{PhysAddr, VirtAddr};

pub type PhysFrame = GenericPhysFrame<Size4KiB>;
pub type VirtPage = Page<Size4KiB>;
pub const PAGE_SIZE: u64 = 4096;

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
}

impl OwnershipLedger {
    const fn new() -> Self {
        Self {
            records: Vec::new(),
            free: Vec::new(),
            live_allocated: 0,
            fresh_issued: 0,
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
        });
        self.live_allocated += 1;
        self.fresh_issued += 1;
        Ok(true)
    }

    /// Reclaimed addresses are always preferred over fresh addresses.
    fn claim_reclaimed(&mut self) -> Option<u64> {
        let address = self.free.pop()?;
        let index = self
            .find(address)
            .expect("free-list address must have an ownership record");
        debug_assert_eq!(self.records[index].state, OwnershipState::Free);
        self.records[index].state = OwnershipState::Allocated;
        self.live_allocated += 1;
        Some(address)
    }

    fn reserve(&mut self, address: u64) -> Result<bool, FrameAllocatorError> {
        if let Some(index) = self.find(address) {
            match self.records[index].state {
                OwnershipState::Reserved => return Ok(false),
                OwnershipState::Allocated => {
                    self.live_allocated -= 1;
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
            return Ok(true);
        }

        self.records
            .try_reserve(1)
            .map_err(|_| FrameAllocatorError::OwnershipTrackingAllocationFailed)?;
        self.records.push(OwnershipRecord {
            address,
            state: OwnershipState::Reserved,
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
        for index in 0..count {
            let address = address_at(index);
            let record_index = self
                .find(address)
                .expect("reclamation was preflighted against ownership records");
            self.records[record_index].state = OwnershipState::Free;
            self.free.push(address);
        }
        self.live_allocated -= count as u64;
        Ok(())
    }
}

pub struct UsableFrameAllocator<'a> {
    entries: Option<MemoryMapEntries<'a>>,
    next: u64,
    current_end: u64,
    physical_address_space_size: u64,
    ownership: OwnershipLedger,
    error: Option<FrameAllocatorError>,
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
        Ok(Self {
            entries: Some(
                memory_map
                    .entries()
                    .map_err(FrameAllocatorError::InvalidMemoryMap)?,
            ),
            next: 0,
            current_end: 0,
            physical_address_space_size,
            ownership: OwnershipLedger::new(),
            error: None,
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
            entries: None,
            next: base,
            current_end: base + length,
            physical_address_space_size,
            ownership: OwnershipLedger::new(),
            error: None,
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

    /// Permanently prevents a physical frame from being returned by future
    /// allocations. Reserving an allocated or free frame transfers it out of
    /// allocator ownership and removes it from the reclaimable free list.
    pub fn reserve_frame(&mut self, frame: PhysFrame) -> Result<bool, FrameAllocatorError> {
        self.ownership.reserve(frame.start_address().as_u64())
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
        if let Some(error) = self.error {
            return Err(error);
        }

        if let Some(address) = self.ownership.claim_reclaimed() {
            return Ok(Some(Self::frame_from_address(address)?));
        }

        loop {
            if self.next < self.current_end {
                let address = self.next;
                match self.ownership.claim_fresh(address) {
                    Ok(claimed) => {
                        self.next += PAGE_SIZE;
                        if !claimed {
                            continue;
                        }
                    }
                    Err(error) => return self.fail(error),
                }

                return match Self::frame_from_address(address) {
                    Ok(frame) => Ok(Some(frame)),
                    Err(error) => self.fail(error),
                };
            }

            let Some(entries) = self.entries.as_mut() else {
                return Ok(None);
            };
            let Some(entry) = entries.next() else {
                return Ok(None);
            };
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => return self.fail(FrameAllocatorError::InvalidMemoryMap(error)),
            };

            if entry.entry_type != MEMORY_MAP_USABLE || entry.length == 0 {
                continue;
            }
            if entry.base % PAGE_SIZE != 0 || entry.length % PAGE_SIZE != 0 {
                return self.fail(FrameAllocatorError::InvalidUsableRegion {
                    base: entry.base,
                    length: entry.length,
                });
            }

            let end = match entry.base.checked_add(entry.length) {
                Some(end) => end,
                None => {
                    return self.fail(FrameAllocatorError::UsableRegionOverflow {
                        base: entry.base,
                        length: entry.length,
                    })
                }
            };
            if end > self.physical_address_space_size {
                return self.fail(FrameAllocatorError::PhysicalAddressTooLarge {
                    base: entry.base,
                    length: entry.length,
                });
            }

            self.next = entry.base;
            self.current_end = end;
        }
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
    use super::{
        physical_address_space_size, FrameAllocatorError, OwnershipLedger, UsableFrameAllocator,
        PAGE_SIZE,
    };

    const A: u64 = 0x1000;
    const B: u64 = 0x2000;
    const C: u64 = 0x3000;

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
