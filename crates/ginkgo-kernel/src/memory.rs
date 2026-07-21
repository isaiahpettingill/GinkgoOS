//! Physical frame allocation backed by the Limine memory map.

use alloc::vec::Vec;

use x86_64::structures::paging::{FrameAllocator, Page, PhysFrame as GenericPhysFrame, Size4KiB};

use crate::limine::{MemoryMapEntries, MemoryMapError, MemoryMapResponse, MEMORY_MAP_USABLE};

pub use x86_64::{PhysAddr, VirtAddr};

pub type PhysFrame = GenericPhysFrame<Size4KiB>;
pub type VirtPage = Page<Size4KiB>;
pub const PAGE_SIZE: u64 = 4096;
pub const MAX_PHYSICAL_ADDRESS: u64 = (1_u64 << 52) - 1;
const PHYSICAL_ADDRESS_SPACE_SIZE: u64 = 1_u64 << 52;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameAllocatorError {
    InvalidMemoryMap(MemoryMapError),
    InvalidUsableRegion { base: u64, length: u64 },
    UsableRegionOverflow { base: u64, length: u64 },
    PhysicalAddressTooLarge { base: u64, length: u64 },
}

pub struct UsableFrameAllocator<'a> {
    entries: MemoryMapEntries<'a>,
    next: u64,
    current_end: u64,
    allocated: u64,
    reserved: Vec<PhysFrame>,
    error: Option<FrameAllocatorError>,
}

impl<'a> UsableFrameAllocator<'a> {
    pub fn new(memory_map: &'a MemoryMapResponse) -> Result<Self, MemoryMapError> {
        Ok(Self {
            entries: memory_map.entries()?,
            next: 0,
            current_end: 0,
            allocated: 0,
            reserved: Vec::new(),
            error: None,
        })
    }

    pub fn allocated_count(&self) -> u64 {
        self.allocated
    }

    pub fn error(&self) -> Option<FrameAllocatorError> {
        self.error
    }

    /// Prevents a physical frame from being returned by future allocations.
    pub fn reserve_frame(&mut self, frame: PhysFrame) -> Result<bool, FrameAllocatorError> {
        if self.reserved.contains(&frame) {
            return Ok(false);
        }
        self.reserved.push(frame);
        Ok(true)
    }

    pub fn reserved_count(&self) -> usize {
        self.reserved.len()
    }

    pub fn allocate_frame(&mut self) -> Result<Option<PhysFrame>, FrameAllocatorError> {
        if let Some(error) = self.error {
            return Err(error);
        }

        loop {
            if self.next < self.current_end {
                if self
                    .reserved
                    .iter()
                    .any(|frame| frame.start_address().as_u64() == self.next)
                {
                    self.next += PAGE_SIZE;
                    continue;
                }

                let address = match PhysAddr::try_new(self.next) {
                    Ok(address) => address,
                    Err(_) => {
                        return self.fail(FrameAllocatorError::PhysicalAddressTooLarge {
                            base: self.next,
                            length: PAGE_SIZE,
                        })
                    }
                };
                let frame = match PhysFrame::from_start_address(address) {
                    Ok(frame) => frame,
                    Err(_) => {
                        return self.fail(FrameAllocatorError::InvalidUsableRegion {
                            base: self.next,
                            length: PAGE_SIZE,
                        })
                    }
                };

                self.next += PAGE_SIZE;
                self.allocated += 1;
                return Ok(Some(frame));
            }

            let Some(entry) = self.entries.next() else {
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
            if end > PHYSICAL_ADDRESS_SPACE_SIZE {
                return self.fail(FrameAllocatorError::PhysicalAddressTooLarge {
                    base: entry.base,
                    length: entry.length,
                });
            }

            self.next = entry.base;
            self.current_end = end;
        }
    }

    fn fail<T>(&mut self, error: FrameAllocatorError) -> Result<T, FrameAllocatorError> {
        self.error = Some(error);
        Err(error)
    }
}

// SAFETY: Limine marks the source regions usable, allocation advances monotonically,
// and `reserved` excludes every live frame discovered before allocation begins.
unsafe impl FrameAllocator<Size4KiB> for UsableFrameAllocator<'_> {
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        UsableFrameAllocator::allocate_frame(self).ok().flatten()
    }
}
