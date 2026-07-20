//! Physical and virtual address types plus a simple usable-frame allocator.

use crate::limine::{
    MemoryMapEntries, MemoryMapError, MemoryMapResponse, MEMORY_MAP_USABLE,
};

pub const PAGE_SIZE: u64 = 4096;
pub const MAX_PHYSICAL_ADDRESS: u64 = (1_u64 << 52) - 1;
const PHYSICAL_ADDRESS_SPACE_SIZE: u64 = 1_u64 << 52;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PhysAddr(u64);

impl PhysAddr {
    pub const fn new(address: u64) -> Option<Self> {
        if address <= MAX_PHYSICAL_ADDRESS {
            Some(Self(address))
        } else {
            None
        }
    }

    pub const fn as_u64(self) -> u64 {
        self.0
    }

    pub const fn checked_add(self, offset: u64) -> Option<Self> {
        match self.0.checked_add(offset) {
            Some(address) => Self::new(address),
            None => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct VirtAddr(u64);

impl VirtAddr {
    pub const fn new(address: u64) -> Option<Self> {
        let upper = address >> 48;
        let sign = (address >> 47) & 1;
        if (sign == 0 && upper == 0) || (sign == 1 && upper == 0xffff) {
            Some(Self(address))
        } else {
            None
        }
    }

    pub const fn as_u64(self) -> u64 {
        self.0
    }

    pub const fn checked_add(self, offset: u64) -> Option<Self> {
        match self.0.checked_add(offset) {
            Some(address) => Self::new(address),
            None => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PhysFrame {
    start: PhysAddr,
}

impl PhysFrame {
    pub const fn from_start_address(address: PhysAddr) -> Option<Self> {
        if address.as_u64() % PAGE_SIZE == 0 {
            Some(Self { start: address })
        } else {
            None
        }
    }

    pub const fn start_address(self) -> PhysAddr {
        self.start
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtPage {
    start: VirtAddr,
}

impl VirtPage {
    pub const fn from_start_address(address: VirtAddr) -> Option<Self> {
        if address.as_u64() % PAGE_SIZE == 0 {
            Some(Self { start: address })
        } else {
            None
        }
    }

    pub const fn start_address(self) -> VirtAddr {
        self.start
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameAllocatorError {
    InvalidMemoryMap(MemoryMapError),
    InvalidUsableRegion { base: u64, length: u64 },
    UsableRegionOverflow { base: u64, length: u64 },
    PhysicalAddressTooLarge { base: u64, length: u64 },
}

pub trait FrameAllocator {
    fn allocate_frame(&mut self) -> Result<Option<PhysFrame>, FrameAllocatorError>;
}

pub struct UsableFrameAllocator<'a> {
    entries: MemoryMapEntries<'a>,
    next: u64,
    current_end: u64,
    allocated: u64,
    error: Option<FrameAllocatorError>,
}

impl<'a> UsableFrameAllocator<'a> {
    pub fn new(memory_map: &'a MemoryMapResponse) -> Result<Self, MemoryMapError> {
        Ok(Self {
            entries: memory_map.entries()?,
            next: 0,
            current_end: 0,
            allocated: 0,
            error: None,
        })
    }

    pub fn allocated_count(&self) -> u64 {
        self.allocated
    }

    pub fn allocate_frame(&mut self) -> Result<Option<PhysFrame>, FrameAllocatorError> {
        if let Some(error) = self.error {
            return Err(error);
        }

        loop {
            if self.next < self.current_end {
                let address = PhysAddr::new(self.next).ok_or(
                    FrameAllocatorError::PhysicalAddressTooLarge {
                        base: self.next,
                        length: PAGE_SIZE,
                    },
                )?;
                let frame = PhysFrame::from_start_address(address).ok_or(
                    FrameAllocatorError::InvalidUsableRegion {
                        base: self.next,
                        length: PAGE_SIZE,
                    },
                )?;

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

impl FrameAllocator for UsableFrameAllocator<'_> {
    fn allocate_frame(&mut self) -> Result<Option<PhysFrame>, FrameAllocatorError> {
        UsableFrameAllocator::allocate_frame(self)
    }
}
