//! Minimal Limine boot-protocol declarations used by the kernel.
//!
//! The layout and constants are derived from the 0BSD-licensed official
//! `limine.h`. Keeping this module local avoids a runtime or crate dependency.

use core::{
    cell::UnsafeCell,
    marker::PhantomData,
    mem::{align_of, size_of},
    ptr,
};

pub const REQUESTS_START_MARKER: [u64; 4] = [
    0xf6b8_f4b3_9de7_d1ae,
    0xfab9_1a69_40fc_b9cf,
    0x785c_6ed0_15d3_e316,
    0x181e_920a_7852_b9d9,
];

pub const REQUESTS_END_MARKER: [u64; 2] = [
    0xadc0_e053_1bb1_0d03,
    0x9572_709f_3176_4c62,
];

const COMMON_MAGIC: [u64; 2] = [
    0xc7b1_dd30_df4c_8b88,
    0x0a82_e883_a194_f07b,
];

const STACK_SIZE_REQUEST_MAGIC: [u64; 2] = [
    0x224e_f046_0a8e_8926,
    0xe1cb_0fc2_5f46_ea3d,
];

const TSC_FREQUENCY_REQUEST_MAGIC: [u64; 2] = [
    0x10f2_ee1d_87d1_95e4,
    0xf747_a2b7_8f6d_db31,
];

const FRAMEBUFFER_REQUEST_MAGIC: [u64; 2] = [
    0x9d58_27dc_d881_dd75,
    0xa314_8604_f6fa_b11b,
];

const MEMORY_MAP_REQUEST_MAGIC: [u64; 2] = [
    0x67cf_3d9d_378a_806f,
    0xe304_acdf_c50c_3c62,
];

const HHDM_REQUEST_MAGIC: [u64; 2] = [
    0x48dc_f1cb_8ad2_b852,
    0x6398_4e95_9a98_244b,
];

pub const MEMORY_MAP_USABLE: u64 = 0;
pub const MEMORY_MAP_RESERVED: u64 = 1;
pub const MEMORY_MAP_ACPI_RECLAIMABLE: u64 = 2;
pub const MEMORY_MAP_ACPI_NVS: u64 = 3;
pub const MEMORY_MAP_BAD_MEMORY: u64 = 4;
pub const MEMORY_MAP_BOOTLOADER_RECLAIMABLE: u64 = 5;
pub const MEMORY_MAP_EXECUTABLE_AND_MODULES: u64 = 6;
pub const MEMORY_MAP_FRAMEBUFFER: u64 = 7;
pub const MEMORY_MAP_RESERVED_MAPPED: u64 = 8;

#[repr(C)]
pub struct BaseRevision {
    words: UnsafeCell<[u64; 3]>,
}

unsafe impl Sync for BaseRevision {}

impl BaseRevision {
    pub const fn new(revision: u64) -> Self {
        Self {
            words: UnsafeCell::new([
                0xf956_2b2d_5c95_a6c8,
                0x6a7b_3849_4453_6bdc,
                revision,
            ]),
        }
    }

    pub fn is_supported(&self) -> bool {
        unsafe { ptr::read_volatile(self.words.get().cast::<u64>().add(2)) == 0 }
    }
}

#[repr(C)]
pub struct StackSizeRequest {
    id: [u64; 4],
    revision: u64,
    response: UnsafeCell<*mut StackSizeResponse>,
    pub stack_size: u64,
}

unsafe impl Sync for StackSizeRequest {}

impl StackSizeRequest {
    pub const fn new(stack_size: u64) -> Self {
        Self {
            id: [
                COMMON_MAGIC[0],
                COMMON_MAGIC[1],
                STACK_SIZE_REQUEST_MAGIC[0],
                STACK_SIZE_REQUEST_MAGIC[1],
            ],
            revision: 0,
            response: UnsafeCell::new(ptr::null_mut()),
            stack_size,
        }
    }
}

#[repr(C)]
pub struct StackSizeResponse {
    pub revision: u64,
}

#[repr(C)]
pub struct TscFrequencyRequest {
    id: [u64; 4],
    revision: u64,
    response: UnsafeCell<*mut TscFrequencyResponse>,
}

unsafe impl Sync for TscFrequencyRequest {}

impl TscFrequencyRequest {
    pub const fn new() -> Self {
        Self {
            id: [
                COMMON_MAGIC[0],
                COMMON_MAGIC[1],
                TSC_FREQUENCY_REQUEST_MAGIC[0],
                TSC_FREQUENCY_REQUEST_MAGIC[1],
            ],
            revision: 0,
            response: UnsafeCell::new(ptr::null_mut()),
        }
    }

    pub fn response(&self) -> Option<&'static TscFrequencyResponse> {
        let response = unsafe { ptr::read_volatile(self.response.get()) };
        unsafe { response.as_ref() }
    }
}

#[repr(C)]
pub struct TscFrequencyResponse {
    pub revision: u64,
    pub frequency: u64,
}

#[repr(C)]
pub struct MemoryMapRequest {
    id: [u64; 4],
    revision: u64,
    response: UnsafeCell<*mut MemoryMapResponse>,
}

unsafe impl Sync for MemoryMapRequest {}

impl MemoryMapRequest {
    pub const fn new() -> Self {
        Self {
            id: [
                COMMON_MAGIC[0],
                COMMON_MAGIC[1],
                MEMORY_MAP_REQUEST_MAGIC[0],
                MEMORY_MAP_REQUEST_MAGIC[1],
            ],
            revision: 0,
            response: UnsafeCell::new(ptr::null_mut()),
        }
    }

    pub fn response(&self) -> Option<&'static MemoryMapResponse> {
        let response = unsafe { ptr::read_volatile(self.response.get()) };
        unsafe { response.as_ref() }
    }
}

#[repr(C)]
pub struct MemoryMapResponse {
    pub revision: u64,
    pub entry_count: u64,
    pub entries: *mut *mut MemoryMapEntry,
}

impl MemoryMapResponse {
    pub fn entries(&self) -> Result<MemoryMapEntries<'_>, MemoryMapError> {
        let count = usize::try_from(self.entry_count)
            .map_err(|_| MemoryMapError::EntryCountTooLarge)?;

        if count == 0 {
            return Ok(MemoryMapEntries {
                entries: self.entries,
                count,
                index: 0,
                response: PhantomData,
            });
        }
        if self.entries.is_null() {
            return Err(MemoryMapError::NullEntries);
        }
        if self.entries.addr() % align_of::<*mut MemoryMapEntry>() != 0 {
            return Err(MemoryMapError::MisalignedEntries);
        }

        let byte_count = count
            .checked_mul(size_of::<*mut MemoryMapEntry>())
            .ok_or(MemoryMapError::EntryCountTooLarge)?;
        if byte_count > isize::MAX as usize {
            return Err(MemoryMapError::EntryCountTooLarge);
        }

        Ok(MemoryMapEntries {
            entries: self.entries,
            count,
            index: 0,
            response: PhantomData,
        })
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryMapEntry {
    pub base: u64,
    pub length: u64,
    pub entry_type: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryMapError {
    EntryCountTooLarge,
    NullEntries,
    MisalignedEntries,
    NullEntry(usize),
    MisalignedEntry(usize),
}

pub struct MemoryMapEntries<'a> {
    entries: *mut *mut MemoryMapEntry,
    count: usize,
    index: usize,
    response: PhantomData<&'a MemoryMapResponse>,
}

impl Iterator for MemoryMapEntries<'_> {
    type Item = Result<MemoryMapEntry, MemoryMapError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index == self.count {
            return None;
        }

        let index = self.index;
        self.index += 1;
        let entry = unsafe { ptr::read_volatile(self.entries.add(index)) };

        if entry.is_null() {
            return Some(Err(MemoryMapError::NullEntry(index)));
        }
        if entry.addr() % align_of::<MemoryMapEntry>() != 0 {
            return Some(Err(MemoryMapError::MisalignedEntry(index)));
        }

        Some(Ok(unsafe { ptr::read_volatile(entry) }))
    }
}

#[repr(C)]
pub struct HhdmRequest {
    id: [u64; 4],
    revision: u64,
    response: UnsafeCell<*mut HhdmResponse>,
}

unsafe impl Sync for HhdmRequest {}

impl HhdmRequest {
    pub const fn new() -> Self {
        Self {
            id: [
                COMMON_MAGIC[0],
                COMMON_MAGIC[1],
                HHDM_REQUEST_MAGIC[0],
                HHDM_REQUEST_MAGIC[1],
            ],
            revision: 0,
            response: UnsafeCell::new(ptr::null_mut()),
        }
    }

    pub fn response(&self) -> Option<&'static HhdmResponse> {
        let response = unsafe { ptr::read_volatile(self.response.get()) };
        unsafe { response.as_ref() }
    }
}

#[repr(C)]
pub struct HhdmResponse {
    pub revision: u64,
    pub offset: u64,
}

#[repr(C)]
pub struct FramebufferRequest {
    id: [u64; 4],
    revision: u64,
    response: UnsafeCell<*mut FramebufferResponse>,
}

unsafe impl Sync for FramebufferRequest {}

impl FramebufferRequest {
    pub const fn new() -> Self {
        Self {
            id: [
                COMMON_MAGIC[0],
                COMMON_MAGIC[1],
                FRAMEBUFFER_REQUEST_MAGIC[0],
                FRAMEBUFFER_REQUEST_MAGIC[1],
            ],
            revision: 0,
            response: UnsafeCell::new(ptr::null_mut()),
        }
    }

    pub fn response(&self) -> Option<&'static FramebufferResponse> {
        let response = unsafe { ptr::read_volatile(self.response.get()) };
        unsafe { response.as_ref() }
    }
}

#[repr(C)]
pub struct FramebufferResponse {
    pub revision: u64,
    pub framebuffer_count: u64,
    pub framebuffers: *mut *mut Framebuffer,
}

impl FramebufferResponse {
    pub fn first(&self) -> Option<&'static Framebuffer> {
        if self.framebuffer_count == 0 || self.framebuffers.is_null() {
            return None;
        }

        let framebuffer = unsafe { ptr::read_volatile(self.framebuffers) };
        unsafe { framebuffer.as_ref() }
    }
}

#[repr(C)]
pub struct Framebuffer {
    pub address: *mut u8,
    pub width: u64,
    pub height: u64,
    pub pitch: u64,
    pub bpp: u16,
    pub memory_model: u8,
    pub red_mask_size: u8,
    pub red_mask_shift: u8,
    pub green_mask_size: u8,
    pub green_mask_shift: u8,
    pub blue_mask_size: u8,
    pub blue_mask_shift: u8,
    pub unused: [u8; 7],
    pub edid_size: u64,
    pub edid: *mut u8,
}
