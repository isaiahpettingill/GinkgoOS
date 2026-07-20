//! Minimal Limine boot-protocol declarations needed for a framebuffer request.
//!
//! The layout and constants are derived from the 0BSD-licensed official
//! `limine.h`. Keeping this tiny module local avoids a runtime or crate
//! dependency in the first kernel milestone.

use core::{cell::UnsafeCell, ptr};

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

const FRAMEBUFFER_REQUEST_MAGIC: [u64; 2] = [
    0x9d58_27dc_d881_dd75,
    0xa314_8604_f6fa_b11b,
];

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
    pub mode_count: u64,
    pub modes: *mut *mut VideoMode,
}

#[repr(C)]
pub struct VideoMode {
    pub pitch: u64,
    pub width: u64,
    pub height: u64,
    pub bpp: u16,
    pub memory_model: u8,
    pub red_mask_size: u8,
    pub red_mask_shift: u8,
    pub green_mask_size: u8,
    pub green_mask_shift: u8,
    pub blue_mask_size: u8,
    pub blue_mask_shift: u8,
}
