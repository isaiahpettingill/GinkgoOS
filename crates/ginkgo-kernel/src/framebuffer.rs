//! Limine-to-graphics framebuffer adapter.

use ginkgo_graphics::FramebufferConfig;
pub use ginkgo_graphics::{FramebufferWriter, Rgb};
use ginkgo_kernel::limine::Framebuffer;

/// Claims a Limine RGB framebuffer for exclusive drawing.
///
/// # Safety
///
/// The Limine descriptor must identify writable mapped memory covering at least
/// `pitch * height` bytes. The caller must also ensure no other code accesses
/// that memory for the lifetime of the returned writer.
pub unsafe fn from_limine(framebuffer: &'static Framebuffer) -> Option<FramebufferWriter<'static>> {
    FramebufferWriter::from_raw(FramebufferConfig {
        address: framebuffer.address,
        width: framebuffer.width,
        height: framebuffer.height,
        pitch: framebuffer.pitch,
        bits_per_pixel: framebuffer.bpp,
        memory_model: framebuffer.memory_model,
        red_mask_size: framebuffer.red_mask_size,
        red_mask_shift: framebuffer.red_mask_shift,
        green_mask_size: framebuffer.green_mask_size,
        green_mask_shift: framebuffer.green_mask_shift,
        blue_mask_size: framebuffer.blue_mask_size,
        blue_mask_shift: framebuffer.blue_mask_shift,
    })
}
