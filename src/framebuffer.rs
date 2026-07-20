use core::ptr;

use crate::font8x8::BASIC_FONT;
use ginkgo_os::limine::Framebuffer;

#[derive(Clone, Copy)]
pub struct Rgb {
    pub red: u8,
    pub green: u8,
    pub blue: u8,
}

impl Rgb {
    pub const fn new(red: u8, green: u8, blue: u8) -> Self {
        Self { red, green, blue }
    }
}

pub struct FramebufferWriter<'a> {
    framebuffer: &'a Framebuffer,
}

impl<'a> FramebufferWriter<'a> {
    pub fn new(framebuffer: &'a Framebuffer) -> Option<Self> {
        let bytes_per_pixel = bytes_per_pixel(framebuffer.bpp);
        let width = usize::try_from(framebuffer.width).ok()?;
        let height = usize::try_from(framebuffer.height).ok()?;
        let pitch = usize::try_from(framebuffer.pitch).ok()?;
        let row_bytes = width.checked_mul(bytes_per_pixel)?;
        let mapped_bytes = pitch.checked_mul(height)?;
        let valid_channel = |size: u8, shift: u8| {
            size > 0
                && u16::from(shift) + u16::from(size) <= framebuffer.bpp
                && u16::from(shift) + u16::from(size) <= 32
        };

        if framebuffer.address.is_null()
            || width == 0
            || height == 0
            || framebuffer.memory_model != 1
            || !(3..=4).contains(&bytes_per_pixel)
            || pitch < row_bytes
            || mapped_bytes > isize::MAX as usize
            || (framebuffer.address as usize)
                .checked_add(mapped_bytes.saturating_sub(1))
                .is_none()
            || !valid_channel(framebuffer.red_mask_size, framebuffer.red_mask_shift)
            || !valid_channel(framebuffer.green_mask_size, framebuffer.green_mask_shift)
            || !valid_channel(framebuffer.blue_mask_size, framebuffer.blue_mask_shift)
        {
            return None;
        }

        Some(Self { framebuffer })
    }

    pub fn width(&self) -> usize {
        self.framebuffer.width as usize
    }

    pub fn height(&self) -> usize {
        self.framebuffer.height as usize
    }

    pub fn clear(&mut self, color: Rgb) {
        for y in 0..self.height() {
            for x in 0..self.width() {
                self.put_pixel(x, y, color);
            }
        }
    }

    pub fn fill_rect(&mut self, x: usize, y: usize, width: usize, height: usize, color: Rgb) {
        let x_end = x.saturating_add(width).min(self.width());
        let y_end = y.saturating_add(height).min(self.height());

        for pixel_y in y..y_end {
            for pixel_x in x..x_end {
                self.put_pixel(pixel_x, pixel_y, color);
            }
        }
    }

    pub fn draw_text(&mut self, mut x: usize, mut y: usize, scale: usize, text: &str, color: Rgb) {
        let origin_x = x;
        let scale = scale.max(1);

        for byte in text.bytes() {
            match byte {
                b'\n' => {
                    x = origin_x;
                    y = y.saturating_add(9 * scale);
                }
                b'\r' => x = origin_x,
                _ => {
                    self.draw_char(x, y, scale, byte, color);
                    x = x.saturating_add(8 * scale);
                }
            }
        }
    }

    fn draw_char(&mut self, x: usize, y: usize, scale: usize, byte: u8, color: Rgb) {
        let glyph = BASIC_FONT[usize::from(byte.min(127))];

        for (row, bits) in glyph.into_iter().enumerate() {
            for column in 0..8 {
                if bits & (1 << column) == 0 {
                    continue;
                }

                self.fill_rect(
                    x + column * scale,
                    y + row * scale,
                    scale,
                    scale,
                    color,
                );
            }
        }
    }

    fn put_pixel(&mut self, x: usize, y: usize, color: Rgb) {
        if x >= self.width() || y >= self.height() {
            return;
        }

        let bytes_per_pixel = bytes_per_pixel(self.framebuffer.bpp);
        let offset = y * self.framebuffer.pitch as usize + x * bytes_per_pixel;
        let packed = self.pack_color(color);

        unsafe {
            for byte_index in 0..bytes_per_pixel {
                ptr::write_volatile(
                    self.framebuffer.address.add(offset + byte_index),
                    (packed >> (byte_index * 8)) as u8,
                );
            }
        }
    }

    fn pack_color(&self, color: Rgb) -> u32 {
        (scale_channel(color.red, self.framebuffer.red_mask_size)
            << self.framebuffer.red_mask_shift)
            | (scale_channel(color.green, self.framebuffer.green_mask_size)
                << self.framebuffer.green_mask_shift)
            | (scale_channel(color.blue, self.framebuffer.blue_mask_size)
                << self.framebuffer.blue_mask_shift)
    }
}

fn scale_channel(value: u8, bits: u8) -> u32 {
    if bits == 0 {
        return 0;
    }

    let maximum = if bits >= 32 {
        u32::MAX
    } else {
        (1_u32 << bits) - 1
    };

    (u32::from(value) * maximum + 127) / 255
}

fn bytes_per_pixel(bits_per_pixel: u16) -> usize {
    (usize::from(bits_per_pixel) + 7) / 8
}
