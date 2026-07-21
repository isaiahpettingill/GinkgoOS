use core::{convert::Infallible, ptr::NonNull};

use embedded_graphics::{
    draw_target::DrawTarget,
    geometry::{OriginDimensions, Point, Size},
    mono_font::{MonoFont, MonoTextStyle},
    pixelcolor::{Rgb888, RgbColor},
    prelude::{Drawable, Pixel},
    primitives::Rectangle,
    text::{Baseline, Text},
};
use ginkgo_os::limine::Framebuffer;
use profont::{PROFONT_14_POINT, PROFONT_24_POINT, PROFONT_7_POINT};
use volatile::VolatilePtr;

pub type Rgb = Rgb888;

/// An embedded-graphics draw target over a Limine RGB framebuffer.
pub struct FramebufferWriter<'a> {
    framebuffer: &'a Framebuffer,
}

impl<'a> FramebufferWriter<'a> {
    pub fn new(framebuffer: &'a Framebuffer) -> Option<Self> {
        let bytes_per_pixel = bytes_per_pixel(framebuffer.bpp);
        let width = usize::try_from(framebuffer.width).ok()?;
        let height = usize::try_from(framebuffer.height).ok()?;
        u32::try_from(width).ok()?;
        u32::try_from(height).ok()?;
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
        let _ = <Self as DrawTarget>::clear(self, color);
    }

    pub fn fill_rect(&mut self, x: usize, y: usize, width: usize, height: usize, color: Rgb) {
        let (Ok(x), Ok(y), Ok(width), Ok(height)) = (
            i32::try_from(x),
            i32::try_from(y),
            u32::try_from(width),
            u32::try_from(height),
        ) else {
            return;
        };
        let area = Rectangle::new(Point::new(x, y), Size::new(width, height));
        let _ = <Self as DrawTarget>::fill_solid(self, &area, color);
    }

    pub fn draw_text(&mut self, x: usize, y: usize, scale: usize, text: &str, color: Rgb) {
        let (Ok(x), Ok(y)) = (i32::try_from(x), i32::try_from(y)) else {
            return;
        };
        let style = MonoTextStyle::new(font_for_scale(scale), color);
        let _ = Text::with_baseline(text, Point::new(x, y), style, Baseline::Top).draw(self);
    }

    pub fn draw_text_wrapped(
        &mut self,
        mut x: usize,
        mut y: usize,
        width: usize,
        scale: usize,
        text: &str,
        color: Rgb,
    ) {
        let origin_x = x;
        let font = font_for_scale(scale);
        let advance = font.character_size.width as usize + font.character_spacing as usize;
        let line_height = font.character_size.height as usize;
        let right = origin_x.saturating_add(width);
        let style = MonoTextStyle::new(font, color);

        for byte in text.bytes() {
            match byte {
                b'\n' => {
                    x = origin_x;
                    y = y.saturating_add(line_height);
                }
                b'\r' => x = origin_x,
                _ => {
                    if x != origin_x && x.saturating_add(advance) > right {
                        x = origin_x;
                        y = y.saturating_add(line_height);
                    }
                    let bytes = [byte];
                    if let (Ok(glyph), Ok(x), Ok(y)) = (
                        core::str::from_utf8(&bytes),
                        i32::try_from(x),
                        i32::try_from(y),
                    ) {
                        let _ = Text::with_baseline(glyph, Point::new(x, y), style, Baseline::Top)
                            .draw(self);
                    }
                    x = x.saturating_add(advance);
                }
            }
        }
    }

    pub fn read_raw_pixel(&self, x: usize, y: usize) -> Option<u32> {
        if x >= self.width() || y >= self.height() {
            return None;
        }

        let bytes_per_pixel = bytes_per_pixel(self.framebuffer.bpp);
        let offset = y * self.framebuffer.pitch as usize + x * bytes_per_pixel;
        let mut packed = 0_u32;
        for byte_index in 0..bytes_per_pixel {
            let pointer =
                NonNull::new(unsafe { self.framebuffer.address.add(offset + byte_index) })?;
            packed |= u32::from(unsafe { VolatilePtr::new(pointer) }.read()) << (byte_index * 8);
        }
        Some(packed)
    }

    pub fn write_raw_pixel(&mut self, x: usize, y: usize, packed: u32) {
        if x >= self.width() || y >= self.height() {
            return;
        }

        let bytes_per_pixel = bytes_per_pixel(self.framebuffer.bpp);
        let offset = y * self.framebuffer.pitch as usize + x * bytes_per_pixel;
        for byte_index in 0..bytes_per_pixel {
            let Some(pointer) =
                NonNull::new(unsafe { self.framebuffer.address.add(offset + byte_index) })
            else {
                return;
            };
            unsafe { VolatilePtr::new(pointer) }.write((packed >> (byte_index * 8)) as u8);
        }
    }

    fn put_pixel(&mut self, x: usize, y: usize, color: Rgb) {
        self.write_raw_pixel(x, y, self.pack_color(color));
    }

    fn pack_color(&self, color: Rgb) -> u32 {
        (scale_channel(color.r(), self.framebuffer.red_mask_size)
            << self.framebuffer.red_mask_shift)
            | (scale_channel(color.g(), self.framebuffer.green_mask_size)
                << self.framebuffer.green_mask_shift)
            | (scale_channel(color.b(), self.framebuffer.blue_mask_size)
                << self.framebuffer.blue_mask_shift)
    }
}

impl OriginDimensions for FramebufferWriter<'_> {
    fn size(&self) -> Size {
        Size::new(
            self.framebuffer.width as u32,
            self.framebuffer.height as u32,
        )
    }
}

impl DrawTarget for FramebufferWriter<'_> {
    type Color = Rgb;
    type Error = Infallible;

    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Pixel<Self::Color>>,
    {
        for Pixel(point, color) in pixels {
            let (Ok(x), Ok(y)) = (usize::try_from(point.x), usize::try_from(point.y)) else {
                continue;
            };
            if x < self.width() && y < self.height() {
                self.put_pixel(x, y, color);
            }
        }
        Ok(())
    }

    fn fill_solid(&mut self, area: &Rectangle, color: Self::Color) -> Result<(), Self::Error> {
        let left = i64::from(area.top_left.x).max(0) as usize;
        let top = i64::from(area.top_left.y).max(0) as usize;
        let right = i64::from(area.top_left.x)
            .saturating_add(i64::from(area.size.width))
            .clamp(0, self.width() as i64) as usize;
        let bottom = i64::from(area.top_left.y)
            .saturating_add(i64::from(area.size.height))
            .clamp(0, self.height() as i64) as usize;
        let packed = self.pack_color(color);

        for y in top.min(bottom)..bottom {
            for x in left.min(right)..right {
                self.write_raw_pixel(x, y, packed);
            }
        }
        Ok(())
    }

    fn clear(&mut self, color: Self::Color) -> Result<(), Self::Error> {
        let packed = self.pack_color(color);
        for y in 0..self.height() {
            for x in 0..self.width() {
                self.write_raw_pixel(x, y, packed);
            }
        }
        Ok(())
    }
}

fn font_for_scale(scale: usize) -> &'static MonoFont<'static> {
    match scale {
        0 | 1 => &PROFONT_7_POINT,
        2 => &PROFONT_14_POINT,
        _ => &PROFONT_24_POINT,
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
