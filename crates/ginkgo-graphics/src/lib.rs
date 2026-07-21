#![no_std]

//! Framebuffer drawing primitives shared by the kernel and future userspace.

use core::{convert::Infallible, marker::PhantomData, ptr::NonNull};

use embedded_graphics::{
    draw_target::DrawTarget,
    geometry::{OriginDimensions, Point, Size},
    mono_font::{MonoFont, MonoTextStyle},
    pixelcolor::{Rgb888, RgbColor},
    prelude::{Drawable, Pixel},
    primitives::Rectangle,
    text::{Baseline, Text},
};
use profont::{PROFONT_14_POINT, PROFONT_24_POINT, PROFONT_7_POINT};
use volatile::VolatilePtr;

pub type Rgb = Rgb888;

/// The packed 32-bit pixel format used by a [`PixelSurface`].
///
/// Both formats store pixels in little-endian byte order as blue, green, red,
/// followed by either an unused byte or alpha.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PixelFormat {
    /// `0x00RRGGBB`, stored in memory as `[B, G, R, 0]`.
    Xrgb8888,
    /// `0xAARRGGBB`, stored in memory as `[B, G, R, A]`.
    Argb8888,
}

impl PixelFormat {
    pub const fn bytes_per_pixel(self) -> usize {
        4
    }

    fn pack_rgb(self, color: Rgb) -> u32 {
        let alpha_or_unused = match self {
            Self::Xrgb8888 => 0,
            Self::Argb8888 => u8::MAX,
        };
        SurfacePixel::new(color.r(), color.g(), color.b(), alpha_or_unused).raw()
    }
}

/// Geometry and row layout for a [`PixelSurface`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SurfaceLayout {
    pub width: usize,
    pub height: usize,
    /// Number of bytes from the start of one row to the start of the next.
    pub stride: usize,
    pub format: PixelFormat,
}

impl SurfaceLayout {
    pub const fn new(width: usize, height: usize, stride: usize, format: PixelFormat) -> Self {
        Self {
            width,
            height,
            stride,
            format,
        }
    }

    /// Returns the number of bytes occupied by all rows after validating the
    /// dimensions and stride.
    pub fn required_bytes(self) -> Result<usize, SurfaceError> {
        if self.width == 0 || self.height == 0 {
            return Err(SurfaceError::ZeroDimension);
        }
        if u32::try_from(self.width).is_err() || u32::try_from(self.height).is_err() {
            return Err(SurfaceError::DimensionTooLarge);
        }

        let row_bytes = self
            .width
            .checked_mul(self.format.bytes_per_pixel())
            .ok_or(SurfaceError::LayoutOverflow)?;
        if self.stride < row_bytes {
            return Err(SurfaceError::StrideTooSmall {
                minimum: row_bytes,
                actual: self.stride,
            });
        }

        self.stride
            .checked_mul(self.height)
            .ok_or(SurfaceError::LayoutOverflow)
    }
}

/// An error returned when constructing a [`PixelSurface`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SurfaceError {
    ZeroDimension,
    DimensionTooLarge,
    StrideTooSmall { minimum: usize, actual: usize },
    LayoutOverflow,
    BufferTooSmall { required: usize, actual: usize },
}

/// A typed view of the four bytes occupied by a surface pixel.
///
/// The final byte is alpha for [`PixelFormat::Argb8888`] and unused for
/// [`PixelFormat::Xrgb8888`]. The `repr(C)` layout and byte-sized fields make
/// references returned by [`PixelSurface::pixel`] safe even for unaligned rows.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SurfacePixel {
    pub blue: u8,
    pub green: u8,
    pub red: u8,
    pub alpha_or_unused: u8,
}

impl SurfacePixel {
    pub const fn new(red: u8, green: u8, blue: u8, alpha_or_unused: u8) -> Self {
        Self {
            blue,
            green,
            red,
            alpha_or_unused,
        }
    }

    pub const fn xrgb(red: u8, green: u8, blue: u8) -> Self {
        Self::new(red, green, blue, 0)
    }

    pub const fn argb(alpha: u8, red: u8, green: u8, blue: u8) -> Self {
        Self::new(red, green, blue, alpha)
    }

    pub const fn from_raw(raw: u32) -> Self {
        Self {
            blue: raw as u8,
            green: (raw >> 8) as u8,
            red: (raw >> 16) as u8,
            alpha_or_unused: (raw >> 24) as u8,
        }
    }

    pub const fn raw(self) -> u32 {
        self.blue as u32
            | ((self.green as u32) << 8)
            | ((self.red as u32) << 16)
            | ((self.alpha_or_unused as u32) << 24)
    }
}

/// An embedded-graphics draw target over ordinary, non-volatile pixel memory.
pub struct PixelSurface<'a> {
    bytes: &'a mut [u8],
    layout: SurfaceLayout,
}

impl<'a> PixelSurface<'a> {
    /// Creates a surface after validating dimensions, stride, arithmetic, and
    /// the size of the provided backing memory.
    pub fn new(bytes: &'a mut [u8], layout: SurfaceLayout) -> Result<Self, SurfaceError> {
        let required = layout.required_bytes()?;
        if bytes.len() < required {
            return Err(SurfaceError::BufferTooSmall {
                required,
                actual: bytes.len(),
            });
        }
        Ok(Self { bytes, layout })
    }

    pub const fn layout(&self) -> SurfaceLayout {
        self.layout
    }

    pub const fn format(&self) -> PixelFormat {
        self.layout.format
    }

    pub const fn width(&self) -> usize {
        self.layout.width
    }

    pub const fn height(&self) -> usize {
        self.layout.height
    }

    pub const fn stride(&self) -> usize {
        self.layout.stride
    }

    /// Returns the entire backing slice, including row padding and any bytes
    /// beyond the minimum required by the layout.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes
    }

    /// Returns the entire mutable backing slice.
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        self.bytes
    }

    /// Consumes the surface and returns its backing slice.
    pub fn into_bytes(self) -> &'a mut [u8] {
        self.bytes
    }

    /// Returns a typed reference to a pixel, or `None` when out of bounds.
    pub fn pixel(&self, x: usize, y: usize) -> Option<&SurfacePixel> {
        let offset = self.pixel_offset(x, y)?;
        let pointer = self.bytes[offset..offset + 4]
            .as_ptr()
            .cast::<SurfacePixel>();
        // SurfacePixel consists of four u8 fields, has alignment one, and all
        // possible byte patterns are valid values.
        Some(unsafe { &*pointer })
    }

    /// Returns a typed mutable reference to a pixel, or `None` when out of
    /// bounds.
    pub fn pixel_mut(&mut self, x: usize, y: usize) -> Option<&mut SurfacePixel> {
        let offset = self.pixel_offset(x, y)?;
        let pointer = self.bytes[offset..offset + 4]
            .as_mut_ptr()
            .cast::<SurfacePixel>();
        // See pixel(): SurfacePixel is an alignment-one view of exactly these
        // four exclusively borrowed bytes.
        Some(unsafe { &mut *pointer })
    }

    pub fn read_raw_pixel(&self, x: usize, y: usize) -> Option<u32> {
        self.pixel(x, y).copied().map(SurfacePixel::raw)
    }

    pub fn write_raw_pixel(&mut self, x: usize, y: usize, packed: u32) {
        if let Some(pixel) = self.pixel_mut(x, y) {
            *pixel = SurfacePixel::from_raw(packed);
        }
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

    fn pixel_offset(&self, x: usize, y: usize) -> Option<usize> {
        if x >= self.width() || y >= self.height() {
            return None;
        }
        Some(y * self.stride() + x * self.format().bytes_per_pixel())
    }

    fn put_pixel(&mut self, x: usize, y: usize, color: Rgb) {
        self.write_raw_pixel(x, y, self.format().pack_rgb(color));
    }
}

impl OriginDimensions for PixelSurface<'_> {
    fn size(&self) -> Size {
        Size::new(self.layout.width as u32, self.layout.height as u32)
    }
}

impl DrawTarget for PixelSurface<'_> {
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
        let packed = self.format().pack_rgb(color);

        for y in top.min(bottom)..bottom {
            for x in left.min(right)..right {
                self.write_raw_pixel(x, y, packed);
            }
        }
        Ok(())
    }

    fn clear(&mut self, color: Self::Color) -> Result<(), Self::Error> {
        let packed = self.format().pack_rgb(color);
        for y in 0..self.height() {
            for x in 0..self.width() {
                self.write_raw_pixel(x, y, packed);
            }
        }
        Ok(())
    }
}

/// Raw RGB framebuffer geometry and pixel-channel layout.
#[derive(Clone, Copy, Debug)]
pub struct FramebufferConfig {
    pub address: *mut u8,
    pub width: u64,
    pub height: u64,
    pub pitch: u64,
    pub bits_per_pixel: u16,
    pub memory_model: u8,
    pub red_mask_size: u8,
    pub red_mask_shift: u8,
    pub green_mask_size: u8,
    pub green_mask_shift: u8,
    pub blue_mask_size: u8,
    pub blue_mask_shift: u8,
}

/// An embedded-graphics draw target over a packed RGB framebuffer.
pub struct FramebufferWriter<'a> {
    framebuffer: FramebufferConfig,
    marker: PhantomData<&'a mut [u8]>,
}

impl<'a> FramebufferWriter<'a> {
    /// Validates and claims a raw framebuffer.
    ///
    /// # Safety
    ///
    /// `framebuffer.address` must identify writable mapped memory covering at
    /// least `pitch * height` bytes, and that memory must remain exclusively
    /// borrowed for `'a`.
    pub unsafe fn from_raw(framebuffer: FramebufferConfig) -> Option<Self> {
        let bytes_per_pixel = bytes_per_pixel(framebuffer.bits_per_pixel);
        let width = usize::try_from(framebuffer.width).ok()?;
        let height = usize::try_from(framebuffer.height).ok()?;
        u32::try_from(width).ok()?;
        u32::try_from(height).ok()?;
        let pitch = usize::try_from(framebuffer.pitch).ok()?;
        let row_bytes = width.checked_mul(bytes_per_pixel)?;
        let mapped_bytes = pitch.checked_mul(height)?;
        let valid_channel = |size: u8, shift: u8| {
            size > 0 && u16::from(shift) + u16::from(size) <= framebuffer.bits_per_pixel
        };
        let red_mask = packed_channel_mask(framebuffer.red_mask_size, framebuffer.red_mask_shift)?;
        let green_mask =
            packed_channel_mask(framebuffer.green_mask_size, framebuffer.green_mask_shift)?;
        let blue_mask =
            packed_channel_mask(framebuffer.blue_mask_size, framebuffer.blue_mask_shift)?;
        let overlapping_channels =
            red_mask & green_mask != 0 || red_mask & blue_mask != 0 || green_mask & blue_mask != 0;

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
            || overlapping_channels
        {
            return None;
        }

        Some(Self {
            framebuffer,
            marker: PhantomData,
        })
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

        let bytes_per_pixel = bytes_per_pixel(self.framebuffer.bits_per_pixel);
        let offset = y * self.framebuffer.pitch as usize + x * bytes_per_pixel;
        let mut packed = 0_u32;
        for byte_index in 0..bytes_per_pixel {
            let pointer =
                NonNull::new(unsafe { self.framebuffer.address.add(offset + byte_index) })?;
            packed |= u32::from(unsafe { VolatilePtr::new(pointer) }.read()) << (byte_index * 8);
        }
        Some(packed)
    }

    /// Reads and expands one framebuffer pixel according to its channel masks.
    ///
    /// Hardware memory is read with volatile accesses. Channels narrower than
    /// eight bits are scaled to the full `0..=255` range.
    pub fn read_rgb_pixel(&self, x: usize, y: usize) -> Option<Rgb> {
        let packed = self.read_raw_pixel(x, y)?;
        Some(Rgb::new(
            unpack_channel(
                packed,
                self.framebuffer.red_mask_size,
                self.framebuffer.red_mask_shift,
            ),
            unpack_channel(
                packed,
                self.framebuffer.green_mask_size,
                self.framebuffer.green_mask_shift,
            ),
            unpack_channel(
                packed,
                self.framebuffer.blue_mask_size,
                self.framebuffer.blue_mask_shift,
            ),
        ))
    }

    /// Writes one RGB pixel using the framebuffer's channel masks.
    ///
    /// Returns `false` without accessing memory when the coordinate is out of
    /// bounds. A `true` result means every byte was written with a volatile
    /// access.
    pub fn write_rgb_pixel(&mut self, x: usize, y: usize, color: Rgb) -> bool {
        if x >= self.width() || y >= self.height() {
            return false;
        }
        self.write_raw_pixel(x, y, self.pack_color(color));
        true
    }

    pub fn write_raw_pixel(&mut self, x: usize, y: usize, packed: u32) {
        if x >= self.width() || y >= self.height() {
            return;
        }

        let bytes_per_pixel = bytes_per_pixel(self.framebuffer.bits_per_pixel);
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

    ((u64::from(value) * u64::from(maximum) + 127) / 255) as u32
}

fn unpack_channel(packed: u32, bits: u8, shift: u8) -> u8 {
    let maximum = if bits >= 32 {
        u32::MAX
    } else {
        (1_u32 << bits) - 1
    };
    let value = (packed >> shift) & maximum;
    ((u64::from(value) * 255 + u64::from(maximum) / 2) / u64::from(maximum)) as u8
}

fn packed_channel_mask(bits: u8, shift: u8) -> Option<u32> {
    if bits == 0 || u16::from(bits) + u16::from(shift) > 32 {
        return None;
    }
    let unshifted = if bits == 32 {
        u32::MAX
    } else {
        (1_u32 << bits) - 1
    };
    unshifted.checked_shl(u32::from(shift))
}

fn bytes_per_pixel(bits_per_pixel: u16) -> usize {
    (usize::from(bits_per_pixel) + 7) / 8
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rgb_config(address: *mut u8) -> FramebufferConfig {
        FramebufferConfig {
            address,
            width: 2,
            height: 1,
            pitch: 8,
            bits_per_pixel: 32,
            memory_model: 1,
            red_mask_size: 8,
            red_mask_shift: 16,
            green_mask_size: 8,
            green_mask_shift: 8,
            blue_mask_size: 8,
            blue_mask_shift: 0,
        }
    }

    fn surface_layout(
        width: usize,
        height: usize,
        stride: usize,
        format: PixelFormat,
    ) -> SurfaceLayout {
        SurfaceLayout::new(width, height, stride, format)
    }

    #[test]
    fn surface_honors_stride_and_exposes_raw_bytes() {
        let mut bytes = [0xAA; 24];
        let layout = surface_layout(2, 2, 12, PixelFormat::Xrgb8888);
        let mut surface = PixelSurface::new(&mut bytes, layout).expect("valid surface");

        assert_eq!(surface.layout(), layout);
        assert_eq!(surface.stride(), 12);
        surface.write_raw_pixel(1, 1, 0x0012_3456);
        assert_eq!(surface.read_raw_pixel(1, 1), Some(0x0012_3456));
        assert_eq!(&surface.as_bytes()[16..20], &[0x56, 0x34, 0x12, 0x00]);
        assert_eq!(&surface.as_bytes()[8..12], &[0xAA; 4]);
        surface.as_bytes_mut()[23] = 0x55;

        let bytes = surface.into_bytes();
        assert_eq!(bytes[23], 0x55);
    }

    #[test]
    fn surface_draws_xrgb_and_argb_in_documented_byte_order() {
        let color = Rgb::new(0x12, 0x34, 0x56);
        let mut xrgb_bytes = [0xAA; 4];
        let mut xrgb = PixelSurface::new(
            &mut xrgb_bytes,
            surface_layout(1, 1, 4, PixelFormat::Xrgb8888),
        )
        .expect("valid XRGB surface");
        xrgb.clear(color);
        assert_eq!(xrgb.read_raw_pixel(0, 0), Some(0x0012_3456));
        drop(xrgb);
        assert_eq!(xrgb_bytes, [0x56, 0x34, 0x12, 0x00]);

        let mut argb_bytes = [0; 4];
        let mut argb = PixelSurface::new(
            &mut argb_bytes,
            surface_layout(1, 1, 4, PixelFormat::Argb8888),
        )
        .expect("valid ARGB surface");
        argb.clear(color);
        assert_eq!(argb.read_raw_pixel(0, 0), Some(0xFF12_3456));
        drop(argb);
        assert_eq!(argb_bytes, [0x56, 0x34, 0x12, 0xFF]);
    }

    #[test]
    fn surface_provides_safe_typed_pixel_access() {
        let mut bytes = [0; 8];
        let mut surface =
            PixelSurface::new(&mut bytes, surface_layout(2, 1, 8, PixelFormat::Argb8888))
                .expect("valid surface");

        *surface.pixel_mut(0, 0).expect("in bounds") = SurfacePixel::argb(0x78, 0x12, 0x34, 0x56);
        assert_eq!(
            surface.pixel(0, 0),
            Some(&SurfacePixel {
                blue: 0x56,
                green: 0x34,
                red: 0x12,
                alpha_or_unused: 0x78,
            })
        );
        assert_eq!(surface.read_raw_pixel(0, 0), Some(0x7812_3456));

        surface.write_raw_pixel(1, 0, SurfacePixel::xrgb(1, 2, 3).raw());
        assert_eq!(surface.pixel(1, 0), Some(&SurfacePixel::xrgb(1, 2, 3)));
    }

    #[test]
    fn surface_pixel_operations_clip_to_bounds() {
        let mut bytes = [0; 16];
        let mut surface =
            PixelSurface::new(&mut bytes, surface_layout(2, 2, 8, PixelFormat::Xrgb8888))
                .expect("valid surface");

        surface
            .draw_iter([
                Pixel(Point::new(-1, 0), Rgb::new(1, 2, 3)),
                Pixel(Point::new(0, -1), Rgb::new(4, 5, 6)),
                Pixel(Point::new(2, 0), Rgb::new(7, 8, 9)),
                Pixel(Point::new(0, 2), Rgb::new(10, 11, 12)),
                Pixel(Point::new(1, 1), Rgb::new(0x12, 0x34, 0x56)),
            ])
            .unwrap();
        surface.write_raw_pixel(usize::MAX, usize::MAX, u32::MAX);

        assert_eq!(surface.read_raw_pixel(0, 0), Some(0));
        assert_eq!(surface.read_raw_pixel(1, 1), Some(0x0012_3456));
        assert_eq!(surface.read_raw_pixel(2, 0), None);
        assert_eq!(surface.read_raw_pixel(0, 2), None);
        assert!(surface.pixel(usize::MAX, 0).is_none());
        assert!(surface.pixel_mut(0, usize::MAX).is_none());
    }

    #[test]
    fn surface_fill_solid_clips_and_preserves_row_padding() {
        let mut bytes = [0xAA; 24];
        let mut surface =
            PixelSurface::new(&mut bytes, surface_layout(2, 2, 12, PixelFormat::Xrgb8888))
                .expect("valid surface");

        surface
            .fill_solid(
                &Rectangle::new(Point::new(-1, -1), Size::new(2, 2)),
                Rgb::new(1, 2, 3),
            )
            .unwrap();
        surface
            .fill_solid(
                &Rectangle::new(Point::new(1, 1), Size::new(10, 10)),
                Rgb::new(4, 5, 6),
            )
            .unwrap();

        assert_eq!(surface.read_raw_pixel(0, 0), Some(0x0001_0203));
        assert_eq!(surface.read_raw_pixel(1, 0), Some(0xAAAA_AAAA));
        assert_eq!(surface.read_raw_pixel(0, 1), Some(0xAAAA_AAAA));
        assert_eq!(surface.read_raw_pixel(1, 1), Some(0x0004_0506));
        assert_eq!(&surface.as_bytes()[8..12], &[0xAA; 4]);
        assert_eq!(&surface.as_bytes()[20..24], &[0xAA; 4]);
    }

    #[test]
    fn rejects_malformed_surface_layouts() {
        let mut bytes = [0; 16];

        assert_eq!(
            PixelSurface::new(&mut bytes, surface_layout(0, 1, 4, PixelFormat::Xrgb8888)).err(),
            Some(SurfaceError::ZeroDimension)
        );
        assert_eq!(
            PixelSurface::new(&mut bytes, surface_layout(1, 0, 4, PixelFormat::Xrgb8888)).err(),
            Some(SurfaceError::ZeroDimension)
        );
        assert_eq!(
            PixelSurface::new(&mut bytes, surface_layout(2, 1, 7, PixelFormat::Argb8888)).err(),
            Some(SurfaceError::StrideTooSmall {
                minimum: 8,
                actual: 7,
            })
        );
        assert_eq!(
            PixelSurface::new(
                &mut bytes,
                surface_layout(1, 2, usize::MAX, PixelFormat::Xrgb8888)
            )
            .err(),
            Some(SurfaceError::LayoutOverflow)
        );
        assert_eq!(
            PixelSurface::new(
                &mut bytes[..15],
                surface_layout(2, 2, 8, PixelFormat::Xrgb8888)
            )
            .err(),
            Some(SurfaceError::BufferTooSmall {
                required: 16,
                actual: 15,
            })
        );
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn rejects_surface_dimensions_larger_than_embedded_graphics_supports() {
        let mut bytes = [];
        let layout = surface_layout(u32::MAX as usize + 1, 1, usize::MAX, PixelFormat::Xrgb8888);
        assert_eq!(
            PixelSurface::new(&mut bytes, layout).err(),
            Some(SurfaceError::DimensionTooLarge)
        );
    }

    #[test]
    fn packs_rgb_channels_and_writes_framebuffer_memory() {
        let mut bytes = [0_u8; 8];
        let mut writer = unsafe { FramebufferWriter::from_raw(rgb_config(bytes.as_mut_ptr())) }
            .expect("valid framebuffer");

        writer.fill_rect(0, 0, 1, 1, Rgb::new(0x12, 0x34, 0x56));
        assert_eq!(writer.read_raw_pixel(0, 0), Some(0x0012_3456));
        drop(writer);
        assert_eq!(&bytes[..4], &[0x56, 0x34, 0x12, 0x00]);
    }

    #[test]
    fn rgb_helpers_honor_arbitrary_channel_masks() {
        let mut bytes = [0_u8; 8];
        let mut config = rgb_config(bytes.as_mut_ptr());
        config.red_mask_shift = 0;
        config.green_mask_shift = 10;
        config.blue_mask_shift = 20;
        config.red_mask_size = 10;
        config.green_mask_size = 10;
        config.blue_mask_size = 10;
        let mut writer = unsafe { FramebufferWriter::from_raw(config) }.expect("valid framebuffer");

        assert!(writer.write_rgb_pixel(0, 0, Rgb::new(0x12, 0x80, 0xEF)));
        assert!(!writer.write_rgb_pixel(2, 0, Rgb::new(1, 2, 3)));
        let color = writer.read_rgb_pixel(0, 0).expect("written pixel");
        assert!((i16::from(color.r()) - 0x12).abs() <= 1);
        assert!((i16::from(color.g()) - 0x80).abs() <= 1);
        assert!((i16::from(color.b()) - 0xEF).abs() <= 1);
        assert_eq!(writer.read_rgb_pixel(2, 0), None);
    }

    #[test]
    fn rejects_invalid_framebuffer_layouts() {
        let mut bytes = [0_u8; 8];
        let mut config = rgb_config(bytes.as_mut_ptr());
        config.memory_model = 0;
        assert!(unsafe { FramebufferWriter::from_raw(config) }.is_none());

        config = rgb_config(core::ptr::null_mut());
        assert!(unsafe { FramebufferWriter::from_raw(config) }.is_none());

        config = rgb_config(bytes.as_mut_ptr());
        config.pitch = 4;
        assert!(unsafe { FramebufferWriter::from_raw(config) }.is_none());

        config = rgb_config(bytes.as_mut_ptr());
        config.green_mask_shift = config.red_mask_shift;
        assert!(unsafe { FramebufferWriter::from_raw(config) }.is_none());
    }

    #[test]
    fn scales_wide_color_channels_without_overflow() {
        assert_eq!(scale_channel(255, 30), (1_u32 << 30) - 1);
        assert_eq!(scale_channel(255, 32), u32::MAX);
    }
}
