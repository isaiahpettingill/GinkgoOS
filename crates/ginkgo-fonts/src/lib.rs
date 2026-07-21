#![no_std]

//! Allocation-free packed bitmap fonts.
//!
//! Glyphs are stored as tightly packed, row-major, 1-bit pixels. The first
//! pixel is bit 7 of the first byte; rows are not byte-aligned. Rendering uses
//! [`embedded_graphics::draw_target::DrawTarget`], so it works directly with
//! `ginkgo_graphics::PixelSurface`, `ginkgo_graphics::FramebufferWriter`, and
//! other embedded-graphics targets.

mod gkf;

use core::cmp::Ordering;

use embedded_graphics::{
    draw_target::DrawTarget, geometry::Point, pixelcolor::PixelColor, prelude::Pixel,
};

pub use embedded_graphics;
pub use gkf::{
    GkfError, GkfFont, GKF_GLYPH_RECORD_SIZE, GKF_HEADER_SIZE, GKF_KERNING_RECORD_SIZE, GKF_MAGIC,
    GKF_NO_FALLBACK, GKF_VERSION,
};

/// Global vertical measurements in pixels.
///
/// `ascent` is non-negative, `descent` is non-positive, and `line_gap` is
/// non-negative. Glyph `bearing_y` is measured upward from the baseline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FontMetrics {
    pub ascent: i16,
    pub descent: i16,
    pub line_gap: i16,
    pub units_per_em: u16,
}

impl FontMetrics {
    pub const fn new(ascent: i16, descent: i16, line_gap: i16, units_per_em: u16) -> Self {
        Self {
            ascent,
            descent,
            line_gap,
            units_per_em,
        }
    }

    /// Baseline-to-baseline distance in pixels.
    pub const fn line_height(self) -> i32 {
        self.ascent as i32 - self.descent as i32 + self.line_gap as i32
    }

    pub const fn is_valid(self) -> bool {
        self.ascent >= 0 && self.descent <= 0 && self.line_gap >= 0 && self.units_per_em != 0
    }
}

/// Metadata for one glyph in a shared packed bitmap byte slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BitmapGlyph {
    pub character: char,
    pub width: u16,
    pub height: u16,
    pub bearing_x: i16,
    pub bearing_y: i16,
    pub advance: i16,
    pub bitmap_offset: u32,
}

impl BitmapGlyph {
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        character: char,
        width: u16,
        height: u16,
        bearing_x: i16,
        bearing_y: i16,
        advance: i16,
        bitmap_offset: u32,
    ) -> Self {
        Self {
            character,
            width,
            height,
            bearing_x,
            bearing_y,
            advance,
            bitmap_offset,
        }
    }

    /// Number of bytes occupied by this tightly packed glyph.
    pub fn packed_len(self) -> Option<usize> {
        packed_bitmap_len(self.width, self.height)
    }
}

/// A sorted kerning adjustment between two Unicode scalar values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KerningPair {
    pub left: char,
    pub right: char,
    pub adjustment: i16,
}

impl KerningPair {
    pub const fn new(left: char, right: char, adjustment: i16) -> Self {
        Self {
            left,
            right,
            adjustment,
        }
    }
}

/// Validation failures for an in-memory [`BitmapFont`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FontError {
    InvalidMetrics,
    InvalidGlyph,
    GlyphsNotSorted,
    BitmapOutOfBounds,
    KerningNotSorted,
    UnknownKerningGlyph,
    MissingFallbackGlyph,
}

/// A validated, allocation-free font assembled from conversion-friendly parts.
#[derive(Clone, Copy, Debug)]
pub struct BitmapFont<'a> {
    metrics: FontMetrics,
    glyphs: &'a [BitmapGlyph],
    bitmap: &'a [u8],
    kerning: &'a [KerningPair],
    fallback: Option<char>,
}

impl<'a> BitmapFont<'a> {
    /// Validates borrowed converter output and constructs a font face.
    pub fn from_parts(
        metrics: FontMetrics,
        glyphs: &'a [BitmapGlyph],
        bitmap: &'a [u8],
        kerning: &'a [KerningPair],
        fallback: Option<char>,
    ) -> Result<Self, FontError> {
        if !metrics.is_valid() {
            return Err(FontError::InvalidMetrics);
        }

        let mut previous = None;
        for glyph in glyphs {
            if glyph.advance < 0 || glyph.packed_len().is_none() {
                return Err(FontError::InvalidGlyph);
            }
            if previous.is_some_and(|character| character >= glyph.character) {
                return Err(FontError::GlyphsNotSorted);
            }
            previous = Some(glyph.character);

            let start =
                usize::try_from(glyph.bitmap_offset).map_err(|_| FontError::BitmapOutOfBounds)?;
            let end = start
                .checked_add(glyph.packed_len().ok_or(FontError::InvalidGlyph)?)
                .ok_or(FontError::BitmapOutOfBounds)?;
            if end > bitmap.len() {
                return Err(FontError::BitmapOutOfBounds);
            }
        }

        let mut previous_pair = None;
        for pair in kerning {
            let key = (pair.left, pair.right);
            if previous_pair.is_some_and(|previous| previous >= key) {
                return Err(FontError::KerningNotSorted);
            }
            if find_glyph(glyphs, pair.left).is_none() || find_glyph(glyphs, pair.right).is_none() {
                return Err(FontError::UnknownKerningGlyph);
            }
            previous_pair = Some(key);
        }

        if fallback.is_some_and(|character| find_glyph(glyphs, character).is_none()) {
            return Err(FontError::MissingFallbackGlyph);
        }

        Ok(Self {
            metrics,
            glyphs,
            bitmap,
            kerning,
            fallback,
        })
    }

    pub const fn glyphs(&self) -> &'a [BitmapGlyph] {
        self.glyphs
    }

    pub const fn bitmap(&self) -> &'a [u8] {
        self.bitmap
    }

    pub const fn kerning_pairs(&self) -> &'a [KerningPair] {
        self.kerning
    }
}

/// Common access to in-memory and borrowed wire-format font faces.
pub trait FontFace {
    fn metrics(&self) -> FontMetrics;
    fn glyph(&self, character: char) -> Option<GlyphRef<'_>>;
    fn kerning(&self, left: char, right: char) -> i16;
    fn fallback(&self) -> Option<char>;

    fn glyph_or_fallback(&self, character: char) -> Option<GlyphRef<'_>> {
        self.glyph(character)
            .or_else(|| self.fallback().and_then(|fallback| self.glyph(fallback)))
    }
}

impl FontFace for BitmapFont<'_> {
    fn metrics(&self) -> FontMetrics {
        self.metrics
    }

    fn glyph(&self, character: char) -> Option<GlyphRef<'_>> {
        let glyph = *find_glyph(self.glyphs, character)?;
        let start = glyph.bitmap_offset as usize;
        let end = start + glyph.packed_len()?;
        GlyphRef::new(glyph, self.bitmap.get(start..end)?)
    }

    fn kerning(&self, left: char, right: char) -> i16 {
        self.kerning
            .binary_search_by(|pair| (pair.left, pair.right).cmp(&(left, right)))
            .map(|index| self.kerning[index].adjustment)
            .unwrap_or(0)
    }

    fn fallback(&self) -> Option<char> {
        self.fallback
    }
}

/// A glyph and its exact packed bitmap bytes.
#[derive(Clone, Copy, Debug)]
pub struct GlyphRef<'a> {
    glyph: BitmapGlyph,
    bitmap: &'a [u8],
}

impl<'a> GlyphRef<'a> {
    /// Constructs a glyph reference when `bitmap` has exactly the packed size.
    pub fn new(glyph: BitmapGlyph, bitmap: &'a [u8]) -> Option<Self> {
        (glyph.packed_len()? == bitmap.len()).then_some(Self { glyph, bitmap })
    }

    pub const fn glyph(self) -> BitmapGlyph {
        self.glyph
    }

    pub const fn bitmap(self) -> &'a [u8] {
        self.bitmap
    }

    /// Reads one glyph-local pixel, or returns `None` for an invalid position.
    pub fn bit(self, x: u16, y: u16) -> Option<bool> {
        if x >= self.glyph.width || y >= self.glyph.height {
            return None;
        }
        let index = usize::from(y)
            .checked_mul(usize::from(self.glyph.width))?
            .checked_add(usize::from(x))?;
        let byte = *self.bitmap.get(index / 8)?;
        Some(byte & (0x80 >> (index % 8)) != 0)
    }

    /// Iterates set pixels positioned relative to a baseline origin.
    pub fn pixels<C: PixelColor>(self, baseline: Point, color: C) -> GlyphPixels<'a, C> {
        GlyphPixels {
            glyph: self,
            baseline,
            color,
            next: 0,
            total: u32::from(self.glyph.width) * u32::from(self.glyph.height),
        }
    }

    /// Draws set bits, leaving zero bits transparent.
    pub fn draw<D>(self, target: &mut D, baseline: Point, color: D::Color) -> Result<(), D::Error>
    where
        D: DrawTarget,
    {
        target.draw_iter(self.pixels(baseline, color))
    }
}

/// Iterator over the visible pixels of a [`GlyphRef`].
pub struct GlyphPixels<'a, C> {
    glyph: GlyphRef<'a>,
    baseline: Point,
    color: C,
    next: u32,
    total: u32,
}

impl<C: PixelColor> Iterator for GlyphPixels<'_, C> {
    type Item = Pixel<C>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.next < self.total {
            let index = self.next;
            self.next += 1;
            let width = u32::from(self.glyph.glyph.width);
            let x = (index % width) as u16;
            let y = (index / width) as u16;
            if self.glyph.bit(x, y) != Some(true) {
                continue;
            }

            let absolute_x =
                i64::from(self.baseline.x) + i64::from(self.glyph.glyph.bearing_x) + i64::from(x);
            let absolute_y =
                i64::from(self.baseline.y) - i64::from(self.glyph.glyph.bearing_y) + i64::from(y);
            let (Ok(absolute_x), Ok(absolute_y)) =
                (i32::try_from(absolute_x), i32::try_from(absolute_y))
            else {
                continue;
            };
            return Some(Pixel(Point::new(absolute_x, absolute_y), self.color));
        }
        None
    }
}

/// Draws a single-line string and returns its final baseline cursor.
///
/// Missing characters use the face fallback when configured. Characters with
/// no glyph and no fallback are skipped without changing the cursor.
pub fn draw_text<D, F>(
    target: &mut D,
    face: &F,
    text: &str,
    baseline: Point,
    color: D::Color,
) -> Result<Point, D::Error>
where
    D: DrawTarget,
    F: FontFace + ?Sized,
{
    let mut cursor = baseline;
    let mut previous = None;

    for character in text.chars() {
        let Some(glyph) = face.glyph_or_fallback(character) else {
            previous = None;
            continue;
        };
        let glyph_character = glyph.glyph().character;
        if let Some(left) = previous {
            cursor.x = cursor
                .x
                .saturating_add(i32::from(face.kerning(left, glyph_character)));
        }
        glyph.draw(target, cursor, color)?;
        cursor.x = cursor.x.saturating_add(i32::from(glyph.glyph().advance));
        previous = Some(glyph_character);
    }

    Ok(cursor)
}

pub(crate) fn packed_bitmap_len(width: u16, height: u16) -> Option<usize> {
    usize::from(width)
        .checked_mul(usize::from(height))?
        .checked_add(7)
        .map(|bits| bits / 8)
}

fn find_glyph(glyphs: &[BitmapGlyph], character: char) -> Option<&BitmapGlyph> {
    glyphs
        .binary_search_by_key(&character, |glyph| glyph.character)
        .ok()
        .map(|index| &glyphs[index])
}

pub(crate) fn compare_pair(
    left: char,
    right: char,
    other_left: char,
    other_right: char,
) -> Ordering {
    (left, right).cmp(&(other_left, other_right))
}

#[cfg(test)]
mod tests;
