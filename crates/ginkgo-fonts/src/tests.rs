extern crate std;

use core::convert::Infallible;
use std::vec::Vec;

use embedded_graphics::{
    draw_target::DrawTarget,
    geometry::{OriginDimensions, Point, Size},
    pixelcolor::BinaryColor,
    prelude::Pixel,
};

use super::*;

const METRICS: FontMetrics = FontMetrics::new(3, -1, 1, 4);
const GLYPHS: [BitmapGlyph; 3] = [
    BitmapGlyph::new('?', 1, 1, 0, 1, 2, 0),
    BitmapGlyph::new('A', 3, 3, -1, 2, 4, 1),
    BitmapGlyph::new('V', 1, 1, 0, 1, 3, 3),
];
const BITMAP: [u8; 4] = [0x80, 0xab, 0x80, 0x80];
const KERNING: [KerningPair; 1] = [KerningPair::new('A', 'V', -1)];

fn font() -> BitmapFont<'static> {
    BitmapFont::from_parts(METRICS, &GLYPHS, &BITMAP, &KERNING, Some('?')).unwrap()
}

#[test]
fn sorted_lookup_and_fallback_return_exact_packed_slices() {
    let font = font();
    assert_eq!(font.glyph('A').unwrap().bitmap(), &[0xab, 0x80]);
    assert_eq!(font.glyph('V').unwrap().bitmap(), &[0x80]);
    assert!(font.glyph('B').is_none());
    assert_eq!(font.glyph_or_fallback('B').unwrap().glyph().character, '?');

    let unsorted = [GLYPHS[1], GLYPHS[0]];
    assert_eq!(
        BitmapFont::from_parts(METRICS, &unsorted, &BITMAP, &[], None).unwrap_err(),
        FontError::GlyphsNotSorted
    );
}

#[test]
fn packed_bits_cross_byte_boundaries_and_render_at_bearings() {
    let font = font();
    let glyph = font.glyph('A').unwrap();
    let expected = [
        [true, false, true],
        [false, true, false],
        [true, true, true],
    ];
    for y in 0..3 {
        for x in 0..3 {
            assert_eq!(glyph.bit(x, y), Some(expected[y as usize][x as usize]));
        }
    }
    assert_eq!(glyph.bit(3, 0), None);

    let mut display = TestDisplay::new();
    glyph
        .draw(&mut display, Point::new(3, 3), BinaryColor::On)
        .unwrap();
    let expected_points = [(2, 1), (4, 1), (3, 2), (2, 3), (3, 3), (4, 3)];
    for y in 0..8 {
        for x in 0..8 {
            assert_eq!(
                display.pixels[y][x],
                expected_points.contains(&(x as i32, y as i32)),
                "unexpected pixel at ({x}, {y})"
            );
        }
    }
}

#[test]
fn text_rendering_applies_sorted_kerning_pairs() {
    let font = font();
    assert_eq!(font.kerning('A', 'V'), -1);
    assert_eq!(font.kerning('V', 'A'), 0);

    let mut display = TestDisplay::new();
    let cursor = draw_text(&mut display, &font, "AV", Point::new(1, 3), BinaryColor::On).unwrap();
    assert_eq!(cursor, Point::new(7, 3));
    assert!(display.pixels[2][4]);
}

#[test]
fn borrowed_gkf_supports_lookup_and_rejects_malformed_data() {
    let bytes = gkf_fixture();
    let font = GkfFont::from_bytes(&bytes).unwrap();
    assert_eq!(font.metrics(), METRICS);
    assert_eq!(font.glyph('A').unwrap().bitmap(), &[0xab, 0x80]);
    assert_eq!(font.kerning('A', 'V'), -1);
    assert_eq!(font.fallback(), Some('?'));

    assert!(matches!(
        GkfFont::from_bytes(&bytes[..20]),
        Err(GkfError::TooShort)
    ));

    let mut bad_magic = bytes.clone();
    bad_magic[0] = b'X';
    assert!(matches!(
        GkfFont::from_bytes(&bad_magic),
        Err(GkfError::BadMagic)
    ));

    let mut bad_bitmap_range = bytes.clone();
    let a_record = GKF_HEADER_SIZE + GKF_GLYPH_RECORD_SIZE;
    bad_bitmap_range[a_record + 4..a_record + 8].copy_from_slice(&99_u32.to_le_bytes());
    assert!(matches!(
        GkfFont::from_bytes(&bad_bitmap_range),
        Err(GkfError::BitmapOutOfBounds)
    ));

    let mut unsorted = bytes.clone();
    unsorted[GKF_HEADER_SIZE..GKF_HEADER_SIZE + 4].copy_from_slice(&('Z' as u32).to_le_bytes());
    assert!(matches!(
        GkfFont::from_bytes(&unsorted),
        Err(GkfError::GlyphsNotSorted)
    ));
}

fn gkf_fixture() -> Vec<u8> {
    let glyph_offset = GKF_HEADER_SIZE as u32;
    let kerning_offset = glyph_offset + 3 * GKF_GLYPH_RECORD_SIZE as u32;
    let bitmap_offset = kerning_offset + GKF_KERNING_RECORD_SIZE as u32;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&GKF_MAGIC);
    push_u16(&mut bytes, GKF_VERSION);
    push_u16(&mut bytes, GKF_HEADER_SIZE as u16);
    push_u32(&mut bytes, 0);
    push_i16(&mut bytes, METRICS.ascent);
    push_i16(&mut bytes, METRICS.descent);
    push_i16(&mut bytes, METRICS.line_gap);
    push_u16(&mut bytes, METRICS.units_per_em);
    push_u32(&mut bytes, 3);
    push_u32(&mut bytes, 1);
    push_u32(&mut bytes, '?' as u32);
    push_u32(&mut bytes, glyph_offset);
    push_u32(&mut bytes, kerning_offset);
    push_u32(&mut bytes, bitmap_offset);
    push_u32(&mut bytes, BITMAP.len() as u32);

    for glyph in GLYPHS {
        push_u32(&mut bytes, glyph.character as u32);
        push_u32(&mut bytes, glyph.bitmap_offset);
        push_u16(&mut bytes, glyph.width);
        push_u16(&mut bytes, glyph.height);
        push_i16(&mut bytes, glyph.bearing_x);
        push_i16(&mut bytes, glyph.bearing_y);
        push_i16(&mut bytes, glyph.advance);
        push_u16(&mut bytes, 0);
        push_u32(&mut bytes, glyph.packed_len().unwrap() as u32);
    }

    push_u32(&mut bytes, 'A' as u32);
    push_u32(&mut bytes, 'V' as u32);
    push_i16(&mut bytes, -1);
    push_u16(&mut bytes, 0);
    bytes.extend_from_slice(&BITMAP);
    bytes
}

fn push_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_i16(bytes: &mut Vec<u8>, value: i16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

struct TestDisplay {
    pixels: [[bool; 8]; 8],
}

impl TestDisplay {
    const fn new() -> Self {
        Self {
            pixels: [[false; 8]; 8],
        }
    }
}

impl OriginDimensions for TestDisplay {
    fn size(&self) -> Size {
        Size::new(8, 8)
    }
}

impl DrawTarget for TestDisplay {
    type Color = BinaryColor;
    type Error = Infallible;

    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Pixel<Self::Color>>,
    {
        for Pixel(point, color) in pixels {
            if (0..8).contains(&point.x) && (0..8).contains(&point.y) {
                self.pixels[point.y as usize][point.x as usize] = color == BinaryColor::On;
            }
        }
        Ok(())
    }
}
