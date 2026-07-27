extern crate alloc;

use alloc::{collections::BTreeSet, vec::Vec};

use libyaff::{GlyphDefinition, Label, YaffFont};

use crate::{BitmapGlyph, FontMetrics, KerningPair};

/// An owned, normalized font suitable for embedding as a [`BitmapFont`].
#[derive(Clone, Debug, PartialEq)]
pub struct NormalizedFont {
    pub metrics: FontMetrics,
    pub glyphs: Vec<BitmapGlyph>,
    pub bitmap: Vec<u8>,
    pub kerning: Vec<KerningPair>,
    pub fallback: Option<char>,
}

impl NormalizedFont {
    pub fn as_font(&self) -> Result<crate::BitmapFont<'_>, crate::FontError> {
        crate::BitmapFont::from_parts(
            self.metrics,
            &self.glyphs,
            &self.bitmap,
            &self.kerning,
            self.fallback,
        )
    }
}

/// Errors raised while converting YAFF data into Ginkgo's packed font model.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum YaffError {
    MissingMetrics,
    InvalidMetrics,
    NoUnicodeGlyphs,
    DuplicateGlyph,
    InvalidBitmap,
    BitmapTooLarge,
    InvalidBearing,
    InvalidAdvance,
    InvalidKerning,
    TooManyGlyphs,
}

/// Normalize a parsed YAFF font into Ginkgo's sorted, packed representation.
///
/// Only single-scalar Unicode labels become glyphs. Legacy codepoint and tag
/// labels remain available to host tooling but are not silently assigned a
/// Unicode meaning. Glyphs without ink are retained when they have a valid
/// advance, which preserves space and other blank glyphs.
pub fn normalize_yaff(font: &YaffFont) -> Result<NormalizedFont, YaffError> {
    let ascent = font.ascent.ok_or(YaffError::MissingMetrics)?;
    let descent = font.descent.unwrap_or(0);
    let line_height = font.line_height.unwrap_or(ascent - descent);
    let line_gap = line_height
        .checked_sub(ascent - descent)
        .ok_or(YaffError::InvalidMetrics)?;
    let units_per_em = font
        .pixel_size
        .or(font.ascent.map(|value| value.saturating_sub(descent)))
        .unwrap_or(0);
    if ascent < 0 || descent > 0 || line_gap < 0 || units_per_em <= 0 {
        return Err(YaffError::InvalidMetrics);
    }

    let metrics = FontMetrics::new(
        i16::try_from(ascent).map_err(|_| YaffError::InvalidMetrics)?,
        i16::try_from(descent).map_err(|_| YaffError::InvalidMetrics)?,
        i16::try_from(line_gap).map_err(|_| YaffError::InvalidMetrics)?,
        u16::try_from(units_per_em).map_err(|_| YaffError::InvalidMetrics)?,
    );

    let mut glyphs = Vec::new();
    let mut bitmap = Vec::new();
    let mut seen = BTreeSet::new();
    let mut sources: Vec<(char, &GlyphDefinition)> = Vec::new();

    for glyph in &font.glyphs {
        let Some(character) = single_unicode_label(glyph) else {
            continue;
        };
        if !seen.insert(character) {
            return Err(YaffError::DuplicateGlyph);
        }
        if glyph.bitmap.height != glyph.bitmap.pixels.len()
            || glyph.bitmap.width > usize::from(u16::MAX)
            || glyph.bitmap.height > usize::from(u16::MAX)
            || glyph
                .bitmap
                .width
                .checked_mul(glyph.bitmap.height)
                .is_none()
        {
            return Err(YaffError::InvalidBitmap);
        }
        if glyph
            .bitmap
            .pixels
            .iter()
            .any(|row| row.len() != glyph.bitmap.width)
        {
            return Err(YaffError::InvalidBitmap);
        }
        let advance = glyph
            .scalable_width
            .or_else(|| {
                Some(
                    glyph.bitmap.width as f32
                        + glyph.left_bearing.unwrap_or(0) as f32
                        + glyph.right_bearing.unwrap_or(0) as f32,
                )
            })
            .ok_or(YaffError::InvalidAdvance)?;
        if !advance.is_finite() || !(0.0..=i16::MAX as f32).contains(&advance) {
            return Err(YaffError::InvalidAdvance);
        }
        sources.push((character, glyph));
    }

    if sources.is_empty() {
        return Err(YaffError::NoUnicodeGlyphs);
    }
    sources.sort_unstable_by_key(|(character, _)| *character);
    if sources.len() > u32::MAX as usize {
        return Err(YaffError::TooManyGlyphs);
    }

    for (character, glyph) in &sources {
        let offset = u32::try_from(bitmap.len()).map_err(|_| YaffError::BitmapTooLarge)?;
        append_packed_bitmap(&mut bitmap, glyph)?;
        let bearing_x = glyph.left_bearing.unwrap_or(0);
        let bearing_y = glyph
            .shift_up
            .unwrap_or_else(|| ascent.saturating_sub(glyph.bitmap.height as i32));
        if !(i16::MIN as i32..=i16::MAX as i32).contains(&bearing_x)
            || !(i16::MIN as i32..=i16::MAX as i32).contains(&bearing_y)
        {
            return Err(YaffError::InvalidBearing);
        }
        let advance = round_float(glyph.scalable_width.unwrap_or(
            glyph.bitmap.width as f32
                + glyph.left_bearing.unwrap_or(0) as f32
                + glyph.right_bearing.unwrap_or(0) as f32,
        )) as i16;
        glyphs.push(BitmapGlyph::new(
            *character,
            u16::try_from(glyph.bitmap.width).map_err(|_| YaffError::InvalidBitmap)?,
            u16::try_from(glyph.bitmap.height).map_err(|_| YaffError::InvalidBitmap)?,
            bearing_x as i16,
            bearing_y as i16,
            advance,
            offset,
        ));
    }

    let mut kerning = Vec::new();
    for (left, glyph) in &sources {
        if let Some(pairs) = &glyph.right_kerning {
            for (label, value) in pairs {
                let Some(right) = single_unicode_label_value(label) else {
                    continue;
                };
                if !value.is_finite() || !(i16::MIN as f32..=i16::MAX as f32).contains(value) {
                    return Err(YaffError::InvalidKerning);
                }
                kerning.push(KerningPair::new(*left, right, round_float(*value) as i16));
            }
        }
    }
    kerning.sort_unstable_by_key(|pair| (pair.left, pair.right));
    kerning.dedup_by_key(|pair| (pair.left, pair.right));

    let fallback = if seen.contains(&'?') { Some('?') } else { None };
    Ok(NormalizedFont {
        metrics,
        glyphs,
        bitmap,
        kerning,
        fallback,
    })
}

fn single_unicode_label(glyph: &GlyphDefinition) -> Option<char> {
    glyph.labels.iter().find_map(single_unicode_label_value)
}

fn single_unicode_label_value(label: &Label) -> Option<char> {
    match label {
        Label::Unicode(values) if values.len() == 1 => char::from_u32(values[0]),
        _ => None,
    }
}

fn round_float(value: f32) -> f32 {
    if value >= 0.0 {
        (value + 0.5) as i32 as f32
    } else {
        (value - 0.5) as i32 as f32
    }
}

fn append_packed_bitmap(bitmap: &mut Vec<u8>, glyph: &GlyphDefinition) -> Result<(), YaffError> {
    let pixels = glyph
        .bitmap
        .width
        .checked_mul(glyph.bitmap.height)
        .ok_or(YaffError::BitmapTooLarge)?;
    let bytes = pixels.checked_add(7).ok_or(YaffError::BitmapTooLarge)? / 8;
    bitmap
        .try_reserve(bytes)
        .map_err(|_| YaffError::BitmapTooLarge)?;
    let mut current = 0u8;
    for (index, pixel) in glyph.bitmap.pixels.iter().flatten().enumerate() {
        if *pixel {
            current |= 0x80 >> (index % 8);
        }
        if index % 8 == 7 {
            bitmap.push(current);
            current = 0;
        }
    }
    if pixels % 8 != 0 {
        bitmap.push(current);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use super::*;

    #[test]
    fn normalizes_unicode_glyphs_into_sorted_packed_data() {
        let source = "ascent: 3\ndescent: -1\npixel-size: 4\n\n'?':\n  @\n\n'A':\n  .@\n  @@\n  right-kerning:\n    '?' -1\n";
        let yaff = YaffFont::from_str(source).unwrap();
        let normalized = normalize_yaff(&yaff).unwrap();

        assert_eq!(normalized.metrics, FontMetrics::new(3, -1, 0, 4));
        assert_eq!(normalized.glyphs[0].character, '?');
        assert_eq!(normalized.glyphs[1].character, 'A');
        assert_eq!(normalized.bitmap, [0x80, 0x70]);
        assert_eq!(normalized.kerning, [KerningPair::new('A', '?', -1)]);
        assert_eq!(normalized.fallback, Some('?'));
        assert!(normalized.as_font().is_ok());
    }

    #[test]
    fn rejects_duplicate_unicode_scalars() {
        let source = "ascent: 1\ndescent: 0\npixel-size: 1\n\n'A':\n  @\n\nu+0041:\n  @\n";
        let yaff = YaffFont::from_str(source).unwrap();
        assert_eq!(normalize_yaff(&yaff), Err(YaffError::DuplicateGlyph));
    }
}
