use core::cmp::Ordering;

use crate::{compare_pair, packed_bitmap_len, BitmapGlyph, FontFace, FontMetrics, GlyphRef};

/// Four-byte signature at the start of every `.gkf` file.
pub const GKF_MAGIC: [u8; 4] = *b"GKF\0";
pub const GKF_VERSION: u16 = 1;
pub const GKF_HEADER_SIZE: usize = 48;
pub const GKF_GLYPH_RECORD_SIZE: usize = 24;
pub const GKF_KERNING_RECORD_SIZE: usize = 12;
pub const GKF_NO_FALLBACK: u32 = u32::MAX;

/// Validation errors for the borrowed `.gkf` format.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GkfError {
    TooShort,
    BadMagic,
    UnsupportedVersion(u16),
    InvalidHeaderSize(u16),
    UnsupportedFlags(u32),
    InvalidLayout,
    InvalidMetrics,
    InvalidCodepoint,
    InvalidGlyph,
    GlyphsNotSorted,
    BitmapOutOfBounds,
    KerningNotSorted,
    UnknownKerningGlyph,
    MissingFallbackGlyph,
}

/// A validated font borrowing a version 1 `.gkf` byte slice.
///
/// Version 1 is little-endian and canonical. Its header fields are, in order:
/// magic `[u8; 4]`; version and header size `u16`; flags `u32`; ascent,
/// descent, and line gap `i16`; units per em `u16`; glyph count, kerning count,
/// fallback scalar, glyph offset, kerning offset, bitmap offset, and bitmap
/// length `u32`. [`GKF_NO_FALLBACK`] means no fallback.
///
/// The header is immediately followed by sorted glyph records, sorted kerning
/// records, and packed bitmap bytes. A glyph record contains scalar and bitmap
/// offset `u32`; width and height `u16`; x/y bearings and advance `i16`;
/// reserved `u16`; and packed length `u32`. A kerning record contains left and
/// right scalars `u32`, adjustment `i16`, and reserved `u16`. Reserved fields
/// and header flags must be zero.
#[derive(Clone, Copy, Debug)]
pub struct GkfFont<'a> {
    metrics: FontMetrics,
    glyph_records: &'a [u8],
    kerning_records: &'a [u8],
    bitmap: &'a [u8],
    fallback: Option<char>,
}

impl<'a> GkfFont<'a> {
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, GkfError> {
        if bytes.len() < GKF_HEADER_SIZE {
            return Err(GkfError::TooShort);
        }
        if bytes.get(0..4) != Some(GKF_MAGIC.as_slice()) {
            return Err(GkfError::BadMagic);
        }

        let version = read_u16(bytes, 4)?;
        if version != GKF_VERSION {
            return Err(GkfError::UnsupportedVersion(version));
        }
        let header_size = read_u16(bytes, 6)?;
        if usize::from(header_size) != GKF_HEADER_SIZE {
            return Err(GkfError::InvalidHeaderSize(header_size));
        }
        let flags = read_u32(bytes, 8)?;
        if flags != 0 {
            return Err(GkfError::UnsupportedFlags(flags));
        }

        let metrics = FontMetrics::new(
            read_i16(bytes, 12)?,
            read_i16(bytes, 14)?,
            read_i16(bytes, 16)?,
            read_u16(bytes, 18)?,
        );
        if !metrics.is_valid() {
            return Err(GkfError::InvalidMetrics);
        }

        let glyph_count =
            usize::try_from(read_u32(bytes, 20)?).map_err(|_| GkfError::InvalidLayout)?;
        let kerning_count =
            usize::try_from(read_u32(bytes, 24)?).map_err(|_| GkfError::InvalidLayout)?;
        let fallback_raw = read_u32(bytes, 28)?;
        let glyph_offset =
            usize::try_from(read_u32(bytes, 32)?).map_err(|_| GkfError::InvalidLayout)?;
        let kerning_offset =
            usize::try_from(read_u32(bytes, 36)?).map_err(|_| GkfError::InvalidLayout)?;
        let bitmap_offset =
            usize::try_from(read_u32(bytes, 40)?).map_err(|_| GkfError::InvalidLayout)?;
        let bitmap_len =
            usize::try_from(read_u32(bytes, 44)?).map_err(|_| GkfError::InvalidLayout)?;

        let glyph_bytes = glyph_count
            .checked_mul(GKF_GLYPH_RECORD_SIZE)
            .ok_or(GkfError::InvalidLayout)?;
        let kerning_bytes = kerning_count
            .checked_mul(GKF_KERNING_RECORD_SIZE)
            .ok_or(GkfError::InvalidLayout)?;
        let expected_kerning_offset = glyph_offset
            .checked_add(glyph_bytes)
            .ok_or(GkfError::InvalidLayout)?;
        let expected_bitmap_offset = kerning_offset
            .checked_add(kerning_bytes)
            .ok_or(GkfError::InvalidLayout)?;
        let expected_end = bitmap_offset
            .checked_add(bitmap_len)
            .ok_or(GkfError::InvalidLayout)?;
        if glyph_offset != GKF_HEADER_SIZE
            || kerning_offset != expected_kerning_offset
            || bitmap_offset != expected_bitmap_offset
            || expected_end != bytes.len()
        {
            return Err(GkfError::InvalidLayout);
        }

        let glyph_records = bytes
            .get(glyph_offset..kerning_offset)
            .ok_or(GkfError::InvalidLayout)?;
        let kerning_records = bytes
            .get(kerning_offset..bitmap_offset)
            .ok_or(GkfError::InvalidLayout)?;
        let bitmap = bytes
            .get(bitmap_offset..expected_end)
            .ok_or(GkfError::InvalidLayout)?;
        let fallback = if fallback_raw == GKF_NO_FALLBACK {
            None
        } else {
            Some(char::from_u32(fallback_raw).ok_or(GkfError::InvalidCodepoint)?)
        };

        let font = Self {
            metrics,
            glyph_records,
            kerning_records,
            bitmap,
            fallback,
        };
        font.validate()?;
        Ok(font)
    }

    pub const fn as_bitmap_bytes(&self) -> &'a [u8] {
        self.bitmap
    }

    fn validate(&self) -> Result<(), GkfError> {
        let mut previous = None;
        for index in 0..self.glyph_count() {
            let glyph = self.glyph_at(index)?;
            if previous.is_some_and(|character| character >= glyph.character) {
                return Err(GkfError::GlyphsNotSorted);
            }
            previous = Some(glyph.character);
        }

        let mut previous_pair = None;
        for index in 0..self.kerning_count() {
            let (left, right, _) = self.kerning_at(index)?;
            let key = (left, right);
            if previous_pair.is_some_and(|previous| previous >= key) {
                return Err(GkfError::KerningNotSorted);
            }
            if self.find_glyph(left).is_none() || self.find_glyph(right).is_none() {
                return Err(GkfError::UnknownKerningGlyph);
            }
            previous_pair = Some(key);
        }

        if self
            .fallback
            .is_some_and(|fallback| self.find_glyph(fallback).is_none())
        {
            return Err(GkfError::MissingFallbackGlyph);
        }
        Ok(())
    }

    fn glyph_count(&self) -> usize {
        self.glyph_records.len() / GKF_GLYPH_RECORD_SIZE
    }

    fn kerning_count(&self) -> usize {
        self.kerning_records.len() / GKF_KERNING_RECORD_SIZE
    }

    fn glyph_at(&self, index: usize) -> Result<BitmapGlyph, GkfError> {
        let offset = index
            .checked_mul(GKF_GLYPH_RECORD_SIZE)
            .ok_or(GkfError::InvalidGlyph)?;
        let record = self
            .glyph_records
            .get(offset..offset + GKF_GLYPH_RECORD_SIZE)
            .ok_or(GkfError::InvalidGlyph)?;
        let character = char::from_u32(read_u32(record, 0)?).ok_or(GkfError::InvalidCodepoint)?;
        let bitmap_offset = read_u32(record, 4)?;
        let width = read_u16(record, 8)?;
        let height = read_u16(record, 10)?;
        let bearing_x = read_i16(record, 12)?;
        let bearing_y = read_i16(record, 14)?;
        let advance = read_i16(record, 16)?;
        let reserved = read_u16(record, 18)?;
        let encoded_bitmap_len =
            usize::try_from(read_u32(record, 20)?).map_err(|_| GkfError::InvalidGlyph)?;
        let expected_bitmap_len = packed_bitmap_len(width, height).ok_or(GkfError::InvalidGlyph)?;
        if reserved != 0 || advance < 0 || encoded_bitmap_len != expected_bitmap_len {
            return Err(GkfError::InvalidGlyph);
        }
        let start = usize::try_from(bitmap_offset).map_err(|_| GkfError::BitmapOutOfBounds)?;
        let end = start
            .checked_add(expected_bitmap_len)
            .ok_or(GkfError::BitmapOutOfBounds)?;
        if end > self.bitmap.len() {
            return Err(GkfError::BitmapOutOfBounds);
        }

        Ok(BitmapGlyph::new(
            character,
            width,
            height,
            bearing_x,
            bearing_y,
            advance,
            bitmap_offset,
        ))
    }

    fn kerning_at(&self, index: usize) -> Result<(char, char, i16), GkfError> {
        let offset = index
            .checked_mul(GKF_KERNING_RECORD_SIZE)
            .ok_or(GkfError::InvalidLayout)?;
        let record = self
            .kerning_records
            .get(offset..offset + GKF_KERNING_RECORD_SIZE)
            .ok_or(GkfError::InvalidLayout)?;
        let left = char::from_u32(read_u32(record, 0)?).ok_or(GkfError::InvalidCodepoint)?;
        let right = char::from_u32(read_u32(record, 4)?).ok_or(GkfError::InvalidCodepoint)?;
        let adjustment = read_i16(record, 8)?;
        if read_u16(record, 10)? != 0 {
            return Err(GkfError::InvalidLayout);
        }
        Ok((left, right, adjustment))
    }

    fn find_glyph(&self, character: char) -> Option<BitmapGlyph> {
        let mut left = 0;
        let mut right = self.glyph_count();
        while left < right {
            let middle = left + (right - left) / 2;
            let glyph = self.glyph_at(middle).ok()?;
            match glyph.character.cmp(&character) {
                Ordering::Less => left = middle + 1,
                Ordering::Greater => right = middle,
                Ordering::Equal => return Some(glyph),
            }
        }
        None
    }
}

impl FontFace for GkfFont<'_> {
    fn metrics(&self) -> FontMetrics {
        self.metrics
    }

    fn glyph(&self, character: char) -> Option<GlyphRef<'_>> {
        let glyph = self.find_glyph(character)?;
        let start = glyph.bitmap_offset as usize;
        let end = start.checked_add(glyph.packed_len()?)?;
        GlyphRef::new(glyph, self.bitmap.get(start..end)?)
    }

    fn kerning(&self, left: char, right: char) -> i16 {
        let mut low = 0;
        let mut high = self.kerning_count();
        while low < high {
            let middle = low + (high - low) / 2;
            let Ok((pair_left, pair_right, adjustment)) = self.kerning_at(middle) else {
                return 0;
            };
            match compare_pair(pair_left, pair_right, left, right) {
                Ordering::Less => low = middle + 1,
                Ordering::Greater => high = middle,
                Ordering::Equal => return adjustment,
            }
        }
        0
    }

    fn fallback(&self) -> Option<char> {
        self.fallback
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, GkfError> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or(GkfError::TooShort)?
        .try_into()
        .map_err(|_| GkfError::TooShort)?;
    Ok(u16::from_le_bytes(value))
}

fn read_i16(bytes: &[u8], offset: usize) -> Result<i16, GkfError> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or(GkfError::TooShort)?
        .try_into()
        .map_err(|_| GkfError::TooShort)?;
    Ok(i16::from_le_bytes(value))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, GkfError> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or(GkfError::TooShort)?
        .try_into()
        .map_err(|_| GkfError::TooShort)?;
    Ok(u32::from_le_bytes(value))
}
