use std::{env, error::Error, fs, path::Path};

use ginkgo_fonts::{
    normalize_yaff, NormalizedFont, GKF_GLYPH_RECORD_SIZE, GKF_HEADER_SIZE,
    GKF_KERNING_RECORD_SIZE, GKF_MAGIC, GKF_NO_FALLBACK, GKF_VERSION,
};
use libyaff::YaffFont;

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = env::args_os().skip(1);
    let input = args.next().ok_or("usage: yaff2gkf INPUT.yaff OUTPUT.gkf")?;
    let output = args.next().ok_or("usage: yaff2gkf INPUT.yaff OUTPUT.gkf")?;
    if args.next().is_some() {
        return Err("usage: yaff2gkf INPUT.yaff OUTPUT.gkf".into());
    }

    let input_path = Path::new(&input);
    let output_path = Path::new(&output);
    let source = fs::read_to_string(input_path)?;
    let yaff = source.parse::<YaffFont>()?;
    let normalized =
        normalize_yaff(&yaff).map_err(|error| format!("cannot normalize YAFF: {error:?}"))?;
    let bytes = encode_gkf(&normalized)?;
    let temporary = output_path.with_extension("gkf.tmp");
    fs::write(&temporary, bytes)?;
    fs::rename(&temporary, output_path)?;
    Ok(())
}

fn encode_gkf(font: &NormalizedFont) -> Result<Vec<u8>, Box<dyn Error>> {
    let glyph_offset = GKF_HEADER_SIZE;
    let kerning_offset = glyph_offset
        .checked_add(
            font.glyphs
                .len()
                .checked_mul(GKF_GLYPH_RECORD_SIZE)
                .ok_or("glyph table too large")?,
        )
        .ok_or("glyph table too large")?;
    let bitmap_offset = kerning_offset
        .checked_add(
            font.kerning
                .len()
                .checked_mul(GKF_KERNING_RECORD_SIZE)
                .ok_or("kerning table too large")?,
        )
        .ok_or("kerning table too large")?;
    let mut bytes = Vec::with_capacity(bitmap_offset + font.bitmap.len());

    bytes.extend_from_slice(&GKF_MAGIC);
    push_u16(&mut bytes, GKF_VERSION);
    push_u16(&mut bytes, GKF_HEADER_SIZE as u16);
    push_u32(&mut bytes, 0);
    push_i16(&mut bytes, font.metrics.ascent);
    push_i16(&mut bytes, font.metrics.descent);
    push_i16(&mut bytes, font.metrics.line_gap);
    push_u16(&mut bytes, font.metrics.units_per_em);
    push_u32(&mut bytes, u32::try_from(font.glyphs.len())?);
    push_u32(&mut bytes, u32::try_from(font.kerning.len())?);
    push_u32(
        &mut bytes,
        font.fallback.map_or(GKF_NO_FALLBACK, |c| c as u32),
    );
    push_u32(&mut bytes, u32::try_from(glyph_offset)?);
    push_u32(&mut bytes, u32::try_from(kerning_offset)?);
    push_u32(&mut bytes, u32::try_from(bitmap_offset)?);
    push_u32(&mut bytes, u32::try_from(font.bitmap.len())?);

    for glyph in &font.glyphs {
        push_u32(&mut bytes, glyph.character as u32);
        push_u32(&mut bytes, glyph.bitmap_offset);
        push_u16(&mut bytes, glyph.width);
        push_u16(&mut bytes, glyph.height);
        push_i16(&mut bytes, glyph.bearing_x);
        push_i16(&mut bytes, glyph.bearing_y);
        push_i16(&mut bytes, glyph.advance);
        push_u16(&mut bytes, 0);
        push_u32(
            &mut bytes,
            u32::try_from(glyph.packed_len().ok_or("invalid glyph")?)?,
        );
    }

    for pair in &font.kerning {
        push_u32(&mut bytes, pair.left as u32);
        push_u32(&mut bytes, pair.right as u32);
        push_i16(&mut bytes, pair.adjustment);
        push_u16(&mut bytes, 0);
    }
    bytes.extend_from_slice(&font.bitmap);
    Ok(bytes)
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
