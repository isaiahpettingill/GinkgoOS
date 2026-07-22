use ginkgo_window::KeyboardEvent;

pub const ENTER: u8 = b'\r';
pub const BACKSPACE: u8 = 0x08;
pub const CLEAR: u8 = 0x0c;
pub const CANCEL: u8 = 0x03;
pub const HISTORY_PREVIOUS: u8 = 0x10;
pub const HISTORY_NEXT: u8 = 0x0e;

pub fn translate(event: KeyboardEvent) -> Option<u8> {
    let control = event.modifiers.control;
    match event.usage {
        0x28 => return Some(ENTER),
        0x2a => return Some(BACKSPACE),
        0x52 => return Some(HISTORY_PREVIOUS),
        0x51 => return Some(HISTORY_NEXT),
        0x0f if control => return Some(CLEAR),
        0x06 if control => return Some(CANCEL),
        _ => {}
    }
    if control || event.modifiers.alt || event.modifiers.logo {
        return None;
    }

    let shift = event.modifiers.shift;
    let letter_shift = shift ^ event.modifiers.caps_lock;
    match event.usage {
        0x04..=0x1d => {
            let base = if letter_shift { b'A' } else { b'a' };
            Some(base + (event.usage - 0x04) as u8)
        }
        0x1e..=0x27 => {
            const PLAIN: &[u8; 10] = b"1234567890";
            const SHIFTED: &[u8; 10] = b"!@#$%^&*()";
            let index = (event.usage - 0x1e) as usize;
            Some(if shift { SHIFTED[index] } else { PLAIN[index] })
        }
        0x2c => Some(b' '),
        0x2d => Some(if shift { b'_' } else { b'-' }),
        0x2e => Some(if shift { b'+' } else { b'=' }),
        0x2f => Some(if shift { b'{' } else { b'[' }),
        0x30 => Some(if shift { b'}' } else { b']' }),
        0x31 => Some(if shift { b'|' } else { b'\\' }),
        0x33 => Some(if shift { b':' } else { b';' }),
        0x34 => Some(if shift { b'\"' } else { b'\'' }),
        0x35 => Some(if shift { b'~' } else { b'`' }),
        0x36 => Some(if shift { b'<' } else { b',' }),
        0x37 => Some(if shift { b'>' } else { b'.' }),
        0x38 => Some(if shift { b'?' } else { b'/' }),
        _ => None,
    }
}
