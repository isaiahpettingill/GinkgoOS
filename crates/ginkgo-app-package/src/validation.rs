pub const MAX_APP_ID_LEN: usize = 127;
pub const MAX_DISPLAY_NAME_LEN: usize = 255;
pub const MAX_VERSION_LEN: usize = 63;
pub const MAX_EXECUTABLE_LEN: usize = 16 * 1024 * 1024;
pub const MAX_ASSET_COUNT: usize = 64;
pub const MAX_ASSET_PATH_LEN: usize = 255;
pub const MAX_ASSET_DATA_LEN: usize = 1024 * 1024;
pub const MAX_TOTAL_ASSET_DATA_LEN: usize = 8 * 1024 * 1024;
pub const MAX_PACKAGE_LEN: usize = 24 * 1024 * 1024;
pub const MAX_INSTALLED_APPS: usize = 1024;
pub const MAX_REGISTRY_LEN: usize = 1024 * 1024;
pub const DIGEST_LEN: usize = 32;
pub const GENERATION_SUFFIX_LEN: usize = 1 + DIGEST_LEN * 2 + 4;
pub const MAX_GENERATION_FILENAME_LEN: usize = MAX_APP_ID_LEN + GENERATION_SUFFIX_LEN;

pub fn valid_app_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_APP_ID_LEN
        && value.split('.').all(|part| {
            !part.is_empty()
                && part.as_bytes()[0].is_ascii_lowercase()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && !part.ends_with('-')
        })
}

pub fn valid_display_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_DISPLAY_NAME_LEN
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

pub fn valid_version(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_VERSION_LEN {
        return false;
    }
    let mut previous_separator = true;
    for byte in value.bytes() {
        let separator = matches!(byte, b'.' | b'-' | b'+');
        if !(byte.is_ascii_alphanumeric() || separator) || (separator && previous_separator) {
            return false;
        }
        previous_separator = separator;
    }
    !previous_separator
}

pub fn valid_asset_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ASSET_PATH_LEN
        && !value.starts_with('/')
        && !value.ends_with('/')
        && !value.contains('\\')
        && !value.contains(':')
        && value.split('/').all(valid_path_component)
}

fn valid_path_component(component: &str) -> bool {
    !component.is_empty()
        && component != "."
        && component != ".."
        && component
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b' '))
}

pub fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

pub fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

pub fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}
