use core::{iter::FusedIterator, str};

use crate::validation::{
    read_u16, read_u32, valid_app_id, valid_asset_path, valid_display_name, valid_version,
    MAX_APP_ID_LEN, MAX_ASSET_COUNT, MAX_ASSET_DATA_LEN, MAX_ASSET_PATH_LEN, MAX_DISPLAY_NAME_LEN,
    MAX_EXECUTABLE_LEN, MAX_PACKAGE_LEN, MAX_TOTAL_ASSET_DATA_LEN, MAX_VERSION_LEN,
};

pub const PACKAGE_MAGIC: [u8; 4] = *b"GKP\0";
pub const PACKAGE_VERSION: u16 = 1;
pub const PACKAGE_HEADER_SIZE: usize = 24;
const ASSET_HEADER_SIZE: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum AppKind {
    Graphical = 1,
    Command = 2,
}

impl AppKind {
    pub(crate) fn from_wire(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::Graphical),
            2 => Some(Self::Command),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Field {
    AppId,
    DisplayName,
    Version,
    AssetPath,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackageError {
    PackageTooLarge {
        length: usize,
        maximum: usize,
    },
    TruncatedHeader,
    BadMagic,
    UnsupportedVersion(u16),
    UnknownHeaderFlags(u16),
    UnknownKind(u16),
    UnknownReservedBits(u16),
    TooManyAssets {
        count: usize,
        maximum: usize,
    },
    FieldTooLong {
        field: Field,
        length: usize,
        maximum: usize,
    },
    InvalidUtf8 {
        field: Field,
        asset_index: Option<usize>,
    },
    InvalidAppId,
    InvalidDisplayName,
    InvalidVersion,
    EmptyExecutable,
    ExecutableTooLarge {
        length: usize,
        maximum: usize,
    },
    TruncatedMetadata,
    TruncatedExecutable,
    TruncatedAssetHeader {
        index: usize,
    },
    UnknownAssetFlags {
        index: usize,
        bits: u16,
    },
    AssetTooLarge {
        index: usize,
        length: usize,
        maximum: usize,
    },
    TotalAssetsTooLarge {
        length: usize,
        maximum: usize,
    },
    TruncatedAsset {
        index: usize,
    },
    InvalidAssetPath {
        index: usize,
    },
    DuplicateAsset {
        first_index: usize,
        duplicate_index: usize,
    },
    TrailingData,
    SizeOverflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Asset<'a> {
    pub path: &'a str,
    pub data: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Package<'a> {
    pub app_id: &'a str,
    pub display_name: &'a str,
    pub version: &'a str,
    pub kind: AppKind,
    pub executable: &'a [u8],
    bytes: &'a [u8],
    assets_offset: usize,
    asset_count: usize,
}

impl<'a> Package<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, PackageError> {
        if bytes.len() > MAX_PACKAGE_LEN {
            return Err(PackageError::PackageTooLarge {
                length: bytes.len(),
                maximum: MAX_PACKAGE_LEN,
            });
        }
        if bytes.len() < PACKAGE_HEADER_SIZE {
            return Err(PackageError::TruncatedHeader);
        }
        if bytes[..4] != PACKAGE_MAGIC {
            return Err(PackageError::BadMagic);
        }
        let format_version = read_u16(bytes, 4);
        if format_version != PACKAGE_VERSION {
            return Err(PackageError::UnsupportedVersion(format_version));
        }
        let flags = read_u16(bytes, 6);
        if flags != 0 {
            return Err(PackageError::UnknownHeaderFlags(flags));
        }
        let kind_value = read_u16(bytes, 8);
        let kind = AppKind::from_wire(kind_value).ok_or(PackageError::UnknownKind(kind_value))?;
        let asset_count = read_u16(bytes, 10) as usize;
        if asset_count > MAX_ASSET_COUNT {
            return Err(PackageError::TooManyAssets {
                count: asset_count,
                maximum: MAX_ASSET_COUNT,
            });
        }
        let app_id_len = read_u16(bytes, 12) as usize;
        let display_name_len = read_u16(bytes, 14) as usize;
        let version_len = read_u16(bytes, 16) as usize;
        let reserved = read_u16(bytes, 18);
        if reserved != 0 {
            return Err(PackageError::UnknownReservedBits(reserved));
        }
        let executable_len = read_u32(bytes, 20) as usize;

        check_field_len(Field::AppId, app_id_len, MAX_APP_ID_LEN)?;
        check_field_len(Field::DisplayName, display_name_len, MAX_DISPLAY_NAME_LEN)?;
        check_field_len(Field::Version, version_len, MAX_VERSION_LEN)?;
        if executable_len == 0 {
            return Err(PackageError::EmptyExecutable);
        }
        if executable_len > MAX_EXECUTABLE_LEN {
            return Err(PackageError::ExecutableTooLarge {
                length: executable_len,
                maximum: MAX_EXECUTABLE_LEN,
            });
        }

        let metadata_len = app_id_len
            .checked_add(display_name_len)
            .and_then(|length| length.checked_add(version_len))
            .ok_or(PackageError::SizeOverflow)?;
        let metadata_end = PACKAGE_HEADER_SIZE
            .checked_add(metadata_len)
            .ok_or(PackageError::SizeOverflow)?;
        if metadata_end > bytes.len() {
            return Err(PackageError::TruncatedMetadata);
        }
        let executable_end = metadata_end
            .checked_add(executable_len)
            .ok_or(PackageError::SizeOverflow)?;
        if executable_end > bytes.len() {
            return Err(PackageError::TruncatedExecutable);
        }

        let display_start = PACKAGE_HEADER_SIZE + app_id_len;
        let version_start = display_start + display_name_len;
        let app_id = parse_text(
            &bytes[PACKAGE_HEADER_SIZE..display_start],
            Field::AppId,
            None,
        )?;
        let display_name = parse_text(
            &bytes[display_start..version_start],
            Field::DisplayName,
            None,
        )?;
        let version = parse_text(&bytes[version_start..metadata_end], Field::Version, None)?;
        if !valid_app_id(app_id) {
            return Err(PackageError::InvalidAppId);
        }
        if !valid_display_name(display_name) {
            return Err(PackageError::InvalidDisplayName);
        }
        if !valid_version(version) {
            return Err(PackageError::InvalidVersion);
        }

        let mut cursor = executable_end;
        let mut total_asset_data = 0usize;
        for index in 0..asset_count {
            let (asset, next) = parse_asset(bytes, cursor, index)?;
            total_asset_data = total_asset_data
                .checked_add(asset.data.len())
                .ok_or(PackageError::SizeOverflow)?;
            if total_asset_data > MAX_TOTAL_ASSET_DATA_LEN {
                return Err(PackageError::TotalAssetsTooLarge {
                    length: total_asset_data,
                    maximum: MAX_TOTAL_ASSET_DATA_LEN,
                });
            }
            cursor = next;
        }
        if cursor != bytes.len() {
            return Err(PackageError::TrailingData);
        }

        let package = Self {
            app_id,
            display_name,
            version,
            kind,
            executable: &bytes[metadata_end..executable_end],
            bytes,
            assets_offset: executable_end,
            asset_count,
        };
        package.validate_unique_assets()?;
        Ok(package)
    }

    pub const fn asset_count(&self) -> usize {
        self.asset_count
    }

    pub const fn is_empty(&self) -> bool {
        self.asset_count == 0
    }

    pub fn assets(&self) -> Assets<'a> {
        Assets {
            bytes: self.bytes,
            cursor: self.assets_offset,
            remaining: self.asset_count,
            index: 0,
        }
    }

    fn validate_unique_assets(&self) -> Result<(), PackageError> {
        for (duplicate_index, asset) in self.assets().enumerate() {
            for (first_index, previous) in self.assets().take(duplicate_index).enumerate() {
                if previous.path == asset.path {
                    return Err(PackageError::DuplicateAsset {
                        first_index,
                        duplicate_index,
                    });
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct Assets<'a> {
    bytes: &'a [u8],
    cursor: usize,
    remaining: usize,
    index: usize,
}

impl<'a> Iterator for Assets<'a> {
    type Item = Asset<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let (asset, next) = parse_asset(self.bytes, self.cursor, self.index).ok()?;
        self.cursor = next;
        self.remaining -= 1;
        self.index += 1;
        Some(asset)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for Assets<'_> {}
impl FusedIterator for Assets<'_> {}

fn parse_asset<'a>(
    bytes: &'a [u8],
    cursor: usize,
    index: usize,
) -> Result<(Asset<'a>, usize), PackageError> {
    let header_end = cursor
        .checked_add(ASSET_HEADER_SIZE)
        .ok_or(PackageError::SizeOverflow)?;
    if header_end > bytes.len() {
        return Err(PackageError::TruncatedAssetHeader { index });
    }
    let path_len = read_u16(bytes, cursor) as usize;
    let flags = read_u16(bytes, cursor + 2);
    if flags != 0 {
        return Err(PackageError::UnknownAssetFlags { index, bits: flags });
    }
    if path_len > MAX_ASSET_PATH_LEN {
        return Err(PackageError::FieldTooLong {
            field: Field::AssetPath,
            length: path_len,
            maximum: MAX_ASSET_PATH_LEN,
        });
    }
    let data_len = read_u32(bytes, cursor + 4) as usize;
    if data_len > MAX_ASSET_DATA_LEN {
        return Err(PackageError::AssetTooLarge {
            index,
            length: data_len,
            maximum: MAX_ASSET_DATA_LEN,
        });
    }
    let path_end = header_end
        .checked_add(path_len)
        .ok_or(PackageError::SizeOverflow)?;
    let data_end = path_end
        .checked_add(data_len)
        .ok_or(PackageError::SizeOverflow)?;
    if data_end > bytes.len() {
        return Err(PackageError::TruncatedAsset { index });
    }
    let path = parse_text(&bytes[header_end..path_end], Field::AssetPath, Some(index))?;
    if !valid_asset_path(path) {
        return Err(PackageError::InvalidAssetPath { index });
    }
    Ok((
        Asset {
            path,
            data: &bytes[path_end..data_end],
        },
        data_end,
    ))
}

fn check_field_len(field: Field, length: usize, maximum: usize) -> Result<(), PackageError> {
    if length > maximum {
        Err(PackageError::FieldTooLong {
            field,
            length,
            maximum,
        })
    } else {
        Ok(())
    }
}

fn parse_text(
    bytes: &[u8],
    field: Field,
    asset_index: Option<usize>,
) -> Result<&str, PackageError> {
    str::from_utf8(bytes).map_err(|_| PackageError::InvalidUtf8 { field, asset_index })
}

#[cfg(feature = "host")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssetInput<'a> {
    pub path: &'a str,
    pub data: &'a [u8],
}

#[cfg(feature = "host")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackageInput<'a> {
    pub app_id: &'a str,
    pub display_name: &'a str,
    pub version: &'a str,
    pub kind: AppKind,
    pub executable: &'a [u8],
    pub assets: &'a [AssetInput<'a>],
}

#[cfg(feature = "host")]
pub type EncodeError = PackageError;

#[cfg(feature = "host")]
pub fn encode_package(input: &PackageInput<'_>) -> Result<alloc::vec::Vec<u8>, EncodeError> {
    use alloc::vec::Vec;

    if input.assets.len() > MAX_ASSET_COUNT {
        return Err(PackageError::TooManyAssets {
            count: input.assets.len(),
            maximum: MAX_ASSET_COUNT,
        });
    }
    check_field_len(Field::AppId, input.app_id.len(), MAX_APP_ID_LEN)?;
    check_field_len(
        Field::DisplayName,
        input.display_name.len(),
        MAX_DISPLAY_NAME_LEN,
    )?;
    check_field_len(Field::Version, input.version.len(), MAX_VERSION_LEN)?;
    if !valid_app_id(input.app_id) {
        return Err(PackageError::InvalidAppId);
    }
    if !valid_display_name(input.display_name) {
        return Err(PackageError::InvalidDisplayName);
    }
    if !valid_version(input.version) {
        return Err(PackageError::InvalidVersion);
    }
    if input.executable.is_empty() {
        return Err(PackageError::EmptyExecutable);
    }
    if input.executable.len() > MAX_EXECUTABLE_LEN {
        return Err(PackageError::ExecutableTooLarge {
            length: input.executable.len(),
            maximum: MAX_EXECUTABLE_LEN,
        });
    }
    let mut total_assets = 0usize;
    for (index, asset) in input.assets.iter().enumerate() {
        if !valid_asset_path(asset.path) {
            return Err(PackageError::InvalidAssetPath { index });
        }
        if asset.data.len() > MAX_ASSET_DATA_LEN {
            return Err(PackageError::AssetTooLarge {
                index,
                length: asset.data.len(),
                maximum: MAX_ASSET_DATA_LEN,
            });
        }
        total_assets = total_assets
            .checked_add(asset.data.len())
            .ok_or(PackageError::SizeOverflow)?;
        if total_assets > MAX_TOTAL_ASSET_DATA_LEN {
            return Err(PackageError::TotalAssetsTooLarge {
                length: total_assets,
                maximum: MAX_TOTAL_ASSET_DATA_LEN,
            });
        }
        if let Some(first_index) = input.assets[..index]
            .iter()
            .position(|previous| previous.path == asset.path)
        {
            return Err(PackageError::DuplicateAsset {
                first_index,
                duplicate_index: index,
            });
        }
    }

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&PACKAGE_MAGIC);
    bytes.extend_from_slice(&PACKAGE_VERSION.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&(input.kind as u16).to_le_bytes());
    bytes.extend_from_slice(&(input.assets.len() as u16).to_le_bytes());
    bytes.extend_from_slice(&(input.app_id.len() as u16).to_le_bytes());
    bytes.extend_from_slice(&(input.display_name.len() as u16).to_le_bytes());
    bytes.extend_from_slice(&(input.version.len() as u16).to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&(input.executable.len() as u32).to_le_bytes());
    bytes.extend_from_slice(input.app_id.as_bytes());
    bytes.extend_from_slice(input.display_name.as_bytes());
    bytes.extend_from_slice(input.version.as_bytes());
    bytes.extend_from_slice(input.executable);
    for asset in input.assets {
        bytes.extend_from_slice(&(asset.path.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&(asset.data.len() as u32).to_le_bytes());
        bytes.extend_from_slice(asset.path.as_bytes());
        bytes.extend_from_slice(asset.data);
    }
    if bytes.len() > MAX_PACKAGE_LEN {
        return Err(PackageError::PackageTooLarge {
            length: bytes.len(),
            maximum: MAX_PACKAGE_LEN,
        });
    }
    Ok(bytes)
}
