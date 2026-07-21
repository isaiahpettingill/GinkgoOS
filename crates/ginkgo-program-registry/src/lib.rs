#![no_std]

//! A zero-copy parser for Ginkgo program registry (`GKR`) files.
//!
//! The little-endian wire format starts with a 12-byte header:
//!
//! ```text
//! magic[4] = "GKR\0" | version: u16 | header_flags: u16 | entry_count: u32
//! ```
//!
//! Each entry then contains an 8-byte header followed immediately by its three
//! UTF-8 fields:
//!
//! ```text
//! app_id_len: u16 | display_name_len: u16 | executable_path_len: u16 | flags: u16
//! app_id bytes | display_name bytes | executable_path bytes
//! ```
//!
//! Version 1 requires zero header flags, recognizes only [`EntryFlags::HIDDEN`],
//! and rejects trailing data. App IDs are lowercase dot-separated identifiers;
//! executable paths are absolute, normalized paths without `.` or `..` segments.

#[cfg(any(test, feature = "host"))]
extern crate alloc;

use core::{fmt, iter::FusedIterator, str};

/// The GKR file signature.
pub const MAGIC: [u8; 4] = *b"GKR\0";
/// The only format version understood by this crate.
pub const VERSION: u16 = 1;
/// Size of the version 1 file header.
pub const HEADER_SIZE: usize = 12;
/// Size of each version 1 entry header.
pub const ENTRY_HEADER_SIZE: usize = 8;
/// Maximum number of entries accepted in one registry.
pub const MAX_ENTRIES: u32 = 1024;
/// Maximum encoded app ID length.
pub const MAX_APP_ID_LEN: usize = 255;
/// Maximum encoded display name length.
pub const MAX_DISPLAY_NAME_LEN: usize = 255;
/// Maximum encoded executable path length.
pub const MAX_EXECUTABLE_PATH_LEN: usize = 4096;

/// A field within a registry entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Field {
    AppId,
    DisplayName,
    ExecutablePath,
}

/// Entry behavior flags.
#[derive(Clone, Copy, Default, Eq, Hash, PartialEq)]
pub struct EntryFlags(u16);

impl EntryFlags {
    /// No special behavior.
    pub const EMPTY: Self = Self(0);
    /// Exclude this application from normal launcher listings.
    pub const HIDDEN: Self = Self(1 << 0);

    const KNOWN_BITS: u16 = Self::HIDDEN.0;

    /// Creates flags if every bit is known to this format version.
    pub const fn from_bits(bits: u16) -> Option<Self> {
        if bits & !Self::KNOWN_BITS == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    /// Returns the raw wire-format bits.
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Returns whether all bits in `other` are set.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Returns whether no flags are set.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl core::ops::BitOr for EntryFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl fmt::Debug for EntryFlags {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            formatter.write_str("EntryFlags(EMPTY)")
        } else if *self == Self::HIDDEN {
            formatter.write_str("EntryFlags(HIDDEN)")
        } else {
            write!(formatter, "EntryFlags({:#06x})", self.0)
        }
    }
}

/// A fully validated, borrowed launcher entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Entry<'a> {
    pub app_id: &'a str,
    pub display_name: &'a str,
    pub executable_path: &'a str,
    pub flags: EntryFlags,
}

impl Entry<'_> {
    /// Returns whether this entry should appear in normal launcher listings.
    pub const fn is_visible(&self) -> bool {
        !self.flags.contains(EntryFlags::HIDDEN)
    }
}

/// A registry parse or validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseError {
    TruncatedHeader,
    BadMagic,
    UnsupportedVersion(u16),
    UnknownHeaderFlags(u16),
    TooManyEntries {
        count: u32,
        maximum: u32,
    },
    TruncatedEntryHeader {
        index: usize,
    },
    TruncatedEntryData {
        index: usize,
    },
    FieldTooLong {
        index: usize,
        field: Field,
        length: usize,
        maximum: usize,
    },
    InvalidUtf8 {
        index: usize,
        field: Field,
    },
    InvalidAppId {
        index: usize,
    },
    InvalidDisplayName {
        index: usize,
    },
    InvalidExecutablePath {
        index: usize,
    },
    UnknownEntryFlags {
        index: usize,
        bits: u16,
    },
    DuplicateAppId {
        first_index: usize,
        duplicate_index: usize,
    },
    TrailingData,
}

/// A validated GKR registry borrowing its source bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Registry<'a> {
    bytes: &'a [u8],
    entry_count: usize,
}

impl<'a> Registry<'a> {
    /// Parses and completely validates a version 1 registry.
    ///
    /// Successful construction guarantees that iteration cannot encounter a
    /// later decoding error. No allocation is performed.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, ParseError> {
        if bytes.len() < HEADER_SIZE {
            return Err(ParseError::TruncatedHeader);
        }
        if bytes[..4] != MAGIC {
            return Err(ParseError::BadMagic);
        }

        let version = read_u16(bytes, 4);
        if version != VERSION {
            return Err(ParseError::UnsupportedVersion(version));
        }

        let header_flags = read_u16(bytes, 6);
        if header_flags != 0 {
            return Err(ParseError::UnknownHeaderFlags(header_flags));
        }

        let count = read_u32(bytes, 8);
        if count > MAX_ENTRIES {
            return Err(ParseError::TooManyEntries {
                count,
                maximum: MAX_ENTRIES,
            });
        }
        let entry_count = count as usize;

        let mut cursor = HEADER_SIZE;
        for index in 0..entry_count {
            let (_, next) = parse_entry(bytes, cursor, index)?;
            cursor = next;
        }
        if cursor != bytes.len() {
            return Err(ParseError::TrailingData);
        }

        let registry = Self { bytes, entry_count };
        registry.validate_unique_app_ids()?;
        Ok(registry)
    }

    /// Returns the registry format version.
    pub const fn version(&self) -> u16 {
        VERSION
    }

    /// Returns the number of entries, including hidden entries.
    pub const fn len(&self) -> usize {
        self.entry_count
    }

    /// Returns whether the registry contains no entries.
    pub const fn is_empty(&self) -> bool {
        self.entry_count == 0
    }

    /// Iterates over every entry in wire order.
    pub fn entries(&self) -> Entries<'a> {
        Entries {
            bytes: self.bytes,
            cursor: HEADER_SIZE,
            remaining: self.entry_count,
        }
    }

    /// Iterates over non-hidden entries in wire order.
    pub fn visible_entries(&self) -> VisibleEntries<'a> {
        VisibleEntries {
            entries: self.entries(),
        }
    }

    fn validate_unique_app_ids(&self) -> Result<(), ParseError> {
        for (duplicate_index, entry) in self.entries().enumerate() {
            for (first_index, previous) in self.entries().take(duplicate_index).enumerate() {
                if previous.app_id == entry.app_id {
                    return Err(ParseError::DuplicateAppId {
                        first_index,
                        duplicate_index,
                    });
                }
            }
        }
        Ok(())
    }
}

/// Iterator over all registry entries.
#[derive(Clone, Debug)]
pub struct Entries<'a> {
    bytes: &'a [u8],
    cursor: usize,
    remaining: usize,
}

impl<'a> Iterator for Entries<'a> {
    type Item = Entry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }

        // Registry construction validated every boundary and UTF-8 field. The
        // immutable borrowed bytes preserve those invariants for this iterator.
        let (entry, next) = parse_entry(self.bytes, self.cursor, 0).ok()?;
        self.cursor = next;
        self.remaining -= 1;
        Some(entry)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for Entries<'_> {}
impl FusedIterator for Entries<'_> {}

/// Iterator over entries that do not have [`EntryFlags::HIDDEN`] set.
#[derive(Clone, Debug)]
pub struct VisibleEntries<'a> {
    entries: Entries<'a>,
}

impl<'a> Iterator for VisibleEntries<'a> {
    type Item = Entry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.entries.by_ref().find(Entry::is_visible)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.entries.len()))
    }
}

impl FusedIterator for VisibleEntries<'_> {}

fn parse_entry<'a>(
    bytes: &'a [u8],
    cursor: usize,
    index: usize,
) -> Result<(Entry<'a>, usize), ParseError> {
    let header_end = cursor
        .checked_add(ENTRY_HEADER_SIZE)
        .ok_or(ParseError::TruncatedEntryHeader { index })?;
    if header_end > bytes.len() {
        return Err(ParseError::TruncatedEntryHeader { index });
    }

    let app_id_len = read_u16(bytes, cursor) as usize;
    let display_name_len = read_u16(bytes, cursor + 2) as usize;
    let executable_path_len = read_u16(bytes, cursor + 4) as usize;
    let flag_bits = read_u16(bytes, cursor + 6);

    check_length(index, Field::AppId, app_id_len, MAX_APP_ID_LEN)?;
    check_length(
        index,
        Field::DisplayName,
        display_name_len,
        MAX_DISPLAY_NAME_LEN,
    )?;
    check_length(
        index,
        Field::ExecutablePath,
        executable_path_len,
        MAX_EXECUTABLE_PATH_LEN,
    )?;

    let fields_len = app_id_len
        .checked_add(display_name_len)
        .and_then(|length| length.checked_add(executable_path_len))
        .ok_or(ParseError::TruncatedEntryData { index })?;
    let entry_end = header_end
        .checked_add(fields_len)
        .ok_or(ParseError::TruncatedEntryData { index })?;
    if entry_end > bytes.len() {
        return Err(ParseError::TruncatedEntryData { index });
    }

    let display_start = header_end + app_id_len;
    let path_start = display_start + display_name_len;
    let app_id = parse_utf8(&bytes[header_end..display_start], index, Field::AppId)?;
    let display_name = parse_utf8(&bytes[display_start..path_start], index, Field::DisplayName)?;
    let executable_path = parse_utf8(&bytes[path_start..entry_end], index, Field::ExecutablePath)?;
    let flags = EntryFlags::from_bits(flag_bits).ok_or(ParseError::UnknownEntryFlags {
        index,
        bits: flag_bits,
    })?;

    validate_entry(index, app_id, display_name, executable_path)?;

    Ok((
        Entry {
            app_id,
            display_name,
            executable_path,
            flags,
        },
        entry_end,
    ))
}

fn check_length(
    index: usize,
    field: Field,
    length: usize,
    maximum: usize,
) -> Result<(), ParseError> {
    if length > maximum {
        Err(ParseError::FieldTooLong {
            index,
            field,
            length,
            maximum,
        })
    } else {
        Ok(())
    }
}

fn parse_utf8(bytes: &[u8], index: usize, field: Field) -> Result<&str, ParseError> {
    str::from_utf8(bytes).map_err(|_| ParseError::InvalidUtf8 { index, field })
}

fn validate_entry(
    index: usize,
    app_id: &str,
    display_name: &str,
    executable_path: &str,
) -> Result<(), ParseError> {
    if !valid_app_id(app_id) {
        return Err(ParseError::InvalidAppId { index });
    }
    if !valid_display_name(display_name) {
        return Err(ParseError::InvalidDisplayName { index });
    }
    if !valid_executable_path(executable_path) {
        return Err(ParseError::InvalidExecutablePath { index });
    }
    Ok(())
}

fn valid_app_id(app_id: &str) -> bool {
    if app_id.is_empty() || app_id.len() > MAX_APP_ID_LEN {
        return false;
    }

    app_id.split('.').all(|component| {
        let bytes = component.as_bytes();
        !bytes.is_empty()
            && bytes.len() <= 63
            && bytes[0].is_ascii_lowercase()
            && bytes[bytes.len() - 1].is_ascii_alphanumeric()
            && bytes
                .iter()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
    })
}

fn valid_display_name(display_name: &str) -> bool {
    !display_name.is_empty()
        && display_name.len() <= MAX_DISPLAY_NAME_LEN
        && display_name
            .chars()
            .any(|character| !character.is_whitespace())
        && display_name
            .chars()
            .all(|character| !character.is_control())
}

fn valid_executable_path(path: &str) -> bool {
    if path.len() < 2
        || path.len() > MAX_EXECUTABLE_PATH_LEN
        || !path.starts_with('/')
        || path.ends_with('/')
        || path.contains('\\')
        || path.chars().any(|character| character.is_control())
    {
        return false;
    }

    path[1..]
        .split('/')
        .all(|component| !component.is_empty() && component != "." && component != "..")
}

const fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

const fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

/// Host-side input for [`encode`].
#[cfg(any(test, feature = "host"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncodeEntry<'a> {
    pub app_id: &'a str,
    pub display_name: &'a str,
    pub executable_path: &'a str,
    pub flags: EntryFlags,
}

/// Encodes a validated version 1 registry for host-side tooling.
#[cfg(any(test, feature = "host"))]
pub fn encode(entries: &[EncodeEntry<'_>]) -> Result<alloc::vec::Vec<u8>, ParseError> {
    use alloc::vec::Vec;

    if entries.len() > MAX_ENTRIES as usize {
        return Err(ParseError::TooManyEntries {
            count: u32::try_from(entries.len()).unwrap_or(u32::MAX),
            maximum: MAX_ENTRIES,
        });
    }

    let mut total_len = HEADER_SIZE;
    for (index, entry) in entries.iter().enumerate() {
        check_length(index, Field::AppId, entry.app_id.len(), MAX_APP_ID_LEN)?;
        check_length(
            index,
            Field::DisplayName,
            entry.display_name.len(),
            MAX_DISPLAY_NAME_LEN,
        )?;
        check_length(
            index,
            Field::ExecutablePath,
            entry.executable_path.len(),
            MAX_EXECUTABLE_PATH_LEN,
        )?;
        validate_entry(
            index,
            entry.app_id,
            entry.display_name,
            entry.executable_path,
        )?;
        for (first_index, previous) in entries[..index].iter().enumerate() {
            if previous.app_id == entry.app_id {
                return Err(ParseError::DuplicateAppId {
                    first_index,
                    duplicate_index: index,
                });
            }
        }
        total_len += ENTRY_HEADER_SIZE
            + entry.app_id.len()
            + entry.display_name.len()
            + entry.executable_path.len();
    }

    let mut output = Vec::with_capacity(total_len);
    output.extend_from_slice(&MAGIC);
    output.extend_from_slice(&VERSION.to_le_bytes());
    output.extend_from_slice(&0u16.to_le_bytes());
    output.extend_from_slice(&(entries.len() as u32).to_le_bytes());

    for entry in entries {
        output.extend_from_slice(&(entry.app_id.len() as u16).to_le_bytes());
        output.extend_from_slice(&(entry.display_name.len() as u16).to_le_bytes());
        output.extend_from_slice(&(entry.executable_path.len() as u16).to_le_bytes());
        output.extend_from_slice(&entry.flags.bits().to_le_bytes());
        output.extend_from_slice(entry.app_id.as_bytes());
        output.extend_from_slice(entry.display_name.as_bytes());
        output.extend_from_slice(entry.executable_path.as_bytes());
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{vec, vec::Vec};

    type RawEntry<'a> = (&'a [u8], &'a [u8], &'a [u8], u16);
    type InvalidUtf8Case<'a> = (&'a [u8], &'a [u8], &'a [u8], Field);

    const FILES: EncodeEntry<'_> = EncodeEntry {
        app_id: "org.ginkgo.files",
        display_name: "Files",
        executable_path: "/system/bin/files",
        flags: EntryFlags::EMPTY,
    };

    const SETTINGS: EncodeEntry<'_> = EncodeEntry {
        app_id: "org.ginkgo.settings",
        display_name: "Settings",
        executable_path: "/system/bin/settings",
        flags: EntryFlags::HIDDEN,
    };

    fn raw_registry(entries: &[RawEntry<'_>]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&MAGIC);
        bytes.extend_from_slice(&VERSION.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&(entries.len() as u32).to_le_bytes());
        for (app_id, display_name, path, flags) in entries {
            bytes.extend_from_slice(&(app_id.len() as u16).to_le_bytes());
            bytes.extend_from_slice(&(display_name.len() as u16).to_le_bytes());
            bytes.extend_from_slice(&(path.len() as u16).to_le_bytes());
            bytes.extend_from_slice(&flags.to_le_bytes());
            bytes.extend_from_slice(app_id);
            bytes.extend_from_slice(display_name);
            bytes.extend_from_slice(path);
        }
        bytes
    }

    #[test]
    fn parses_and_borrows_valid_entries() {
        let bytes = encode(&[FILES, SETTINGS]).unwrap();
        let registry = Registry::parse(&bytes).unwrap();
        let entries: Vec<_> = registry.entries().collect();

        assert_eq!(registry.version(), VERSION);
        assert_eq!(registry.len(), 2);
        assert!(!registry.is_empty());
        assert_eq!(entries[0].app_id, FILES.app_id);
        assert_eq!(entries[0].display_name, FILES.display_name);
        assert_eq!(entries[0].executable_path, FILES.executable_path);
        assert!(entries[0].flags.is_empty());
        assert!(entries[1].flags.contains(EntryFlags::HIDDEN));
    }

    #[test]
    fn parses_empty_registry() {
        let bytes = encode(&[]).unwrap();
        let registry = Registry::parse(&bytes).unwrap();
        assert!(registry.is_empty());
        assert_eq!(registry.entries().next(), None);
    }

    #[test]
    fn filters_hidden_entries_without_reordering_visible_entries() {
        let terminal = EncodeEntry {
            app_id: "org.ginkgo.terminal",
            display_name: "Terminal",
            executable_path: "/system/bin/terminal",
            flags: EntryFlags::EMPTY,
        };
        let bytes = encode(&[FILES, SETTINGS, terminal]).unwrap();
        let registry = Registry::parse(&bytes).unwrap();
        let visible: Vec<_> = registry
            .visible_entries()
            .map(|entry| entry.app_id)
            .collect();

        assert_eq!(visible, vec!["org.ginkgo.files", "org.ginkgo.terminal"]);
    }

    #[test]
    fn rejects_every_truncation_of_a_nonempty_registry() {
        let bytes = encode(&[FILES]).unwrap();
        for end in 0..bytes.len() {
            assert!(
                Registry::parse(&bytes[..end]).is_err(),
                "accepted length {end}"
            );
        }
        assert!(Registry::parse(&bytes).is_ok());
    }

    #[test]
    fn distinguishes_truncated_header_entry_header_and_entry_data() {
        let bytes = encode(&[FILES]).unwrap();
        assert_eq!(
            Registry::parse(&bytes[..11]),
            Err(ParseError::TruncatedHeader)
        );
        assert_eq!(
            Registry::parse(&bytes[..19]),
            Err(ParseError::TruncatedEntryHeader { index: 0 })
        );
        assert_eq!(
            Registry::parse(&bytes[..20]),
            Err(ParseError::TruncatedEntryData { index: 0 })
        );
    }

    #[test]
    fn rejects_bad_magic_version_header_flags_and_entry_count() {
        let bytes = encode(&[]).unwrap();

        let mut bad_magic = bytes.clone();
        bad_magic[0] = b'X';
        assert_eq!(Registry::parse(&bad_magic), Err(ParseError::BadMagic));

        let mut bad_version = bytes.clone();
        bad_version[4..6].copy_from_slice(&2u16.to_le_bytes());
        assert_eq!(
            Registry::parse(&bad_version),
            Err(ParseError::UnsupportedVersion(2))
        );

        let mut bad_header_flags = bytes.clone();
        bad_header_flags[6..8].copy_from_slice(&1u16.to_le_bytes());
        assert_eq!(
            Registry::parse(&bad_header_flags),
            Err(ParseError::UnknownHeaderFlags(1))
        );

        let mut too_many = bytes;
        too_many[8..12].copy_from_slice(&(MAX_ENTRIES + 1).to_le_bytes());
        assert_eq!(
            Registry::parse(&too_many),
            Err(ParseError::TooManyEntries {
                count: MAX_ENTRIES + 1,
                maximum: MAX_ENTRIES,
            })
        );
    }

    #[test]
    fn rejects_trailing_data() {
        let mut bytes = encode(&[FILES]).unwrap();
        bytes.push(0);
        assert_eq!(Registry::parse(&bytes), Err(ParseError::TrailingData));
    }

    #[test]
    fn rejects_duplicate_app_ids() {
        let bytes = raw_registry(&[
            (b"org.ginkgo.files", b"Files", b"/bin/files", 0),
            (b"org.ginkgo.files", b"Other Files", b"/bin/other-files", 0),
        ]);
        assert_eq!(
            Registry::parse(&bytes),
            Err(ParseError::DuplicateAppId {
                first_index: 0,
                duplicate_index: 1,
            })
        );
        assert_eq!(
            encode(&[FILES, FILES]),
            Err(ParseError::DuplicateAppId {
                first_index: 0,
                duplicate_index: 1,
            })
        );
    }

    #[test]
    fn rejects_invalid_utf8_in_each_field() {
        let cases: &[InvalidUtf8Case<'_>] = &[
            (&[0xff], b"Files", b"/bin/files", Field::AppId),
            (
                b"org.ginkgo.files",
                &[0xff],
                b"/bin/files",
                Field::DisplayName,
            ),
            (
                b"org.ginkgo.files",
                b"Files",
                &[0xff],
                Field::ExecutablePath,
            ),
        ];

        for &(app_id, display_name, path, field) in cases {
            let bytes = raw_registry(&[(app_id, display_name, path, 0)]);
            assert_eq!(
                Registry::parse(&bytes),
                Err(ParseError::InvalidUtf8 { index: 0, field })
            );
        }
    }

    #[test]
    fn rejects_invalid_app_ids() {
        let invalid = [
            "",
            ".org.ginkgo",
            "org..ginkgo",
            "org.ginkgo.",
            "Org.ginkgo.files",
            "org.ginkgo.file_system",
            "org.ginkgo.-files",
            "org.ginkgo.files-",
            "org.ginkgo.café",
        ];

        for app_id in invalid {
            let bytes = raw_registry(&[(app_id.as_bytes(), b"App", b"/bin/app", 0)]);
            assert_eq!(
                Registry::parse(&bytes),
                Err(ParseError::InvalidAppId { index: 0 }),
                "accepted {app_id:?}"
            );
        }
    }

    #[test]
    fn rejects_empty_whitespace_and_control_character_display_names() {
        for display_name in ["", "   ", "Bad\nName", "Bad\0Name"] {
            let bytes =
                raw_registry(&[(b"org.ginkgo.app", display_name.as_bytes(), b"/bin/app", 0)]);
            assert_eq!(
                Registry::parse(&bytes),
                Err(ParseError::InvalidDisplayName { index: 0 })
            );
        }
    }

    #[test]
    fn rejects_invalid_or_unnormalized_executable_paths() {
        let invalid = [
            "",
            "/",
            "bin/app",
            "/bin/",
            "/bin//app",
            "/bin/./app",
            "/bin/../app",
            "/bin\\app",
            "/bin/app\0suffix",
            "/bin/app\nsuffix",
        ];

        for path in invalid {
            let bytes = raw_registry(&[(b"org.ginkgo.app", b"App", path.as_bytes(), 0)]);
            assert_eq!(
                Registry::parse(&bytes),
                Err(ParseError::InvalidExecutablePath { index: 0 }),
                "accepted {path:?}"
            );
        }
    }

    #[test]
    fn accepts_unicode_display_names_and_paths() {
        let entry = EncodeEntry {
            app_id: "org.ginkgo.calculator",
            display_name: "Calculatrice 🧮",
            executable_path: "/applications/calculatrice-🧮",
            flags: EntryFlags::EMPTY,
        };
        let bytes = encode(&[entry]).unwrap();
        assert_eq!(
            Registry::parse(&bytes).unwrap().entries().next(),
            Some(Entry {
                app_id: entry.app_id,
                display_name: entry.display_name,
                executable_path: entry.executable_path,
                flags: entry.flags,
            })
        );
    }

    #[test]
    fn rejects_unknown_entry_flags() {
        let bytes = raw_registry(&[(b"org.ginkgo.app", b"App", b"/bin/app", 0x8000)]);
        assert_eq!(
            Registry::parse(&bytes),
            Err(ParseError::UnknownEntryFlags {
                index: 0,
                bits: 0x8000,
            })
        );
        assert_eq!(EntryFlags::from_bits(0x8000), None);
    }

    #[test]
    fn rejects_fields_over_semantic_length_limits() {
        let long_display = vec![b'a'; MAX_DISPLAY_NAME_LEN + 1];
        let bytes = raw_registry(&[(b"org.ginkgo.app", &long_display, b"/bin/app", 0)]);
        assert_eq!(
            Registry::parse(&bytes),
            Err(ParseError::FieldTooLong {
                index: 0,
                field: Field::DisplayName,
                length: MAX_DISPLAY_NAME_LEN + 1,
                maximum: MAX_DISPLAY_NAME_LEN,
            })
        );

        let long_path = "/a".repeat((MAX_EXECUTABLE_PATH_LEN / 2) + 1);
        let entry = EncodeEntry {
            app_id: "org.ginkgo.app",
            display_name: "App",
            executable_path: &long_path,
            flags: EntryFlags::EMPTY,
        };
        assert_eq!(
            encode(&[entry]),
            Err(ParseError::FieldTooLong {
                index: 0,
                field: Field::ExecutablePath,
                length: long_path.len(),
                maximum: MAX_EXECUTABLE_PATH_LEN,
            })
        );
    }

    #[test]
    fn declared_field_lengths_cannot_run_past_input() {
        let mut bytes = encode(&[FILES]).unwrap();
        bytes[12..14].copy_from_slice(&u16::MAX.to_le_bytes());
        assert_eq!(
            Registry::parse(&bytes),
            Err(ParseError::FieldTooLong {
                index: 0,
                field: Field::AppId,
                length: u16::MAX as usize,
                maximum: MAX_APP_ID_LEN,
            })
        );

        let mut bytes = encode(&[FILES]).unwrap();
        bytes[16..18].copy_from_slice(&100u16.to_le_bytes());
        assert_eq!(
            Registry::parse(&bytes),
            Err(ParseError::TruncatedEntryData { index: 0 })
        );
    }
}
