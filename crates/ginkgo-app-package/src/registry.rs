use alloc::{string::String, vec::Vec};
use core::str;

use crate::{
    package::{AppKind, Package},
    validation::{
        read_u16, read_u32, read_u64, valid_app_id, valid_display_name, valid_version, DIGEST_LEN,
        MAX_APP_ID_LEN, MAX_DISPLAY_NAME_LEN, MAX_EXECUTABLE_LEN, MAX_GENERATION_FILENAME_LEN,
        MAX_INSTALLED_APPS, MAX_REGISTRY_LEN, MAX_VERSION_LEN,
    },
};

pub const REGISTRY_MAGIC: [u8; 4] = *b"GKI\0";
pub const REGISTRY_VERSION: u16 = 1;
const REGISTRY_HEADER_SIZE: usize = 12;
const ENTRY_HEADER_SIZE: usize = 88;
const PROVENANCE_PACKAGE: u16 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutableGeneration {
    pub filename: String,
    pub digest: [u8; DIGEST_LEN],
    pub length: u64,
}

impl ExecutableGeneration {
    pub fn new(app_id: &str, digest: [u8; DIGEST_LEN], length: u64) -> Result<Self, MutationError> {
        Ok(Self {
            filename: generation_filename(app_id, &digest)?,
            digest,
            length,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Provenance {
    pub package_digest: [u8; DIGEST_LEN],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstalledApp {
    pub app_id: String,
    pub display_name: String,
    pub version: String,
    pub kind: AppKind,
    pub executable: ExecutableGeneration,
    pub provenance: Provenance,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InstalledRegistry {
    entries: Vec<InstalledApp>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryError {
    SnapshotTooLarge {
        length: usize,
        maximum: usize,
    },
    TruncatedHeader,
    BadMagic,
    UnsupportedVersion(u16),
    UnknownHeaderFlags(u16),
    TooManyEntries {
        count: usize,
        maximum: usize,
    },
    TruncatedEntryHeader {
        index: usize,
    },
    UnknownEntryFlags {
        index: usize,
        bits: u16,
    },
    UnknownKind {
        index: usize,
        value: u16,
    },
    UnknownProvenance {
        index: usize,
        value: u16,
    },
    UnknownReservedBits {
        index: usize,
        bits: u16,
    },
    FieldTooLong {
        index: usize,
    },
    TruncatedEntry {
        index: usize,
    },
    InvalidUtf8 {
        index: usize,
    },
    InvalidAppId {
        index: usize,
    },
    InvalidDisplayName {
        index: usize,
    },
    InvalidVersion {
        index: usize,
    },
    InvalidExecutableLength {
        index: usize,
        length: u64,
        maximum: usize,
    },
    InvalidGenerationFilename {
        index: usize,
    },
    NonCanonicalOrder {
        index: usize,
    },
    DuplicateGenerationFilename {
        first_index: usize,
        duplicate_index: usize,
    },
    TrailingData,
    SizeOverflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutationError {
    InvalidAppId,
    ReservedSystemId,
    AlreadyInstalled,
    NotInstalled,
    RegistryFull,
    ExecutableLengthMismatch { package: usize, generation: u64 },
    InvalidGenerationFilename,
    GenerationFilenameCollision,
}

impl InstalledRegistry {
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, RegistryError> {
        if bytes.len() > MAX_REGISTRY_LEN {
            return Err(RegistryError::SnapshotTooLarge {
                length: bytes.len(),
                maximum: MAX_REGISTRY_LEN,
            });
        }
        if bytes.len() < REGISTRY_HEADER_SIZE {
            return Err(RegistryError::TruncatedHeader);
        }
        if bytes[..4] != REGISTRY_MAGIC {
            return Err(RegistryError::BadMagic);
        }
        let version = read_u16(bytes, 4);
        if version != REGISTRY_VERSION {
            return Err(RegistryError::UnsupportedVersion(version));
        }
        let flags = read_u16(bytes, 6);
        if flags != 0 {
            return Err(RegistryError::UnknownHeaderFlags(flags));
        }
        let count = read_u32(bytes, 8) as usize;
        if count > MAX_INSTALLED_APPS {
            return Err(RegistryError::TooManyEntries {
                count,
                maximum: MAX_INSTALLED_APPS,
            });
        }

        let mut entries: Vec<InstalledApp> = Vec::with_capacity(count);
        let mut cursor = REGISTRY_HEADER_SIZE;
        for index in 0..count {
            let (entry, next) = parse_entry(bytes, cursor, index)?;
            if let Some(previous) = entries.last() {
                if previous.app_id.as_str() >= entry.app_id.as_str() {
                    return Err(RegistryError::NonCanonicalOrder { index });
                }
            }
            if let Some(first_index) = entries
                .iter()
                .position(|previous| previous.executable.filename == entry.executable.filename)
            {
                return Err(RegistryError::DuplicateGenerationFilename {
                    first_index,
                    duplicate_index: index,
                });
            }
            entries.push(entry);
            cursor = next;
        }
        if cursor != bytes.len() {
            return Err(RegistryError::TrailingData);
        }
        Ok(Self { entries })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&REGISTRY_MAGIC);
        bytes.extend_from_slice(&REGISTRY_VERSION.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&(self.entries.len() as u32).to_le_bytes());
        for entry in &self.entries {
            bytes.extend_from_slice(&(entry.app_id.len() as u16).to_le_bytes());
            bytes.extend_from_slice(&(entry.display_name.len() as u16).to_le_bytes());
            bytes.extend_from_slice(&(entry.version.len() as u16).to_le_bytes());
            bytes.extend_from_slice(&(entry.executable.filename.len() as u16).to_le_bytes());
            bytes.extend_from_slice(&(entry.kind as u16).to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&PROVENANCE_PACKAGE.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&entry.executable.length.to_le_bytes());
            bytes.extend_from_slice(&entry.executable.digest);
            bytes.extend_from_slice(&entry.provenance.package_digest);
            bytes.extend_from_slice(entry.app_id.as_bytes());
            bytes.extend_from_slice(entry.display_name.as_bytes());
            bytes.extend_from_slice(entry.version.as_bytes());
            bytes.extend_from_slice(entry.executable.filename.as_bytes());
        }
        bytes
    }

    pub fn entries(&self) -> &[InstalledApp] {
        &self.entries
    }

    pub fn get(&self, app_id: &str) -> Option<&InstalledApp> {
        self.find(app_id).ok().map(|index| &self.entries[index])
    }

    pub fn install(
        &mut self,
        package: &Package<'_>,
        executable: ExecutableGeneration,
        provenance: Provenance,
        reserved_system_ids: &[&str],
    ) -> Result<(), MutationError> {
        self.check_mutation(package, &executable, reserved_system_ids)?;
        let index = match self.find(package.app_id) {
            Ok(_) => return Err(MutationError::AlreadyInstalled),
            Err(index) => index,
        };
        if self.entries.len() >= MAX_INSTALLED_APPS {
            return Err(MutationError::RegistryFull);
        }
        let entry = owned_entry(package, executable, provenance);
        self.entries.insert(index, entry);
        Ok(())
    }

    pub fn update(
        &mut self,
        package: &Package<'_>,
        executable: ExecutableGeneration,
        provenance: Provenance,
        reserved_system_ids: &[&str],
    ) -> Result<(), MutationError> {
        self.check_mutation(package, &executable, reserved_system_ids)?;
        let index = self
            .find(package.app_id)
            .map_err(|_| MutationError::NotInstalled)?;
        let entry = owned_entry(package, executable, provenance);
        self.entries[index] = entry;
        Ok(())
    }

    pub fn remove(
        &mut self,
        app_id: &str,
        reserved_system_ids: &[&str],
    ) -> Result<InstalledApp, MutationError> {
        check_target_id(app_id, reserved_system_ids)?;
        let index = self.find(app_id).map_err(|_| MutationError::NotInstalled)?;
        Ok(self.entries.remove(index))
    }

    fn find(&self, app_id: &str) -> Result<usize, usize> {
        self.entries
            .binary_search_by(|entry| entry.app_id.as_str().cmp(app_id))
    }

    fn check_mutation(
        &self,
        package: &Package<'_>,
        executable: &ExecutableGeneration,
        reserved_system_ids: &[&str],
    ) -> Result<(), MutationError> {
        check_target_id(package.app_id, reserved_system_ids)?;
        if executable.length != package.executable.len() as u64 {
            return Err(MutationError::ExecutableLengthMismatch {
                package: package.executable.len(),
                generation: executable.length,
            });
        }
        let expected = generation_filename(package.app_id, &executable.digest)?;
        if executable.filename != expected {
            return Err(MutationError::InvalidGenerationFilename);
        }
        if self.entries.iter().any(|entry| {
            entry.app_id != package.app_id && entry.executable.filename == executable.filename
        }) {
            return Err(MutationError::GenerationFilenameCollision);
        }
        Ok(())
    }
}

pub fn generation_filename(
    app_id: &str,
    digest: &[u8; DIGEST_LEN],
) -> Result<String, MutationError> {
    if !valid_app_id(app_id) {
        return Err(MutationError::InvalidAppId);
    }
    Ok(generation_filename_validated(app_id, digest))
}

fn generation_filename_validated(app_id: &str, digest: &[u8; DIGEST_LEN]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut filename = String::with_capacity(app_id.len() + 69);
    filename.push_str(app_id);
    filename.push('-');
    for byte in digest {
        filename.push(HEX[(byte >> 4) as usize] as char);
        filename.push(HEX[(byte & 0x0f) as usize] as char);
    }
    filename.push_str(".elf");
    filename
}

fn check_target_id(app_id: &str, reserved_system_ids: &[&str]) -> Result<(), MutationError> {
    if !valid_app_id(app_id) {
        return Err(MutationError::InvalidAppId);
    }
    if reserved_system_ids.contains(&app_id) {
        return Err(MutationError::ReservedSystemId);
    }
    Ok(())
}

fn owned_entry(
    package: &Package<'_>,
    executable: ExecutableGeneration,
    provenance: Provenance,
) -> InstalledApp {
    InstalledApp {
        app_id: String::from(package.app_id),
        display_name: String::from(package.display_name),
        version: String::from(package.version),
        kind: package.kind,
        executable,
        provenance,
    }
}

fn parse_entry(
    bytes: &[u8],
    cursor: usize,
    index: usize,
) -> Result<(InstalledApp, usize), RegistryError> {
    let header_end = cursor
        .checked_add(ENTRY_HEADER_SIZE)
        .ok_or(RegistryError::SizeOverflow)?;
    if header_end > bytes.len() {
        return Err(RegistryError::TruncatedEntryHeader { index });
    }
    let app_id_len = read_u16(bytes, cursor) as usize;
    let display_name_len = read_u16(bytes, cursor + 2) as usize;
    let version_len = read_u16(bytes, cursor + 4) as usize;
    let filename_len = read_u16(bytes, cursor + 6) as usize;
    if app_id_len > MAX_APP_ID_LEN
        || display_name_len > MAX_DISPLAY_NAME_LEN
        || version_len > MAX_VERSION_LEN
        || filename_len > MAX_GENERATION_FILENAME_LEN
    {
        return Err(RegistryError::FieldTooLong { index });
    }
    let kind_value = read_u16(bytes, cursor + 8);
    let kind = AppKind::from_wire(kind_value).ok_or(RegistryError::UnknownKind {
        index,
        value: kind_value,
    })?;
    let flags = read_u16(bytes, cursor + 10);
    if flags != 0 {
        return Err(RegistryError::UnknownEntryFlags { index, bits: flags });
    }
    let provenance_kind = read_u16(bytes, cursor + 12);
    if provenance_kind != PROVENANCE_PACKAGE {
        return Err(RegistryError::UnknownProvenance {
            index,
            value: provenance_kind,
        });
    }
    let reserved = read_u16(bytes, cursor + 14);
    if reserved != 0 {
        return Err(RegistryError::UnknownReservedBits {
            index,
            bits: reserved,
        });
    }
    let executable_length = read_u64(bytes, cursor + 16);
    if executable_length == 0 || executable_length > MAX_EXECUTABLE_LEN as u64 {
        return Err(RegistryError::InvalidExecutableLength {
            index,
            length: executable_length,
            maximum: MAX_EXECUTABLE_LEN,
        });
    }
    let mut executable_digest = [0; DIGEST_LEN];
    executable_digest.copy_from_slice(&bytes[cursor + 24..cursor + 56]);
    let mut package_digest = [0; DIGEST_LEN];
    package_digest.copy_from_slice(&bytes[cursor + 56..cursor + 88]);

    let fields_len = app_id_len
        .checked_add(display_name_len)
        .and_then(|length| length.checked_add(version_len))
        .and_then(|length| length.checked_add(filename_len))
        .ok_or(RegistryError::SizeOverflow)?;
    let entry_end = header_end
        .checked_add(fields_len)
        .ok_or(RegistryError::SizeOverflow)?;
    if entry_end > bytes.len() {
        return Err(RegistryError::TruncatedEntry { index });
    }
    let display_start = header_end + app_id_len;
    let version_start = display_start + display_name_len;
    let filename_start = version_start + version_len;
    let app_id = str::from_utf8(&bytes[header_end..display_start])
        .map_err(|_| RegistryError::InvalidUtf8 { index })?;
    let display_name = str::from_utf8(&bytes[display_start..version_start])
        .map_err(|_| RegistryError::InvalidUtf8 { index })?;
    let version = str::from_utf8(&bytes[version_start..filename_start])
        .map_err(|_| RegistryError::InvalidUtf8 { index })?;
    let filename = str::from_utf8(&bytes[filename_start..entry_end])
        .map_err(|_| RegistryError::InvalidUtf8 { index })?;
    if !valid_app_id(app_id) {
        return Err(RegistryError::InvalidAppId { index });
    }
    if !valid_display_name(display_name) {
        return Err(RegistryError::InvalidDisplayName { index });
    }
    if !valid_version(version) {
        return Err(RegistryError::InvalidVersion { index });
    }
    if filename != generation_filename_validated(app_id, &executable_digest) {
        return Err(RegistryError::InvalidGenerationFilename { index });
    }

    Ok((
        InstalledApp {
            app_id: String::from(app_id),
            display_name: String::from(display_name),
            version: String::from(version),
            kind,
            executable: ExecutableGeneration {
                filename: String::from(filename),
                digest: executable_digest,
                length: executable_length,
            },
            provenance: Provenance { package_digest },
        },
        entry_end,
    ))
}
