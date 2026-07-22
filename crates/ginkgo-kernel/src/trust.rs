//! Signed system-bundle manifest verification.
//!
//! The kernel trusts one Ed25519 public key compiled into the boot image. A
//! manifest signature authenticates paths, lengths, and SHA-256 digests; each
//! registry or executable is checked after reading it from persistent storage and
//! before parsing or loading. Authority still comes from capabilities and registry
//! policy—the signature identifies approved code, not a Unix user.

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

pub const MAGIC: [u8; 4] = *b"GKTM";
pub const VERSION: u16 = 1;
pub const HEADER_SIZE: usize = 8;
pub const RECORD_HEADER_SIZE: usize = 2 + 2 + 8 + 32;
pub const MAX_RECORDS: usize = 64;
pub const MAX_PATH_BYTES: usize = 255;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustError {
    InvalidPublicKey,
    InvalidSignature,
    Truncated,
    BadMagic,
    UnsupportedVersion(u16),
    ReservedBits(u16),
    TooManyRecords(u16),
    InvalidPath,
    DuplicatePath,
    TrailingData,
    MissingArtifact,
    LengthMismatch,
    DigestMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Record<'a> {
    path: &'a str,
    length: u64,
    digest: [u8; 32],
}

/// An authenticated, fully validated borrowed manifest.
pub struct TrustedManifest<'a> {
    bytes: &'a [u8],
    record_count: usize,
}

impl<'a> TrustedManifest<'a> {
    pub fn verify(
        bytes: &'a [u8],
        signature: &[u8; 64],
        public_key: &[u8; 32],
    ) -> Result<Self, TrustError> {
        let key = VerifyingKey::from_bytes(public_key).map_err(|_| TrustError::InvalidPublicKey)?;
        let signature = Signature::from_bytes(signature);
        key.verify_strict(bytes, &signature)
            .map_err(|_| TrustError::InvalidSignature)?;
        Self::parse_authenticated(bytes)
    }

    fn parse_authenticated(bytes: &'a [u8]) -> Result<Self, TrustError> {
        if bytes.len() < HEADER_SIZE {
            return Err(TrustError::Truncated);
        }
        if bytes[..4] != MAGIC {
            return Err(TrustError::BadMagic);
        }
        let version = read_u16(bytes, 4)?;
        if version != VERSION {
            return Err(TrustError::UnsupportedVersion(version));
        }
        let count = read_u16(bytes, 6)?;
        if usize::from(count) > MAX_RECORDS {
            return Err(TrustError::TooManyRecords(count));
        }

        let manifest = Self {
            bytes,
            record_count: usize::from(count),
        };
        let mut cursor = HEADER_SIZE;
        for index in 0..manifest.record_count {
            let (record, next) = parse_record(bytes, cursor)?;
            for previous in manifest.records().take(index) {
                if previous.path == record.path {
                    return Err(TrustError::DuplicatePath);
                }
            }
            cursor = next;
        }
        if cursor != bytes.len() {
            return Err(TrustError::TrailingData);
        }
        Ok(manifest)
    }

    pub fn verify_artifact(&self, path: &str, artifact: &[u8]) -> Result<(), TrustError> {
        let record = self
            .records()
            .find(|record| record.path == path)
            .ok_or(TrustError::MissingArtifact)?;
        if record.length != artifact.len() as u64 {
            return Err(TrustError::LengthMismatch);
        }
        let actual: [u8; 32] = Sha256::digest(artifact).into();
        if actual != record.digest {
            return Err(TrustError::DigestMismatch);
        }
        Ok(())
    }

    pub const fn len(&self) -> usize {
        self.record_count
    }

    fn records(&self) -> Records<'a> {
        Records {
            bytes: self.bytes,
            cursor: HEADER_SIZE,
            remaining: self.record_count,
        }
    }
}

struct Records<'a> {
    bytes: &'a [u8],
    cursor: usize,
    remaining: usize,
}

impl<'a> Iterator for Records<'a> {
    type Item = Record<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let (record, next) = parse_record(self.bytes, self.cursor).ok()?;
        self.cursor = next;
        self.remaining -= 1;
        Some(record)
    }
}

fn parse_record(bytes: &[u8], cursor: usize) -> Result<(Record<'_>, usize), TrustError> {
    let header_end = cursor
        .checked_add(RECORD_HEADER_SIZE)
        .ok_or(TrustError::Truncated)?;
    let header = bytes.get(cursor..header_end).ok_or(TrustError::Truncated)?;
    let path_len = usize::from(u16::from_le_bytes([header[0], header[1]]));
    let reserved = u16::from_le_bytes([header[2], header[3]]);
    if reserved != 0 {
        return Err(TrustError::ReservedBits(reserved));
    }
    if path_len == 0 || path_len > MAX_PATH_BYTES {
        return Err(TrustError::InvalidPath);
    }
    let path_end = header_end
        .checked_add(path_len)
        .ok_or(TrustError::Truncated)?;
    let path_bytes = bytes
        .get(header_end..path_end)
        .ok_or(TrustError::Truncated)?;
    let path = core::str::from_utf8(path_bytes).map_err(|_| TrustError::InvalidPath)?;
    if !valid_path(path) {
        return Err(TrustError::InvalidPath);
    }
    let length = u64::from_le_bytes(header[4..12].try_into().expect("fixed record length"));
    let mut digest = [0; 32];
    digest.copy_from_slice(&header[12..44]);
    Ok((
        Record {
            path,
            length,
            digest,
        },
        path_end,
    ))
}

fn valid_path(path: &str) -> bool {
    path.starts_with('/')
        && path.len() > 1
        && !path.ends_with('/')
        && path
            .split('/')
            .skip(1)
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, TrustError> {
    let value = bytes.get(offset..offset + 2).ok_or(TrustError::Truncated)?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn signed_manifest(path: &str, artifact: &[u8]) -> (Vec<u8>, [u8; 64], [u8; 32]) {
        let mut bytes = Vec::from(MAGIC);
        bytes.extend_from_slice(&VERSION.to_le_bytes());
        bytes.extend_from_slice(&1_u16.to_le_bytes());
        bytes.extend_from_slice(&(path.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&0_u16.to_le_bytes());
        bytes.extend_from_slice(&(artifact.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&Sha256::digest(artifact));
        bytes.extend_from_slice(path.as_bytes());
        let key = SigningKey::from_bytes(&[0x39; 32]);
        let signature = key.sign(&bytes).to_bytes();
        (bytes, signature, key.verifying_key().to_bytes())
    }

    #[test]
    fn authenticates_exact_artifact() {
        let (bytes, signature, public_key) = signed_manifest("/desktop.elf", b"elf");
        let manifest = TrustedManifest::verify(&bytes, &signature, &public_key).unwrap();
        assert_eq!(manifest.verify_artifact("/desktop.elf", b"elf"), Ok(()));
        assert_eq!(
            manifest.verify_artifact("/desktop.elf", b"ELF"),
            Err(TrustError::DigestMismatch)
        );
    }

    #[test]
    fn rejects_tampered_manifest_signature() {
        let (mut bytes, signature, public_key) = signed_manifest("/programs.gkr", b"registry");
        *bytes.last_mut().unwrap() ^= 1;
        assert!(matches!(
            TrustedManifest::verify(&bytes, &signature, &public_key),
            Err(TrustError::InvalidSignature)
        ));
    }
}
