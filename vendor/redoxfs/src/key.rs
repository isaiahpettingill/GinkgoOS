//! On-disk key-slot layout retained for RedoxFS format compatibility.
//!
//! GinkgoOS currently supports unencrypted RedoxFS images only, so the
//! cryptographic key-generation and cipher routines are intentionally omitted.

#[derive(Clone, Copy, Default)]
#[repr(transparent)]
pub struct Key([u8; 16]);

#[derive(Clone, Copy, Default)]
#[repr(transparent)]
pub struct EncryptedKey([u8; 16]);

#[derive(Clone, Copy, Default)]
#[repr(transparent)]
pub struct Salt([u8; 16]);

#[derive(Clone, Copy, Default)]
#[repr(C, packed)]
pub struct KeySlot {
    salt: Salt,
    encrypted_keys: (EncryptedKey, EncryptedKey),
}
