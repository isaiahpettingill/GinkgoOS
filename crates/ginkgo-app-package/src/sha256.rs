/// Maintained, allocation-free incremental SHA-256 implementation.
pub use hmac_sha256::Hash as Sha256;

/// Computes the SHA-256 digest of one byte slice.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::hash(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapper_matches_known_vector_and_incremental_api() {
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(sha256(b"abc"), expected);

        let mut hasher = Sha256::new();
        hasher.update(b"a");
        hasher.update(b"bc");
        assert_eq!(hasher.finalize(), expected);
    }
}
