//! Hardware-seeded kernel cryptographic random generator.
//!
//! GinkgoOS deliberately exposes random bytes through process-local capabilities,
//! not direct CPU instructions or a Unix-style global device namespace. The pool
//! refuses to initialize unless RDSEED or RDRAND produces 256 bits; timing and
//! boot-specific values are mixed only as defense in depth and receive no entropy
//! credit.

use core::arch::{asm, x86_64::__cpuid, x86_64::__cpuid_count};

use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use sha2::{Digest, Sha256};

const RDRAND_BIT: u32 = 1 << 30;
const RDSEED_BIT: u32 = 1 << 18;
const SEED_WORDS: usize = 4;
const RETRIES_PER_WORD: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntropyError {
    NoHardwareSource,
    HardwareSourceFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HardwareSource {
    Rdseed,
    Rdrand,
}

/// One boot's non-clonable kernel CSPRNG state.
pub struct EntropyPool {
    generator: ChaCha20Rng,
    generated_bytes: u64,
}

impl EntropyPool {
    /// Seeds ChaCha20 from 256 hardware-generated bits plus boot-specific context.
    pub fn initialize(tsc_frequency: u64, boot_context: u64) -> Result<Self, EntropyError> {
        let source = hardware_source().ok_or(EntropyError::NoHardwareSource)?;
        let mut hasher = Sha256::new();
        hasher.update(b"GinkgoOS entropy seed v1\0");
        hasher.update(tsc_frequency.to_le_bytes());
        hasher.update(boot_context.to_le_bytes());
        for index in 0..SEED_WORDS {
            let word = hardware_word(source).ok_or(EntropyError::HardwareSourceFailed)?;
            hasher.update(word.to_le_bytes());
            hasher.update(read_tsc().to_le_bytes());
            hasher.update((index as u64).to_le_bytes());
        }
        let seed: [u8; 32] = hasher.finalize().into();
        Ok(Self {
            generator: ChaCha20Rng::from_seed(seed),
            generated_bytes: 0,
        })
    }

    /// Fills a kernel-owned buffer with cryptographic random bytes.
    pub fn fill_bytes(&mut self, output: &mut [u8]) {
        self.generator.fill_bytes(output);
        self.generated_bytes = self.generated_bytes.saturating_add(output.len() as u64);
    }

    pub fn next_u64(&mut self) -> u64 {
        self.generated_bytes = self.generated_bytes.saturating_add(8);
        self.generator.next_u64()
    }

    pub const fn generated_bytes(&self) -> u64 {
        self.generated_bytes
    }
}

fn hardware_source() -> Option<HardwareSource> {
    let leaf0 = __cpuid(0);
    if leaf0.eax >= 7 && __cpuid_count(7, 0).ebx & RDSEED_BIT != 0 {
        Some(HardwareSource::Rdseed)
    } else if leaf0.eax >= 1 && __cpuid(1).ecx & RDRAND_BIT != 0 {
        Some(HardwareSource::Rdrand)
    } else {
        None
    }
}

fn hardware_word(source: HardwareSource) -> Option<u64> {
    for _ in 0..RETRIES_PER_WORD {
        let word: u64;
        let success: u8;
        unsafe {
            match source {
                HardwareSource::Rdseed => asm!(
                    "rdseed {word}",
                    "setc {success}",
                    word = out(reg) word,
                    success = out(reg_byte) success,
                    options(nostack),
                ),
                HardwareSource::Rdrand => asm!(
                    "rdrand {word}",
                    "setc {success}",
                    word = out(reg) word,
                    success = out(reg_byte) success,
                    options(nostack),
                ),
            }
        }
        if success != 0 {
            return Some(word);
        }
        core::hint::spin_loop();
    }
    None
}

fn read_tsc() -> u64 {
    let low: u32;
    let high: u32;
    unsafe { asm!("rdtsc", out("eax") low, out("edx") high, options(nomem, nostack)) };
    (u64::from(high) << 32) | u64::from(low)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_selection_requires_an_advertised_instruction() {
        assert_eq!(select_source(false, false), None);
        assert_eq!(select_source(false, true), Some(HardwareSource::Rdrand));
        assert_eq!(select_source(true, true), Some(HardwareSource::Rdseed));
    }

    const fn select_source(rdseed: bool, rdrand: bool) -> Option<HardwareSource> {
        if rdseed {
            Some(HardwareSource::Rdseed)
        } else if rdrand {
            Some(HardwareSource::Rdrand)
        } else {
            None
        }
    }

    #[test]
    fn deterministic_test_seed_produces_nonrepeating_output() {
        let mut pool = EntropyPool {
            generator: ChaCha20Rng::from_seed([0x5a; 32]),
            generated_bytes: 0,
        };
        let first = pool.next_u64();
        let second = pool.next_u64();
        assert_ne!(first, second);
        assert_eq!(pool.generated_bytes(), 16);
    }
}
