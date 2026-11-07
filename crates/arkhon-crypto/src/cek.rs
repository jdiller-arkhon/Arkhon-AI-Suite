//! The content-encryption key (CEK) for one engine release.

use std::fmt;

use rand_core::{CryptoRngCore, OsRng};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A 256-bit AES content-encryption key.
///
/// * Wiped from memory when dropped ([`ZeroizeOnDrop`]).
/// * `Debug` never prints the key bytes.
/// * Not `Clone`/`Copy`, so copies are explicit ([`Cek::from_bytes`] of [`Cek::expose_secret`]).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Cek([u8; 32]);

impl Cek {
    /// Length of a CEK in bytes.
    pub const LEN: usize = 32;

    /// A fresh random key from the operating system's CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        Self::generate_with(&mut OsRng)
    }

    /// A fresh random key from `rng` (tests use a seeded RNG for reproducible vectors).
    #[must_use]
    pub fn generate_with(rng: &mut impl CryptoRngCore) -> Self {
        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key);
        Self(key)
    }

    /// Wrap existing key bytes. The caller should zeroize its own copy.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Copy key bytes from a slice straight into the key (no stray stack copy). `None` unless the
    /// slice is exactly 32 bytes.
    #[must_use]
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::LEN {
            return None;
        }
        let mut cek = Self([0; 32]);
        cek.0.copy_from_slice(bytes);
        Some(cek)
    }

    /// Borrow the raw key. Only for key wrapping and the cipher; never log or persist it.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for Cek {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Cek(<redacted>)")
    }
}

impl PartialEq for Cek {
    /// Constant-time comparison.
    fn eq(&self, other: &Self) -> bool {
        self.0
            .iter()
            .zip(other.0.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
    }
}

impl Eq for Cek {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        let cek = Cek::from_bytes([0xab; 32]);
        let shown = format!("{cek:?}");
        assert_eq!(shown, "Cek(<redacted>)");
        assert!(!shown.to_lowercase().contains("ab"));
    }

    #[test]
    fn generate_is_random_and_eq_works() {
        let a = Cek::generate();
        let b = Cek::generate();
        assert_ne!(a, b);
        let a2 = Cek::from_bytes(*a.expose_secret());
        assert_eq!(a, a2);
        assert_eq!(Cek::from_slice(a.expose_secret()).unwrap(), a);
        assert!(Cek::from_slice(&[0; 31]).is_none());
    }

    #[test]
    fn zeroize_clears_bytes() {
        let mut cek = Cek::from_bytes([7; 32]);
        cek.zeroize();
        assert_eq!(cek.expose_secret(), &[0; 32]);
    }
}
