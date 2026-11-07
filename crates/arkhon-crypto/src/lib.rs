//! Chunked AES-256-GCM model encryption, canonical encoding and release signing.
//!
//! * [`Cek`]: a 256-bit content-encryption key that is wiped from memory when dropped.
//! * [`model`]: the encrypted model-file format (ADR-0008). Encrypt with [`model::encrypt_model`],
//!   decrypt straight into memory with [`model::decrypt_model_to_vec`]. There is deliberately no
//!   "decrypt to path" helper: plaintext weights must never touch the disk.
//! * [`codec`]: the deterministic length-prefixed binary encoding shared with `arkhon-license`
//!   (ADR-0007). Decoders reject every non-canonical byte string.
//! * [`release`]: release manifests signed by an issuing key. This crate checks the manifest
//!   signature against a given issuing public key; checking that the issuing key is certified by the
//!   root and not revoked lives in `arkhon-license` (`verify_release`), next to the other chain checks.
//!
//! Signatures are Ed25519 ([`ed25519_dalek`], re-exported) over a domain-separation tag followed by
//! canonical bytes (see [`codec::domain`]).

pub mod cek;
pub mod codec;
pub mod model;
pub mod release;

pub use cek::Cek;
pub use ed25519_dalek;

/// Crate version, exposed for build/diagnostic reporting.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// SHA-256 of `data`.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(data).into()
}

/// Lower-case hex encoding (for printing public keys and digests; never for secrets in logs).
#[must_use]
pub fn to_hex(data: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Parse lower- or upper-case hex. Returns `None` on odd length or a non-hex character.
#[must_use]
pub fn from_hex(text: &str) -> Option<Vec<u8>> {
    let text = text.trim();
    if text.len() % 2 != 0 {
        return None;
    }
    text.as_bytes()
        .chunks(2)
        .map(|pair| {
            let hi = char::from(pair[0]).to_digit(16)?;
            let lo = char::from(pair[1]).to_digit(16)?;
            u8::try_from(hi * 16 + lo).ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_set() {
        assert_ne!(VERSION, "");
    }

    #[test]
    fn hex_round_trip_and_rejects_bad_input() {
        let data = [0u8, 1, 0xab, 0xff];
        assert_eq!(to_hex(&data), "0001abff");
        assert_eq!(from_hex("0001ABff").unwrap(), data);
        assert!(from_hex("abc").is_none());
        assert!(from_hex("zz").is_none());
        assert_eq!(from_hex(" 00 \n").unwrap(), vec![0]);
    }

    #[test]
    fn sha256_known_answer() {
        assert_eq!(
            to_hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
