//! Signed release manifests.
//!
//! A manifest lists every encrypted file in an engine release with its ciphertext size and SHA-256.
//! The issuing key signs `domain::RELEASE_MANIFEST || canonical bytes`. This module checks the
//! signature against an issuing public key you already trust; `arkhon_license::verify_release`
//! first establishes that trust from the root key, certificate and revocation list.

use std::collections::BTreeMap;
use std::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::codec::{domain, require_canonical, DecodeError, Decoder, Encoder};

const KIND: [u8; 4] = *b"ARRM";
const VERSION: u16 = 1;

/// One encrypted file in a release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseFile {
    /// Ciphertext size in bytes (header included).
    pub size: u64,
    /// SHA-256 of the ciphertext.
    pub sha256: [u8; 32],
}

/// The unsigned contents of a release manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseManifest {
    /// Random release id.
    pub release_id: [u8; 16],
    /// Engine name, e.g. `"inbox"`. Matched against license entitlements.
    pub engine: String,
    /// Human-readable version, e.g. `"1.4.0"`.
    pub version: String,
    /// Release date (Unix seconds). Compared with a license's update-window end.
    pub released_at: u64,
    /// Files by name (sorted, unique).
    pub files: BTreeMap<String, ReleaseFile>,
}

/// Why a manifest was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReleaseError {
    /// The manifest bytes are malformed or non-canonical.
    Decode(DecodeError),
    /// The signature does not match the issuing key.
    BadSignature,
    /// The file is not listed in the manifest.
    UnknownFile(String),
    /// The file's size or hash differs from the manifest.
    FileMismatch(String),
}

impl fmt::Display for ReleaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReleaseError::Decode(e) => write!(f, "The release description is unreadable. {e}"),
            ReleaseError::BadSignature => {
                f.write_str("This update isn't signed by Arkhon. It was not installed.")
            }
            ReleaseError::UnknownFile(name) => {
                write!(f, "\"{name}\" isn't part of this release.")
            }
            ReleaseError::FileMismatch(name) => write!(
                f,
                "\"{name}\" is damaged or has been changed. Download the update again."
            ),
        }
    }
}

impl std::error::Error for ReleaseError {}

impl From<DecodeError> for ReleaseError {
    fn from(e: DecodeError) -> Self {
        ReleaseError::Decode(e)
    }
}

impl ReleaseManifest {
    fn encode_into(&self, e: &mut Encoder) {
        e.array(&self.release_id)
            .str(&self.engine)
            .str(&self.version)
            .u64(self.released_at)
            .len(self.files.len());
        for (name, f) in &self.files {
            e.str(name).u64(f.size).array(&f.sha256);
        }
    }

    fn decode_from(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let release_id = d.array()?;
        let engine = d.string()?;
        let version = d.string()?;
        let released_at = d.u64()?;
        let n = d.len(4 + 8 + 32)?;
        let mut files = BTreeMap::new();
        let mut prev: Option<String> = None;
        for _ in 0..n {
            let name = d.string()?;
            if prev.as_ref().is_some_and(|p| *p >= name) {
                return Err(DecodeError::NotSorted);
            }
            let size = d.u64()?;
            let sha256 = d.array()?;
            prev = Some(name.clone());
            files.insert(name, ReleaseFile { size, sha256 });
        }
        Ok(Self {
            release_id,
            engine,
            version,
            released_at,
            files,
        })
    }

    /// Canonical bytes of the unsigned manifest.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new(KIND, VERSION);
        self.encode_into(&mut e);
        e.finish()
    }

    /// Sign with an issuing key.
    #[must_use]
    pub fn sign(self, issuing_key: &SigningKey) -> SignedReleaseManifest {
        let msg = [domain::RELEASE_MANIFEST, &self.to_canonical_bytes()].concat();
        let signature = issuing_key.sign(&msg).to_bytes();
        SignedReleaseManifest {
            manifest: self,
            signature,
        }
    }
}

/// A manifest plus the issuing key's Ed25519 signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedReleaseManifest {
    /// The signed contents.
    pub manifest: ReleaseManifest,
    /// Ed25519 signature over `domain::RELEASE_MANIFEST || manifest canonical bytes`.
    pub signature: [u8; 64],
}

impl SignedReleaseManifest {
    /// Canonical bytes (manifest then signature).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new(KIND, VERSION);
        self.manifest.encode_into(&mut e);
        e.array(&self.signature);
        e.finish()
    }

    /// Parse canonical bytes, rejecting any non-canonical encoding. Does **not** check the signature.
    ///
    /// # Errors
    /// [`DecodeError`] for malformed or non-canonical input.
    pub fn from_bytes(data: &[u8]) -> Result<Self, DecodeError> {
        let mut d = Decoder::new(data, KIND, VERSION)?;
        let manifest = ReleaseManifest::decode_from(&mut d)?;
        let signature = d.array()?;
        d.finish()?;
        let out = Self {
            manifest,
            signature,
        };
        require_canonical(data, &out.to_bytes())?;
        Ok(out)
    }

    /// Check the signature against a trusted issuing public key.
    ///
    /// # Errors
    /// [`ReleaseError::BadSignature`].
    pub fn verify_signature(
        &self,
        issuing_key: &VerifyingKey,
    ) -> Result<&ReleaseManifest, ReleaseError> {
        let msg = [
            domain::RELEASE_MANIFEST,
            &self.manifest.to_canonical_bytes(),
        ]
        .concat();
        issuing_key
            .verify_strict(&msg, &Signature::from_bytes(&self.signature))
            .map_err(|_| ReleaseError::BadSignature)?;
        Ok(&self.manifest)
    }
}

impl ReleaseManifest {
    /// Check a downloaded encrypted file against this manifest.
    ///
    /// # Errors
    /// [`ReleaseError::UnknownFile`] or [`ReleaseError::FileMismatch`].
    pub fn check_file(&self, name: &str, ciphertext: &[u8]) -> Result<(), ReleaseError> {
        let entry = self
            .files
            .get(name)
            .ok_or_else(|| ReleaseError::UnknownFile(name.to_owned()))?;
        if entry.size != ciphertext.len() as u64 || entry.sha256 != crate::sha256(ciphertext) {
            return Err(ReleaseError::FileMismatch(name.to_owned()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn manifest() -> ReleaseManifest {
        let mut files = BTreeMap::new();
        files.insert(
            "weights.arkm".to_owned(),
            ReleaseFile {
                size: 3,
                sha256: crate::sha256(b"abc"),
            },
        );
        files.insert(
            "adapter.arkm".to_owned(),
            ReleaseFile {
                size: 0,
                sha256: crate::sha256(b""),
            },
        );
        ReleaseManifest {
            release_id: [7; 16],
            engine: "inbox".to_owned(),
            version: "1.0.0".to_owned(),
            released_at: 1_800_000_000,
            files,
        }
    }

    #[test]
    fn sign_round_trip_verify() {
        let signed = manifest().sign(&key(1));
        let bytes = signed.to_bytes();
        let back = SignedReleaseManifest::from_bytes(&bytes).unwrap();
        assert_eq!(back, signed);
        let m = back.verify_signature(&key(1).verifying_key()).unwrap();
        assert_eq!(m.engine, "inbox");
        assert_eq!(
            back.verify_signature(&key(2).verifying_key()).unwrap_err(),
            ReleaseError::BadSignature
        );
    }

    #[test]
    fn check_file_matches_hash_and_size() {
        let m = manifest();
        m.check_file("weights.arkm", b"abc").unwrap();
        assert_eq!(
            m.check_file("weights.arkm", b"abd").unwrap_err(),
            ReleaseError::FileMismatch("weights.arkm".into())
        );
        assert_eq!(
            m.check_file("nope", b"").unwrap_err(),
            ReleaseError::UnknownFile("nope".into())
        );
    }

    #[test]
    fn rejects_unsorted_files_and_trailing_bytes() {
        let signed = manifest().sign(&key(1));
        let mut bytes = signed.to_bytes();
        bytes.push(0);
        assert_eq!(
            SignedReleaseManifest::from_bytes(&bytes).unwrap_err(),
            DecodeError::TrailingBytes
        );
        // Hand-build a manifest with files out of order.
        let mut e = Encoder::new(KIND, VERSION);
        e.array(&[0; 16]).str("e").str("v").u64(0).u32(2);
        e.str("b").u64(0).array(&[0; 32]);
        e.str("a").u64(0).array(&[0; 32]);
        e.array(&[0; 64]);
        assert_eq!(
            SignedReleaseManifest::from_bytes(&e.finish()).unwrap_err(),
            DecodeError::NotSorted
        );
    }

    #[test]
    fn error_messages() {
        for e in [
            ReleaseError::Decode(DecodeError::Truncated),
            ReleaseError::BadSignature,
            ReleaseError::UnknownFile("a".into()),
            ReleaseError::FileMismatch("a".into()),
        ] {
            assert!(e.to_string().ends_with('.'));
        }
        assert_eq!(
            ReleaseError::from(DecodeError::Truncated),
            ReleaseError::Decode(DecodeError::Truncated)
        );
    }

    proptest! {
        #[test]
        fn prop_any_bit_flip_breaks_signed_manifest(pos in any::<prop::sample::Index>(), bit in 0u8..8) {
            let k = key(9);
            let mut bytes = manifest().sign(&k).to_bytes();
            let i = pos.index(bytes.len());
            bytes[i] ^= 1 << bit;
            let ok = SignedReleaseManifest::from_bytes(&bytes)
                .ok()
                .and_then(|m| m.verify_signature(&k.verifying_key()).ok().cloned());
            prop_assert!(ok.is_none());
        }

        #[test]
        fn prop_truncation_rejected(cut in any::<prop::sample::Index>()) {
            let bytes = manifest().sign(&key(9)).to_bytes();
            let keep = cut.index(bytes.len());
            prop_assert!(SignedReleaseManifest::from_bytes(&bytes[..keep]).is_err());
        }
    }
}
