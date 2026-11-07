//! Sealed local storage for the license, the revocation list and licensing state.
//!
//! # Design
//!
//! The state is encrypted to the computer's own device key, the same non-exportable P-256 key the
//! license is bound to (TPM, Secure Enclave or the software fallback). Sealing works like ECIES to
//! ourselves, so only the public half is needed to write and the device's ECDH is needed to read:
//!
//! ```text
//! eph      = fresh P-256 key (software, per write; secret dropped right after)
//! Z        = ECDH(eph, device_public)          == ECDH(device_secret, eph_public)
//! context  = MAGIC || eph_public || device_public
//! key      = HKDF-SHA256(ikm = Z, salt = MAGIC, info = "arkhon/v1/sealed-store" || context)
//! file     = MAGIC || eph_public (65) || nonce (12) || AES-256-GCM(key, nonce, state, aad = context)
//! ```
//!
//! Consequences:
//! * Copying the file to another computer fails to open: that computer's device key yields a
//!   different `Z` (and its public key changes the AAD).
//! * Editing any byte fails the GCM tag.
//! * Restoring an *older* copy of this file on the *same* computer is not prevented here; the
//!   monotonic parts (revocation-list version, last online check) are also bounded by the sealed
//!   clock and by the license server. A TPM NV counter would close this (planned with the TPM
//!   clock work).
//! * With the software device key the protection is only as strong as the software key's own
//!   storage secret (see `arkhon_tpm::software`).

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use arkhon_tpm::p256::ecdh::EphemeralSecret;
use arkhon_tpm::{parse_sec1, sec1_bytes, DeviceKey, SEC1_UNCOMPRESSED_LEN};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::fsutil;

const MAGIC: &[u8; 8] = b"ARKSTO01";
const INFO: &[u8] = b"arkhon/v1/sealed-store";
const HEADER_LEN: usize = 8 + SEC1_UNCOMPRESSED_LEN + 12;

/// Everything the runtime keeps between starts. Never holds customer content.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredState {
    /// Canonical license bytes (base64).
    pub license: String,
    /// Canonical revocation-list bytes (base64).
    pub revocation_list: String,
    /// Highest revocation-list version ever accepted here (only goes up).
    pub revocation_version_seen: u64,
    /// Last successful online check or renewal import (Unix seconds, trusted time).
    pub last_online: u64,
    /// Secret for the sealed clock store (base64, 32 bytes).
    pub clock_secret: String,
    /// License server used for activation, if any.
    pub server_url: Option<String>,
}

impl fmt::Debug for StoredState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredState")
            .field("revocation_version_seen", &self.revocation_version_seen)
            .field("last_online", &self.last_online)
            .field("server_url", &self.server_url)
            .finish_non_exhaustive()
    }
}

/// Why the sealed store couldn't be used.
#[derive(Debug)]
pub enum StoreError {
    /// Nothing stored yet (this computer was never activated, or was deactivated).
    NotFound,
    /// The file can't be opened with this computer's device key: moved from another computer,
    /// edited, or damaged.
    Unsealable,
    /// Reading or writing failed.
    Io(io::Error),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::NotFound => {
                f.write_str("Arkhon isn't activated on this computer yet. Activate it first.")
            }
            StoreError::Unsealable => f.write_str(
                "Arkhon's saved license on this computer can't be opened. It was copied from another computer or damaged. Activate Arkhon again.",
            ),
            StoreError::Io(e) => write!(f, "Couldn't read or save Arkhon's license data: {e}"),
        }
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StoreError::Io(e) => Some(e),
            _ => None,
        }
    }
}

fn context(eph: &[u8; SEC1_UNCOMPRESSED_LEN], device: &[u8; SEC1_UNCOMPRESSED_LEN]) -> Vec<u8> {
    [&MAGIC[..], eph, device].concat()
}

fn cipher(z: &[u8; 32], ctx: &[u8]) -> Aes256Gcm {
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(MAGIC), z)
        .expand(&[INFO, ctx].concat(), key.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    Aes256Gcm::new_from_slice(key.as_ref()).expect("key is 32 bytes")
}

/// Encrypt `plain` to `device` (see module docs).
///
/// # Panics
/// Never: AES-GCM encryption of an in-memory buffer cannot fail.
#[must_use]
pub fn seal(device: &dyn DeviceKey, plain: &[u8]) -> Vec<u8> {
    let eph = EphemeralSecret::random(&mut OsRng);
    let eph_pub = sec1_bytes(&eph.public_key());
    let shared = eph.diffie_hellman(&device.public_key());
    let mut z = Zeroizing::new([0u8; 32]);
    z.copy_from_slice(shared.raw_secret_bytes());
    drop(shared);
    let ctx = context(&eph_pub, &device.public_key_sec1());
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ct = cipher(&z, &ctx)
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plain,
                aad: &ctx,
            },
        )
        .expect("AES-GCM encryption of an in-memory buffer cannot fail");
    [&MAGIC[..], &eph_pub, &nonce, &ct].concat()
}

/// Decrypt data written by [`seal`] with `device`.
///
/// # Errors
/// [`StoreError::Unsealable`] for a wrong device, edited or truncated data; device errors map to
/// [`StoreError::Unsealable`] too (the caller can't do anything different).
pub fn unseal(device: &dyn DeviceKey, data: &[u8]) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    if data.len() < HEADER_LEN + 16 || &data[..8] != MAGIC {
        return Err(StoreError::Unsealable);
    }
    let mut eph_pub = [0u8; SEC1_UNCOMPRESSED_LEN];
    eph_pub.copy_from_slice(&data[8..8 + SEC1_UNCOMPRESSED_LEN]);
    let eph = parse_sec1(&eph_pub).map_err(|_| StoreError::Unsealable)?;
    let shared = device.ecdh(&eph).map_err(|_| StoreError::Unsealable)?;
    let ctx = context(&eph_pub, &device.public_key_sec1());
    let nonce = &data[8 + SEC1_UNCOMPRESSED_LEN..HEADER_LEN];
    cipher(shared.as_bytes(), &ctx)
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: &data[HEADER_LEN..],
                aad: &ctx,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| StoreError::Unsealable)
}

/// The sealed state file in the runtime's data directory.
#[derive(Debug, Clone)]
pub struct SealedStore {
    path: PathBuf,
}

impl SealedStore {
    /// File name inside the data directory.
    pub const FILE_NAME: &'static str = "license.sealed";

    /// The store in `dir`.
    #[must_use]
    pub fn in_dir(dir: &Path) -> Self {
        Self {
            path: dir.join(Self::FILE_NAME),
        }
    }

    /// Path of the sealed file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// True if a sealed file exists.
    #[must_use]
    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// Load and decrypt the state.
    ///
    /// # Errors
    /// [`StoreError`].
    pub fn load(&self, device: &dyn DeviceKey) -> Result<StoredState, StoreError> {
        let data = match std::fs::read(&self.path) {
            Ok(d) => d,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(StoreError::NotFound),
            Err(e) => return Err(StoreError::Io(e)),
        };
        let plain = unseal(device, &data)?;
        serde_json::from_slice(&plain).map_err(|_| StoreError::Unsealable)
    }

    /// Encrypt and atomically save the state.
    ///
    /// # Errors
    /// [`StoreError::Io`].
    ///
    /// # Panics
    /// Never: the state always serializes.
    pub fn save(&self, device: &dyn DeviceKey, state: &StoredState) -> Result<(), StoreError> {
        let plain = Zeroizing::new(serde_json::to_vec(state).expect("state serializes"));
        fsutil::replace_private(&self.path, &seal(device, &plain)).map_err(StoreError::Io)
    }

    /// Delete the state (deactivation).
    ///
    /// # Errors
    /// [`StoreError::Io`].
    pub fn remove(&self) -> Result<(), StoreError> {
        fsutil::remove_if_exists(&self.path).map_err(StoreError::Io)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsutil::test_dir::TestDir;
    use arkhon_tpm::SoftwareDeviceKey;

    fn state() -> StoredState {
        StoredState {
            license: "bGlj".into(),
            revocation_list: "cmw=".into(),
            revocation_version_seen: 3,
            last_online: 1_000,
            clock_secret: "c2Vj".into(),
            server_url: None,
        }
    }

    #[test]
    fn round_trip_and_wrong_device() {
        let dir = TestDir::new("store");
        let store = SealedStore::in_dir(dir.path());
        let dev = SoftwareDeviceKey::generate();
        assert!(matches!(store.load(&dev), Err(StoreError::NotFound)));
        store.save(&dev, &state()).unwrap();
        assert!(store.exists());
        assert_eq!(store.load(&dev).unwrap(), state());
        let other = SoftwareDeviceKey::generate();
        assert!(matches!(store.load(&other), Err(StoreError::Unsealable)));
        let dbg = format!("{:?}", state());
        assert!(!dbg.contains("bGlj") && !dbg.contains("c2Vj"));
        store.remove().unwrap();
        assert!(!store.exists());
    }

    #[test]
    fn every_byte_is_authenticated() {
        let dev = SoftwareDeviceKey::generate();
        let sealed = seal(&dev, b"hello world");
        assert_eq!(&*unseal(&dev, &sealed).unwrap(), b"hello world");
        for i in [
            0,
            9,
            8 + SEC1_UNCOMPRESSED_LEN,
            HEADER_LEN,
            sealed.len() - 1,
        ] {
            let mut bad = sealed.clone();
            bad[i] ^= 1;
            assert!(unseal(&dev, &bad).is_err(), "byte {i}");
        }
        assert!(unseal(&dev, &sealed[..HEADER_LEN]).is_err());
        assert!(unseal(&dev, b"short").is_err());
    }

    #[test]
    fn messages_are_plain() {
        use std::error::Error;
        for e in [
            StoreError::NotFound,
            StoreError::Unsealable,
            StoreError::Io(io::Error::other("x")),
        ] {
            assert_ne!(e.to_string().len(), 0);
            let _ = e.source();
        }
    }
}
