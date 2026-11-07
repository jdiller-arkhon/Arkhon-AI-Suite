//! Software device key (`binding: software`): a P-256 key kept in a file, encrypted at rest.
//!
//! **This is weaker than a TPM or Secure Enclave key.** The private key exists in process memory
//! during ECDH, and anyone who obtains both the key file and the storage secret can copy the
//! binding to another machine. How strong the storage secret is depends on the caller (an OS
//! keychain / DPAPI secret is better than one derived from the fingerprint). Licenses record the
//! binding kind, and the license server may refuse software binding on some plans.
//!
//! File layout (68 bytes): `magic (8) || nonce (12) || AES-256-GCM(secret scalar) (32 + 16)`, with
//! the magic as AAD and the key-encryption key `HKDF-SHA256(storage_secret, salt = magic,
//! info = "arkhon/v1/software-device-key")`.

use std::fmt;
use std::path::Path;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use p256::{PublicKey, SecretKey};
use rand_core::{CryptoRngCore, OsRng, RngCore};
use zeroize::Zeroizing;

use crate::binding::{BindingError, BindingKind, DeviceKey, SharedSecret};
use crate::{fsutil, keys};

const MAGIC: &[u8; 8] = b"ARKSWK01";
const FILE_LEN: usize = 8 + 12 + 32 + 16;
const KEK_INFO: &[u8] = b"arkhon/v1/software-device-key";

/// A P-256 device key held in software.
pub struct SoftwareDeviceKey {
    secret: SecretKey,
}

impl fmt::Debug for SoftwareDeviceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SoftwareDeviceKey")
            .field(
                "public_key",
                &crate::binding::sec1_bytes(&self.public_key()),
            )
            .finish_non_exhaustive()
    }
}

fn cipher(storage_secret: &[u8]) -> Aes256Gcm {
    keys::aes(&keys::hkdf32(MAGIC, storage_secret, KEK_INFO))
}

fn seal(storage_secret: &[u8], nonce: &[u8; 12], scalar: &[u8]) -> Vec<u8> {
    cipher(storage_secret)
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: scalar,
                aad: MAGIC,
            },
        )
        .expect("encrypting 32 bytes cannot fail")
}

impl SoftwareDeviceKey {
    /// A new random key held only in memory (tests and tooling).
    #[must_use]
    pub fn generate() -> Self {
        Self::generate_with(&mut OsRng)
    }

    /// A new key from `rng`.
    #[must_use]
    pub fn generate_with(rng: &mut impl CryptoRngCore) -> Self {
        Self {
            secret: SecretKey::random(rng),
        }
    }

    /// A key from a fixed 32-byte scalar (published test vectors only).
    ///
    /// # Errors
    /// [`BindingError::Corrupt`] if the bytes are not a valid non-zero scalar.
    pub fn from_scalar_bytes(bytes: &[u8; 32]) -> Result<Self, BindingError> {
        SecretKey::from_slice(bytes)
            .map(|secret| Self { secret })
            .map_err(|_| BindingError::Corrupt)
    }

    /// Generate a key and store it encrypted at `path`. Refuses to overwrite an existing file.
    ///
    /// # Errors
    /// [`BindingError::AlreadyExists`] or [`BindingError::Io`].
    pub fn create(path: &Path, storage_secret: &[u8]) -> Result<Self, BindingError> {
        let key = Self::generate();
        key.save(path, storage_secret)?;
        Ok(key)
    }

    /// Store this key encrypted at `path` (owner-only permissions, never overwrites).
    ///
    /// # Errors
    /// [`BindingError::AlreadyExists`] or [`BindingError::Io`].
    pub fn save(&self, path: &Path, storage_secret: &[u8]) -> Result<(), BindingError> {
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let scalar = Zeroizing::new(self.secret.to_bytes());
        let ct = seal(storage_secret, &nonce, scalar.as_slice());
        let file = [&MAGIC[..], &nonce, &ct].concat();
        fsutil::write_new_private(path, &file).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                BindingError::AlreadyExists
            } else {
                BindingError::Io(e)
            }
        })
    }

    /// Load a key stored by [`SoftwareDeviceKey::create`].
    ///
    /// # Errors
    /// [`BindingError::NotFound`], [`BindingError::Corrupt`] or [`BindingError::Io`].
    pub fn open(path: &Path, storage_secret: &[u8]) -> Result<Self, BindingError> {
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(BindingError::NotFound)
            }
            Err(e) => return Err(BindingError::Io(e)),
        };
        if data.len() != FILE_LEN || &data[..8] != MAGIC {
            return Err(BindingError::Corrupt);
        }
        let scalar = Zeroizing::new(
            cipher(storage_secret)
                .decrypt(
                    Nonce::from_slice(&data[8..20]),
                    Payload {
                        msg: &data[20..],
                        aad: MAGIC,
                    },
                )
                .map_err(|_| BindingError::Corrupt)?,
        );
        SecretKey::from_slice(&scalar)
            .map(|secret| Self { secret })
            .map_err(|_| BindingError::Corrupt)
    }

    /// Open the key at `path`, creating it first if there is none.
    ///
    /// # Errors
    /// As [`SoftwareDeviceKey::open`] and [`SoftwareDeviceKey::create`].
    pub fn open_or_create(path: &Path, storage_secret: &[u8]) -> Result<Self, BindingError> {
        match Self::open(path, storage_secret) {
            Err(BindingError::NotFound) => Self::create(path, storage_secret),
            other => other,
        }
    }
}

impl DeviceKey for SoftwareDeviceKey {
    fn binding_kind(&self) -> BindingKind {
        BindingKind::Software
    }

    fn public_key(&self) -> PublicKey {
        self.secret.public_key()
    }

    fn ecdh(&self, peer: &PublicKey) -> Result<SharedSecret, BindingError> {
        let shared = p256::ecdh::diffie_hellman(self.secret.to_nonzero_scalar(), peer.as_affine());
        let mut out = [0u8; 32];
        out.copy_from_slice(shared.raw_secret_bytes());
        Ok(SharedSecret::new(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsutil::test_dir::TestDir;

    #[test]
    fn ecdh_agrees_both_ways() {
        let a = SoftwareDeviceKey::generate();
        let b = SoftwareDeviceKey::generate();
        let ab = a.ecdh(&b.public_key()).unwrap();
        let ba = b.ecdh(&a.public_key()).unwrap();
        assert_eq!(ab.as_bytes(), ba.as_bytes());
        assert_eq!(a.binding_kind(), BindingKind::Software);
        assert_eq!(a.public_key_sec1()[0], 4);
    }

    #[test]
    fn create_open_and_refuse_overwrite() {
        let dir = TestDir::new("swk");
        let path = dir.path().join("device.key");
        assert!(matches!(
            SoftwareDeviceKey::open(&path, b"s"),
            Err(BindingError::NotFound)
        ));
        let k = SoftwareDeviceKey::open_or_create(&path, b"secret").unwrap();
        let again = SoftwareDeviceKey::open_or_create(&path, b"secret").unwrap();
        assert_eq!(k.public_key(), again.public_key());
        assert!(matches!(
            SoftwareDeviceKey::create(&path, b"secret"),
            Err(BindingError::AlreadyExists)
        ));
        assert!(matches!(
            SoftwareDeviceKey::open(&path, b"wrong"),
            Err(BindingError::Corrupt)
        ));
        let dbg = format!("{k:?}");
        assert!(dbg.contains("public_key") && !dbg.contains("secret:"));
    }

    #[test]
    fn tampered_or_short_file_is_corrupt() {
        let dir = TestDir::new("swk2");
        let path = dir.path().join("device.key");
        SoftwareDeviceKey::create(&path, b"s").unwrap();
        let mut data = std::fs::read(&path).unwrap();
        for i in [0, 9, 30, FILE_LEN - 1] {
            let mut bad = data.clone();
            bad[i] ^= 1;
            std::fs::write(&path, &bad).unwrap();
            assert!(matches!(
                SoftwareDeviceKey::open(&path, b"s"),
                Err(BindingError::Corrupt)
            ));
        }
        data.pop();
        std::fs::write(&path, &data).unwrap();
        assert!(matches!(
            SoftwareDeviceKey::open(&path, b"s"),
            Err(BindingError::Corrupt)
        ));
    }

    #[test]
    fn io_errors_surface() {
        let dir = TestDir::new("swk3");
        // A directory where a file is expected.
        assert!(matches!(
            SoftwareDeviceKey::open(dir.path(), b"s"),
            Err(BindingError::Io(_))
        ));
        let missing = dir.path().join("no-such-dir").join("k");
        assert!(matches!(
            SoftwareDeviceKey::create(&missing, b"s"),
            Err(BindingError::Io(_))
        ));
    }

    #[test]
    fn fixed_scalar() {
        let k = SoftwareDeviceKey::from_scalar_bytes(&[1; 32]).unwrap();
        let k2 = SoftwareDeviceKey::from_scalar_bytes(&[1; 32]).unwrap();
        assert_eq!(k.public_key(), k2.public_key());
        assert!(SoftwareDeviceKey::from_scalar_bytes(&[0; 32]).is_err());
        assert!(SoftwareDeviceKey::from_scalar_bytes(&[0xff; 32]).is_err());
    }
}
