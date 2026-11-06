//! Server-side key material, behind traits so a KMS/HSM can replace the file-backed versions.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use arkhon_crypto::ed25519_dalek::SigningKey;
use arkhon_crypto::Cek;
use arkhon_license::IssuingCertificate;
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

/// Signs licenses and release manifests with the online issuing key.
///
/// Production: implement over a KMS/HSM so the private key never sits in process memory.
pub trait IssuingSigner: Send + Sync {
    /// The issuing key (for in-process signing). KMS implementations sign remotely instead.
    fn signing_key(&self) -> &SigningKey;
    /// The root-signed certificate for this issuing key.
    fn certificate(&self) -> &IssuingCertificate;
}

/// Issuing key loaded from a file written by `arkhon-keygen issuing`.
pub struct FileIssuingSigner {
    key: SigningKey,
    cert: IssuingCertificate,
}

impl FileIssuingSigner {
    /// Wrap an in-memory key and certificate.
    ///
    /// # Errors
    /// The key doesn't match the certificate.
    pub fn new(key: SigningKey, cert: IssuingCertificate) -> Result<Self, String> {
        if key.verifying_key().to_bytes() != cert.issuing_public_key {
            return Err("The issuing key doesn't match its certificate.".into());
        }
        Ok(Self { key, cert })
    }
}

impl IssuingSigner for FileIssuingSigner {
    fn signing_key(&self) -> &SigningKey {
        &self.key
    }
    fn certificate(&self) -> &IssuingCertificate {
        &self.cert
    }
}

/// Encrypts release CEKs at rest in Postgres (AES-256-GCM, release id as AAD).
///
/// Production: back this with a KMS data key.
pub struct CekVault {
    kek: Zeroizing<[u8; 32]>,
}

impl CekVault {
    /// From 32 raw key bytes.
    #[must_use]
    pub fn new(kek: [u8; 32]) -> Self {
        Self {
            kek: Zeroizing::new(kek),
        }
    }

    /// Seal a CEK for storage: `nonce (12) || ciphertext+tag (48)`.
    ///
    /// # Panics
    /// Never: AES-GCM encryption of a 32-byte message cannot fail.
    #[must_use]
    pub fn seal(&self, release_id: &str, cek: &Cek) -> Vec<u8> {
        let cipher = Aes256Gcm::new((&*self.kek).into());
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: cek.expose_secret(),
                    aad: release_id.as_bytes(),
                },
            )
            .expect("AES-GCM encryption of 32 bytes cannot fail");
        [nonce.as_slice(), &ct].concat()
    }

    /// Open a stored CEK.
    ///
    /// # Errors
    /// Wrong key, wrong release id or damaged data.
    pub fn open(&self, release_id: &str, sealed: &[u8]) -> Result<Cek, String> {
        if sealed.len() != 12 + 32 + 16 {
            return Err("Stored release key is damaged.".into());
        }
        let cipher = Aes256Gcm::new((&*self.kek).into());
        let pt = Zeroizing::new(
            cipher
                .decrypt(
                    Nonce::from_slice(&sealed[..12]),
                    Payload {
                        msg: &sealed[12..],
                        aad: release_id.as_bytes(),
                    },
                )
                .map_err(|_| "Stored release key couldn't be opened.".to_owned())?,
        );
        let bytes: [u8; 32] = pt
            .as_slice()
            .try_into()
            .map_err(|_| "bad key length".to_owned())?;
        Ok(Cek::from_bytes(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cek_vault_round_trips_and_binds_release_id() {
        let v = CekVault::new([7; 32]);
        let cek = Cek::from_bytes([9; 32]);
        let sealed = v.seal("rel-a", &cek);
        assert_eq!(
            v.open("rel-a", &sealed).unwrap().expose_secret(),
            cek.expose_secret()
        );
        assert!(
            v.open("rel-b", &sealed).is_err(),
            "moved to another release"
        );
        assert!(
            CekVault::new([8; 32]).open("rel-a", &sealed).is_err(),
            "wrong KEK"
        );
        let mut bad = sealed.clone();
        bad[20] ^= 1;
        assert!(v.open("rel-a", &bad).is_err());
    }
}
