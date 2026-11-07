//! Wrapping engine CEKs to a device's P-256 key.
//!
//! ```text
//! eph            = fresh P-256 key (server side, per wrap)
//! Z              = ECDH(eph, device_public)                  (x-coordinate)
//! context        = len-prefixed(eph_pub_sec1, device_pub_sec1, license_id, engine)
//! kek            = HKDF-SHA256(ikm = Z, salt = "arkhon/v1/cek-wrap", info = context)
//! ciphertext     = AES-256-GCM(kek, random 96-bit nonce, CEK, aad = context)
//! ```
//!
//! The device recomputes `Z` with its non-exportable key (`DeviceKey::ecdh`). Binding the license
//! id and engine name into both the KDF and the AAD means a wrapped key can't be moved to another
//! license or relabelled as another engine.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use arkhon_crypto::codec::{DecodeError, Decoder, Encoder};
use arkhon_crypto::Cek;
use arkhon_tpm::p256::ecdh::EphemeralSecret;
use arkhon_tpm::p256::PublicKey;
use arkhon_tpm::{parse_sec1, sec1_bytes, DeviceKey, SEC1_UNCOMPRESSED_LEN as SEC1_LEN};
use hkdf::Hkdf;
use rand_core::CryptoRngCore;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::LicenseError;

const SALT: &[u8] = b"arkhon/v1/cek-wrap";

/// Encoded length of a [`WrappedCek`].
pub const WRAPPED_CEK_LEN: usize = SEC1_LEN + 12 + 32 + 16;

/// A CEK encrypted to one device for one license and engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedCek {
    /// Server's ephemeral P-256 public key (uncompressed SEC1).
    pub ephemeral_public: [u8; SEC1_LEN],
    /// AES-GCM nonce.
    pub nonce: [u8; 12],
    /// Encrypted CEK followed by the GCM tag.
    pub ciphertext: [u8; 48],
}

impl WrappedCek {
    pub(crate) fn encode(&self, e: &mut Encoder) {
        e.array(&self.ephemeral_public)
            .array(&self.nonce)
            .array(&self.ciphertext);
    }

    pub(crate) fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let w = Self {
            ephemeral_public: d.array()?,
            nonce: d.array()?,
            ciphertext: d.array()?,
        };
        parse_sec1(&w.ephemeral_public).map_err(|_| DecodeError::InvalidValue("ephemeral key"))?;
        Ok(w)
    }
}

fn context(
    eph: &[u8; SEC1_LEN],
    device: &[u8; SEC1_LEN],
    license_id: &str,
    engine: &str,
) -> Vec<u8> {
    let mut e = Encoder::bare();
    e.bytes(eph).bytes(device).str(license_id).str(engine);
    e.finish()
}

fn cipher(shared: &[u8; 32], ctx: &[u8]) -> Aes256Gcm {
    let hk = Hkdf::<Sha256>::new(Some(SALT), shared);
    let mut kek = Zeroizing::new([0u8; 32]);
    hk.expand(ctx, kek.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    Aes256Gcm::new_from_slice(kek.as_ref()).expect("key is 32 bytes")
}

/// Wrap `cek` to `device_public` for `license_id` / `engine` (license-server side).
///
/// # Panics
/// Never: AES-GCM encryption of a 32-byte key cannot fail.
#[must_use]
pub fn wrap_cek(
    rng: &mut impl CryptoRngCore,
    cek: &Cek,
    device_public: &PublicKey,
    license_id: &str,
    engine: &str,
) -> WrappedCek {
    let eph = EphemeralSecret::random(rng);
    let eph_pub = sec1_bytes(&eph.public_key());
    let shared = eph.diffie_hellman(device_public);
    let mut z = Zeroizing::new([0u8; 32]);
    z.copy_from_slice(shared.raw_secret_bytes());
    let ctx = context(&eph_pub, &sec1_bytes(device_public), license_id, engine);
    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut nonce);
    let ct = cipher(&z, &ctx)
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: cek.expose_secret(),
                aad: &ctx,
            },
        )
        .expect("encrypting 32 bytes cannot fail");
    let mut ciphertext = [0u8; 48];
    ciphertext.copy_from_slice(&ct);
    WrappedCek {
        ephemeral_public: eph_pub,
        nonce,
        ciphertext,
    }
}

/// Unwrap with the device's key (runtime side). Prefer `VerifiedLicense::unwrap_cek`, which only
/// unwraps after the license has been verified.
///
/// # Errors
/// [`LicenseError::UnwrapFailed`] or a [`LicenseError::Binding`] error from the device.
pub fn unwrap_cek(
    wrapped: &WrappedCek,
    device: &dyn DeviceKey,
    license_id: &str,
    engine: &str,
) -> Result<Cek, LicenseError> {
    let eph = parse_sec1(&wrapped.ephemeral_public).map_err(|_| LicenseError::UnwrapFailed)?;
    let shared = device.ecdh(&eph)?;
    let ctx = context(
        &wrapped.ephemeral_public,
        &device.public_key_sec1(),
        license_id,
        engine,
    );
    let plain = Zeroizing::new(
        cipher(shared.as_bytes(), &ctx)
            .decrypt(
                Nonce::from_slice(&wrapped.nonce),
                Payload {
                    msg: &wrapped.ciphertext,
                    aad: &ctx,
                },
            )
            .map_err(|_| LicenseError::UnwrapFailed)?,
    );
    Cek::from_slice(&plain).ok_or(LicenseError::UnwrapFailed)
}
