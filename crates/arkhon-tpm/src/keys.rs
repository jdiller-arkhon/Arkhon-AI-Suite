//! Internal key-derivation helpers. The `expect`s here cannot fire: every input has a fixed,
//! valid size.

use aes_gcm::aead::KeyInit;
use aes_gcm::Aes256Gcm;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

/// `HKDF-SHA256(salt, ikm, info)` → 32 bytes.
pub(crate) fn hkdf32(salt: &[u8], ikm: &[u8], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, out.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    out
}

/// HMAC-SHA256 keyed with `key`.
pub(crate) fn hmac(key: &[u8]) -> Hmac<Sha256> {
    <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length")
}

/// AES-256-GCM keyed with a derived key.
pub(crate) fn aes(key: &Zeroizing<[u8; 32]>) -> Aes256Gcm {
    Aes256Gcm::new_from_slice(key.as_ref()).expect("key is 32 bytes")
}
