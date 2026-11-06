//! The device binding key: a P-256 key that never leaves the device and can do ECDH.
//!
//! TPM 2.0 (`TPM2_ECDH_ZGen`) and Apple's Secure Enclave both offer ECDH on NIST P-256, not X25519,
//! so the whole binding scheme is P-256. The shared secret is the x-coordinate of the ECDH point
//! (SEC1 / SP 800-56A "Z"), which is what every backend returns.

use std::fmt;
use std::io;

use p256::PublicKey;
use zeroize::Zeroizing;

/// Length of an uncompressed SEC1 P-256 public key.
pub const SEC1_UNCOMPRESSED_LEN: usize = 65;

/// Where the device key lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BindingKind {
    /// A TPM 2.0 key that can't be exported.
    Tpm,
    /// An Apple Secure Enclave key that can't be exported.
    SecureEnclave,
    /// A key file encrypted at rest. Weaker: anyone who can read the file *and* the storage
    /// secret can copy it. The license server may refuse this binding for some plans.
    Software,
}

impl BindingKind {
    /// Every kind, in wire-tag order.
    pub const ALL: [BindingKind; 3] = [
        BindingKind::Tpm,
        BindingKind::SecureEnclave,
        BindingKind::Software,
    ];

    /// Stable one-byte wire tag (used by `arkhon-license`).
    #[must_use]
    pub fn tag(self) -> u8 {
        match self {
            BindingKind::Tpm => 1,
            BindingKind::SecureEnclave => 2,
            BindingKind::Software => 3,
        }
    }

    /// Inverse of [`BindingKind::tag`].
    #[must_use]
    pub fn from_tag(tag: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.tag() == tag)
    }

    /// Stable lower-case name: `tpm`, `secure-enclave`, `software`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            BindingKind::Tpm => "tpm",
            BindingKind::SecureEnclave => "secure-enclave",
            BindingKind::Software => "software",
        }
    }

    /// Plain-language label for screens.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            BindingKind::Tpm => "Security chip (TPM)",
            BindingKind::SecureEnclave => "Apple Secure Enclave",
            BindingKind::Software => "Software key (less secure)",
        }
    }
}

impl fmt::Display for BindingKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A 32-byte ECDH shared secret, wiped on drop. Feed it to a KDF; never use it directly as a key.
pub struct SharedSecret(Zeroizing<[u8; 32]>);

impl SharedSecret {
    /// Wrap raw secret bytes.
    #[must_use]
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Borrow the secret bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SharedSecret(<redacted>)")
    }
}

/// Why a device-key operation failed.
#[derive(Debug)]
pub enum BindingError {
    /// No key has been created at this location yet.
    NotFound,
    /// A key already exists here; refusing to overwrite it.
    AlreadyExists,
    /// The stored key could not be decrypted: wrong storage secret, or the file was changed.
    Corrupt,
    /// A peer public key is not a valid P-256 point.
    InvalidPublicKey,
    /// The security chip reported an error (message from the backend).
    Hardware(String),
    /// Reading or writing the key file failed.
    Io(io::Error),
}

impl fmt::Display for BindingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BindingError::NotFound => {
                f.write_str("This computer hasn't been activated yet. Activate Arkhon first.")
            }
            BindingError::AlreadyExists => f.write_str(
                "This computer already has an Arkhon device key. It was left unchanged.",
            ),
            BindingError::Corrupt => f.write_str(
                "The device key on this computer is damaged or was moved from another computer. Activate Arkhon again.",
            ),
            BindingError::InvalidPublicKey => {
                f.write_str("The license holds an invalid key. Ask Arkhon support for a new license.")
            }
            BindingError::Hardware(msg) => {
                write!(f, "The security chip on this computer reported a problem: {msg}")
            }
            BindingError::Io(e) => write!(f, "Couldn't read or write the device key: {e}"),
        }
    }
}

impl std::error::Error for BindingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            BindingError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for BindingError {
    fn from(e: io::Error) -> Self {
        BindingError::Io(e)
    }
}

/// A non-exportable P-256 key bound to this device.
pub trait DeviceKey {
    /// Where the key lives.
    fn binding_kind(&self) -> BindingKind;

    /// The public half.
    fn public_key(&self) -> PublicKey;

    /// ECDH with `peer`: returns the x-coordinate of `device_secret * peer`.
    ///
    /// # Errors
    /// [`BindingError::Hardware`] if the chip refuses, or a backend-specific error.
    fn ecdh(&self, peer: &PublicKey) -> Result<SharedSecret, BindingError>;

    /// The public key as uncompressed SEC1 bytes (`0x04 || X || Y`).
    fn public_key_sec1(&self) -> [u8; SEC1_UNCOMPRESSED_LEN] {
        sec1_bytes(&self.public_key())
    }
}

/// Uncompressed SEC1 encoding of a P-256 public key.
#[must_use]
pub fn sec1_bytes(key: &PublicKey) -> [u8; SEC1_UNCOMPRESSED_LEN] {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let point = key.to_encoded_point(false);
    let mut out = [0u8; SEC1_UNCOMPRESSED_LEN];
    out.copy_from_slice(point.as_bytes());
    out
}

/// Parse an uncompressed SEC1 P-256 public key, rejecting the identity and off-curve points.
///
/// # Errors
/// [`BindingError::InvalidPublicKey`].
pub fn parse_sec1(bytes: &[u8]) -> Result<PublicKey, BindingError> {
    if bytes.len() != SEC1_UNCOMPRESSED_LEN || bytes[0] != 0x04 {
        return Err(BindingError::InvalidPublicKey);
    }
    PublicKey::from_sec1_bytes(bytes).map_err(|_| BindingError::InvalidPublicKey)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_and_names_round_trip() {
        for k in BindingKind::ALL {
            assert_eq!(BindingKind::from_tag(k.tag()), Some(k));
            assert_eq!(k.to_string(), k.as_str());
            assert_ne!(k.label(), "");
        }
        assert_eq!(BindingKind::from_tag(0), None);
        assert_eq!(BindingKind::from_tag(4), None);
    }

    #[test]
    fn shared_secret_redacted() {
        let s = SharedSecret::new([0xcd; 32]);
        assert_eq!(format!("{s:?}"), "SharedSecret(<redacted>)");
        assert_eq!(s.as_bytes(), &[0xcd; 32]);
    }

    #[test]
    fn parse_sec1_rejects_bad_points() {
        assert!(matches!(
            parse_sec1(&[4; 10]),
            Err(BindingError::InvalidPublicKey)
        ));
        let mut not_on_curve = [0u8; 65];
        not_on_curve[0] = 4;
        assert!(matches!(
            parse_sec1(&not_on_curve),
            Err(BindingError::InvalidPublicKey)
        ));
        let mut compressed_tag = [1u8; 65];
        compressed_tag[0] = 2;
        assert!(parse_sec1(&compressed_tag).is_err());
    }

    #[test]
    fn errors_are_plain() {
        use std::error::Error;
        let errs = [
            BindingError::NotFound,
            BindingError::AlreadyExists,
            BindingError::Corrupt,
            BindingError::InvalidPublicKey,
            BindingError::Hardware("TPM_RC_LOCKOUT".into()),
            BindingError::Io(io::Error::other("denied")),
        ];
        for e in &errs {
            assert_ne!(e.to_string(), "");
        }
        assert!(errs[5].source().is_some());
        assert!(errs[0].source().is_none());
        assert!(matches!(
            BindingError::from(io::Error::other("x")),
            BindingError::Io(_)
        ));
    }
}
