//! Device binding, sealed clock and hardware fingerprint.
//!
//! * [`DeviceKey`]: a non-exportable P-256 key that can do ECDH. TPM 2.0 and Apple Secure Enclave
//!   support ECDH on P-256 (not X25519), so the binding scheme is P-256 throughout.
//!   * [`SoftwareDeviceKey`]: fallback and test backend; key file encrypted at rest (weaker, see
//!     its docs).
//!   * `tpm::TpmDeviceKey` (cargo feature `tpm`): TPM 2.0 through `tss-esapi`.
//!   * Secure Enclave: not implemented yet (macOS, Phase 4).
//! * [`SoftwareClockStore`]: HMAC-sealed "last seen" time for clock-rollback detection.
//! * [`HardwareFingerprint`]: salted component hashes; matches with at most one changed component.

pub mod binding;
pub mod clock;
pub mod fingerprint;
mod fsutil;
mod keys;
pub mod software;
#[cfg(feature = "tpm")]
pub mod tpm;

pub use binding::{
    parse_sec1, sec1_bytes, BindingError, BindingKind, DeviceKey, SharedSecret,
    SEC1_UNCOMPRESSED_LEN,
};
pub use clock::{ClockError, SoftwareClockStore};
pub use fingerprint::FINGERPRINT_LEN;
pub use fingerprint::{FingerprintSalt, HardwareFingerprint, RawComponents};
pub use p256;
pub use software::SoftwareDeviceKey;

/// Crate version, exposed for build/diagnostic reporting.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    #[test]
    fn version_is_set() {
        assert_ne!(super::VERSION, "");
    }
}
