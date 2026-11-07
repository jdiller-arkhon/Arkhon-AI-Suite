//! License format, canonical encoding, signing, verification and CEK wrapping (single source of
//! truth for the license server and the runtime).
//!
//! Key hierarchy:
//!
//! ```text
//! root Ed25519 (offline) ──signs──▶ IssuingCertificate (issuing key, window, serial)
//!                        ──signs──▶ RevocationList (revoked certificate serials, version)
//! issuing Ed25519 (online) ─signs─▶ License, SignedReleaseManifest
//! ```
//!
//! The runtime embeds only the root public key. Everything else travels with the license or release
//! and is checked by [`verify`] / [`verify_release`].
//!
//! Encoding is the deterministic binary format of ADR-0007 (`arkhon_crypto::codec`); every parser
//! rejects non-canonical bytes. Engine CEKs are wrapped to the device's P-256 key ([`wrap`]).

mod chain;
mod error;
mod license;
pub mod renewal;
mod verify;
pub mod wrap;

pub use arkhon_crypto::codec::DecodeError;
pub use chain::{trusted_issuer, IssuingCertificate, RevocationList};
pub use error::LicenseError;
pub use license::{License, LicenseBody, MAX_NAME_LEN};
pub use renewal::{verify_renewal, RenewalRequest, RenewalResponse};
pub use verify::{verify, verify_release, VerifiedLicense, CLOCK_SKEW_SECS};
pub use wrap::{unwrap_cek, wrap_cek, WrappedCek};

/// Crate version, exposed for build/diagnostic reporting.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests;
