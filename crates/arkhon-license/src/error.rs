//! License errors, each with a plain-language message.

use std::fmt;

use arkhon_crypto::codec::DecodeError;
use arkhon_tpm::{BindingError, BindingKind};

/// Why a license, certificate, revocation list or release was rejected.
#[derive(Debug)]
pub enum LicenseError {
    /// The bytes are malformed or not canonical.
    Decode(DecodeError),
    /// The revocation list isn't signed by the Arkhon root key.
    BadRevocationList,
    /// The revocation list is older than one already seen on this computer.
    RevocationListRollback {
        /// Version already seen.
        seen: u64,
        /// Version offered.
        offered: u64,
    },
    /// The issuing certificate isn't signed by the Arkhon root key.
    UntrustedIssuer,
    /// The issuing key has been revoked.
    IssuerRevoked {
        /// Revoked certificate serial.
        serial: u64,
    },
    /// The document was signed outside the issuing certificate's validity window.
    IssuedOutsideCertificate,
    /// The license or manifest signature doesn't match the issuing key.
    BadSignature,
    /// A field holds a value that isn't allowed (named).
    Invalid(&'static str),
    /// The computer's clock is earlier than the license's issue time.
    ClockBehind {
        /// License issue time (Unix seconds).
        issued_at: u64,
    },
    /// The license has expired.
    Expired {
        /// Expiry time (Unix seconds).
        expired_at: u64,
    },
    /// Arkhon hasn't been able to check the license online for longer than allowed.
    OfflineTooLong {
        /// The deadline that passed (Unix seconds).
        deadline: u64,
    },
    /// This computer's hardware doesn't match the license.
    WrongMachine,
    /// The device key here isn't the one the license was issued to.
    WrongDeviceKey,
    /// The license requires a different kind of device key.
    WrongBinding {
        /// What the license requires.
        required: BindingKind,
        /// What this computer has.
        found: BindingKind,
    },
    /// The license doesn't include this engine.
    NotEntitled(String),
    /// The license doesn't carry a key for this engine.
    MissingKey(String),
    /// The engine key couldn't be unwrapped (damaged license or wrong device).
    UnwrapFailed,
    /// The release is newer than the license's update window.
    OutsideUpdateWindow {
        /// Update window end (Unix seconds).
        window_end: u64,
    },
    /// A renewal doesn't belong to the current license or device.
    RenewalMismatch,
    /// The device key backend failed.
    Binding(BindingError),
}

impl fmt::Display for LicenseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LicenseError::Decode(e) => write!(f, "The license file couldn't be read. {e}"),
            LicenseError::BadRevocationList => f.write_str(
                "Arkhon's list of withdrawn signing keys isn't genuine. Reinstall or update Arkhon.",
            ),
            LicenseError::RevocationListRollback { .. } => f.write_str(
                "An older list of withdrawn signing keys was offered. Arkhon kept the newer one.",
            ),
            LicenseError::UntrustedIssuer | LicenseError::BadSignature => f.write_str(
                "This license isn't signed by Arkhon. Contact Arkhon support for a valid license.",
            ),
            LicenseError::IssuerRevoked { .. } | LicenseError::IssuedOutsideCertificate => f
                .write_str(
                    "This license was signed with a key Arkhon no longer trusts. Contact Arkhon support for a replacement.",
                ),
            LicenseError::Invalid(field) => write!(
                f,
                "This license is damaged (bad \"{field}\"). Contact Arkhon support for a new copy."
            ),
            LicenseError::ClockBehind { .. } => f.write_str(
                "This computer's date is earlier than when your license was issued. Set the correct date and time.",
            ),
            LicenseError::Expired { .. } => {
                f.write_str("Your license has expired. Renew it to keep using Arkhon.")
            }
            LicenseError::OfflineTooLong { .. } => f.write_str(
                "Arkhon needs to check your license. Connect to the internet, or import a renewal file from your admin.",
            ),
            LicenseError::WrongMachine => f.write_str(
                "This license belongs to a different computer. Move the license from your account page.",
            ),
            LicenseError::WrongDeviceKey | LicenseError::UnwrapFailed => f.write_str(
                "This license was activated on a different computer, or its security key changed. Activate Arkhon again.",
            ),
            LicenseError::WrongBinding { required, found } => write!(
                f,
                "This license needs a \"{}\" but this computer is using a \"{}\". Contact Arkhon support.",
                required.label(),
                found.label()
            ),
            LicenseError::NotEntitled(engine) => {
                write!(f, "Your plan doesn't include \"{engine}\". Upgrade to use it.")
            }
            LicenseError::MissingKey(engine) => write!(
                f,
                "Your license doesn't unlock \"{engine}\" yet. Check for a license update."
            ),
            LicenseError::OutsideUpdateWindow { .. } => f.write_str(
                "This update was released after your update plan ended. Renew updates to install it.",
            ),
            LicenseError::RenewalMismatch => f.write_str(
                "This renewal file is for a different license or computer. Ask your admin for the right file.",
            ),
            LicenseError::Binding(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for LicenseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            LicenseError::Decode(e) => Some(e),
            LicenseError::Binding(e) => Some(e),
            _ => None,
        }
    }
}

impl From<DecodeError> for LicenseError {
    fn from(e: DecodeError) -> Self {
        LicenseError::Decode(e)
    }
}

impl From<BindingError> for LicenseError {
    fn from(e: BindingError) -> Self {
        LicenseError::Binding(e)
    }
}
