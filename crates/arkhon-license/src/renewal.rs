//! Offline renewal by file exchange.
//!
//! An air-gapped site exports a [`RenewalRequest`] (no customer content: ids, public key and
//! fingerprint hashes only), carries it to a connected machine, and imports the
//! [`RenewalResponse`] the license server returns. Importing counts as an online check.

use arkhon_crypto::codec::{require_canonical, DecodeError, Decoder, Encoder};
use arkhon_tpm::{HardwareFingerprint, FINGERPRINT_LEN, SEC1_UNCOMPRESSED_LEN as SEC1_LEN};
use ed25519_dalek::VerifyingKey;

use crate::chain::RevocationList;
use crate::license::License;
use crate::verify::{verify, VerifiedLicense};
use crate::LicenseError;

const REQ_KIND: [u8; 4] = *b"ARRQ";
const RESP_KIND: [u8; 4] = *b"ARRS";
const VERSION: u16 = 1;

/// What the runtime exports to ask for a renewed license.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenewalRequest {
    /// Current license id.
    pub license_id: String,
    /// Device public key (uncompressed SEC1).
    pub device_public_key: [u8; SEC1_LEN],
    /// Current fingerprint.
    pub fingerprint: HardwareFingerprint,
    /// Highest revocation-list version seen here.
    pub revocation_version: u64,
    /// Latest trusted time seen here (Unix seconds).
    pub last_seen: u64,
    /// Random request id (lets the server spot replays of old requests).
    pub request_id: [u8; 16],
}

impl RenewalRequest {
    /// Canonical bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new(REQ_KIND, VERSION);
        e.str(&self.license_id)
            .array(&self.device_public_key)
            .array(&self.fingerprint.to_bytes())
            .u64(self.revocation_version)
            .u64(self.last_seen)
            .array(&self.request_id);
        e.finish()
    }

    /// Parse canonical bytes.
    ///
    /// # Errors
    /// [`DecodeError`].
    pub fn from_bytes(data: &[u8]) -> Result<Self, DecodeError> {
        let mut d = Decoder::new(data, REQ_KIND, VERSION)?;
        let req = Self {
            license_id: d.string()?,
            device_public_key: d.array()?,
            fingerprint: HardwareFingerprint::from_bytes(&d.array::<FINGERPRINT_LEN>()?),
            revocation_version: d.u64()?,
            last_seen: d.u64()?,
            request_id: d.array()?,
        };
        d.finish()?;
        require_canonical(data, &req.to_bytes())?;
        Ok(req)
    }
}

/// What the license server returns: a renewed license and the current revocation list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenewalResponse {
    /// The renewed license.
    pub license: License,
    /// The current revocation list.
    pub revocation_list: RevocationList,
}

impl RenewalResponse {
    /// Canonical bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new(RESP_KIND, VERSION);
        e.bytes(&self.license.to_bytes())
            .bytes(&self.revocation_list.to_bytes());
        e.finish()
    }

    /// Parse canonical bytes.
    ///
    /// # Errors
    /// [`DecodeError`].
    pub fn from_bytes(data: &[u8]) -> Result<Self, DecodeError> {
        let mut d = Decoder::new(data, RESP_KIND, VERSION)?;
        let license = License::from_bytes(d.bytes()?)?;
        let revocation_list = RevocationList::from_bytes(d.bytes()?)?;
        d.finish()?;
        let resp = Self {
            license,
            revocation_list,
        };
        require_canonical(data, &resp.to_bytes())?;
        Ok(resp)
    }
}

/// Verify an imported renewal against the license currently installed.
///
/// The revocation list must be genuine and not older than `seen_revocation_version`; the new
/// license must pass [`verify`] with that list, keep the same license id and device key, and not be
/// older than the current one. On success, store the new license and list, and record `now` as the
/// last online check.
///
/// # Errors
/// Any [`LicenseError`] from the checks, or [`LicenseError::RenewalMismatch`].
pub fn verify_renewal<'a>(
    current: &License,
    response: &'a RenewalResponse,
    root: &VerifyingKey,
    seen_revocation_version: u64,
    now: u64,
    fingerprint: &HardwareFingerprint,
) -> Result<VerifiedLicense<'a>, LicenseError> {
    response
        .revocation_list
        .verify_update(root, seen_revocation_version)?;
    let verified = verify(
        &response.license,
        root,
        &response.revocation_list,
        now,
        fingerprint,
    )?;
    let (old, new) = (&current.body, &response.license.body);
    if old.license_id != new.license_id
        || old.device_public_key != new.device_public_key
        || new.issued_at < old.issued_at
    {
        return Err(LicenseError::RenewalMismatch);
    }
    Ok(verified)
}
