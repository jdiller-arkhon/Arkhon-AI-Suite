//! Offline verification of licenses and releases.

use arkhon_crypto::codec::domain;
use arkhon_crypto::release::{ReleaseManifest, SignedReleaseManifest};
use arkhon_crypto::Cek;
use arkhon_tpm::{DeviceKey, HardwareFingerprint};
use ed25519_dalek::VerifyingKey;

use crate::chain::{trusted_issuer, verify_sig, RevocationList};
use crate::license::License;
use crate::wrap::unwrap_cek;
use crate::LicenseError;

/// Allowed clock difference between the license server and this computer (5 minutes).
pub const CLOCK_SKEW_SECS: u64 = 300;

const DAY_SECS: u64 = 86_400;

/// A license that passed [`verify`]. Engine keys can only be unwrapped through this type.
#[derive(Debug, Clone, Copy)]
pub struct VerifiedLicense<'a> {
    license: &'a License,
}

/// Verify a license completely, offline.
///
/// Checks, in order: the revocation list is root-signed; the issuing certificate is root-signed and
/// not revoked, and covers the license's issue time; the license signature; the license's own rules;
/// `now` is not before the issue time (minus [`CLOCK_SKEW_SECS`]) and is before expiry; and
/// `fingerprint` matches the licensed machine (at most one component changed).
///
/// `now` should come from `arkhon_tpm::SoftwareClockStore::check_and_record` (or the TPM clock), not
/// straight from the system clock. Separately, check the revocation list's version with
/// [`RevocationList::verify_update`] when storing a new one, and check offline grace with
/// [`VerifiedLicense::check_offline_grace`].
///
/// # Errors
/// The first failing check, as a [`LicenseError`].
pub fn verify<'a>(
    license: &'a License,
    root: &VerifyingKey,
    revocations: &RevocationList,
    now: u64,
    fingerprint: &HardwareFingerprint,
) -> Result<VerifiedLicense<'a>, LicenseError> {
    let body = &license.body;
    let issuer = trusted_issuer(
        &license.issuing_certificate,
        root,
        revocations,
        body.issued_at,
    )?;
    if !verify_sig(
        &issuer,
        domain::LICENSE,
        &license.signed_bytes(),
        &license.signature,
    ) {
        return Err(LicenseError::BadSignature);
    }
    body.validate()?;
    if now.saturating_add(CLOCK_SKEW_SECS) < body.issued_at {
        return Err(LicenseError::ClockBehind {
            issued_at: body.issued_at,
        });
    }
    if now >= body.expires_at {
        return Err(LicenseError::Expired {
            expired_at: body.expires_at,
        });
    }
    if !body.fingerprint.matches(fingerprint) {
        return Err(LicenseError::WrongMachine);
    }
    Ok(VerifiedLicense { license })
}

impl<'a> VerifiedLicense<'a> {
    /// The verified license.
    #[must_use]
    pub fn license(&self) -> &'a License {
        self.license
    }

    /// True if the license includes `engine`.
    #[must_use]
    pub fn entitles_engine(&self, engine: &str) -> bool {
        self.license.body.engines.contains(engine)
    }

    /// Latest time the runtime may keep running without an online check, given the last
    /// successful check (or renewal import) at `last_online`.
    #[must_use]
    pub fn offline_deadline(&self, last_online: u64) -> u64 {
        last_online.saturating_add(u64::from(self.license.body.offline_grace_days) * DAY_SECS)
    }

    /// Fail if more than the offline grace period has passed since `last_online`.
    ///
    /// # Errors
    /// [`LicenseError::OfflineTooLong`].
    pub fn check_offline_grace(&self, last_online: u64, now: u64) -> Result<(), LicenseError> {
        let deadline = self.offline_deadline(last_online);
        if now > deadline {
            Err(LicenseError::OfflineTooLong { deadline })
        } else {
            Ok(())
        }
    }

    /// May this release be installed? The engine must be licensed and the release dated within
    /// the update window. (Verify the manifest itself first with [`verify_release`].)
    ///
    /// # Errors
    /// [`LicenseError::NotEntitled`] or [`LicenseError::OutsideUpdateWindow`].
    pub fn may_install(&self, manifest: &ReleaseManifest) -> Result<(), LicenseError> {
        if !self.entitles_engine(&manifest.engine) {
            return Err(LicenseError::NotEntitled(manifest.engine.clone()));
        }
        let window_end = self.license.body.update_window_end;
        if manifest.released_at > window_end {
            return Err(LicenseError::OutsideUpdateWindow { window_end });
        }
        Ok(())
    }

    /// Unwrap `engine`'s CEK with this computer's device key.
    ///
    /// # Errors
    /// [`LicenseError::NotEntitled`], [`LicenseError::MissingKey`], [`LicenseError::WrongBinding`],
    /// [`LicenseError::WrongDeviceKey`], [`LicenseError::UnwrapFailed`] or a device error.
    pub fn unwrap_cek(&self, engine: &str, device: &dyn DeviceKey) -> Result<Cek, LicenseError> {
        let body = &self.license.body;
        if !self.entitles_engine(engine) {
            return Err(LicenseError::NotEntitled(engine.to_owned()));
        }
        let wrapped = body
            .wrapped_ceks
            .get(engine)
            .ok_or_else(|| LicenseError::MissingKey(engine.to_owned()))?;
        if device.binding_kind() != body.binding {
            return Err(LicenseError::WrongBinding {
                required: body.binding,
                found: device.binding_kind(),
            });
        }
        if device.public_key_sec1() != body.device_public_key {
            return Err(LicenseError::WrongDeviceKey);
        }
        unwrap_cek(wrapped, device, &body.license_id, engine)
    }
}

/// Verify a signed release manifest against the root key: genuine revocation list, root-signed and
/// unrevoked issuing certificate covering the release date, and the issuing key's signature.
///
/// # Errors
/// As [`crate::chain::trusted_issuer`], plus [`LicenseError::BadSignature`].
pub fn verify_release<'a>(
    signed: &'a SignedReleaseManifest,
    cert: &crate::IssuingCertificate,
    root: &VerifyingKey,
    revocations: &RevocationList,
) -> Result<&'a ReleaseManifest, LicenseError> {
    let issuer = trusted_issuer(cert, root, revocations, signed.manifest.released_at)?;
    signed
        .verify_signature(&issuer)
        .map_err(|_| LicenseError::BadSignature)
}
