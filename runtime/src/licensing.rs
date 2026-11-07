//! Activation and the licensing state machine.
//!
//! ```text
//!            activate (online)                 check-in when due (online)
//! [not activated] ──────────▶ [active] ◀──────────────────────────────┐
//!                               │  every start / periodically:        │
//!                               │  1. open sealed store (device key)  │
//!                               │  2. sealed clock: refuse rollback   │
//!                               │  3. verify license offline          │
//!                               │  4. offline grace left?             │
//!                               ├──── grace nearly over ──▶ warnings ─┤
//!                               └──── grace over / clock reset ──▶ [models locked] ─┘
//!                                     (check in online, or import a renewal file)
//! ```
//!
//! * **Trusted time.** Every start runs the system clock through `SoftwareClockStore` (HMAC-sealed
//!   "last seen" time, keyed by a secret kept in the sealed store). A clock earlier than the last
//!   time seen, or earlier than the last online check, is refused. If the clock file is missing
//!   while the sealed store exists (someone deleted it to reset the clock), models stay locked
//!   until an online check-in or a renewal import. A TPM NV monotonic counter is the planned
//!   hardware-backed replacement.
//! * **Check-in** is due at half the license term after the last online check, or 3 days before
//!   the offline deadline if that comes first; when it fails for
//!   lack of network the runtime keeps running inside the offline grace period.
//! * **Revocation list** versions only move forward (`RevocationList::verify_update`).
//! * **Releases** are gated by `VerifiedLicense::may_install` (entitlement + update window).

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};

use arkhon_crypto::release::{ReleaseManifest, SignedReleaseManifest};
use arkhon_crypto::Cek;
use arkhon_license::{
    verify, verify_release, verify_renewal, License, LicenseError, RenewalRequest, RenewalResponse,
    RevocationList, VerifiedLicense,
};
use arkhon_tpm::{
    BindingKind, ClockError, DeviceKey, FingerprintSalt, HardwareFingerprint, SoftwareClockStore,
};
use ed25519_dalek::VerifyingKey;
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use crate::client::{
    b64, unb64, ActivateRequest, CheckinRequest, ClientError, DeactivateRequest, DeviceInfo,
    LicenseResponse, LicenseServer,
};
use crate::fsutil;
use crate::store::{SealedStore, StoreError, StoredState};

/// Product salt for hardware-fingerprint hashes (public; keeps hashes product-specific).
pub const FINGERPRINT_SALT: FingerprintSalt = FingerprintSalt(*b"arkhon/v1/runtime-fp-salt-000001");

/// Start warning this many seconds before the offline deadline (3 days).
pub const WARN_BEFORE_DEADLINE_SECS: u64 = 3 * DAY;

const DAY: u64 = 86_400;
const CLOCK_FILE: &str = "clock.sealed";
/// Tolerance for small backwards clock steps (NTP corrections), as in `arkhon-tpm`.
const CLOCK_TOLERANCE_SECS: u64 = 300;

/// Why a licensing operation failed. Every message is written for the person at the computer.
#[derive(Debug)]
pub enum RuntimeError {
    /// The sealed store couldn't be used.
    Store(StoreError),
    /// The clock check failed (rolled back or tampered).
    Clock(ClockError),
    /// The license, certificate, revocation list or release was rejected.
    License(LicenseError),
    /// The license server couldn't be reached or refused.
    Client(ClientError),
    /// The license server's answer was malformed (named part).
    BadServerResponse(&'static str),
    /// Models stay locked until an online check or renewal (clock record missing).
    NeedsOnlineCheck,
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RuntimeError::Store(e) => e.fmt(f),
            RuntimeError::Clock(e) => e.fmt(f),
            RuntimeError::License(e) => e.fmt(f),
            RuntimeError::Client(e) => e.fmt(f),
            RuntimeError::BadServerResponse(what) => write!(
                f,
                "The Arkhon license server sent a damaged {what}. Try again later."
            ),
            RuntimeError::NeedsOnlineCheck => f.write_str(
                "Arkhon needs to check your license online before it can load models. Connect to the internet, or import a renewal file from your admin.",
            ),
        }
    }
}

impl std::error::Error for RuntimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            RuntimeError::Store(e) => Some(e),
            RuntimeError::Clock(e) => Some(e),
            RuntimeError::License(e) => Some(e),
            RuntimeError::Client(e) => Some(e),
            _ => None,
        }
    }
}

impl From<StoreError> for RuntimeError {
    fn from(e: StoreError) -> Self {
        RuntimeError::Store(e)
    }
}
impl From<ClockError> for RuntimeError {
    fn from(e: ClockError) -> Self {
        RuntimeError::Clock(e)
    }
}
impl From<LicenseError> for RuntimeError {
    fn from(e: LicenseError) -> Self {
        RuntimeError::License(e)
    }
}
impl From<ClientError> for RuntimeError {
    fn from(e: ClientError) -> Self {
        RuntimeError::Client(e)
    }
}

/// Where the license stands right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    /// License id.
    pub license_id: String,
    /// Customer id.
    pub customer_id: String,
    /// Entitled engines.
    pub engines: BTreeSet<String>,
    /// Binding kind of this computer's key.
    pub binding: BindingKind,
    /// Trusted time used for these checks.
    pub now: u64,
    /// License expiry.
    pub expires_at: u64,
    /// Last successful online check or renewal import.
    pub last_online: u64,
    /// After this, models are locked until an online check.
    pub offline_deadline: u64,
    /// When the next check-in is due.
    pub checkin_due_at: u64,
    /// A check-in should be attempted now.
    pub checkin_due: bool,
    /// Models may be decrypted and loaded.
    pub may_load_models: bool,
    /// Plain-language notes for the person (warnings or the reason models are locked).
    pub messages: Vec<String>,
}

/// What [`LicenseManager::checkin_if_due`] did.
#[derive(Debug)]
pub enum CheckinOutcome {
    /// Not due; nothing sent.
    NotDue,
    /// Checked in; the stored license was replaced.
    Renewed,
    /// Due but the server couldn't be reached; running on offline grace.
    Offline(ClientError),
}

struct Opened {
    state: StoredState,
    license: License,
    revocations: RevocationList,
    now: u64,
    clock_reset: bool,
}

/// Owns this computer's device key and licensing state.
pub struct LicenseManager {
    root: VerifyingKey,
    device: Box<dyn DeviceKey>,
    fingerprint: HardwareFingerprint,
    store: SealedStore,
    clock_path: PathBuf,
    clock: Box<dyn Fn() -> u64>,
}

impl fmt::Debug for LicenseManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LicenseManager")
            .field("store", &self.store)
            .field("binding", &self.device.binding_kind())
            .finish_non_exhaustive()
    }
}

fn system_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn decode_response(resp: &LicenseResponse) -> Result<(License, RevocationList), RuntimeError> {
    let lic = unb64(&resp.license).ok_or(RuntimeError::BadServerResponse("license"))?;
    let rl = unb64(&resp.revocation_list).ok_or(RuntimeError::BadServerResponse("key list"))?;
    let license = License::from_bytes(&lic).map_err(LicenseError::from)?;
    let revocations = RevocationList::from_bytes(&rl).map_err(LicenseError::from)?;
    Ok((license, revocations))
}

impl LicenseManager {
    /// A manager keeping its files in `dir`, trusting `root`, using `device` and `fingerprint`.
    #[must_use]
    pub fn new(
        dir: &Path,
        root: VerifyingKey,
        device: Box<dyn DeviceKey>,
        fingerprint: HardwareFingerprint,
    ) -> Self {
        Self {
            root,
            device,
            fingerprint,
            store: SealedStore::in_dir(dir),
            clock_path: dir.join(CLOCK_FILE),
            clock: Box::new(system_now),
        }
    }

    /// Replace the system clock (tests, demos).
    #[must_use]
    pub fn with_clock(mut self, clock: impl Fn() -> u64 + 'static) -> Self {
        self.clock = Box::new(clock);
        self
    }

    /// This computer's device key.
    #[must_use]
    pub fn device(&self) -> &dyn DeviceKey {
        self.device.as_ref()
    }

    /// True if a sealed license exists here.
    #[must_use]
    pub fn is_activated(&self) -> bool {
        self.store.exists()
    }

    fn clock_store(&self, state: &StoredState) -> Result<SoftwareClockStore, RuntimeError> {
        let secret = Zeroizing::new(
            unb64(&state.clock_secret).ok_or(RuntimeError::Store(StoreError::Unsealable))?,
        );
        Ok(SoftwareClockStore::new(&self.clock_path, &secret).with_tolerance(CLOCK_TOLERANCE_SECS))
    }

    /// Open the store and establish trusted time.
    fn open(&self) -> Result<Opened, RuntimeError> {
        let state = self.store.load(self.device.as_ref())?;
        let license_bytes =
            unb64(&state.license).ok_or(RuntimeError::Store(StoreError::Unsealable))?;
        let rl_bytes =
            unb64(&state.revocation_list).ok_or(RuntimeError::Store(StoreError::Unsealable))?;
        let license = License::from_bytes(&license_bytes).map_err(LicenseError::from)?;
        let revocations = RevocationList::from_bytes(&rl_bytes).map_err(LicenseError::from)?;
        let sys = (self.clock)();
        // Never earlier than the last online check, even if the clock file was deleted.
        if sys.saturating_add(CLOCK_TOLERANCE_SECS) < state.last_online {
            return Err(ClockError::RolledBack {
                last_seen: state.last_online,
                now: sys,
            }
            .into());
        }
        let clock = self.clock_store(&state)?;
        // A missing clock record stays missing (models locked) until an online check or renewal
        // import writes a new one; recording it here would silently accept the reset.
        let clock_reset = clock.last_seen()?.is_none();
        let now = if clock_reset {
            sys
        } else {
            clock.check_and_record(sys)?
        };
        Ok(Opened {
            state,
            license,
            revocations,
            now,
            clock_reset,
        })
    }

    /// Full offline verification, plus: the license is bound to *this* device key and binding.
    fn verify<'a>(&self, o: &'a Opened) -> Result<VerifiedLicense<'a>, RuntimeError> {
        if o.revocations.version < o.state.revocation_version_seen {
            return Err(LicenseError::RevocationListRollback {
                seen: o.state.revocation_version_seen,
                offered: o.revocations.version,
            }
            .into());
        }
        let v = verify(
            &o.license,
            &self.root,
            &o.revocations,
            o.now,
            &self.fingerprint,
        )?;
        self.check_bound(&o.license)?;
        Ok(v)
    }

    fn check_bound(&self, license: &License) -> Result<(), LicenseError> {
        let body = &license.body;
        if body.binding != self.device.binding_kind() {
            return Err(LicenseError::WrongBinding {
                required: body.binding,
                found: self.device.binding_kind(),
            });
        }
        if body.device_public_key != self.device.public_key_sec1() {
            return Err(LicenseError::WrongDeviceKey);
        }
        Ok(())
    }

    fn device_info(&self) -> DeviceInfo {
        DeviceInfo::of(self.device.as_ref(), &self.fingerprint)
    }

    /// Check a server response and store it. `previous` is the state being replaced (check-in).
    fn accept(
        &self,
        resp: &LicenseResponse,
        previous: Option<&StoredState>,
        server_url: Option<String>,
    ) -> Result<(), RuntimeError> {
        let (license, revocations) = decode_response(resp)?;
        let seen = previous.map_or(0, |p| p.revocation_version_seen);
        revocations.verify_update(&self.root, seen)?;
        let sys = (self.clock)();
        verify(&license, &self.root, &revocations, sys, &self.fingerprint)?;
        self.check_bound(&license)?;
        if let Some(p) = previous {
            let old = unb64(&p.license)
                .and_then(|b| License::from_bytes(&b).ok())
                .ok_or(RuntimeError::Store(StoreError::Unsealable))?;
            if old.body.license_id != license.body.license_id {
                return Err(LicenseError::RenewalMismatch.into());
            }
        }
        let clock_secret = if let Some(p) = previous {
            p.clock_secret.clone()
        } else {
            let mut s = Zeroizing::new([0u8; 32]);
            OsRng.fill_bytes(s.as_mut());
            // A fresh secret makes any old clock file unreadable; start a new record.
            fsutil::remove_if_exists(&self.clock_path).map_err(StoreError::Io)?;
            b64(s.as_ref())
        };
        let state = StoredState {
            license: b64(&license.to_bytes()),
            revocation_list: b64(&revocations.to_bytes()),
            revocation_version_seen: seen.max(revocations.version),
            last_online: sys,
            clock_secret,
            server_url: server_url.or_else(|| previous.and_then(|p| p.server_url.clone())),
        };
        self.clock_store(&state)?.check_and_record(sys)?;
        self.store.save(self.device.as_ref(), &state)?;
        Ok(())
    }

    /// Activate this computer with an activation key (online).
    ///
    /// # Errors
    /// [`RuntimeError`] from the server call or from verifying what it returned.
    pub fn activate(
        &self,
        server: &dyn LicenseServer,
        activation_key: &str,
        server_url: Option<String>,
    ) -> Result<Status, RuntimeError> {
        let req = ActivateRequest {
            activation_key: activation_key.trim().to_owned(),
            device: self.device_info(),
        };
        let resp = server.activate(&req)?;
        self.accept(&resp, None, server_url)?;
        self.status()
    }

    /// Check in now (online): fetch a fresh license and revocation list.
    ///
    /// # Errors
    /// [`RuntimeError`].
    pub fn checkin(&self, server: &dyn LicenseServer) -> Result<Status, RuntimeError> {
        let o = self.open()?;
        let req = CheckinRequest {
            license_id: o.license.body.license_id.clone(),
            device: self.device_info(),
        };
        let resp = server.checkin(&req)?;
        self.accept(&resp, Some(&o.state), None)?;
        self.status()
    }

    /// Check in if due (or if models are locked); a network failure is not an error.
    ///
    /// # Errors
    /// [`RuntimeError`] other than an unreachable server.
    pub fn checkin_if_due(
        &self,
        server: &dyn LicenseServer,
    ) -> Result<CheckinOutcome, RuntimeError> {
        let due = match self.status() {
            Ok(s) => s.checkin_due || !s.may_load_models,
            // An expired license can still be renewed online.
            Err(RuntimeError::License(LicenseError::Expired { .. })) => true,
            Err(e) => return Err(e),
        };
        if !due {
            return Ok(CheckinOutcome::NotDue);
        }
        match self.checkin(server) {
            Ok(_) => Ok(CheckinOutcome::Renewed),
            Err(RuntimeError::Client(e @ ClientError::Network(_))) => {
                Ok(CheckinOutcome::Offline(e))
            }
            Err(e) => Err(e),
        }
    }

    /// Verify everything offline and report where the license stands.
    ///
    /// # Errors
    /// Hard failures: not activated, store moved or damaged, clock rolled back, license forged,
    /// tampered, revoked, expired, or for another computer.
    pub fn status(&self) -> Result<Status, RuntimeError> {
        let o = self.open()?;
        let v = self.verify(&o)?;
        let body = &v.license().body;
        let deadline = v.offline_deadline(o.state.last_online);
        let term = body.expires_at.saturating_sub(body.issued_at);
        let checkin_due_at = o
            .state
            .last_online
            .saturating_add(term / 2)
            .min(deadline.saturating_sub(WARN_BEFORE_DEADLINE_SECS));
        let mut messages = Vec::new();
        let mut may_load = true;
        if let Err(e) = v.check_offline_grace(o.state.last_online, o.now) {
            may_load = false;
            messages.push(e.to_string());
        } else if o.clock_reset {
            may_load = false;
            messages.push(RuntimeError::NeedsOnlineCheck.to_string());
        } else if deadline.saturating_sub(o.now) <= WARN_BEFORE_DEADLINE_SECS {
            messages.push(grace_warning(deadline.saturating_sub(o.now)));
        }
        if body.expires_at.saturating_sub(o.now) <= WARN_BEFORE_DEADLINE_SECS {
            messages.push(
                "Your license ends in less than 3 days. Arkhon will renew it at the next online check."
                    .into(),
            );
        }
        if self.device.binding_kind() == BindingKind::Software {
            messages.push(
                "This computer uses a software security key (no security chip found). That is less secure."
                    .into(),
            );
        }
        Ok(Status {
            license_id: body.license_id.clone(),
            customer_id: body.customer_id.clone(),
            engines: body.engines.clone(),
            binding: body.binding,
            now: o.now,
            expires_at: body.expires_at,
            last_online: o.state.last_online,
            offline_deadline: deadline,
            checkin_due_at,
            checkin_due: o.now >= checkin_due_at || o.clock_reset,
            may_load_models: may_load,
            messages,
        })
    }

    /// Unwrap an engine's content key: only when the license verifies, offline grace remains and
    /// trusted time is intact.
    ///
    /// # Errors
    /// [`RuntimeError`], e.g. `License(OfflineTooLong)`, `License(NotEntitled)`,
    /// [`RuntimeError::NeedsOnlineCheck`].
    pub fn unlock_engine(&self, engine: &str) -> Result<Cek, RuntimeError> {
        let o = self.open()?;
        let v = self.verify(&o)?;
        v.check_offline_grace(o.state.last_online, o.now)?;
        if o.clock_reset {
            return Err(RuntimeError::NeedsOnlineCheck);
        }
        Ok(v.unwrap_cek(engine, self.device.as_ref())?)
    }

    /// Check a signed release manifest: genuine (root → issuing key of this license) and allowed
    /// by the license (engine entitled, released inside the update window).
    ///
    /// # Errors
    /// [`RuntimeError::License`].
    pub fn check_release(
        &self,
        signed: &SignedReleaseManifest,
    ) -> Result<ReleaseManifest, RuntimeError> {
        let o = self.open()?;
        let v = self.verify(&o)?;
        let manifest = verify_release(
            signed,
            &o.license.issuing_certificate,
            &self.root,
            &o.revocations,
        )?;
        v.may_install(manifest)?;
        Ok(manifest.clone())
    }

    /// Store a newer revocation list (e.g. shipped with an update). Older lists are refused.
    ///
    /// # Errors
    /// [`RuntimeError::License`] (`BadRevocationList`, `RevocationListRollback`), or if the stored
    /// license is now revoked.
    pub fn update_revocation_list(&self, list: &RevocationList) -> Result<(), RuntimeError> {
        let o = self.open()?;
        list.verify_update(&self.root, o.state.revocation_version_seen)?;
        let mut state = o.state;
        state.revocation_version_seen = state.revocation_version_seen.max(list.version);
        state.revocation_list = b64(&list.to_bytes());
        self.store.save(self.device.as_ref(), &state)?;
        Ok(())
    }

    /// The binary offline renewal request (license metadata only) for an air-gapped site.
    ///
    /// # Errors
    /// [`RuntimeError`] if the store can't be opened.
    pub fn export_renewal_request(&self) -> Result<Vec<u8>, RuntimeError> {
        let o = self.open()?;
        let mut request_id = [0u8; 16];
        OsRng.fill_bytes(&mut request_id);
        Ok(RenewalRequest {
            license_id: o.license.body.license_id.clone(),
            device_public_key: self.device.public_key_sec1(),
            fingerprint: self.fingerprint.clone(),
            revocation_version: o.state.revocation_version_seen,
            last_seen: o.now,
            request_id,
        }
        .to_bytes())
    }

    /// Import a renewal response file. Counts as an online check.
    ///
    /// # Errors
    /// [`RuntimeError`] if the file is malformed, forged, older, or for another license/computer.
    pub fn import_renewal(&self, response: &[u8]) -> Result<Status, RuntimeError> {
        let o = self.open()?;
        let resp = RenewalResponse::from_bytes(response).map_err(LicenseError::from)?;
        verify_renewal(
            &o.license,
            &resp,
            &self.root,
            o.state.revocation_version_seen,
            o.now,
            &self.fingerprint,
        )?;
        self.check_bound(&resp.license)?;
        let state = StoredState {
            license: b64(&resp.license.to_bytes()),
            revocation_list: b64(&resp.revocation_list.to_bytes()),
            revocation_version_seen: o
                .state
                .revocation_version_seen
                .max(resp.revocation_list.version),
            last_online: o.now,
            ..o.state
        };
        self.store.save(self.device.as_ref(), &state)?;
        self.status()
    }

    /// Release this computer's seat (online), then delete local license data.
    ///
    /// # Errors
    /// [`RuntimeError`]; local data is kept if the server call fails.
    pub fn deactivate(&self, server: &dyn LicenseServer) -> Result<(), RuntimeError> {
        let state = self.store.load(self.device.as_ref())?;
        let license = unb64(&state.license)
            .and_then(|b| License::from_bytes(&b).ok())
            .ok_or(RuntimeError::Store(StoreError::Unsealable))?;
        server.deactivate(&DeactivateRequest {
            license_id: license.body.license_id,
            device_public_key: b64(&self.device.public_key_sec1()),
        })?;
        self.store.remove()?;
        fsutil::remove_if_exists(&self.clock_path).map_err(StoreError::Io)?;
        Ok(())
    }
}

fn grace_warning(left: u64) -> String {
    let days = left / DAY;
    if days == 0 {
        "Arkhon can keep working offline for less than a day. Connect to the internet so it can check your license.".into()
    } else {
        format!(
            "Arkhon can keep working offline for {days} more day{}. Connect to the internet so it can check your license.",
            if days == 1 { "" } else { "s" }
        )
    }
}

#[cfg(test)]
mod tests;
