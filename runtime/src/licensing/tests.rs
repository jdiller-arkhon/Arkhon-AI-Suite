//! Licensing state machine tests, including the Phase 4 gate tests (`gate_*`).

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use arkhon_crypto::release::ReleaseManifest;
use arkhon_license::{IssuingCertificate, License, LicenseError, RevocationList};
use arkhon_tpm::{ClockError, SoftwareDeviceKey};
use ed25519_dalek::SigningKey;

use super::*;
use crate::fsutil::test_dir::TestDir;
use crate::testkit::{fingerprint, Authority, FakeServer, DAY, T0};

const ENGINES: &[&str] = &["core", "lite", "embed"];

struct Rig {
    dir: TestDir,
    server: FakeServer,
    clock: Rc<Cell<u64>>,
    scalar: [u8; 32],
}

impl Rig {
    fn new() -> Self {
        let mut scalar = [0u8; 32];
        OsRng.fill_bytes(&mut scalar);
        scalar[0] = 0x01; // keep below the P-256 order
        Self {
            dir: TestDir::new("lic"),
            server: FakeServer::new(ENGINES),
            clock: Rc::new(Cell::new(T0)),
            scalar,
        }
    }

    fn device(&self) -> Box<dyn DeviceKey> {
        Box::new(SoftwareDeviceKey::from_scalar_bytes(&self.scalar).unwrap())
    }

    fn manager_with(
        &self,
        dir: &Path,
        device: Box<dyn DeviceKey>,
        machine: &str,
    ) -> LicenseManager {
        let clock = self.clock.clone();
        LicenseManager::new(
            dir,
            self.server.authority.borrow().root_public(),
            device,
            fingerprint(machine),
        )
        .with_clock(move || clock.get())
    }

    fn manager(&self) -> LicenseManager {
        self.manager_with(self.dir.path(), self.device(), "machine-a")
    }

    fn set_time(&self, t: u64) {
        self.clock.set(t);
        self.server.now.set(t);
    }

    fn activated(&self) -> LicenseManager {
        let m = self.manager();
        m.activate(&self.server, "GOOD-KEY", None).unwrap();
        m
    }

    /// Re-seal a modified state with the right device key (an attacker who has the device key).
    fn rewrite_state(&self, m: &LicenseManager, f: impl FnOnce(&mut StoredState)) {
        let store = SealedStore::in_dir(self.dir.path());
        let mut state = store.load(m.device()).unwrap();
        f(&mut state);
        store.save(m.device(), &state).unwrap();
    }
}

fn stored_license(state: &StoredState) -> License {
    License::from_bytes(&unb64(&state.license).unwrap()).unwrap()
}

#[test]
fn activate_then_status() {
    let rig = Rig::new();
    let m = rig.manager();
    assert!(!m.is_activated());
    assert!(matches!(
        m.status(),
        Err(RuntimeError::Store(StoreError::NotFound))
    ));
    let err = m.activate(&rig.server, "BAD-KEY", None).unwrap_err();
    assert!(err.to_string().contains("activation key"), "{err}");
    let s = m
        .activate(&rig.server, "  GOOD-KEY ", Some("https://lm.test".into()))
        .unwrap();
    assert!(m.is_activated());
    assert!(s.may_load_models);
    assert_eq!(s.engines, ENGINES.iter().map(|e| (*e).to_owned()).collect());
    assert_eq!(s.last_online, T0);
    assert_eq!(s.offline_deadline, T0 + 7 * DAY);
    assert_eq!(s.checkin_due_at, T0 + 4 * DAY); // 7-day grace minus 3 days of warning
    assert!(!s.checkin_due);
    // Software binding is called out plainly.
    assert!(s.messages.iter().any(|m| m.contains("less secure")));
    let cek = m.unlock_engine("core").unwrap();
    assert_eq!(
        cek.expose_secret(),
        rig.server
            .authority
            .borrow_mut()
            .cek("core")
            .expose_secret()
    );
    // Nothing secret in the files on disk.
    let raw = std::fs::read(rig.dir.path().join(SealedStore::FILE_NAME)).unwrap();
    assert!(!String::from_utf8_lossy(&raw).contains("lic-test-1"));
}

// ---------- Gate: a copied install fails ----------

#[test]
fn gate_copied_install_fails_with_other_device_key() {
    let rig = Rig::new();
    rig.activated();
    let other_dir = TestDir::new("copy");
    for f in [SealedStore::FILE_NAME, CLOCK_FILE] {
        std::fs::copy(rig.dir.path().join(f), other_dir.path().join(f)).unwrap();
    }
    // Same hardware fingerprint, different device key: the store can't even be opened.
    let copy = rig.manager_with(
        other_dir.path(),
        Box::new(SoftwareDeviceKey::generate()),
        "machine-a",
    );
    assert!(matches!(
        copy.status(),
        Err(RuntimeError::Store(StoreError::Unsealable))
    ));
    assert!(matches!(
        copy.unlock_engine("core"),
        Err(RuntimeError::Store(StoreError::Unsealable))
    ));
    assert!(copy
        .status()
        .unwrap_err()
        .to_string()
        .contains("copied from another computer"));
}

#[test]
fn gate_copied_install_fails_on_other_hardware() {
    let rig = Rig::new();
    rig.activated();
    let other_dir = TestDir::new("copy2");
    for f in [SealedStore::FILE_NAME, CLOCK_FILE] {
        std::fs::copy(rig.dir.path().join(f), other_dir.path().join(f)).unwrap();
    }
    // Even with the device key copied too (software binding), different hardware is refused.
    let copy = rig.manager_with(other_dir.path(), rig.device(), "machine-b");
    assert!(matches!(
        copy.status(),
        Err(RuntimeError::License(LicenseError::WrongMachine))
    ));
    assert!(matches!(
        copy.unlock_engine("core"),
        Err(RuntimeError::License(LicenseError::WrongMachine))
    ));
}

#[test]
fn gate_license_for_another_device_key_is_refused() {
    // A genuine license issued to another device's key, placed into this device's store.
    let rig = Rig::new();
    let m = rig.activated();
    let other = SoftwareDeviceKey::generate();
    let foreign = {
        let mut a = rig.server.authority.borrow_mut();
        let body = a.body(
            other.public_key_sec1(),
            &fingerprint("machine-a"),
            ENGINES,
            T0,
        );
        a.sign(body)
    };
    rig.rewrite_state(&m, |s| s.license = b64(&foreign.to_bytes()));
    assert!(matches!(
        m.status(),
        Err(RuntimeError::License(LicenseError::WrongDeviceKey))
    ));
}

// ---------- Gate: a tampered license fails ----------

#[test]
fn gate_tampered_license_fails() {
    let rig = Rig::new();
    let m = rig.activated();
    // Grant an extra engine and push expiry out, keeping the old signature.
    rig.rewrite_state(&m, |s| {
        let mut lic = stored_license(s);
        lic.body.engines.insert("pro".into());
        lic.body.expires_at += 365 * DAY;
        s.license = b64(&lic.to_bytes());
    });
    assert!(matches!(
        m.status(),
        Err(RuntimeError::License(LicenseError::BadSignature))
    ));
    assert!(m.unlock_engine("core").is_err());
}

#[test]
fn gate_tampered_store_bytes_fail() {
    let rig = Rig::new();
    let m = rig.activated();
    let path = rig.dir.path().join(SealedStore::FILE_NAME);
    let mut data = std::fs::read(&path).unwrap();
    let mid = data.len() / 2;
    data[mid] ^= 0x40;
    std::fs::write(&path, &data).unwrap();
    assert!(matches!(
        m.status(),
        Err(RuntimeError::Store(StoreError::Unsealable))
    ));
}

// ---------- Gate: forged licenses fail ----------

#[test]
fn gate_forged_by_other_root_fails_activation() {
    let rig = Rig::new();
    // The server's authority is replaced by one the runtime doesn't trust.
    let m = rig.manager();
    *rig.server.authority.borrow_mut() = Authority::new();
    let err = m.activate(&rig.server, "GOOD-KEY", None).unwrap_err();
    // Its revocation list is checked first, then the certificate.
    assert!(
        matches!(
            err,
            RuntimeError::License(LicenseError::BadRevocationList | LicenseError::UntrustedIssuer)
        ),
        "{err:?}"
    );
    assert!(!m.is_activated());
}

#[test]
fn gate_forged_certificate_not_root_signed_fails() {
    let rig = Rig::new();
    let m = rig.activated();
    // Attacker makes their own issuing key and a certificate signed by their own "root".
    let rogue_root = SigningKey::generate(&mut OsRng);
    let rogue_issuing = SigningKey::generate(&mut OsRng);
    let rogue_cert = IssuingCertificate::issue(
        &rogue_root,
        1,
        &rogue_issuing.verifying_key(),
        0,
        u64::MAX / 2,
    )
    .unwrap();
    rig.rewrite_state(&m, |s| {
        let lic = stored_license(s);
        let forged = License::sign(lic.body, rogue_cert, &rogue_issuing).unwrap();
        s.license = b64(&forged.to_bytes());
    });
    assert!(matches!(
        m.status(),
        Err(RuntimeError::License(LicenseError::UntrustedIssuer))
    ));
}

#[test]
fn gate_forged_with_wrong_issuing_key_fails() {
    let rig = Rig::new();
    let m = rig.activated();
    // Genuine certificate, but the license is signed by a different key.
    let wrong = SigningKey::generate(&mut OsRng);
    rig.rewrite_state(&m, |s| {
        let mut lic = stored_license(s);
        let msg = [arkhon_crypto::codec::domain::LICENSE, &lic.signed_bytes()].concat();
        lic.signature = ed25519_dalek::Signer::sign(&wrong, &msg).to_bytes();
        s.license = b64(&lic.to_bytes());
    });
    assert!(matches!(
        m.status(),
        Err(RuntimeError::License(LicenseError::BadSignature))
    ));
}

#[test]
fn gate_revoked_issuing_key_fails() {
    let rig = Rig::new();
    let m = rig.activated();
    let revoked = {
        let a = rig.server.authority.borrow();
        RevocationList::sign(&a.root, 2, T0, BTreeSet::from([a.cert.serial]))
    };
    // Accepting a newer list is allowed; afterwards the license no longer verifies.
    m.update_revocation_list(&revoked).unwrap();
    assert!(matches!(
        m.status(),
        Err(RuntimeError::License(LicenseError::IssuerRevoked {
            serial: 1
        }))
    ));
    assert!(m.unlock_engine("core").is_err());
    // And a server still handing out licenses from the revoked key is refused at check-in.
    rig.server.authority.borrow_mut().revocations = revoked;
    assert!(matches!(
        m.checkin(&rig.server),
        Err(RuntimeError::License(LicenseError::IssuerRevoked { .. }))
    ));
}

// ---------- Gate: clock rollback is detected and refused ----------

#[test]
fn gate_clock_rollback_refused() {
    let rig = Rig::new();
    let m = rig.activated();
    rig.set_time(T0 + 2 * DAY);
    assert!(m.status().unwrap().may_load_models);
    // Turn the clock back a day.
    rig.set_time(T0 + DAY);
    assert!(matches!(
        m.status(),
        Err(RuntimeError::Clock(ClockError::RolledBack { .. }))
    ));
    assert!(matches!(
        m.unlock_engine("core"),
        Err(RuntimeError::Clock(ClockError::RolledBack { .. }))
    ));
    // Small NTP-style corrections are tolerated.
    rig.set_time(T0 + 2 * DAY - 60);
    assert!(m.status().is_ok());
}

#[test]
fn gate_clock_rollback_refused_even_if_clock_file_deleted() {
    let rig = Rig::new();
    let m = rig.activated();
    std::fs::remove_file(rig.dir.path().join(CLOCK_FILE)).unwrap();
    // Before the last online check: refused outright.
    rig.set_time(T0 - DAY);
    assert!(matches!(
        m.status(),
        Err(RuntimeError::Clock(ClockError::RolledBack { .. }))
    ));
}

#[test]
fn deleted_clock_file_locks_models_until_online_check() {
    let rig = Rig::new();
    let m = rig.activated();
    std::fs::remove_file(rig.dir.path().join(CLOCK_FILE)).unwrap();
    rig.set_time(T0 + DAY);
    let s = m.status().unwrap();
    assert!(!s.may_load_models && s.checkin_due);
    assert!(matches!(
        m.unlock_engine("core"),
        Err(RuntimeError::NeedsOnlineCheck)
    ));
    assert!(matches!(
        m.checkin_if_due(&rig.server).unwrap(),
        CheckinOutcome::Renewed
    ));
    assert!(m.status().unwrap().may_load_models);
    m.unlock_engine("core").unwrap();
}

#[test]
fn tampered_clock_file_refused() {
    let rig = Rig::new();
    let m = rig.activated();
    let p = rig.dir.path().join(CLOCK_FILE);
    let mut d = std::fs::read(&p).unwrap();
    d[12] ^= 1;
    std::fs::write(&p, d).unwrap();
    assert!(matches!(
        m.status(),
        Err(RuntimeError::Clock(ClockError::Tampered))
    ));
}

// ---------- Gate: expired offline grace refuses to load models ----------

#[test]
fn gate_offline_grace_expiry_refuses_models() {
    let rig = Rig::new();
    let m = rig.activated();
    rig.server.offline.set(true);
    // Day 3: fine, no warning yet.
    rig.set_time(T0 + 3 * DAY);
    let s = m.status().unwrap();
    assert!(s.may_load_models);
    assert!(!s.messages.iter().any(|x| x.contains("offline")));
    // Day 5: warning with days left.
    rig.set_time(T0 + 5 * DAY);
    let s = m.status().unwrap();
    assert!(s.may_load_models);
    assert!(
        s.messages
            .iter()
            .any(|x| x.contains("offline for 2 more days")),
        "{:?}",
        s.messages
    );
    rig.set_time(T0 + 7 * DAY - 3600);
    assert!(m
        .status()
        .unwrap()
        .messages
        .iter()
        .any(|x| x.contains("less than a day")));
    // Day 8: locked; offline check-in attempt reports offline without failing.
    rig.set_time(T0 + 8 * DAY);
    let s = m.status().unwrap();
    assert!(!s.may_load_models);
    assert!(s
        .messages
        .iter()
        .any(|x| x.contains("Connect to the internet")));
    assert!(matches!(
        m.unlock_engine("core"),
        Err(RuntimeError::License(LicenseError::OfflineTooLong { .. }))
    ));
    assert!(matches!(
        m.checkin_if_due(&rig.server).unwrap(),
        CheckinOutcome::Offline(_)
    ));
    // Back online: check-in restores everything.
    rig.server.offline.set(false);
    assert!(matches!(
        m.checkin_if_due(&rig.server).unwrap(),
        CheckinOutcome::Renewed
    ));
    let s = m.status().unwrap();
    assert!(s.may_load_models && s.last_online == T0 + 8 * DAY);
    m.unlock_engine("core").unwrap();
}

#[test]
fn checkin_only_when_due() {
    let rig = Rig::new();
    let m = rig.activated();
    rig.set_time(T0 + DAY);
    assert!(matches!(
        m.checkin_if_due(&rig.server).unwrap(),
        CheckinOutcome::NotDue
    ));
    // Due 3 days before the 7-day offline deadline (earlier than half the 30-day term).
    rig.set_time(T0 + 4 * DAY);
    assert!(m.status().unwrap().checkin_due);
    rig.set_time(T0 + 15 * DAY);
    assert!(m.status().is_err() || !m.status().unwrap().may_load_models);
    assert!(matches!(
        m.checkin_if_due(&rig.server).unwrap(),
        CheckinOutcome::Renewed
    ));
    assert_eq!(
        rig.server
            .calls
            .borrow()
            .iter()
            .filter(|c| *c == "checkin")
            .count(),
        1
    );
    let s = m.status().unwrap();
    assert_eq!(s.checkin_due_at, T0 + 19 * DAY);
}

#[test]
fn expired_license_is_renewed_online() {
    let rig = Rig::new();
    let m = rig.activated();
    rig.set_time(T0 + 31 * DAY);
    assert!(matches!(
        m.status(),
        Err(RuntimeError::License(LicenseError::Expired { .. }))
    ));
    assert!(matches!(
        m.checkin_if_due(&rig.server).unwrap(),
        CheckinOutcome::Renewed
    ));
    assert!(m.status().unwrap().may_load_models);
}

#[test]
fn server_refusal_surfaces() {
    let rig = Rig::new();
    let m = rig.activated();
    rig.server.activations.borrow_mut().clear();
    rig.set_time(T0 + 16 * DAY);
    let err = m.checkin_if_due(&rig.server).unwrap_err();
    assert!(err.to_string().contains("isn't activated"), "{err}");
}

// ---------- Revocation list only moves forward ----------

#[test]
fn revocation_list_only_moves_forward() {
    let rig = Rig::new();
    let m = rig.activated();
    let (v3, v2, forged) = {
        let a = rig.server.authority.borrow();
        (
            RevocationList::sign(&a.root, 3, T0, BTreeSet::new()),
            RevocationList::sign(&a.root, 2, T0, BTreeSet::new()),
            RevocationList::sign(&SigningKey::generate(&mut OsRng), 9, T0, BTreeSet::new()),
        )
    };
    m.update_revocation_list(&v3).unwrap();
    assert!(matches!(
        m.update_revocation_list(&v2),
        Err(RuntimeError::License(
            LicenseError::RevocationListRollback {
                seen: 3,
                offered: 2
            }
        ))
    ));
    assert!(matches!(
        m.update_revocation_list(&forged),
        Err(RuntimeError::License(LicenseError::BadRevocationList))
    ));
    // A check-in answer carrying an older list (v1) is refused.
    rig.set_time(T0 + 16 * DAY);
    assert!(matches!(
        m.checkin(&rig.server),
        Err(RuntimeError::License(
            LicenseError::RevocationListRollback { .. }
        ))
    ));
    // Restoring an older list into the store directly is caught at verification too.
    rig.rewrite_state(&m, |s| {
        s.revocation_list = b64(&v2.to_bytes());
    });
    assert!(matches!(
        m.status(),
        Err(RuntimeError::License(
            LicenseError::RevocationListRollback { .. }
        ))
    ));
}

// ---------- Releases gated by entitlement and update window ----------

#[test]
fn releases_are_gated() {
    let rig = Rig::new();
    let m = rig.activated();
    let manifest = |engine: &str, released_at: u64| {
        ReleaseManifest {
            release_id: [1; 16],
            engine: engine.into(),
            version: "1.0.0".into(),
            released_at,
            files: BTreeMap::new(),
        }
        .sign(&rig.server.authority.borrow().issuing)
    };
    assert_eq!(
        m.check_release(&manifest("core", T0)).unwrap().engine,
        "core"
    );
    assert!(matches!(
        m.check_release(&manifest("pro", T0)),
        Err(RuntimeError::License(LicenseError::NotEntitled(_)))
    ));
    assert!(matches!(
        m.check_release(&manifest("core", T0 + 400 * DAY)),
        Err(RuntimeError::License(
            LicenseError::OutsideUpdateWindow { .. }
        ))
    ));
    let forged = ReleaseManifest {
        release_id: [2; 16],
        engine: "core".into(),
        version: "6.6.6".into(),
        released_at: T0,
        files: BTreeMap::new(),
    }
    .sign(&SigningKey::generate(&mut OsRng));
    assert!(matches!(
        m.check_release(&forged),
        Err(RuntimeError::License(LicenseError::BadSignature))
    ));
}

#[test]
fn entitlement_is_enforced_at_unlock() {
    let rig = Rig::new();
    let m = rig.activated();
    assert!(matches!(
        m.unlock_engine("pro"),
        Err(RuntimeError::License(LicenseError::NotEntitled(_)))
    ));
}

// ---------- Offline renewal by file ----------

#[test]
fn offline_renewal_round_trip() {
    let rig = Rig::new();
    let m = rig.activated();
    rig.server.offline.set(true);
    rig.set_time(T0 + 6 * DAY);
    let req = m.export_renewal_request().unwrap();
    // Carried to a connected machine and answered there.
    rig.server.offline.set(false);
    let resp = rig.server.offline_renew(&req).unwrap();
    rig.set_time(T0 + 6 * DAY + 3600);
    let s = m.import_renewal(&resp).unwrap();
    assert_eq!(s.last_online, T0 + 6 * DAY + 3600);
    assert_eq!(s.offline_deadline, T0 + 13 * DAY + 3600);
    assert!(m.import_renewal(b"not a renewal").is_err());
    // A renewal for another computer's key is refused.
    let other = Rig::new();
    let other_m = other.activated();
    let foreign = other
        .server
        .offline_renew(&other_m.export_renewal_request().unwrap())
        .unwrap();
    assert!(m.import_renewal(&foreign).is_err());
}

#[test]
fn deactivate_removes_local_data() {
    let rig = Rig::new();
    let m = rig.activated();
    rig.server.offline.set(true);
    assert!(m.deactivate(&rig.server).is_err());
    assert!(m.is_activated(), "kept when the server can't be reached");
    rig.server.offline.set(false);
    m.deactivate(&rig.server).unwrap();
    assert!(!m.is_activated());
    assert!(!rig.dir.path().join(CLOCK_FILE).exists());
    assert_eq!(rig.server.activations.borrow().len(), 0);
}

#[test]
fn error_messages_are_plain() {
    use std::error::Error;
    let errs = [
        RuntimeError::Store(StoreError::NotFound),
        RuntimeError::Clock(ClockError::Tampered),
        RuntimeError::License(LicenseError::WrongMachine),
        RuntimeError::Client(ClientError::BadResponse),
        RuntimeError::BadServerResponse("license"),
        RuntimeError::NeedsOnlineCheck,
    ];
    for e in &errs {
        assert_ne!(e.to_string().len(), 0);
    }
    assert!(errs[0].source().is_some() && errs[5].source().is_none());
    assert!(format!("{:?}", Rig::new().manager()).contains("LicenseManager"));
}

/// Runs only with `--features tpm` and `ARKHON_TEST_TCTI` naming a TPM (e.g. swtpm).
#[cfg(feature = "tpm")]
#[test]
fn tpm_bound_activation_and_copy_refusal() {
    use arkhon_tpm::tpm::TpmDeviceKey;
    let Ok(tcti) = std::env::var("ARKHON_TEST_TCTI") else {
        eprintln!("ARKHON_TEST_TCTI not set; skipping TPM test");
        return;
    };
    let rig = Rig::new();
    let tpm = || Box::new(TpmDeviceKey::open(&tcti).expect("open TPM")) as Box<dyn DeviceKey>;
    let m = rig.manager_with(rig.dir.path(), tpm(), "machine-a");
    let s = m.activate(&rig.server, "GOOD-KEY", None).unwrap();
    assert_eq!(s.binding, BindingKind::Tpm);
    assert!(s.may_load_models);
    assert!(!s.messages.iter().any(|x| x.contains("less secure")));
    m.unlock_engine("core").unwrap();
    // The same TPM (re-opened) reads the store.
    drop(m);
    let again = rig.manager_with(rig.dir.path(), tpm(), "machine-a");
    again.status().unwrap();
    // A copy opened with any other key can't.
    let copy = rig.manager_with(
        rig.dir.path(),
        Box::new(SoftwareDeviceKey::generate()),
        "machine-a",
    );
    assert!(matches!(
        copy.status(),
        Err(RuntimeError::Store(StoreError::Unsealable))
    ));
    eprintln!("TPM-bound licensing verified against {tcti}");
}
