//! Test-only license authority and fake license server, built from throwaway keys.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};

use arkhon_crypto::Cek;
use arkhon_license::{
    wrap_cek, IssuingCertificate, License, LicenseBody, RenewalRequest, RenewalResponse,
    RevocationList,
};
use arkhon_tpm::{parse_sec1, BindingKind, FingerprintSalt, HardwareFingerprint, RawComponents};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::OsRng;

use crate::client::{
    b64, unb64, ActivateRequest, CheckinRequest, ClientError, DeactivateRequest, LicenseResponse,
    LicenseServer, ReleaseEntry,
};

pub(crate) const DAY: u64 = 86_400;
/// A fixed "now" well after the issuing certificate starts.
pub(crate) const T0: u64 = 1_800_000_000;

pub(crate) fn fingerprint(machine: &str) -> HardwareFingerprint {
    let raw = RawComponents {
        machine_id: Some(machine.into()),
        cpu: Some(format!("{machine}-cpu")),
        disk: Some(format!("{machine}-disk")),
        board: Some(format!("{machine}-board")),
        mac: Some(format!("{machine}-mac")),
    };
    HardwareFingerprint::from_raw(&FingerprintSalt([3; 32]), &raw)
}

/// Root + one issuing key, like the real offline/online split.
pub(crate) struct Authority {
    pub root: SigningKey,
    pub issuing: SigningKey,
    pub cert: IssuingCertificate,
    pub revocations: RevocationList,
    pub ceks: BTreeMap<String, Cek>,
}

impl Authority {
    pub(crate) fn new() -> Self {
        let root = SigningKey::generate(&mut OsRng);
        let issuing = SigningKey::generate(&mut OsRng);
        let cert =
            IssuingCertificate::issue(&root, 1, &issuing.verifying_key(), 0, u64::MAX / 2).unwrap();
        let revocations = RevocationList::sign(&root, 1, T0 - DAY, BTreeSet::new());
        Self {
            root,
            issuing,
            cert,
            revocations,
            ceks: BTreeMap::new(),
        }
    }

    pub(crate) fn root_public(&self) -> VerifyingKey {
        self.root.verifying_key()
    }

    pub(crate) fn cek(&mut self, engine: &str) -> Cek {
        Cek::from_bytes(
            *self
                .ceks
                .entry(engine.to_owned())
                .or_insert_with(Cek::generate)
                .expose_secret(),
        )
    }

    /// A license body for `device` / `fp` with sensible defaults.
    pub(crate) fn body(
        &mut self,
        device_public: [u8; 65],
        fp: &HardwareFingerprint,
        engines: &[&str],
        issued_at: u64,
    ) -> LicenseBody {
        let pk = parse_sec1(&device_public).unwrap();
        let license_id = "lic-test-1".to_owned();
        let mut wrapped = BTreeMap::new();
        for e in engines {
            let cek = self.cek(e);
            wrapped.insert(
                (*e).to_owned(),
                wrap_cek(&mut OsRng, &cek, &pk, &license_id, e),
            );
        }
        LicenseBody {
            license_id,
            customer_id: "cust-1".into(),
            workspaces: ["inbox".to_owned()].into(),
            engines: engines.iter().map(|e| (*e).to_owned()).collect(),
            packs: BTreeSet::new(),
            update_window_end: issued_at + 365 * DAY,
            seats: 5,
            issued_at,
            expires_at: issued_at + 30 * DAY,
            offline_grace_days: 7,
            binding: BindingKind::Software,
            device_public_key: device_public,
            fingerprint: fp.clone(),
            wrapped_ceks: wrapped,
        }
    }

    pub(crate) fn sign(&self, body: LicenseBody) -> License {
        License::sign(body, self.cert.clone(), &self.issuing).unwrap()
    }

    pub(crate) fn response(&self, license: &License) -> LicenseResponse {
        LicenseResponse {
            license_id: license.body.license_id.clone(),
            license: b64(&license.to_bytes()),
            revocation_list: b64(&self.revocations.to_bytes()),
        }
    }
}

/// An in-process stand-in for the License Manager's device API.
pub(crate) struct FakeServer {
    pub authority: RefCell<Authority>,
    pub engines: Vec<&'static str>,
    pub now: Cell<u64>,
    pub offline: Cell<bool>,
    pub activations: RefCell<BTreeSet<String>>,
    pub calls: RefCell<Vec<String>>,
}

impl FakeServer {
    pub(crate) fn new(engines: &[&'static str]) -> Self {
        Self {
            authority: RefCell::new(Authority::new()),
            engines: engines.to_vec(),
            now: Cell::new(T0),
            offline: Cell::new(false),
            activations: RefCell::new(BTreeSet::new()),
            calls: RefCell::new(Vec::new()),
        }
    }

    fn issue_for(&self, pk_b64: &str, fp_b64: &str, binding: &str) -> Result<License, ClientError> {
        let pk: [u8; 65] = unb64(pk_b64)
            .and_then(|v| v.try_into().ok())
            .ok_or(ClientError::BadResponse)?;
        let fp: [u8; 160] = unb64(fp_b64)
            .and_then(|v| v.try_into().ok())
            .ok_or(ClientError::BadResponse)?;
        let fp = HardwareFingerprint::from_bytes(&fp);
        let mut a = self.authority.borrow_mut();
        let mut body = a.body(pk, &fp, &self.engines, self.now.get());
        body.binding = BindingKind::ALL
            .into_iter()
            .find(|k| k.as_str() == binding)
            .ok_or(ClientError::BadResponse)?;
        Ok(a.sign(body))
    }

    fn online(&self, call: &str) -> Result<(), ClientError> {
        self.calls.borrow_mut().push(call.to_owned());
        if self.offline.get() {
            Err(ClientError::Network("offline (test)".into()))
        } else {
            Ok(())
        }
    }
}

impl LicenseServer for FakeServer {
    fn activate(&self, req: &ActivateRequest) -> Result<LicenseResponse, ClientError> {
        self.online("activate")?;
        if req.activation_key != "GOOD-KEY" {
            return Err(ClientError::Rejected {
                status: 404,
                message: "That activation key isn't valid.".into(),
            });
        }
        self.activations
            .borrow_mut()
            .insert(req.device.device_public_key.clone());
        let lic = self.issue_for(
            &req.device.device_public_key,
            &req.device.fingerprint,
            &req.device.binding,
        )?;
        Ok(self.authority.borrow().response(&lic))
    }

    fn checkin(&self, req: &CheckinRequest) -> Result<LicenseResponse, ClientError> {
        self.online("checkin")?;
        if !self
            .activations
            .borrow()
            .contains(&req.device.device_public_key)
        {
            return Err(ClientError::Rejected {
                status: 403,
                message: "This computer isn't activated on this license.".into(),
            });
        }
        let lic = self.issue_for(
            &req.device.device_public_key,
            &req.device.fingerprint,
            &req.device.binding,
        )?;
        Ok(self.authority.borrow().response(&lic))
    }

    fn deactivate(&self, req: &DeactivateRequest) -> Result<(), ClientError> {
        self.online("deactivate")?;
        self.activations.borrow_mut().remove(&req.device_public_key);
        Ok(())
    }

    fn offline_renew(&self, request: &[u8]) -> Result<Vec<u8>, ClientError> {
        self.online("offline_renew")?;
        let req = RenewalRequest::from_bytes(request).map_err(|_| ClientError::BadResponse)?;
        let lic = self.issue_for(
            &b64(&req.device_public_key),
            &b64(&req.fingerprint.to_bytes()),
            "software",
        )?;
        Ok(RenewalResponse {
            license: lic,
            revocation_list: self.authority.borrow().revocations.clone(),
        }
        .to_bytes())
    }

    fn releases(&self, _license_id: &str) -> Result<Vec<ReleaseEntry>, ClientError> {
        self.online("releases")?;
        Ok(Vec::new())
    }
}
