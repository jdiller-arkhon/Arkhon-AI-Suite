use std::collections::{BTreeMap, BTreeSet};

use arkhon_crypto::release::{ReleaseFile, ReleaseManifest, SignedReleaseManifest};
use arkhon_crypto::{sha256, Cek};
use arkhon_tpm::{
    BindingError, BindingKind, DeviceKey, FingerprintSalt, HardwareFingerprint, RawComponents,
    SharedSecret, SoftwareDeviceKey,
};
use ed25519_dalek::SigningKey;
use proptest::prelude::*;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

use super::*;

const T0: u64 = 1_800_000_000; // 2027-01-15
const DAY: u64 = 86_400;

fn root() -> SigningKey {
    SigningKey::from_bytes(&sha256(b"arkhon test vector root key - NOT SECRET"))
}
fn issuing() -> SigningKey {
    SigningKey::from_bytes(&sha256(b"arkhon test vector issuing key - NOT SECRET"))
}
fn device() -> SoftwareDeviceKey {
    SoftwareDeviceKey::from_scalar_bytes(&sha256(b"arkhon test vector device key - NOT SECRET"))
        .unwrap()
}
fn engine_cek() -> Cek {
    Cek::from_bytes(sha256(b"arkhon test vector CEK - NOT SECRET"))
}
fn salt() -> FingerprintSalt {
    FingerprintSalt(sha256(b"arkhon test vector fingerprint salt"))
}
fn raw(disk: &str, mac: &str) -> RawComponents {
    RawComponents {
        machine_id: Some("test-machine".into()),
        cpu: Some("test-cpu".into()),
        disk: Some(disk.into()),
        board: Some("test-board".into()),
        mac: Some(mac.into()),
    }
}
fn fp() -> HardwareFingerprint {
    HardwareFingerprint::from_raw(&salt(), &raw("disk-1", "02:00:00:00:00:01"))
}
fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| (*s).to_owned()).collect()
}

fn cert() -> IssuingCertificate {
    IssuingCertificate::issue(
        &root(),
        7,
        &issuing().verifying_key(),
        T0 - DAY,
        T0 + 365 * DAY,
    )
    .unwrap()
}

fn revocations(serials: &[u64]) -> RevocationList {
    RevocationList::sign(&root(), 3, T0, serials.iter().copied().collect())
}

fn body(rng: &mut ChaCha20Rng) -> LicenseBody {
    let dev = device();
    let mut wrapped = BTreeMap::new();
    wrapped.insert(
        "inbox".to_owned(),
        wrap_cek(rng, &engine_cek(), &dev.public_key(), "lic-0001", "inbox"),
    );
    LicenseBody {
        license_id: "lic-0001".into(),
        customer_id: "cust-0001".into(),
        workspaces: set(&["docs", "inbox"]),
        engines: set(&["docs", "inbox"]),
        packs: set(&["trades"]),
        update_window_end: T0 + 365 * DAY,
        seats: 5,
        issued_at: T0,
        expires_at: T0 + 30 * DAY,
        offline_grace_days: 14,
        binding: BindingKind::Software,
        device_public_key: dev.public_key_sec1(),
        fingerprint: fp(),
        wrapped_ceks: wrapped,
    }
}

fn license() -> License {
    let mut rng = ChaCha20Rng::from_seed([1; 32]);
    License::sign(body(&mut rng), cert(), &issuing()).unwrap()
}

fn verify_ok(l: &License) -> Result<VerifiedLicense<'_>, LicenseError> {
    verify(
        l,
        &root().verifying_key(),
        &revocations(&[]),
        T0 + DAY,
        &fp(),
    )
}

fn resign(mut b: LicenseBody) -> License {
    b.wrapped_ceks.retain(|k, _| b.engines.contains(k));
    License::sign(b, cert(), &issuing()).unwrap()
}

// ------------------------------------------------------------------------------------------------
// Happy path
// ------------------------------------------------------------------------------------------------

#[test]
fn sign_encode_decode_verify_unwrap() {
    let l = license();
    let bytes = l.to_bytes();
    let back = License::from_bytes(&bytes).unwrap();
    assert_eq!(back, l);
    let v = verify_ok(&back).unwrap();
    assert_eq!(v.license().body.seats, 5);
    assert!(v.entitles_engine("inbox"));
    assert!(!v.entitles_engine("meetings"));
    let cek = v.unwrap_cek("inbox", &device()).unwrap();
    assert_eq!(cek, engine_cek());
}

#[test]
fn one_hardware_change_still_verifies_two_do_not() {
    let l = license();
    let one = HardwareFingerprint::from_raw(&salt(), &raw("disk-2", "02:00:00:00:00:01"));
    let two = HardwareFingerprint::from_raw(&salt(), &raw("disk-2", "02:00:00:00:00:02"));
    let rl = revocations(&[]);
    assert!(verify(&l, &root().verifying_key(), &rl, T0, &one).is_ok());
    assert!(matches!(
        verify(&l, &root().verifying_key(), &rl, T0, &two),
        Err(LicenseError::WrongMachine)
    ));
}

// ------------------------------------------------------------------------------------------------
// Each verification failure
// ------------------------------------------------------------------------------------------------

#[test]
fn wrong_root_key_is_rejected() {
    let other = SigningKey::from_bytes(&[5; 32]);
    let l = license();
    // Revocation list checked first.
    assert!(matches!(
        verify(&l, &other.verifying_key(), &revocations(&[]), T0, &fp()),
        Err(LicenseError::BadRevocationList)
    ));
    // Genuine list from the other root, but certificate from ours.
    let rl = RevocationList::sign(&other, 1, T0, BTreeSet::new());
    assert!(matches!(
        verify(&l, &other.verifying_key(), &rl, T0, &fp()),
        Err(LicenseError::UntrustedIssuer)
    ));
}

#[test]
fn revoked_issuer_is_rejected() {
    let l = license();
    assert!(matches!(
        verify(
            &l,
            &root().verifying_key(),
            &revocations(&[1, 7]),
            T0,
            &fp()
        ),
        Err(LicenseError::IssuerRevoked { serial: 7 })
    ));
}

#[test]
fn issued_outside_certificate_window() {
    let mut rng = ChaCha20Rng::from_seed([1; 32]);
    let mut b = body(&mut rng);
    b.issued_at = T0 + 400 * DAY;
    b.expires_at = b.issued_at + DAY;
    assert!(matches!(
        License::sign(b.clone(), cert(), &issuing()),
        Err(LicenseError::IssuedOutsideCertificate)
    ));
    // Forge by signing with a cert whose window was edited: root signature breaks.
    let mut c = cert();
    c.not_after = T0 + 500 * DAY;
    let l = License::sign(b, c, &issuing()).unwrap();
    assert!(matches!(verify_ok(&l), Err(LicenseError::UntrustedIssuer)));
}

#[test]
fn tampered_body_or_signature_is_rejected() {
    let mut l = license();
    l.body.seats = 500;
    assert!(matches!(verify_ok(&l), Err(LicenseError::BadSignature)));
    let mut l = license();
    l.signature[0] ^= 1;
    assert!(matches!(verify_ok(&l), Err(LicenseError::BadSignature)));
}

#[test]
fn signed_by_wrong_issuing_key() {
    let mut rng = ChaCha20Rng::from_seed([1; 32]);
    let other = SigningKey::from_bytes(&[9; 32]);
    assert!(matches!(
        License::sign(body(&mut rng), cert(), &other),
        Err(LicenseError::Invalid("issuing key"))
    ));
}

#[test]
fn clock_and_expiry() {
    let l = license();
    let rl = revocations(&[]);
    let root = root().verifying_key();
    assert!(verify(&l, &root, &rl, T0 - CLOCK_SKEW_SECS, &fp()).is_ok());
    assert!(matches!(
        verify(&l, &root, &rl, T0 - CLOCK_SKEW_SECS - 1, &fp()),
        Err(LicenseError::ClockBehind { issued_at: T0 })
    ));
    assert!(verify(&l, &root, &rl, T0 + 30 * DAY - 1, &fp()).is_ok());
    assert!(matches!(
        verify(&l, &root, &rl, T0 + 30 * DAY, &fp()),
        Err(LicenseError::Expired { .. })
    ));
}

#[test]
fn offline_grace() {
    let l = license();
    let v = verify_ok(&l).unwrap();
    assert_eq!(v.offline_deadline(T0), T0 + 14 * DAY);
    assert!(v.check_offline_grace(T0, T0 + 14 * DAY).is_ok());
    assert!(matches!(
        v.check_offline_grace(T0, T0 + 14 * DAY + 1),
        Err(LicenseError::OfflineTooLong { .. })
    ));
}

#[test]
fn body_rules() {
    type Mutation = Box<dyn Fn(&mut LicenseBody)>;
    let mut rng = ChaCha20Rng::from_seed([1; 32]);
    let good = body(&mut rng);
    let cases: Vec<(&str, Mutation)> = vec![
        ("license id", Box::new(|b| b.license_id.clear())),
        (
            "customer id",
            Box::new(|b| b.customer_id = "x".repeat(MAX_NAME_LEN + 1)),
        ),
        (
            "workspaces",
            Box::new(|b| {
                b.workspaces.insert(String::new());
            }),
        ),
        ("seats", Box::new(|b| b.seats = 0)),
        ("expiry", Box::new(|b| b.expires_at = b.issued_at)),
        ("device key", Box::new(|b| b.device_public_key = [0; 65])),
        (
            "engine keys",
            Box::new(|b| {
                b.engines.remove("inbox");
            }),
        ),
    ];
    for (field, mutate) in cases {
        let mut b = good.clone();
        mutate(&mut b);
        match b.validate() {
            Err(LicenseError::Invalid(f)) => assert_eq!(f, field),
            other => panic!("{field}: {other:?}"),
        }
        assert!(License::sign(b, cert(), &issuing()).is_err());
    }
}

#[test]
fn decode_rejects_invalid_body_even_if_canonical() {
    // A license whose body breaks a rule can't be produced by `sign`, so build one by hand.
    let mut l = license();
    l.body.seats = 0;
    assert_eq!(
        License::from_bytes(&l.to_bytes()).unwrap_err(),
        DecodeError::InvalidValue("seats")
    );
}

#[test]
fn decode_rejects_bad_binding_tag_and_bad_ephemeral_key() {
    let l = license();
    let bytes = l.to_bytes();
    let rest = &l.body.device_public_key;
    let pos = bytes
        .windows(65)
        .position(|w| w == rest)
        .expect("device key in encoding")
        - 1;
    let mut bad = bytes.clone();
    bad[pos] = 9;
    assert_eq!(
        License::from_bytes(&bad).unwrap_err(),
        DecodeError::InvalidValue("binding")
    );
    let eph = l.body.wrapped_ceks["inbox"].ephemeral_public;
    let p = bytes.windows(65).position(|w| w == eph).unwrap();
    let mut bad = bytes;
    bad[p + 64] ^= 1; // off-curve point
    assert_eq!(
        License::from_bytes(&bad).unwrap_err(),
        DecodeError::InvalidValue("ephemeral key")
    );
}

#[test]
fn decode_rejects_unsorted_wrapped_keys_and_trailing_bytes() {
    let mut bytes = license().to_bytes();
    bytes.push(0);
    assert_eq!(
        License::from_bytes(&bytes).unwrap_err(),
        DecodeError::TrailingBytes
    );
    // Two wrapped keys out of order.
    let mut rng = ChaCha20Rng::from_seed([2; 32]);
    let mut b = body(&mut rng);
    let dev = device();
    b.wrapped_ceks.insert(
        "docs".into(),
        wrap_cek(
            &mut rng,
            &engine_cek(),
            &dev.public_key(),
            "lic-0001",
            "docs",
        ),
    );
    let l = License::sign(b, cert(), &issuing()).unwrap();
    let bytes = l.to_bytes();
    // The last "docs" is the wrapped-key map entry (earlier ones are in the entitlement sets).
    let docs = bytes
        .windows(8)
        .rposition(|w| w == b"\0\0\0\x04docs")
        .unwrap();
    let rec = 8 + wrap::WRAPPED_CEK_LEN;
    // Find the "inbox" record that follows and swap the two records.
    let first = bytes[docs..docs + rec].to_vec();
    let second_len = 9 + wrap::WRAPPED_CEK_LEN;
    let second = bytes[docs + rec..docs + rec + second_len].to_vec();
    let mut swapped = bytes.clone();
    swapped[docs..docs + second_len].copy_from_slice(&second);
    swapped[docs + second_len..docs + second_len + rec].copy_from_slice(&first);
    assert_eq!(
        License::from_bytes(&swapped).unwrap_err(),
        DecodeError::NotSorted
    );
}

// ------------------------------------------------------------------------------------------------
// Unwrapping
// ------------------------------------------------------------------------------------------------

/// A device that claims to be a TPM (or fails ECDH) for error-path tests.
struct FakeTpm(SoftwareDeviceKey, bool);
impl DeviceKey for FakeTpm {
    fn binding_kind(&self) -> BindingKind {
        if self.1 {
            BindingKind::Software
        } else {
            BindingKind::Tpm
        }
    }
    fn public_key(&self) -> arkhon_tpm::p256::PublicKey {
        self.0.public_key()
    }
    fn ecdh(&self, _: &arkhon_tpm::p256::PublicKey) -> Result<SharedSecret, BindingError> {
        Err(BindingError::Hardware("TPM_RC_FAILURE".into()))
    }
}

#[test]
fn unwrap_failures() {
    let l = license();
    let v = verify_ok(&l).unwrap();
    assert!(matches!(
        v.unwrap_cek("meetings", &device()),
        Err(LicenseError::NotEntitled(_))
    ));
    assert!(matches!(
        v.unwrap_cek("docs", &device()),
        Err(LicenseError::MissingKey(_))
    ));
    let other = SoftwareDeviceKey::generate();
    assert!(matches!(
        v.unwrap_cek("inbox", &other),
        Err(LicenseError::WrongDeviceKey)
    ));

    assert!(matches!(
        v.unwrap_cek("inbox", &FakeTpm(device(), false)),
        Err(LicenseError::WrongBinding {
            required: BindingKind::Software,
            found: BindingKind::Tpm
        })
    ));
    assert!(matches!(
        v.unwrap_cek("inbox", &FakeTpm(device(), true)),
        Err(LicenseError::Binding(BindingError::Hardware(_)))
    ));
}

#[test]
fn wrapped_key_is_bound_to_license_and_engine() {
    let mut rng = ChaCha20Rng::from_seed([3; 32]);
    let dev = device();
    let w = wrap_cek(&mut rng, &engine_cek(), &dev.public_key(), "lic-A", "inbox");
    assert_eq!(
        unwrap_cek(&w, &dev, "lic-A", "inbox").unwrap(),
        engine_cek()
    );
    assert!(matches!(
        unwrap_cek(&w, &dev, "lic-B", "inbox"),
        Err(LicenseError::UnwrapFailed)
    ));
    assert!(matches!(
        unwrap_cek(&w, &dev, "lic-A", "docs"),
        Err(LicenseError::UnwrapFailed)
    ));
    let mut bad = w.clone();
    bad.ephemeral_public[0] = 0;
    assert!(matches!(
        unwrap_cek(&bad, &dev, "lic-A", "inbox"),
        Err(LicenseError::UnwrapFailed)
    ));
    let mut bad = w;
    bad.nonce[0] ^= 1;
    assert!(matches!(
        unwrap_cek(&bad, &dev, "lic-A", "inbox"),
        Err(LicenseError::UnwrapFailed)
    ));
}

// ------------------------------------------------------------------------------------------------
// Certificates and revocation lists
// ------------------------------------------------------------------------------------------------

#[test]
fn certificate_round_trip_and_rules() {
    let c = cert();
    assert_eq!(IssuingCertificate::from_bytes(&c.to_bytes()).unwrap(), c);
    assert_eq!(
        c.verify(&root().verifying_key()).unwrap(),
        issuing().verifying_key()
    );
    assert!(c.covers(T0) && !c.covers(T0 + 366 * DAY));
    assert!(matches!(
        IssuingCertificate::issue(&root(), 1, &issuing().verifying_key(), 10, 9),
        Err(LicenseError::Invalid("validity window"))
    ));
    let mut inverted = c.clone();
    inverted.not_before = inverted.not_after + 1;
    assert_eq!(
        IssuingCertificate::from_bytes(&inverted.to_bytes()).unwrap_err(),
        DecodeError::InvalidValue("validity window")
    );
    // A certificate for a weak (small-order) key is refused even if root-signed.
    let mut weak = c.clone();
    weak.issuing_public_key = [0; 32];
    weak.issuing_public_key[0] = 1; // identity point encoding
    weak.root_signature = chain::sign(
        &root(),
        arkhon_crypto::codec::domain::ISSUING_CERT,
        &weak.tbs_bytes(),
    );
    assert!(matches!(
        weak.verify(&root().verifying_key()),
        Err(LicenseError::UntrustedIssuer)
    ));
}

#[test]
fn revocation_list_round_trip_and_monotonic() {
    let rl = revocations(&[3, 1, 2]);
    assert_eq!(RevocationList::from_bytes(&rl.to_bytes()).unwrap(), rl);
    let root = root().verifying_key();
    rl.verify_update(&root, 3).unwrap();
    rl.verify_update(&root, 2).unwrap();
    assert!(matches!(
        rl.verify_update(&root, 4),
        Err(LicenseError::RevocationListRollback {
            seen: 4,
            offered: 3
        })
    ));
    let mut forged = rl.clone();
    forged.version = 99;
    assert!(matches!(
        forged.verify_update(&root, 0),
        Err(LicenseError::BadRevocationList)
    ));
    // Unsorted serials on the wire.
    let mut e = arkhon_crypto::codec::Encoder::new(*b"ARRL", 1);
    e.u64(1).u64(0).u32(2).u64(5).u64(4).array(&[0; 64]);
    assert_eq!(
        RevocationList::from_bytes(&e.finish()).unwrap_err(),
        DecodeError::NotSorted
    );
}

// ------------------------------------------------------------------------------------------------
// Releases
// ------------------------------------------------------------------------------------------------

fn manifest(released_at: u64, engine: &str) -> SignedReleaseManifest {
    let mut files = BTreeMap::new();
    files.insert(
        "weights.arkm".to_owned(),
        ReleaseFile {
            size: 3,
            sha256: sha256(b"abc"),
        },
    );
    ReleaseManifest {
        release_id: [4; 16],
        engine: engine.into(),
        version: "1.0.0".into(),
        released_at,
        files,
    }
    .sign(&issuing())
}

#[test]
fn release_verification_and_install_rules() {
    let root = root().verifying_key();
    let rl = revocations(&[]);
    let m = manifest(T0 + DAY, "inbox");
    let verified = verify_release(&m, &cert(), &root, &rl).unwrap();
    let l = license();
    let v = verify_ok(&l).unwrap();
    v.may_install(verified).unwrap();
    assert!(matches!(
        v.may_install(&manifest(T0, "meetings").manifest),
        Err(LicenseError::NotEntitled(_))
    ));
    let late = manifest(T0 + 365 * DAY + 1, "inbox");
    assert!(matches!(
        v.may_install(&late.manifest),
        Err(LicenseError::OutsideUpdateWindow { .. })
    ));
    // Release dated outside the certificate's window.
    assert!(matches!(
        verify_release(&late, &cert(), &root, &rl),
        Err(LicenseError::IssuedOutsideCertificate)
    ));
    let mut tampered = m.clone();
    tampered.manifest.version = "9.9.9".into();
    assert!(matches!(
        verify_release(&tampered, &cert(), &root, &rl),
        Err(LicenseError::BadSignature)
    ));
    assert!(matches!(
        verify_release(&m, &cert(), &root, &revocations(&[7])),
        Err(LicenseError::IssuerRevoked { serial: 7 })
    ));
}

#[test]
fn domain_separation_prevents_cross_type_signature_reuse() {
    // A license signature must not verify as a release-manifest signature over the same bytes.
    let l = license();
    let msg = [
        arkhon_crypto::codec::domain::RELEASE_MANIFEST,
        &l.signed_bytes(),
    ]
    .concat();
    let sig = ed25519_dalek::Signature::from_bytes(&l.signature);
    assert!(issuing().verifying_key().verify_strict(&msg, &sig).is_err());
}

// ------------------------------------------------------------------------------------------------
// Renewal
// ------------------------------------------------------------------------------------------------

#[test]
fn renewal_round_trip_and_checks() {
    let current = license();
    let mut rng = ChaCha20Rng::from_seed([5; 32]);
    let mut b = body(&mut rng);
    b.issued_at = T0 + 20 * DAY;
    b.expires_at = T0 + 60 * DAY;
    let renewed = License::sign(b, cert(), &issuing()).unwrap();
    let resp = RenewalResponse {
        license: renewed,
        revocation_list: revocations(&[]),
    };
    let resp = RenewalResponse::from_bytes(&resp.to_bytes()).unwrap();
    let root = root().verifying_key();
    let now = T0 + 25 * DAY;
    verify_renewal(&current, &resp, &root, 3, now, &fp()).unwrap();
    assert!(matches!(
        verify_renewal(&current, &resp, &root, 4, now, &fp()),
        Err(LicenseError::RevocationListRollback { .. })
    ));
    // Older license offered as a "renewal".
    let backwards = RenewalResponse {
        license: current.clone(),
        revocation_list: revocations(&[]),
    };
    assert!(matches!(
        verify_renewal(&resp.license, &backwards, &root, 0, T0 + DAY, &fp()),
        Err(LicenseError::RenewalMismatch)
    ));
    // Different license id.
    let mut other = body(&mut rng);
    other.license_id = "lic-9999".into();
    other.wrapped_ceks.clear();
    let other = RenewalResponse {
        license: resign(other),
        revocation_list: revocations(&[]),
    };
    assert!(matches!(
        verify_renewal(&current, &other, &root, 0, T0 + DAY, &fp()),
        Err(LicenseError::RenewalMismatch)
    ));
    let mut extra = resp.to_bytes();
    extra.push(1);
    assert!(RenewalResponse::from_bytes(&extra).is_err());
}

#[test]
fn renewal_request_round_trip() {
    let req = RenewalRequest {
        license_id: "lic-0001".into(),
        device_public_key: device().public_key_sec1(),
        fingerprint: fp(),
        revocation_version: 3,
        last_seen: T0,
        request_id: [8; 16],
    };
    let bytes = req.to_bytes();
    assert_eq!(RenewalRequest::from_bytes(&bytes).unwrap(), req);
    assert!(RenewalRequest::from_bytes(&bytes[..bytes.len() - 1]).is_err());
}

// ------------------------------------------------------------------------------------------------
// Errors
// ------------------------------------------------------------------------------------------------

#[test]
fn every_error_has_a_plain_message() {
    use std::error::Error;
    let errs = vec![
        LicenseError::Decode(DecodeError::Truncated),
        LicenseError::BadRevocationList,
        LicenseError::RevocationListRollback {
            seen: 2,
            offered: 1,
        },
        LicenseError::UntrustedIssuer,
        LicenseError::IssuerRevoked { serial: 1 },
        LicenseError::IssuedOutsideCertificate,
        LicenseError::BadSignature,
        LicenseError::Invalid("seats"),
        LicenseError::ClockBehind { issued_at: 1 },
        LicenseError::Expired { expired_at: 1 },
        LicenseError::OfflineTooLong { deadline: 1 },
        LicenseError::WrongMachine,
        LicenseError::WrongDeviceKey,
        LicenseError::WrongBinding {
            required: BindingKind::Tpm,
            found: BindingKind::Software,
        },
        LicenseError::NotEntitled("x".into()),
        LicenseError::MissingKey("x".into()),
        LicenseError::UnwrapFailed,
        LicenseError::OutsideUpdateWindow { window_end: 1 },
        LicenseError::RenewalMismatch,
        LicenseError::Binding(BindingError::NotFound),
    ];
    for e in &errs {
        let m = e.to_string();
        assert!(m.ends_with('.'), "{m}");
        assert!(!m.contains("Error"), "{m}");
    }
    assert!(errs[0].source().is_some());
    assert!(errs.last().unwrap().source().is_some());
    assert!(errs[1].source().is_none());
    assert!(matches!(
        LicenseError::from(DecodeError::Truncated),
        LicenseError::Decode(_)
    ));
    assert!(matches!(
        LicenseError::from(BindingError::Corrupt),
        LicenseError::Binding(_)
    ));
}

// ------------------------------------------------------------------------------------------------
// Published test vectors (fixed seeds; see test-vectors/README.md)
// ------------------------------------------------------------------------------------------------

fn check_vector(name: &str, bytes: &[u8]) -> Vec<u8> {
    let path = format!("{}/test-vectors/{name}.hex", env!("CARGO_MANIFEST_DIR"));
    if std::env::var_os("ARKHON_REGEN_VECTORS").is_some() {
        std::fs::write(&path, arkhon_crypto::to_hex(bytes) + "\n").unwrap();
    }
    let expected = arkhon_crypto::from_hex(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(bytes, &expected[..], "test vector {name} changed");
    expected
}

#[test]
fn test_vectors() {
    let root_pub = check_vector("root-public", &root().verifying_key().to_bytes());
    let root_pub = ed25519_dalek::VerifyingKey::from_bytes(&root_pub.try_into().unwrap()).unwrap();
    check_vector("issuing-public", &issuing().verifying_key().to_bytes());
    check_vector("device-public", &device().public_key_sec1());
    let c =
        IssuingCertificate::from_bytes(&check_vector("issuing-certificate", &cert().to_bytes()))
            .unwrap();
    let rl = RevocationList::from_bytes(&check_vector(
        "revocation-list",
        &revocations(&[2]).to_bytes(),
    ))
    .unwrap();
    let l = License::from_bytes(&check_vector("license", &license().to_bytes())).unwrap();
    let m = SignedReleaseManifest::from_bytes(&check_vector(
        "release-manifest",
        &manifest(T0 + DAY, "inbox").to_bytes(),
    ))
    .unwrap();
    let v = verify(&l, &root_pub, &rl, T0 + DAY, &fp()).unwrap();
    assert_eq!(v.unwrap_cek("inbox", &device()).unwrap(), engine_cek());
    v.may_install(verify_release(&m, &c, &root_pub, &rl).unwrap())
        .unwrap();
}

// ------------------------------------------------------------------------------------------------
// Property tests
// ------------------------------------------------------------------------------------------------

fn name() -> impl Strategy<Value = String> {
    "[a-z0-9-]{1,12}"
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn prop_license_round_trip(
        license_id in name(),
        customer_id in name(),
        workspaces in prop::collection::btree_set(name(), 0..5),
        engines in prop::collection::btree_set(name(), 0..4),
        packs in prop::collection::btree_set(name(), 0..3),
        seats in 1u32..10_000,
        span in 1u64..10_000_000,
        grace in any::<u32>(),
        window in any::<u64>(),
        kind in 0usize..3,
        seed in any::<[u8; 32]>(),
    ) {
        let mut rng = ChaCha20Rng::from_seed(seed);
        let dev = device();
        let wrapped_ceks = engines
            .iter()
            .map(|e| (e.clone(), wrap_cek(&mut rng, &engine_cek(), &dev.public_key(), &license_id, e)))
            .collect();
        let b = LicenseBody {
            license_id, customer_id, workspaces, engines, packs,
            update_window_end: window, seats, issued_at: T0, expires_at: T0 + span,
            offline_grace_days: grace, binding: BindingKind::ALL[kind],
            device_public_key: dev.public_key_sec1(), fingerprint: fp(), wrapped_ceks,
        };
        let l = License::sign(b, cert(), &issuing()).unwrap();
        let bytes = l.to_bytes();
        let back = License::from_bytes(&bytes).unwrap();
        prop_assert_eq!(&back, &l);
        prop_assert_eq!(back.to_bytes(), bytes);
        prop_assert!(verify(&back, &root().verifying_key(), &revocations(&[]), T0, &fp()).is_ok());
    }

    #[test]
    fn prop_any_bit_flip_in_license_is_rejected(pos in any::<prop::sample::Index>(), bit in 0u8..8) {
        let mut bytes = license().to_bytes();
        let i = pos.index(bytes.len());
        bytes[i] ^= 1 << bit;
        let accepted = License::from_bytes(&bytes).is_ok_and(|l| verify_ok(&l).is_ok());
        prop_assert!(!accepted);
    }

    #[test]
    fn prop_any_truncation_of_license_is_rejected(cut in any::<prop::sample::Index>()) {
        let bytes = license().to_bytes();
        prop_assert!(License::from_bytes(&bytes[..cut.index(bytes.len())]).is_err());
    }

    #[test]
    fn prop_any_bit_flip_in_cert_or_revocation_is_rejected(pos in any::<prop::sample::Index>(), bit in 0u8..8) {
        let root = root().verifying_key();
        let mut c = cert().to_bytes();
        let i = pos.index(c.len());
        c[i] ^= 1 << bit;
        prop_assert!(IssuingCertificate::from_bytes(&c).ok().is_none_or(|c| c.verify(&root).is_err()));
        let mut r = revocations(&[1, 2, 3]).to_bytes();
        let i = pos.index(r.len());
        r[i] ^= 1 << bit;
        prop_assert!(RevocationList::from_bytes(&r).ok().is_none_or(|r| r.verify(&root).is_err()));
    }

    #[test]
    fn prop_wrap_round_trip(cek in any::<[u8; 32]>(), id in name(), engine in name(), seed in any::<[u8; 32]>()) {
        let mut rng = ChaCha20Rng::from_seed(seed);
        let dev = SoftwareDeviceKey::generate_with(&mut rng);
        let w = wrap_cek(&mut rng, &Cek::from_bytes(cek), &dev.public_key(), &id, &engine);
        prop_assert_eq!(unwrap_cek(&w, &dev, &id, &engine).unwrap(), Cek::from_bytes(cek));
    }

    #[test]
    fn prop_arbitrary_bytes_never_panic(data in prop::collection::vec(any::<u8>(), 0..512)) {
        let _ = License::from_bytes(&data);
        let _ = IssuingCertificate::from_bytes(&data);
        let _ = RevocationList::from_bytes(&data);
        let _ = RenewalRequest::from_bytes(&data);
        let _ = RenewalResponse::from_bytes(&data);
    }
}
