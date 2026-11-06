//! Integration tests against a real Postgres.
//!
//! Set `ARKHON_TEST_DATABASE_URL` to a server URL whose user may create databases, e.g.
//! `postgresql://arkhon@127.0.0.1:5433/postgres`. Each test creates its own database.
//! Without the variable the tests are skipped locally but **fail in CI** (`CI` is set there).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use arkhon_crypto::ed25519_dalek::SigningKey;
use arkhon_crypto::Cek;
use arkhon_license::{
    verify, verify_renewal, IssuingCertificate, License, RenewalRequest, RenewalResponse,
    RevocationList,
};
use arkhon_tpm::{
    DeviceKey, FingerprintSalt, HardwareFingerprint, RawComponents, SoftwareDeviceKey,
};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use rand_core::OsRng;
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use sqlx::Executor;
use totp_rs::{Algorithm, TOTP};
use tower::ServiceExt;

use super::*;

const T0: u64 = 1_800_000_000;
const SALT: FingerprintSalt = FingerprintSalt([3; 32]);

struct Env {
    app: Router,
    state: AppState,
    clock: Arc<AtomicU64>,
    root: SigningKey,
    token: String,
    totp_secret: Vec<u8>,
}

fn fp(disk: &str, mac: &str) -> HardwareFingerprint {
    HardwareFingerprint::from_raw(
        &SALT,
        &RawComponents {
            machine_id: Some("m-1".into()),
            cpu: Some("Xeon".into()),
            disk: Some(disk.into()),
            board: Some("B-9".into()),
            mac: Some(mac.into()),
        },
    )
}

async fn env_with(limit: u32) -> Option<Env> {
    let Ok(base) = std::env::var("ARKHON_TEST_DATABASE_URL") else {
        assert!(
            std::env::var("CI").is_err(),
            "ARKHON_TEST_DATABASE_URL must be set in CI"
        );
        eprintln!("ARKHON_TEST_DATABASE_URL not set; skipping");
        return None;
    };
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&base)
        .await
        .unwrap();
    let mut n = [0u8; 6];
    rand_core::RngCore::fill_bytes(&mut OsRng, &mut n);
    let db = format!("arkhon_test_{}", crate::hex(&n));
    admin
        .execute(format!("CREATE DATABASE {db}").as_str())
        .await
        .unwrap();
    let url = match base.rsplit_once('/') {
        Some((head, _)) => format!("{head}/{db}"),
        None => panic!("bad URL"),
    };
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await
        .unwrap();
    MIGRATOR.run(&pool).await.unwrap();

    let root = SigningKey::generate(&mut OsRng);
    let issuing = SigningKey::generate(&mut OsRng);
    let cert = IssuingCertificate::issue(
        &root,
        1,
        &issuing.verifying_key(),
        T0 - 86_400,
        T0 + 400 * 86_400,
    )
    .unwrap();
    let clock = Arc::new(AtomicU64::new(T0));
    let c = clock.clone();
    let state = AppState::new(
        pool,
        Arc::new(FileIssuingSigner::new(issuing, cert).unwrap()),
        Arc::new(CekVault::new([5; 32])),
        root.verifying_key(),
    )
    .with_clock(move || c.load(Ordering::SeqCst))
    .with_rate_limit(limit, Duration::from_secs(60));

    let url = admin::create_admin(
        &state,
        "ops@arkhonindustries.com",
        "correct horse battery staple",
    )
    .await
    .unwrap();
    assert!(url.starts_with("otpauth://totp/"));
    let app = router(state.clone());
    let (totp_secret,): (Vec<u8>,) = sqlx::query_as("SELECT totp_secret FROM admins LIMIT 1")
        .fetch_one(&state.pool)
        .await
        .unwrap();
    let mut env = Env {
        app,
        state,
        clock,
        root,
        token: String::new(),
        totp_secret,
    };
    let (st, body) = env
        .call("POST", "/admin/login", Some(json!({ "email": "ops@arkhonindustries.com", "password": "correct horse battery staple", "code": env.code() })))
        .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    env.token = body["token"].as_str().unwrap().to_owned();
    Some(env)
}

impl Env {
    fn code(&self) -> String {
        TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            self.totp_secret.clone(),
            Some("Arkhon".into()),
            "ops@arkhonindustries.com".into(),
        )
        .unwrap()
        .generate(self.clock.load(Ordering::SeqCst))
    }

    async fn call(&self, method: &str, uri: &str, body: Option<Value>) -> (StatusCode, Value) {
        let mut b = Request::builder().method(method).uri(uri);
        if !self.token.is_empty() {
            b = b.header("authorization", format!("Bearer {}", self.token));
        }
        let req = match body {
            Some(v) => b
                .header("content-type", "application/json")
                .body(Body::from(v.to_string()))
                .unwrap(),
            None => b.body(Body::empty()).unwrap(),
        };
        let res = self.app.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn relogin(&mut self) {
        self.token.clear();
        let (st, b) = self
            .call("POST", "/admin/login", Some(json!({ "email": "ops@arkhonindustries.com", "password": "correct horse battery staple", "code": self.code() })))
            .await;
        assert_eq!(st, StatusCode::OK, "{b}");
        self.token = b["token"].as_str().unwrap().into();
    }

    async fn raw(&self, uri: &str, body: Vec<u8>) -> (StatusCode, Vec<u8>) {
        let req = Request::builder()
            .method("POST")
            .uri(uri)
            .body(Body::from(body))
            .unwrap();
        let res = self.app.clone().oneshot(req).await.unwrap();
        let status = res.status();
        (
            status,
            res.into_body().collect().await.unwrap().to_bytes().to_vec(),
        )
    }

    /// Customer + license + one release + revocation list. Returns (license id, activation key, CEK).
    async fn seed(&self, allow_software: bool, max_devices: i32) -> (String, String, Cek) {
        let (_, c) = self
            .call(
                "POST",
                "/admin/customers",
                Some(json!({ "name": "Coastline Mechanical", "email": "dana@coastline.com" })),
            )
            .await;
        let (st, l) = self
            .call("POST", "/admin/licenses", Some(json!({
                "customer_id": c["id"], "plan": "business", "seats": 10, "max_devices": max_devices,
                "workspaces": ["inbox", "docs"], "engines": ["core", "lite"], "allow_software_binding": allow_software,
                "days": 365, "update_window_days": 365
            })))
            .await;
        assert_eq!(st, StatusCode::OK, "{l}");
        let cek = Cek::generate();
        let (st, r) = self
            .call(
                "POST",
                "/admin/releases",
                Some(json!({
                    "engine": "core", "version": "1.0.0", "cek": b64(cek.expose_secret()),
                    "files": { "core-q4.arkm": { "size": 123, "sha256": "ab".repeat(32) } }
                })),
            )
            .await;
        assert_eq!(st, StatusCode::OK, "{r}");
        if !self.has_revocations().await {
            let rl = RevocationList::sign(&self.root, 1, T0, std::collections::BTreeSet::new());
            let (st, b) = self
                .call(
                    "POST",
                    "/admin/revocations",
                    Some(json!({ "list": b64(&rl.to_bytes()) })),
                )
                .await;
            assert_eq!(st, StatusCode::OK, "{b}");
        }
        (
            l["license_id"].as_str().unwrap().into(),
            l["activation_key"].as_str().unwrap().into(),
            cek,
        )
    }

    async fn has_revocations(&self) -> bool {
        let (n,): (i64,) = sqlx::query_as("SELECT count(*) FROM revocation_lists")
            .fetch_one(&self.state.pool)
            .await
            .unwrap();
        n > 0
    }
}

fn device_body(key: &SoftwareDeviceKey, f: &HardwareFingerprint, binding: &str) -> Value {
    json!({ "device_public_key": b64(&key.public_key_sec1()), "fingerprint": b64(&f.to_bytes()), "binding": binding })
}

fn with(mut v: Value, k: &str, val: Value) -> Value {
    v[k] = val;
    v
}

#[tokio::test]
async fn activation_issues_a_license_the_runtime_accepts() {
    let Some(e) = env_with(1000).await else {
        return;
    };
    let (lic_id, key, cek) = e.seed(true, 2).await;
    let dev = SoftwareDeviceKey::generate();
    let f = fp("disk-1", "mac-1");
    let (st, r) = e
        .call(
            "POST",
            "/v1/activate",
            Some(with(
                device_body(&dev, &f, "software"),
                "activation_key",
                json!(key.to_lowercase()),
            )),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{r}");
    let license =
        License::from_bytes(&unb64(r["license"].as_str().unwrap(), "x").unwrap()).unwrap();
    let rl =
        RevocationList::from_bytes(&unb64(r["revocation_list"].as_str().unwrap(), "x").unwrap())
            .unwrap();
    let ok = verify(&license, &e.root.verifying_key(), &rl, T0 + 10, &f).unwrap();
    assert_eq!(ok.license().body.license_id, lic_id);
    assert_eq!(
        ok.unwrap_cek("core", &dev).unwrap().expose_secret(),
        cek.expose_secret()
    );
    assert!(
        ok.unwrap_cek("lite", &dev).is_err(),
        "no lite release yet, so no lite key"
    );
    // Device license lasts license_term_days (30), not the full year.
    assert_eq!(license.body.expires_at, T0 + 30 * 86_400);
}

#[tokio::test]
async fn activation_rules() {
    let Some(e) = env_with(1000).await else {
        return;
    };
    let (lic_id, key, _) = e.seed(false, 1).await;
    let a = SoftwareDeviceKey::generate();
    let b = SoftwareDeviceKey::generate();
    let act = |d: &SoftwareDeviceKey, binding: &str| {
        with(
            device_body(d, &fp("d", "m"), binding),
            "activation_key",
            json!(key),
        )
    };

    let (st, r) = e
        .call("POST", "/v1/activate", Some(act(&a, "software")))
        .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert!(r["error"].as_str().unwrap().contains("TPM"));
    let (st, _) = e
        .call(
            "POST",
            "/v1/activate",
            Some(with(act(&a, "tpm"), "activation_key", json!("ARKH-NOPE"))),
        )
        .await;
    assert_eq!(st, StatusCode::NOT_FOUND);

    assert_eq!(
        e.call("POST", "/v1/activate", Some(act(&a, "tpm"))).await.0,
        StatusCode::OK
    );
    assert_eq!(
        e.call("POST", "/v1/activate", Some(act(&a, "tpm"))).await.0,
        StatusCode::OK,
        "same device again is fine"
    );
    let (st, r) = e.call("POST", "/v1/activate", Some(act(&b, "tpm"))).await;
    assert_eq!(st, StatusCode::CONFLICT, "{r}");
    assert!(r["error"].as_str().unwrap().contains("Deactivate one"));

    // Transfer: deactivate A, then B can activate.
    let (st, _) = e
        .call(
            "POST",
            "/v1/deactivate",
            Some(json!({ "license_id": lic_id, "device_public_key": b64(&a.public_key_sec1()) })),
        )
        .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        e.call("POST", "/v1/activate", Some(act(&b, "tpm"))).await.0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn checkin_renews_and_enforces_status_and_hardware() {
    let Some(mut e) = env_with(1000).await else {
        return;
    };
    let (lic_id, key, _) = e.seed(true, 3).await;
    let d = SoftwareDeviceKey::generate();
    let act = with(
        device_body(&d, &fp("d1", "m1"), "software"),
        "activation_key",
        json!(key),
    );
    assert_eq!(
        e.call("POST", "/v1/activate", Some(act)).await.0,
        StatusCode::OK
    );

    e.clock.store(T0 + 20 * 86_400, Ordering::SeqCst);
    let ci =
        |f: HardwareFingerprint| with(device_body(&d, &f, "software"), "license_id", json!(lic_id));
    let (st, r) = e
        .call("POST", "/v1/checkin", Some(ci(fp("d2", "m1"))))
        .await;
    assert_eq!(
        st,
        StatusCode::OK,
        "one changed component is tolerated: {r}"
    );
    let lic = License::from_bytes(&unb64(r["license"].as_str().unwrap(), "x").unwrap()).unwrap();
    assert_eq!(lic.body.issued_at, T0 + 20 * 86_400);
    let (st, _) = e
        .call("POST", "/v1/checkin", Some(ci(fp("d3", "m3"))))
        .await;
    assert_eq!(
        st,
        StatusCode::FORBIDDEN,
        "two changed components (vs the stored d2/m1) is a different machine"
    );

    e.relogin().await;
    let (st, _) = e
        .call(
            "POST",
            &format!("/admin/licenses/{lic_id}/status"),
            Some(json!({ "status": "suspended", "reason": "failed payment" })),
        )
        .await;
    assert_eq!(st, StatusCode::OK);
    let (st, r) = e
        .call("POST", "/v1/checkin", Some(ci(fp("d2", "m1"))))
        .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert!(r["error"].as_str().unwrap().contains("paused"));
    e.call(
        "POST",
        &format!("/admin/licenses/{lic_id}/status"),
        Some(json!({ "status": "revoked" })),
    )
    .await;
    let (st, _) = e
        .call(
            "POST",
            &format!("/admin/licenses/{lic_id}/status"),
            Some(json!({ "status": "active" })),
        )
        .await;
    assert_eq!(st, StatusCode::CONFLICT, "revoked is final");
}

#[tokio::test]
async fn offline_renewal_file_exchange_and_replay() {
    let Some(e) = env_with(1000).await else {
        return;
    };
    let (lic_id, key, _) = e.seed(true, 1).await;
    let d = SoftwareDeviceKey::generate();
    let f = fp("d", "m");
    let (_, r) = e
        .call(
            "POST",
            "/v1/activate",
            Some(with(
                device_body(&d, &f, "software"),
                "activation_key",
                json!(key),
            )),
        )
        .await;
    let current =
        License::from_bytes(&unb64(r["license"].as_str().unwrap(), "x").unwrap()).unwrap();

    e.clock.store(T0 + 60 * 86_400, Ordering::SeqCst);
    let req = RenewalRequest {
        license_id: lic_id,
        device_public_key: d.public_key_sec1(),
        fingerprint: f.clone(),
        revocation_version: 1,
        last_seen: T0 + 59 * 86_400,
        request_id: [9; 16],
    };
    let (st, bytes) = e.raw("/v1/offline/renew", req.to_bytes()).await;
    assert_eq!(st, StatusCode::OK);
    let resp = RenewalResponse::from_bytes(&bytes).unwrap();
    verify_renewal(
        &current,
        &resp,
        &e.root.verifying_key(),
        1,
        T0 + 60 * 86_400,
        &f,
    )
    .unwrap();
    let (st, _) = e.raw("/v1/offline/renew", req.to_bytes()).await;
    assert_eq!(st, StatusCode::CONFLICT, "a renewal file works once");
    let (st, _) = e.raw("/v1/offline/renew", b"not a file".to_vec()).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn admin_auth_audit_and_key_hygiene() {
    let Some(mut e) = env_with(1000).await else {
        return;
    };
    let (lic_id, key, _) = e.seed(true, 1).await;
    let (st, body) = e
        .call("GET", &format!("/admin/licenses/{lic_id}"), None)
        .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body["plan"], "business");
    let (_, log) = e
        .call("GET", &format!("/admin/audit?target={lic_id}"), None)
        .await;
    assert!(log
        .as_array()
        .unwrap()
        .iter()
        .any(|x| x["action"] == "create-license" && x["actor"] == "ops@arkhonindustries.com"));
    let (_, ov) = e.call("GET", "/admin/overview", None).await;
    assert_eq!(ov["active_licenses"], 1);

    // The activation key is never stored, only its hash.
    let (n,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM licenses WHERE encode(key_hash,'escape') LIKE '%' || $1 || '%'",
    )
    .bind(&key[5..10])
    .fetch_one(&e.state.pool)
    .await
    .unwrap();
    assert_eq!(n, 0);

    let good = e.token.clone();
    e.token = "nope".into();
    assert_eq!(
        e.call("GET", "/admin/customers", None).await.0,
        StatusCode::UNAUTHORIZED
    );
    e.token.clear();
    let (st, _) = e
        .call("POST", "/admin/login", Some(json!({ "email": "ops@arkhonindustries.com", "password": "correct horse battery staple", "code": "000000" })))
        .await;
    assert_eq!(
        st,
        StatusCode::FORBIDDEN,
        "password without a valid code is refused"
    );
    e.token = good;
    e.clock.store(T0 + 9 * 3600, Ordering::SeqCst);
    assert_eq!(
        e.call("GET", "/admin/customers", None).await.0,
        StatusCode::UNAUTHORIZED,
        "sessions expire"
    );
}

#[tokio::test]
async fn revocation_lists_must_be_root_signed_and_newer() {
    let Some(e) = env_with(1000).await else {
        return;
    };
    e.seed(true, 1).await;
    let forged = RevocationList::sign(
        &SigningKey::generate(&mut OsRng),
        5,
        T0,
        std::collections::BTreeSet::new(),
    );
    let (st, _) = e
        .call(
            "POST",
            "/admin/revocations",
            Some(json!({ "list": b64(&forged.to_bytes()) })),
        )
        .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let old = RevocationList::sign(&e.root, 1, T0, std::collections::BTreeSet::new());
    assert_eq!(
        e.call(
            "POST",
            "/admin/revocations",
            Some(json!({ "list": b64(&old.to_bytes()) }))
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let newer = RevocationList::sign(&e.root, 2, T0, [7].into());
    assert_eq!(
        e.call(
            "POST",
            "/admin/revocations",
            Some(json!({ "list": b64(&newer.to_bytes()) }))
        )
        .await
        .0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn releases_follow_the_update_window() {
    let Some(e) = env_with(1000).await else {
        return;
    };
    let (lic_id, _, _) = e.seed(true, 1).await;
    let (_, r) = e
        .call("GET", &format!("/v1/releases?license_id={lic_id}"), None)
        .await;
    assert_eq!(r["releases"].as_array().unwrap().len(), 1);
    e.clock.store(T0 + 400 * 86_400, Ordering::SeqCst);
    // Re-login: the earlier session expired with the clock jump.
    let mut e = e;
    e.token.clear();
    let (_, b) = e
        .call("POST", "/admin/login", Some(json!({ "email": "ops@arkhonindustries.com", "password": "correct horse battery staple", "code": e.code() })))
        .await;
    e.token = b["token"].as_str().unwrap().into();
    e.call("POST", "/admin/releases", Some(json!({ "engine": "core", "version": "2.0.0", "cek": b64(Cek::generate().expose_secret()), "files": { "f": { "size": 1, "sha256": "cd".repeat(32) } } }))).await;
    let (_, r) = e
        .call("GET", &format!("/v1/releases?license_id={lic_id}"), None)
        .await;
    let versions: Vec<_> = r["releases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["version"].clone())
        .collect();
    assert_eq!(
        versions,
        vec![json!("1.0.0")],
        "2.0.0 is after the update window"
    );
}

#[tokio::test]
async fn rate_limit_applies() {
    let Some(e) = env_with(6).await else { return };
    let mut last = StatusCode::OK;
    for _ in 0..8 {
        last = e.call("GET", "/healthz", None).await.0;
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
}

#[test]
fn activation_keys_hash_case_and_dash_insensitively() {
    assert_eq!(
        public::key_hash("ARKH-ABCDE-12345"),
        public::key_hash(" arkh abcde 12345 ")
    );
    assert_ne!(
        public::key_hash("ARKH-ABCDE-12345"),
        public::key_hash("ARKH-ABCDE-12346")
    );
}

#[test]
fn openapi_documents_every_route_and_nothing_else() {
    let spec = include_str!("../openapi.yaml");
    let documented: std::collections::BTreeSet<&str> = spec
        .lines()
        .filter(|l| l.starts_with("  /") && l.trim_end().ends_with(':'))
        .map(|l| l.trim().trim_end_matches(':'))
        .collect();
    let source = [include_str!("lib.rs"), include_str!("admin.rs")].concat();
    let squashed: String = source.split_whitespace().collect();
    let routed: std::collections::BTreeSet<String> = squashed
        .match_indices(".route(\"")
        .map(|(i, m)| {
            let rest = &squashed[i + m.len()..];
            rest[..rest.find('"').unwrap()].to_owned()
        })
        .filter(|p| p != "/openapi.yaml" && p != "/console")
        .collect();
    let documented: std::collections::BTreeSet<String> =
        documented.into_iter().map(str::to_owned).collect();
    assert_eq!(documented, routed);
}
