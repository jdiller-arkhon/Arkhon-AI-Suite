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
    .with_rate_limit(limit, Duration::from_secs(60))
    .with_trial_limit(3, Duration::from_secs(3600));

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
        let (releases,): (i64,) = sqlx::query_as("SELECT count(*) FROM releases")
            .fetch_one(&self.state.pool)
            .await
            .unwrap();
        let (st, r) = self
            .call(
                "POST",
                "/admin/releases",
                Some(json!({
                    "engine": "core", "version": format!("1.0.{releases}"), "cek": b64(cek.expose_secret()),
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
    let source = [
        include_str!("lib.rs"),
        include_str!("admin.rs"),
        include_str!("portal.rs"),
    ]
    .concat();
    let squashed: String = source.split_whitespace().collect();
    let routed: std::collections::BTreeSet<String> = squashed
        .match_indices(".route(\"")
        .map(|(i, m)| {
            let rest = &squashed[i + m.len()..];
            rest[..rest.find('"').unwrap()].to_owned()
        })
        .filter(|p| p != "/openapi.yaml" && p != "/console" && p != "/portal")
        .collect();
    let documented: std::collections::BTreeSet<String> =
        documented.into_iter().map(str::to_owned).collect();
    assert_eq!(documented, routed);
}

// ------------------------------------------------------------------ customer portal

impl Env {
    /// Call with an explicit bearer token (a portal session), or none.
    async fn as_user(
        &self,
        token: Option<&str>,
        method: &str,
        uri: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut b = Request::builder().method(method).uri(uri);
        if let Some(t) = token {
            b = b.header("authorization", format!("Bearer {t}"));
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

    async fn upload_as(&self, token: &str, uri: &str, body: Vec<u8>) -> (StatusCode, Vec<u8>) {
        let req = Request::builder()
            .method("POST")
            .uri(uri)
            .header("authorization", format!("Bearer {token}"))
            .body(Body::from(body))
            .unwrap();
        let res = self.app.clone().oneshot(req).await.unwrap();
        let status = res.status();
        (
            status,
            res.into_body().collect().await.unwrap().to_bytes().to_vec(),
        )
    }

    async fn customer_of(&self, license_id: &str) -> String {
        let (c,): (String,) = sqlx::query_as("SELECT customer_id FROM licenses WHERE id = $1")
            .bind(license_id)
            .fetch_one(&self.state.pool)
            .await
            .unwrap();
        c
    }

    /// Admin invites `email` to `customer` with `role`; the person accepts. Returns their session.
    async fn portal_user(&self, customer: &str, email: &str, role: &str) -> String {
        let (st, inv) = self
            .call(
                "POST",
                &format!("/admin/customers/{customer}/portal-invite"),
                Some(json!({ "email": email, "role": role })),
            )
            .await;
        assert_eq!(st, StatusCode::OK, "{inv}");
        assert!(inv["invite_link"]
            .as_str()
            .unwrap()
            .starts_with("/portal#accept="));
        let (st, s) = self
            .as_user(
                None,
                "POST",
                "/portal/invites/accept",
                Some(json!({ "token": inv["invite_token"], "password": "a long portal password" })),
            )
            .await;
        assert_eq!(st, StatusCode::OK, "{s}");
        s["token"].as_str().unwrap().to_owned()
    }

    async fn activate_software(&self, key: &str, dev: &SoftwareDeviceKey) -> (StatusCode, Value) {
        self.call(
            "POST",
            "/v1/activate",
            Some(with(
                device_body(dev, &fp("d", "m"), "software"),
                "activation_key",
                json!(key),
            )),
        )
        .await
    }

    async fn audit_has(&self, actor: &str, action: &str) -> bool {
        let (n,): (i64,) =
            sqlx::query_as("SELECT count(*) FROM audit_log WHERE actor = $1 AND action = $2")
                .bind(actor)
                .bind(action)
                .fetch_one(&self.state.pool)
                .await
                .unwrap();
        n > 0
    }
}

#[tokio::test]
async fn portal_users_only_ever_see_their_own_company() {
    let Some(e) = env_with(1000).await else {
        return;
    };
    let (lic_a, key_a, _) = e.seed(true, 2).await;
    let (lic_b, key_b, _) = e.seed(true, 2).await;
    let (cust_a, cust_b) = (e.customer_of(&lic_a).await, e.customer_of(&lic_b).await);
    let a = e.portal_user(&cust_a, "owner@a.example", "owner").await;
    let b = e.portal_user(&cust_b, "owner@b.example", "owner").await;
    let dev_b = SoftwareDeviceKey::generate();
    assert_eq!(e.activate_software(&key_b, &dev_b).await.0, StatusCode::OK);
    assert_eq!(
        e.activate_software(&key_a, &SoftwareDeviceKey::generate())
            .await
            .0,
        StatusCode::OK
    );

    let (st, ov) = e.as_user(Some(&a), "GET", "/portal/overview", None).await;
    assert_eq!(st, StatusCode::OK, "{ov}");
    let ids: Vec<_> = ov["licenses"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l["id"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(ids, vec![lic_a.clone()]);
    assert_eq!(ov["computers_in_use"], 1);
    let (_, lics) = e.as_user(Some(&a), "GET", "/portal/licenses", None).await;
    assert_eq!(lics.as_array().unwrap().len(), 1);
    let (_, comps) = e.as_user(Some(&a), "GET", "/portal/computers", None).await;
    assert!(comps
        .as_array()
        .unwrap()
        .iter()
        .all(|c| c["license_id"] == lic_a.as_str()));
    let (_, team) = e.as_user(Some(&a), "GET", "/portal/team", None).await;
    assert_eq!(team.as_array().unwrap().len(), 1);
    let (_, dl) = e.as_user(Some(&a), "GET", "/portal/downloads", None).await;
    assert_eq!(dl["licenses"].as_array().unwrap().len(), 1);

    // Everything of company B is invisible to A: 404, as if it didn't exist.
    let (b_act,): (i64,) = sqlx::query_as("SELECT id FROM activations WHERE license_id = $1")
        .bind(&lic_b)
        .fetch_one(&e.state.pool)
        .await
        .unwrap();
    let (b_user,): (String,) = sqlx::query_as("SELECT id FROM portal_users WHERE customer_id = $1")
        .bind(&cust_b)
        .fetch_one(&e.state.pool)
        .await
        .unwrap();
    for (method, uri) in [
        ("GET", format!("/portal/licenses/{lic_b}")),
        ("POST", format!("/portal/licenses/{lic_b}/new-key")),
        ("POST", format!("/portal/computers/{b_act}/deactivate")),
        ("POST", format!("/portal/team/{b_user}/remove")),
        ("POST", format!("/portal/team/{b_user}/reset-link")),
    ] {
        let (st, r) = e.as_user(Some(&a), method, &uri, None).await;
        assert_eq!(st, StatusCode::NOT_FOUND, "{method} {uri}: {r}");
    }
    assert_eq!(
        e.activate_software(&key_b, &dev_b).await.0,
        StatusCode::OK,
        "B's key and computer are untouched"
    );
    let (_, still) = e.as_user(Some(&b), "GET", "/portal/computers", None).await;
    assert_eq!(still[0]["status"], "active");

    // B's offline renewal file uploaded by A: 404, and the file still works for B afterwards.
    let req = RenewalRequest {
        license_id: lic_b.clone(),
        device_public_key: dev_b.public_key_sec1(),
        fingerprint: fp("d", "m"),
        revocation_version: 1,
        last_seen: T0,
        request_id: [4; 16],
    };
    let (st, _) = e
        .upload_as(&a, "/portal/offline/renew", req.to_bytes())
        .await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    let (st, _) = e
        .upload_as(&b, "/portal/offline/renew", req.to_bytes())
        .await;
    assert_eq!(st, StatusCode::OK);

    // Sessions don't cross between admin and portal.
    assert_eq!(
        e.as_user(Some(&a), "GET", "/admin/customers", None).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        e.as_user(Some(&e.token), "GET", "/portal/overview", None)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        e.as_user(None, "GET", "/portal/overview", None).await.0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn portal_roles_limit_what_people_can_change() {
    let Some(e) = env_with(1000).await else {
        return;
    };
    let (lic, key, _) = e.seed(true, 2).await;
    let cust = e.customer_of(&lic).await;
    let viewer = e.portal_user(&cust, "viewer@a.example", "viewer").await;
    let billing = e.portal_user(&cust, "billing@a.example", "billing").await;
    let owner = e.portal_user(&cust, "owner@a.example", "owner").await;
    assert_eq!(
        e.activate_software(&key, &SoftwareDeviceKey::generate())
            .await
            .0,
        StatusCode::OK
    );
    let (act,): (i64,) = sqlx::query_as("SELECT id FROM activations LIMIT 1")
        .fetch_one(&e.state.pool)
        .await
        .unwrap();

    for t in [&viewer, &billing, &owner] {
        for uri in [
            "/portal/overview",
            "/portal/licenses",
            "/portal/computers",
            "/portal/downloads",
            "/portal/team",
            "/portal/me",
        ] {
            assert_eq!(
                e.as_user(Some(t), "GET", uri, None).await.0,
                StatusCode::OK,
                "{uri}"
            );
        }
        assert_eq!(
            e.as_user(Some(t), "GET", &format!("/portal/licenses/{lic}"), None)
                .await
                .0,
            StatusCode::OK
        );
    }
    for t in [&viewer, &billing] {
        for (m, uri, body) in [
            ("POST", format!("/portal/licenses/{lic}/new-key"), None),
            ("POST", format!("/portal/computers/{act}/deactivate"), None),
            (
                "POST",
                "/portal/team".to_owned(),
                Some(json!({ "email": "x@a.example", "role": "viewer" })),
            ),
        ] {
            let (st, r) = e.as_user(Some(t), m, &uri, body).await;
            assert_eq!(st, StatusCode::FORBIDDEN, "{uri}: {r}");
            assert!(r["error"].as_str().unwrap().contains("owner"));
        }
        let (st, _) = e
            .upload_as(t, "/portal/offline/renew", b"whatever".to_vec())
            .await;
        assert_eq!(st, StatusCode::FORBIDDEN);
    }
    // Billing placeholder: owners and billing, not viewers. No payment provider is wired.
    assert_eq!(
        e.as_user(Some(&viewer), "GET", "/portal/invoices", None)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    for t in [&billing, &owner] {
        let (st, inv) = e.as_user(Some(t), "GET", "/portal/invoices", None).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(inv["status"], "not-set-up");
        assert_eq!(inv["title"], "Billing is being set up");
        assert_eq!(inv["invoices"], json!([]));
    }
    // The license detail never contains an activation key.
    let (_, d) = e
        .as_user(
            Some(&viewer),
            "GET",
            &format!("/portal/licenses/{lic}"),
            None,
        )
        .await;
    assert!(d.get("activation_key").is_none());
    assert!(!d.to_string().contains(&key));
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // one account lifecycle, end to end
async fn portal_invites_sign_in_two_step_and_team_rules() {
    let Some(e) = env_with(1000).await else {
        return;
    };
    let (lic, _, _) = e.seed(true, 1).await;
    let cust = e.customer_of(&lic).await;
    let (other_lic, _, _) = e.seed(true, 1).await;
    let other = e.customer_of(&other_lic).await;

    assert_eq!(
        e.call(
            "POST",
            "/admin/customers/cust-nope/portal-invite",
            Some(json!({ "email": "a@b.example" }))
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    let (st, inv) = e
        .call(
            "POST",
            &format!("/admin/customers/{cust}/portal-invite"),
            Some(json!({ "email": "Dana@Coastline.example" })),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{inv}");
    let token = inv["invite_token"].as_str().unwrap();
    let accept = |pw: &str| json!({ "token": token, "password": pw, "name": "Dana" });
    // Invited but not accepted: can't sign in.
    let login = |pw: &str, code: Option<String>| json!({ "email": "dana@coastline.example", "password": pw, "code": code });
    assert_eq!(
        e.as_user(
            None,
            "POST",
            "/portal/login",
            Some(login("a long portal password", None))
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let (st, r) = e
        .as_user(
            None,
            "POST",
            "/portal/invites/accept",
            Some(accept("short")),
        )
        .await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "{r}");
    let (st, _) = e
        .as_user(
            None,
            "POST",
            "/portal/invites/accept",
            Some(accept("a long portal password")),
        )
        .await;
    assert_eq!(st, StatusCode::OK);
    let (st, _) = e
        .as_user(
            None,
            "POST",
            "/portal/invites/accept",
            Some(accept("another long password")),
        )
        .await;
    assert_eq!(st, StatusCode::NOT_FOUND, "an invite link works once");
    assert!(
        e.audit_has("ops@arkhonindustries.com", "portal-invite")
            .await
    );

    // Password sign-in.
    assert_eq!(
        e.as_user(
            None,
            "POST",
            "/portal/login",
            Some(login("wrong password!!", None))
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let (st, s) = e
        .as_user(
            None,
            "POST",
            "/portal/login",
            Some(login("a long portal password", None)),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{s}");
    let owner = s["token"].as_str().unwrap().to_owned();
    let (_, me) = e.as_user(Some(&owner), "GET", "/portal/me", None).await;
    assert_eq!(me["role"], "owner");
    assert_eq!(me["name"], "Dana");
    assert_eq!(me["two_step"], false);

    // Two-step sign-in (TOTP).
    let (st, t) = e
        .as_user(Some(&owner), "POST", "/portal/me/totp", None)
        .await;
    assert_eq!(st, StatusCode::OK);
    assert!(t["otpauth_url"]
        .as_str()
        .unwrap()
        .starts_with("otpauth://totp/"));
    let (pending,): (Vec<u8>,) = sqlx::query_as(
        "SELECT totp_pending FROM portal_users WHERE email = 'dana@coastline.example'",
    )
    .fetch_one(&e.state.pool)
    .await
    .unwrap();
    let code = |at: u64| {
        TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            pending.clone(),
            Some("Arkhon".into()),
            "dana@coastline.example".into(),
        )
        .unwrap()
        .generate(at)
    };
    assert_eq!(
        e.as_user(
            Some(&owner),
            "POST",
            "/portal/me/totp/confirm",
            Some(json!({ "code": "000000" }))
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let now = e.clock.load(Ordering::SeqCst);
    assert_eq!(
        e.as_user(
            Some(&owner),
            "POST",
            "/portal/me/totp/confirm",
            Some(json!({ "code": code(now) }))
        )
        .await
        .0,
        StatusCode::OK
    );
    let (st, r) = e
        .as_user(
            None,
            "POST",
            "/portal/login",
            Some(login("a long portal password", None)),
        )
        .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    assert_eq!(r["totp_required"], true);
    assert_eq!(
        e.as_user(
            None,
            "POST",
            "/portal/login",
            Some(login("a long portal password", Some("123456".into())))
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let (st, _) = e
        .as_user(
            None,
            "POST",
            "/portal/login",
            Some(login("a long portal password", Some(code(now)))),
        )
        .await;
    assert_eq!(st, StatusCode::OK);

    // Team: invite, someone else's email is refused, remove, last-owner and self rules.
    let (st, r) = e
        .as_user(
            Some(&owner),
            "POST",
            "/portal/team",
            Some(json!({ "email": "sam@coastline.example", "role": "viewer" })),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{r}");
    let sam_id = r["user_id"].as_str().unwrap().to_owned();
    let (_, sam) = e
        .as_user(
            None,
            "POST",
            "/portal/invites/accept",
            Some(json!({ "token": r["invite_token"], "password": "sam's long password" })),
        )
        .await;
    let sam = sam["token"].as_str().unwrap().to_owned();
    let _ = e
        .portal_user(&other, "elsewhere@other.example", "owner")
        .await;
    let (st, _) = e
        .as_user(
            Some(&owner),
            "POST",
            "/portal/team",
            Some(json!({ "email": "elsewhere@other.example", "role": "viewer" })),
        )
        .await;
    assert_eq!(st, StatusCode::CONFLICT, "an email belongs to one company");
    let (st, _) = e
        .as_user(
            Some(&owner),
            "POST",
            "/portal/team",
            Some(json!({ "email": "x@coastline.example", "role": "admin" })),
        )
        .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let (owner_id,): (String,) =
        sqlx::query_as("SELECT id FROM portal_users WHERE email = 'dana@coastline.example'")
            .fetch_one(&e.state.pool)
            .await
            .unwrap();
    assert_eq!(
        e.as_user(
            Some(&owner),
            "POST",
            &format!("/portal/team/{owner_id}/remove"),
            None
        )
        .await
        .0,
        StatusCode::BAD_REQUEST,
        "can't remove yourself"
    );
    let (st, _) = e
        .as_user(
            Some(&owner),
            "POST",
            &format!("/portal/team/{sam_id}/remove"),
            None,
        )
        .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        e.as_user(Some(&sam), "GET", "/portal/overview", None)
            .await
            .0,
        StatusCode::UNAUTHORIZED,
        "a removed person's session ends at once"
    );
    assert!(
        e.audit_has("portal:dana@coastline.example", "portal-remove-user")
            .await
    );
    // Promote a second owner, then the first can't be removed by them if they're the last.
    let second = e.portal_user(&cust, "lee@coastline.example", "owner").await;
    let (lee_id,): (String,) =
        sqlx::query_as("SELECT id FROM portal_users WHERE email = 'lee@coastline.example'")
            .fetch_one(&e.state.pool)
            .await
            .unwrap();
    assert_eq!(
        e.as_user(
            Some(&second),
            "POST",
            &format!("/portal/team/{owner_id}/remove"),
            None
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        e.as_user(
            Some(&second),
            "POST",
            &format!("/portal/team/{lee_id}/remove"),
            None
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );

    // Reset link: a fresh one-time link sets a new password.
    let viewer = e
        .portal_user(&cust, "kim@coastline.example", "viewer")
        .await;
    let (kim_id,): (String,) =
        sqlx::query_as("SELECT id FROM portal_users WHERE email = 'kim@coastline.example'")
            .fetch_one(&e.state.pool)
            .await
            .unwrap();
    let (st, link) = e
        .as_user(
            Some(&second),
            "POST",
            &format!("/portal/team/{kim_id}/reset-link"),
            None,
        )
        .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        e.as_user(
            None,
            "POST",
            "/portal/invites/accept",
            Some(json!({ "token": link["invite_token"], "password": "kim's new password" }))
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        e.as_user(Some(&viewer), "GET", "/portal/me", None).await.0,
        StatusCode::UNAUTHORIZED,
        "a new password ends older sessions"
    );

    // Sessions are short; invite links expire.
    let (_, inv2) = e
        .call(
            "POST",
            &format!("/admin/customers/{cust}/portal-invite"),
            Some(json!({ "email": "late@coastline.example", "role": "viewer" })),
        )
        .await;
    e.clock.store(T0 + 3 * 3600, Ordering::SeqCst);
    assert_eq!(
        e.as_user(Some(&second), "GET", "/portal/me", None).await.0,
        StatusCode::UNAUTHORIZED,
        "portal sessions last two hours"
    );
    e.clock.store(T0 + 8 * 86_400, Ordering::SeqCst);
    assert_eq!(
        e.as_user(
            None,
            "POST",
            "/portal/invites/accept",
            Some(json!({ "token": inv2["invite_token"], "password": "late long password" }))
        )
        .await
        .0,
        StatusCode::NOT_FOUND,
        "invite links expire after 7 days"
    );
}

#[tokio::test]
async fn portal_deactivates_a_computer_and_frees_the_slot() {
    let Some(e) = env_with(1000).await else {
        return;
    };
    let (lic, key, _) = e.seed(true, 1).await;
    let owner = e
        .portal_user(&e.customer_of(&lic).await, "o@a.example", "owner")
        .await;
    let first = SoftwareDeviceKey::generate();
    let second = SoftwareDeviceKey::generate();
    assert_eq!(e.activate_software(&key, &first).await.0, StatusCode::OK);
    assert_eq!(
        e.activate_software(&key, &second).await.0,
        StatusCode::CONFLICT,
        "the only slot is in use"
    );
    let (_, comps) = e
        .as_user(Some(&owner), "GET", "/portal/computers", None)
        .await;
    let id = comps[0]["id"].as_i64().unwrap();
    assert_eq!(comps[0]["status"], "active");
    let (st, r) = e
        .as_user(
            Some(&owner),
            "POST",
            &format!("/portal/computers/{id}/deactivate"),
            None,
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{r}");
    assert_eq!(
        e.as_user(
            Some(&owner),
            "POST",
            &format!("/portal/computers/{id}/deactivate"),
            None
        )
        .await
        .0,
        StatusCode::NOT_FOUND,
        "already free"
    );
    assert!(
        e.audit_has("portal:o@a.example", "portal-deactivate-computer")
            .await
    );
    assert_eq!(e.activate_software(&key, &second).await.0, StatusCode::OK);
    let (_, ov) = e
        .as_user(Some(&owner), "GET", "/portal/overview", None)
        .await;
    assert_eq!(ov["computers_in_use"], 1);
    // The deactivated computer can no longer renew.
    let (st, _) = e
        .call(
            "POST",
            "/v1/checkin",
            Some(with(
                device_body(&first, &fp("d", "m"), "software"),
                "license_id",
                json!(lic),
            )),
        )
        .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn portal_offline_activation_file_works_once() {
    let Some(e) = env_with(1000).await else {
        return;
    };
    let (lic, key, _) = e.seed(true, 1).await;
    let owner = e
        .portal_user(&e.customer_of(&lic).await, "o@a.example", "owner")
        .await;
    let d = SoftwareDeviceKey::generate();
    let (_, r) = e.activate_software(&key, &d).await;
    let current =
        License::from_bytes(&unb64(r["license"].as_str().unwrap(), "x").unwrap()).unwrap();
    e.clock.store(T0 + 40 * 86_400, Ordering::SeqCst);
    let owner = {
        // The earlier session expired with the clock jump; sign in again.
        let _ = owner;
        let (_, s) = e
            .as_user(
                None,
                "POST",
                "/portal/login",
                Some(json!({ "email": "o@a.example", "password": "a long portal password" })),
            )
            .await;
        s["token"].as_str().unwrap().to_owned()
    };
    let req = RenewalRequest {
        license_id: lic.clone(),
        device_public_key: d.public_key_sec1(),
        fingerprint: fp("d", "m"),
        revocation_version: 1,
        last_seen: T0 + 39 * 86_400,
        request_id: [7; 16],
    };
    let (st, bytes) = e
        .upload_as(&owner, "/portal/offline/renew", req.to_bytes())
        .await;
    assert_eq!(st, StatusCode::OK);
    let resp = RenewalResponse::from_bytes(&bytes).unwrap();
    verify_renewal(
        &current,
        &resp,
        &e.root.verifying_key(),
        1,
        T0 + 40 * 86_400,
        &fp("d", "m"),
    )
    .unwrap();
    let (st, body) = e
        .upload_as(&owner, "/portal/offline/renew", req.to_bytes())
        .await;
    assert_eq!(st, StatusCode::CONFLICT, "single use");
    assert!(String::from_utf8_lossy(&body).contains("already used"));
    assert_eq!(
        e.raw("/v1/offline/renew", req.to_bytes()).await.0,
        StatusCode::CONFLICT,
        "also spent for the device endpoint"
    );
    let (st, _) = e
        .upload_as(
            &owner,
            "/portal/offline/renew",
            b"not a renewal file".to_vec(),
        )
        .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert!(e.audit_has("portal:o@a.example", "offline-renew").await);
}

#[tokio::test]
async fn portal_new_activation_key_rotates_without_revoking() {
    let Some(e) = env_with(1000).await else {
        return;
    };
    let (lic, old_key, _) = e.seed(true, 3).await;
    let owner = e
        .portal_user(&e.customer_of(&lic).await, "o@a.example", "owner")
        .await;
    let running = SoftwareDeviceKey::generate();
    assert_eq!(
        e.activate_software(&old_key, &running).await.0,
        StatusCode::OK
    );
    let (st, r) = e
        .as_user(
            Some(&owner),
            "POST",
            &format!("/portal/licenses/{lic}/new-key"),
            None,
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{r}");
    let new_key = r["activation_key"].as_str().unwrap().to_owned();
    assert!(new_key.starts_with("ARKH-"));
    assert_ne!(new_key, old_key);
    assert_eq!(
        e.activate_software(&old_key, &SoftwareDeviceKey::generate())
            .await
            .0,
        StatusCode::NOT_FOUND,
        "the old key stops activating new computers"
    );
    assert_eq!(
        e.activate_software(&new_key, &SoftwareDeviceKey::generate())
            .await
            .0,
        StatusCode::OK
    );
    let (st, _) = e
        .call(
            "POST",
            "/v1/checkin",
            Some(with(
                device_body(&running, &fp("d", "m"), "software"),
                "license_id",
                json!(lic),
            )),
        )
        .await;
    assert_eq!(
        st,
        StatusCode::OK,
        "computers already running are unaffected"
    );
    let (_, l) = e
        .as_user(
            Some(&owner),
            "GET",
            &format!("/portal/licenses/{lic}"),
            None,
        )
        .await;
    assert!(!l.to_string().contains(&new_key), "never shown again");
    let (n,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM audit_log WHERE action = 'portal-new-activation-key' AND target = $1 AND actor = 'portal:o@a.example'",
    )
    .bind(&lic)
    .fetch_one(&e.state.pool)
    .await
    .unwrap();
    assert_eq!(n, 1);
    assert!(!e.state.pool.is_closed());
    let (n,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM audit_log WHERE details::text LIKE '%' || $1 || '%'")
            .bind(&new_key[5..15])
            .fetch_one(&e.state.pool)
            .await
            .unwrap();
    assert_eq!(n, 0, "the key isn't written to the audit log");
}

#[tokio::test]
async fn portal_trial_signup_creates_a_working_trial() {
    let Some(e) = env_with(1000).await else {
        return;
    };
    e.seed(true, 1).await; // a revocation list + a core release exist
    let body =
        json!({ "company": "Harbor Dental", "name": "Ana Ruiz", "email": "ana@harbor.example" });
    let (st, t) = e
        .as_user(None, "POST", "/portal/trial", Some(body.clone()))
        .await;
    assert_eq!(st, StatusCode::OK, "{t}");
    assert_eq!(t["trial_ends_at"], T0 + 14 * 86_400);
    let key = t["activation_key"].as_str().unwrap().to_owned();
    let lic = t["license_id"].as_str().unwrap().to_owned();
    // The trial allows computers without a TPM.
    assert_eq!(
        e.activate_software(&key, &SoftwareDeviceKey::generate())
            .await
            .0,
        StatusCode::OK
    );
    let (st, s) = e
        .as_user(
            None,
            "POST",
            "/portal/invites/accept",
            Some(json!({ "token": t["invite_token"], "password": "ana's long password" })),
        )
        .await;
    assert_eq!(st, StatusCode::OK);
    let ana = s["token"].as_str().unwrap();
    let (_, me) = e.as_user(Some(ana), "GET", "/portal/me", None).await;
    assert_eq!(me["role"], "owner");
    assert_eq!(me["company"], "Harbor Dental");
    assert_eq!(me["name"], "Ana Ruiz");
    let (_, ov) = e.as_user(Some(ana), "GET", "/portal/overview", None).await;
    assert_eq!(ov["licenses"][0]["id"], lic.as_str());
    assert_eq!(ov["licenses"][0]["plan"], "trial");
    assert_eq!(ov["licenses"][0]["seats"], 10);
    assert_eq!(ov["licenses"][0]["state"], "ending-soon");
    let (_, dl) = e.as_user(Some(ana), "GET", "/portal/downloads", None).await;
    let rel = &dl["licenses"][0]["releases"][0];
    assert_eq!(rel["engine"], "core");
    assert_eq!(rel["files"][0]["size"], 123);
    assert_eq!(rel["files"][0]["sha256"], "ab".repeat(32));
    assert!(
        e.audit_has("portal:ana@harbor.example", "portal-trial-signup")
            .await
    );

    let (st, _) = e.as_user(None, "POST", "/portal/trial", Some(body)).await;
    assert_eq!(st, StatusCode::CONFLICT, "one account per email");
    let (st, _) = e
        .as_user(
            None,
            "POST",
            "/portal/trial",
            Some(json!({ "company": "", "name": "x", "email": "x@y.example" })),
        )
        .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    // The test limit is 3 trial sign-ups per hour per address (all four calls above count).
    let (st, _) = e
        .as_user(
            None,
            "POST",
            "/portal/trial",
            Some(json!({ "company": "Four", "name": "x", "email": "four@y.example" })),
        )
        .await;
    assert_eq!(st, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn portal_page_is_served_with_a_strict_policy() {
    let Some(e) = env_with(1000).await else {
        return;
    };
    let req = Request::builder()
        .uri("/portal")
        .body(Body::empty())
        .unwrap();
    let res = e.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let csp = res.headers()["content-security-policy"]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(csp.contains("default-src 'none'") && csp.contains("connect-src 'self'"));
    assert_eq!(res.headers()["x-frame-options"], "DENY");
    let html = res.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&html);
    assert!(html.contains("/portal/login"));
    assert!(
        !html.contains("http://") && !html.contains("https://"),
        "no external resources"
    );
}

#[tokio::test]
async fn arkhon_staff_can_reset_a_locked_out_owner() {
    let Some(e) = env_with(1000).await else {
        return;
    };
    let (lic, _, _) = e.seed(true, 1).await;
    let cust = e.customer_of(&lic).await;
    let old = e.portal_user(&cust, "solo@a.example", "owner").await;
    // Same call again from the admin side: password cleared, sessions ended, a new link issued.
    let fresh = e.portal_user(&cust, "solo@a.example", "owner").await;
    assert_eq!(
        e.as_user(Some(&old), "GET", "/portal/me", None).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        e.as_user(Some(&fresh), "GET", "/portal/me", None).await.0,
        StatusCode::OK
    );
    // An owner can't do the same to an active person through Team (they use a reset link).
    let (st, _) = e
        .as_user(
            Some(&fresh),
            "POST",
            "/portal/team",
            Some(json!({ "email": "solo@a.example", "role": "viewer" })),
        )
        .await;
    assert_eq!(st, StatusCode::CONFLICT);
}
