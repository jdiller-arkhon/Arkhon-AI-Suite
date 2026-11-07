//! A throwaway stand-in for the License Manager's device API, for local demos of the runtime
//! without Postgres. Generates fresh root and issuing keys on every start (never use them for
//! anything else), prints the root public key, and issues 30-day software-bound licenses for
//! activation key `DEMO-KEY`.
//!
//! ```text
//! cargo run -p arkhon-runtime --example demo-license-server -- 8455 core,lite,embed
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use arkhon_crypto::Cek;
use arkhon_license::{wrap_cek, IssuingCertificate, License, LicenseBody, RevocationList};
use arkhon_tpm::{parse_sec1, BindingKind, HardwareFingerprint};
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use serde_json::{json, Value};

struct Demo {
    issuing: SigningKey,
    cert: IssuingCertificate,
    revocations: RevocationList,
    engines: Vec<String>,
}

fn b64(d: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(d)
}

fn unb64(v: &Value, k: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(v.get(k)?.as_str()?)
        .ok()
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn issue(d: &Demo, req: &Value) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let bad = || {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Bad device description."})),
        )
    };
    let pk: [u8; 65] = unb64(req, "device_public_key")
        .and_then(|v| v.try_into().ok())
        .ok_or_else(bad)?;
    let fp: [u8; 160] = unb64(req, "fingerprint")
        .and_then(|v| v.try_into().ok())
        .ok_or_else(bad)?;
    let device = parse_sec1(&pk).map_err(|_| bad())?;
    let license_id = "lic-demo-1".to_owned();
    let t = now();
    let wrapped_ceks = d
        .engines
        .iter()
        .map(|e| {
            (
                e.clone(),
                wrap_cek(&mut OsRng, &Cek::generate(), &device, &license_id, e),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let body = LicenseBody {
        license_id: license_id.clone(),
        customer_id: "cust-demo".into(),
        workspaces: BTreeSet::from(["inbox".to_owned()]),
        engines: d.engines.iter().cloned().collect(),
        packs: BTreeSet::new(),
        update_window_end: t + 365 * 86_400,
        seats: 1,
        issued_at: t,
        expires_at: t + 30 * 86_400,
        offline_grace_days: 14,
        binding: BindingKind::Software,
        device_public_key: pk,
        fingerprint: HardwareFingerprint::from_bytes(&fp),
        wrapped_ceks,
    };
    let lic = License::sign(body, d.cert.clone(), &d.issuing).map_err(|_| bad())?;
    Ok(Json(json!({
        "license_id": license_id,
        "license": b64(&lic.to_bytes()),
        "revocation_list": b64(&d.revocations.to_bytes()),
    })))
}

type Reply = Result<Json<Value>, (StatusCode, Json<Value>)>;

async fn activate(State(d): State<Arc<Demo>>, Json(req): Json<Value>) -> Reply {
    if req.get("activation_key").and_then(Value::as_str) != Some("DEMO-KEY") {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error": "That activation key isn't valid."})),
        ));
    }
    issue(&d, &req)
}

async fn checkin(State(d): State<Arc<Demo>>, Json(req): Json<Value>) -> Reply {
    issue(&d, &req)
}

async fn deactivate() -> Json<Value> {
    Json(json!({"message": "This computer is deactivated."}))
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let port = args.first().map_or("8455", String::as_str).to_owned();
    let engines = args
        .get(1)
        .map_or("core,lite,embed", String::as_str)
        .split(',')
        .map(str::to_owned)
        .collect();
    let root = SigningKey::generate(&mut OsRng);
    let issuing = SigningKey::generate(&mut OsRng);
    let t = now();
    let cert = IssuingCertificate::issue(&root, 1, &issuing.verifying_key(), t - 60, t + 86_400)
        .expect("valid window");
    let revocations = RevocationList::sign(&root, 1, t, BTreeSet::new());
    let hex = root
        .verifying_key()
        .to_bytes()
        .iter()
        .fold(String::new(), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        });
    println!("ARKHON_ROOT_PUBLIC_KEY={hex}");
    let demo = Arc::new(Demo {
        issuing,
        cert,
        revocations,
        engines,
    });
    let app = Router::new()
        .route("/v1/activate", post(activate))
        .route("/v1/checkin", post(checkin))
        .route("/v1/deactivate", post(deactivate))
        .with_state(demo);
    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}"))
        .await
        .expect("bind");
    eprintln!("demo license server on http://127.0.0.1:{port}");
    axum::serve(listener, app).await.expect("serve");
}
