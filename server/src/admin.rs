//! Admin API: Arkhon staff manage customers, licenses, devices, releases and revocations.
//!
//! Sign-in needs a password **and** a TOTP code (authenticator app). It returns an 8-hour bearer
//! session. Every change is written to the audit log with the admin's email.

use std::collections::BTreeMap;

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use arkhon_crypto::release::{ReleaseFile, ReleaseManifest};
use arkhon_crypto::Cek;
use arkhon_license::RevocationList;
use axum::extract::{FromRequestParts, Path, Query, State};
use axum::http::request::Parts;
use axum::routing::{get, post};
use axum::{Json, Router};
use rand_core::{OsRng, RngCore};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use totp_rs::{Algorithm, TOTP};

use crate::public::{key_hash, LicenseRow, LICENSE_COLS};
use crate::{audit, b64, to_i64, unb64, ApiError, ApiResult, AppState};

const SESSION_SECS: u64 = 8 * 3600;

fn totp(secret: &[u8], email: &str) -> ApiResult<TOTP> {
    TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret.to_vec(),
        Some("Arkhon".into()),
        email.into(),
    )
    .map_err(|_| ApiError::bad("TOTP secret is invalid."))
}

/// Create an admin account. Returns the `otpauth://` URL to add to an authenticator app.
///
/// # Errors
/// Weak password, duplicate admin, database errors.
pub async fn create_admin(state: &AppState, email: &str, password: &str) -> ApiResult<String> {
    let email = email.trim().to_lowercase();
    if password.chars().count() < 14 {
        return Err(ApiError::bad("Use a password of at least 14 characters."));
    }
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| ApiError::bad("Couldn't hash the password."))?
        .to_string();
    let mut secret = vec![0u8; 20];
    OsRng.fill_bytes(&mut secret);
    let url = totp(&secret, &email)?.get_url();
    sqlx::query(
        "INSERT INTO admins (email, password_hash, totp_secret, created_at) VALUES ($1,$2,$3,$4)",
    )
    .bind(&email)
    .bind(&hash)
    .bind(&secret)
    .bind(to_i64(state.now()))
    .execute(&state.pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(d) if d.is_unique_violation() => {
            ApiError::conflict("That admin already exists.")
        }
        other => other.into(),
    })?;
    audit(
        &state.pool,
        state.now(),
        "system",
        "create-admin",
        &email,
        json!({}),
    )
    .await?;
    Ok(url)
}

/// `POST /admin/login` body.
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    /// Email.
    pub email: String,
    /// Password.
    pub password: String,
    /// 6-digit authenticator code.
    pub code: String,
}

async fn login(State(s): State<AppState>, Json(req): Json<LoginRequest>) -> ApiResult<Json<Value>> {
    let email = req.email.trim().to_lowercase();
    let now = s.now();
    let row: Option<(String, Vec<u8>)> =
        sqlx::query_as("SELECT password_hash, totp_secret FROM admins WHERE email = $1")
            .bind(&email)
            .fetch_optional(&s.pool)
            .await?;
    let fail = || ApiError::forbidden("Email, password or code is wrong.");
    let Some((hash, secret)) = row else {
        // Spend comparable time on unknown accounts.
        let _ = Argon2::default()
            .hash_password(req.password.as_bytes(), &SaltString::generate(&mut OsRng));
        audit(&s.pool, now, &email, "login-failed", "admin", json!({})).await?;
        return Err(fail());
    };
    let parsed = PasswordHash::new(&hash).map_err(|_| fail())?;
    let pw_ok = Argon2::default()
        .verify_password(req.password.as_bytes(), &parsed)
        .is_ok();
    let code_ok = totp(&secret, &email)?.check(req.code.trim(), now);
    if !(pw_ok && code_ok) {
        audit(&s.pool, now, &email, "login-failed", "admin", json!({})).await?;
        return Err(fail());
    }
    let mut token = [0u8; 32];
    OsRng.fill_bytes(&mut token);
    let token_b64 = b64(&token);
    sqlx::query("INSERT INTO admin_sessions (token_hash, email, expires_at) VALUES ($1,$2,$3)")
        .bind(Sha256::digest(token_b64.as_bytes()).to_vec())
        .bind(&email)
        .bind(to_i64(now + SESSION_SECS))
        .execute(&s.pool)
        .await?;
    audit(&s.pool, now, &email, "login", "admin", json!({})).await?;
    Ok(Json(
        json!({ "token": token_b64, "expires_at": now + SESSION_SECS }),
    ))
}

/// An authenticated admin (from `Authorization: Bearer <token>`).
#[derive(Debug, Clone)]
pub struct Admin(pub String);

impl FromRequestParts<AppState> for Admin {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, s: &AppState) -> Result<Self, Self::Rejection> {
        let token = parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or_else(|| {
                ApiError(
                    axum::http::StatusCode::UNAUTHORIZED,
                    "Sign in first.".into(),
                )
            })?;
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT email FROM admin_sessions WHERE token_hash = $1 AND expires_at > $2",
        )
        .bind(Sha256::digest(token.trim().as_bytes()).to_vec())
        .bind(to_i64(s.now()))
        .fetch_optional(&s.pool)
        .await?;
        row.map(|r| Admin(r.0)).ok_or_else(|| {
            ApiError(
                axum::http::StatusCode::UNAUTHORIZED,
                "Your session has ended. Sign in again.".into(),
            )
        })
    }
}

fn random_id(prefix: &str) -> String {
    let mut b = [0u8; 9];
    OsRng.fill_bytes(&mut b);
    format!("{prefix}-{}", crate::hex(&b))
}

/// A new activation key: `ARKH-XXXXX-XXXXX-XXXXX-XXXXX` (Crockford-style base32, no I/L/O/U).
fn new_activation_key() -> String {
    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut raw = [0u8; 20];
    OsRng.fill_bytes(&mut raw);
    let chars: Vec<char> = raw
        .iter()
        .map(|b| ALPHABET[usize::from(b & 31)] as char)
        .collect();
    format!(
        "ARKH-{}-{}-{}-{}",
        chars[0..5].iter().collect::<String>(),
        chars[5..10].iter().collect::<String>(),
        chars[10..15].iter().collect::<String>(),
        chars[15..20].iter().collect::<String>()
    )
}

/// `POST /admin/customers` body.
#[derive(Debug, Deserialize)]
pub struct NewCustomer {
    /// Company name.
    pub name: String,
    /// Billing/admin contact email.
    pub email: String,
}

async fn create_customer(
    State(s): State<AppState>,
    Admin(by): Admin,
    Json(c): Json<NewCustomer>,
) -> ApiResult<Json<Value>> {
    if c.name.trim().is_empty() || !c.email.contains('@') {
        return Err(ApiError::bad("Enter a company name and a contact email."));
    }
    let id = random_id("cust");
    sqlx::query("INSERT INTO customers (id, name, email, created_at) VALUES ($1,$2,$3,$4)")
        .bind(&id)
        .bind(c.name.trim())
        .bind(c.email.trim().to_lowercase())
        .bind(to_i64(s.now()))
        .execute(&s.pool)
        .await?;
    audit(
        &s.pool,
        s.now(),
        &by,
        "create-customer",
        &id,
        json!({ "name": c.name.trim() }),
    )
    .await?;
    Ok(Json(json!({ "id": id })))
}

async fn list_customers(State(s): State<AppState>, _a: Admin) -> ApiResult<Json<Value>> {
    let rows: Vec<(String, String, String, i64, i64)> = sqlx::query_as(
        "SELECT c.id, c.name, c.email, c.created_at, \
         (SELECT count(*) FROM licenses l WHERE l.customer_id = c.id) \
         FROM customers c ORDER BY c.created_at DESC",
    )
    .fetch_all(&s.pool)
    .await?;
    Ok(Json(json!(rows
        .into_iter()
        .map(|(id, name, email, created_at, licenses)| json!({ "id": id, "name": name, "email": email, "created_at": created_at, "licenses": licenses }))
        .collect::<Vec<_>>())))
}

/// `POST /admin/licenses` body.
#[derive(Debug, Deserialize)]
pub struct NewLicense {
    /// Customer id.
    pub customer_id: String,
    /// starter | business | pro | trial. Everything else defaults from [`plan_preset`].
    pub plan: String,
    /// Seats (default: the plan's).
    #[serde(default)]
    pub seats: Option<i32>,
    /// Computers that may be active at once.
    #[serde(default = "one")]
    pub max_devices: i32,
    /// Workspaces (default: the plan's).
    #[serde(default)]
    pub workspaces: Option<Vec<String>>,
    /// Engines (default: the plan's).
    #[serde(default)]
    pub engines: Option<Vec<String>>,
    /// Industry packs (e.g. `trades`).
    #[serde(default)]
    pub packs: Vec<String>,
    /// Allow software binding (computers without a TPM). Default: only for trials.
    #[serde(default)]
    pub allow_software_binding: Option<bool>,
    /// License length in days (default: the plan's).
    #[serde(default)]
    pub days: Option<u64>,
    /// Updates included for this many days (default: the plan's).
    #[serde(default)]
    pub update_window_days: Option<u64>,
    /// Offline grace days (90 for air-gapped sites).
    #[serde(default = "thirty")]
    pub offline_grace_days: i32,
    /// Each device license lasts this many days before renewal.
    #[serde(default = "thirty")]
    pub license_term_days: i32,
}

/// What a plan includes by default. The one place plan contents are defined.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Preset {
    /// Plan key.
    pub plan: &'static str,
    /// Display name.
    pub label: &'static str,
    /// Default seats.
    pub seats: i32,
    /// License length.
    pub days: u64,
    /// Update window.
    pub update_window_days: u64,
    /// Workspaces.
    pub workspaces: &'static [&'static str],
    /// Engines.
    pub engines: &'static [&'static str],
    /// Software binding allowed by default.
    pub allow_software_binding: bool,
}

const STARTER_WS: &[&str] = &["inbox", "knowledge", "docs"];
const BUSINESS_WS: &[&str] = &[
    "inbox",
    "knowledge",
    "docs",
    "desk",
    "meetings",
    "growth",
    "insights",
];
const PRO_WS: &[&str] = &[
    "inbox",
    "knowledge",
    "docs",
    "desk",
    "meetings",
    "growth",
    "insights",
    "tune",
];

/// Plan presets (brief section 7).
pub const PRESETS: [Preset; 4] = [
    Preset {
        plan: "trial",
        label: "14-day trial",
        seats: 10,
        days: 14,
        update_window_days: 14,
        workspaces: BUSINESS_WS,
        engines: &[
            "lite",
            "core",
            "vision",
            "embed",
            "rerank",
            "scribe",
            "scribe-small",
        ],
        allow_software_binding: true,
    },
    Preset {
        plan: "starter",
        label: "Starter",
        seats: 5,
        days: 365,
        update_window_days: 365,
        workspaces: STARTER_WS,
        engines: &["lite", "core", "vision", "embed", "rerank"],
        allow_software_binding: false,
    },
    Preset {
        plan: "business",
        label: "Business",
        seats: 10,
        days: 365,
        update_window_days: 365,
        workspaces: BUSINESS_WS,
        engines: &[
            "lite",
            "core",
            "vision",
            "reason",
            "embed",
            "rerank",
            "scribe",
            "scribe-small",
        ],
        allow_software_binding: false,
    },
    Preset {
        plan: "pro",
        label: "Pro",
        seats: 25,
        days: 365,
        update_window_days: 365,
        workspaces: PRO_WS,
        engines: &[
            "lite",
            "core",
            "vision",
            "reason",
            "pro",
            "code",
            "embed",
            "rerank",
            "scribe",
            "scribe-small",
        ],
        allow_software_binding: false,
    },
];

/// The preset for a plan key.
#[must_use]
pub fn plan_preset(plan: &str) -> Option<&'static Preset> {
    PRESETS.iter().find(|p| p.plan == plan)
}

async fn list_plans(_a: Admin) -> Json<Value> {
    Json(json!(PRESETS))
}

fn one() -> i32 {
    1
}
fn thirty() -> i32 {
    30
}

async fn create_license(
    State(s): State<AppState>,
    Admin(by): Admin,
    Json(n): Json<NewLicense>,
) -> ApiResult<Json<Value>> {
    let preset = plan_preset(&n.plan)
        .ok_or_else(|| ApiError::bad("plan must be starter, business, pro or trial."))?;
    let own = |v: &[&str]| v.iter().map(|x| (*x).to_owned()).collect::<Vec<_>>();
    let seats = n.seats.unwrap_or(preset.seats);
    let workspaces = n
        .workspaces
        .clone()
        .unwrap_or_else(|| own(preset.workspaces));
    let engines = n.engines.clone().unwrap_or_else(|| own(preset.engines));
    let days = n.days.unwrap_or(preset.days);
    let update_window_days = n.update_window_days.unwrap_or(preset.update_window_days);
    let allow_software = n
        .allow_software_binding
        .unwrap_or(preset.allow_software_binding);
    if seats < 1 || n.max_devices < 1 || days == 0 || engines.is_empty() || workspaces.is_empty() {
        return Err(ApiError::bad(
            "A license needs seats, devices, days, at least one workspace and one engine.",
        ));
    }
    let exists: Option<(String,)> = sqlx::query_as("SELECT id FROM customers WHERE id = $1")
        .bind(&n.customer_id)
        .fetch_optional(&s.pool)
        .await?;
    if exists.is_none() {
        return Err(ApiError::not_found("No customer with that id."));
    }
    let now = s.now();
    let id = random_id("lic");
    let key = new_activation_key();
    sqlx::query(
        "INSERT INTO licenses (id, customer_id, key_hash, plan, seats, max_devices, workspaces, engines, packs, \
         allow_software_binding, starts_at, expires_at, update_window_end, offline_grace_days, license_term_days, status, created_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,'active',$11)",
    )
    .bind(&id)
    .bind(&n.customer_id)
    .bind(key_hash(&key))
    .bind(&n.plan)
    .bind(seats)
    .bind(n.max_devices)
    .bind(&workspaces)
    .bind(&engines)
    .bind(&n.packs)
    .bind(allow_software)
    .bind(to_i64(now))
    .bind(to_i64(now + days * 86_400))
    .bind(to_i64(now + update_window_days * 86_400))
    .bind(n.offline_grace_days)
    .bind(n.license_term_days)
    .execute(&s.pool)
    .await?;
    audit(
        &s.pool,
        now,
        &by,
        "create-license",
        &id,
        json!({ "customer": n.customer_id, "plan": n.plan, "seats": seats }),
    )
    .await?;
    Ok(Json(
        json!({ "license_id": id, "activation_key": key, "note": "Give this key to the customer now. Arkhon stores only its hash." }),
    ))
}

fn license_json(l: &LicenseRow) -> Value {
    json!({
        "id": l.id, "customer_id": l.customer_id, "plan": l.plan, "seats": l.seats, "max_devices": l.max_devices,
        "workspaces": l.workspaces, "engines": l.engines, "packs": l.packs,
        "allow_software_binding": l.allow_software_binding, "starts_at": l.starts_at, "expires_at": l.expires_at,
        "update_window_end": l.update_window_end, "offline_grace_days": l.offline_grace_days,
        "license_term_days": l.license_term_days, "status": l.status, "created_at": l.created_at,
    })
}

/// `GET /admin/licenses` query.
#[derive(Debug, Deserialize)]
pub struct LicenseFilter {
    /// Only this customer's licenses.
    pub customer_id: Option<String>,
}

async fn list_licenses(
    State(s): State<AppState>,
    _a: Admin,
    Query(f): Query<LicenseFilter>,
) -> ApiResult<Json<Value>> {
    let rows: Vec<LicenseRow> = sqlx::query_as(&format!(
        "SELECT {LICENSE_COLS} FROM licenses WHERE ($1::text IS NULL OR customer_id = $1) ORDER BY created_at DESC"
    ))
    .bind(f.customer_id)
    .fetch_all(&s.pool)
    .await?;
    Ok(Json(json!(rows
        .iter()
        .map(license_json)
        .collect::<Vec<_>>())))
}

async fn get_license(
    State(s): State<AppState>,
    _a: Admin,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let l: LicenseRow = sqlx::query_as(&format!(
        "SELECT {LICENSE_COLS} FROM licenses WHERE id = $1"
    ))
    .bind(&id)
    .fetch_optional(&s.pool)
    .await?
    .ok_or_else(|| ApiError::not_found("No license with that id."))?;
    let acts: Vec<(i64, String, String, i64, i64)> = sqlx::query_as(
        "SELECT id, binding, status, activated_at, last_checkin_at FROM activations WHERE license_id = $1 ORDER BY activated_at DESC",
    )
    .bind(&id)
    .fetch_all(&s.pool)
    .await?;
    let mut v = license_json(&l);
    v["activations"] = json!(acts
        .into_iter()
        .map(|(id, binding, status, activated_at, last_checkin_at)| json!({ "id": id, "binding": binding, "status": status, "activated_at": activated_at, "last_checkin_at": last_checkin_at }))
        .collect::<Vec<_>>());
    Ok(Json(v))
}

/// `POST /admin/licenses/{id}/status` body.
#[derive(Debug, Deserialize)]
pub struct StatusChange {
    /// active | suspended | revoked.
    pub status: String,
    /// Why (kept in the audit log).
    #[serde(default)]
    pub reason: String,
}

async fn set_status(
    State(s): State<AppState>,
    Admin(by): Admin,
    Path(id): Path<String>,
    Json(c): Json<StatusChange>,
) -> ApiResult<Json<Value>> {
    if !["active", "suspended", "revoked"].contains(&c.status.as_str()) {
        return Err(ApiError::bad(
            "status must be active, suspended or revoked.",
        ));
    }
    let current: Option<(String,)> = sqlx::query_as("SELECT status FROM licenses WHERE id = $1")
        .bind(&id)
        .fetch_optional(&s.pool)
        .await?;
    let current = current
        .ok_or_else(|| ApiError::not_found("No license with that id."))?
        .0;
    if current == "revoked" && c.status != "revoked" {
        return Err(ApiError::conflict(
            "A revoked license can't be reactivated. Issue a new one.",
        ));
    }
    sqlx::query("UPDATE licenses SET status = $1 WHERE id = $2")
        .bind(&c.status)
        .bind(&id)
        .execute(&s.pool)
        .await?;
    audit(
        &s.pool,
        s.now(),
        &by,
        "set-license-status",
        &id,
        json!({ "from": current, "to": c.status, "reason": c.reason }),
    )
    .await?;
    Ok(Json(json!({ "id": id, "status": c.status })))
}

/// `POST /admin/licenses/{id}/renew` body.
#[derive(Debug, Deserialize)]
pub struct Renewal {
    /// Extend expiry by this many days (from the later of now and current expiry).
    pub days: u64,
    /// Extend the update window by this many days.
    pub update_window_days: u64,
}

async fn renew(
    State(s): State<AppState>,
    Admin(by): Admin,
    Path(id): Path<String>,
    Json(r): Json<Renewal>,
) -> ApiResult<Json<Value>> {
    let now = to_i64(s.now());
    let done = sqlx::query(
        "UPDATE licenses SET expires_at = GREATEST(expires_at, $1) + $2, update_window_end = GREATEST(update_window_end, $1) + $3 WHERE id = $4",
    )
    .bind(now)
    .bind(to_i64(r.days * 86_400))
    .bind(to_i64(r.update_window_days * 86_400))
    .bind(&id)
    .execute(&s.pool)
    .await?;
    if done.rows_affected() == 0 {
        return Err(ApiError::not_found("No license with that id."));
    }
    audit(
        &s.pool,
        s.now(),
        &by,
        "renew-license",
        &id,
        json!({ "days": r.days, "update_window_days": r.update_window_days }),
    )
    .await?;
    Ok(Json(json!({ "id": id, "renewed": true })))
}

async fn deactivate_device(
    State(s): State<AppState>,
    Admin(by): Admin,
    Path(id): Path<i64>,
) -> ApiResult<Json<Value>> {
    let row: Option<(String,)> = sqlx::query_as(
        "UPDATE activations SET status = 'deactivated', deactivated_at = $1 WHERE id = $2 AND status = 'active' RETURNING license_id",
    )
    .bind(to_i64(s.now()))
    .bind(id)
    .fetch_optional(&s.pool)
    .await?;
    let lic = row
        .ok_or_else(|| ApiError::not_found("No active device with that id."))?
        .0;
    audit(
        &s.pool,
        s.now(),
        &by,
        "deactivate-device",
        &lic,
        json!({ "activation": id }),
    )
    .await?;
    Ok(Json(json!({ "deactivated": id })))
}

/// `POST /admin/releases` body.
#[derive(Debug, Deserialize)]
pub struct NewRelease {
    /// Engine name.
    pub engine: String,
    /// Version label.
    pub version: String,
    /// Files: name → { size, sha256 (hex) } of the encrypted files.
    pub files: BTreeMap<String, FileEntry>,
    /// The release CEK (base64), sealed under the server KEK on arrival.
    pub cek: String,
}

/// One encrypted file in a release.
#[derive(Debug, Deserialize)]
pub struct FileEntry {
    /// Ciphertext size.
    pub size: u64,
    /// SHA-256 of the ciphertext, hex.
    pub sha256: String,
}

fn unhex32(s: &str) -> ApiResult<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 {
        return Err(ApiError::bad("sha256 must be 64 hex characters."));
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|_| ApiError::bad("sha256 isn't hex."))?;
    }
    Ok(out)
}

async fn create_release(
    State(s): State<AppState>,
    Admin(by): Admin,
    Json(r): Json<NewRelease>,
) -> ApiResult<Json<Value>> {
    if r.files.is_empty() {
        return Err(ApiError::bad("A release needs at least one file."));
    }
    let cek_bytes = unb64(&r.cek, "cek")?;
    let cek = Cek::from_slice(&cek_bytes).ok_or_else(|| ApiError::bad("cek must be 32 bytes."))?;
    let mut files = BTreeMap::new();
    for (name, f) in &r.files {
        files.insert(
            name.clone(),
            ReleaseFile {
                size: f.size,
                sha256: unhex32(&f.sha256)?,
            },
        );
    }
    let mut release_id = [0u8; 16];
    OsRng.fill_bytes(&mut release_id);
    let now = s.now();
    let manifest = ReleaseManifest {
        release_id,
        engine: r.engine.clone(),
        version: r.version.clone(),
        released_at: now,
        files,
    }
    .sign(s.signer.signing_key());
    let id: String = crate::hex(&release_id);
    sqlx::query(
        "INSERT INTO releases (id, engine, version, released_at, manifest, cek_sealed, created_at) VALUES ($1,$2,$3,$4,$5,$6,$4)",
    )
    .bind(&id)
    .bind(&r.engine)
    .bind(&r.version)
    .bind(to_i64(now))
    .bind(manifest.to_bytes())
    .bind(s.vault.seal(&id, &cek))
    .execute(&s.pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(d) if d.is_unique_violation() => ApiError::conflict("That engine version already exists."),
        other => other.into(),
    })?;
    audit(
        &s.pool,
        now,
        &by,
        "create-release",
        &id,
        json!({ "engine": r.engine, "version": r.version }),
    )
    .await?;
    Ok(Json(
        json!({ "release_id": id, "manifest": b64(&manifest.to_bytes()) }),
    ))
}

/// `POST /admin/revocations` body.
#[derive(Debug, Deserialize)]
pub struct NewRevocations {
    /// Root-signed revocation list (base64), from `arkhon-keygen revoke`.
    pub list: String,
}

async fn upload_revocations(
    State(s): State<AppState>,
    Admin(by): Admin,
    Json(r): Json<NewRevocations>,
) -> ApiResult<Json<Value>> {
    let bytes = unb64(&r.list, "list")?;
    let list = RevocationList::from_bytes(&bytes)
        .map_err(|_| ApiError::bad("That isn't a revocation list."))?;
    list.verify(&s.root)
        .map_err(|_| ApiError::forbidden("That list isn't signed by the Arkhon root key."))?;
    let (latest,): (Option<i64>,) = sqlx::query_as("SELECT max(version) FROM revocation_lists")
        .fetch_one(&s.pool)
        .await?;
    if let Some(v) = latest {
        if to_i64(list.version) <= v {
            return Err(ApiError::conflict(format!(
                "Upload a newer list: the current version is {v}."
            )));
        }
    }
    sqlx::query("INSERT INTO revocation_lists (version, list, uploaded_at) VALUES ($1,$2,$3)")
        .bind(to_i64(list.version))
        .bind(&bytes)
        .bind(to_i64(s.now()))
        .execute(&s.pool)
        .await?;
    audit(
        &s.pool,
        s.now(),
        &by,
        "upload-revocations",
        "revocations",
        json!({ "version": list.version, "revoked": list.revoked_serials }),
    )
    .await?;
    Ok(Json(json!({ "version": list.version })))
}

/// `GET /admin/audit` query.
#[derive(Debug, Deserialize)]
pub struct AuditFilter {
    /// Only entries about this target (license id, customer id, ...).
    pub target: Option<String>,
    /// Most entries to return (default 100, max 1000).
    pub limit: Option<i64>,
}

async fn audit_log(
    State(s): State<AppState>,
    _a: Admin,
    Query(f): Query<AuditFilter>,
) -> ApiResult<Json<Value>> {
    let rows: Vec<(i64, i64, String, String, String, Value)> = sqlx::query_as(
        "SELECT id, at, actor, action, target, details FROM audit_log WHERE ($1::text IS NULL OR target = $1) ORDER BY id DESC LIMIT $2",
    )
    .bind(f.target)
    .bind(f.limit.unwrap_or(100).clamp(1, 1000))
    .fetch_all(&s.pool)
    .await?;
    Ok(Json(json!(rows
        .into_iter()
        .map(|(id, at, actor, action, target, details)| json!({ "id": id, "at": at, "actor": actor, "action": action, "target": target, "details": details }))
        .collect::<Vec<_>>())))
}

async fn overview(State(s): State<AppState>, _a: Admin) -> ApiResult<Json<Value>> {
    let (customers,): (i64,) = sqlx::query_as("SELECT count(*) FROM customers")
        .fetch_one(&s.pool)
        .await?;
    let (active,): (i64,) = sqlx::query_as("SELECT count(*) FROM licenses WHERE status = 'active'")
        .fetch_one(&s.pool)
        .await?;
    let (devices,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM activations WHERE status = 'active'")
            .fetch_one(&s.pool)
            .await?;
    let (seats,): (Option<i64>,) =
        sqlx::query_as("SELECT sum(seats)::bigint FROM licenses WHERE status = 'active'")
            .fetch_one(&s.pool)
            .await?;
    let soon = to_i64(s.now() + 30 * 86_400);
    let (expiring,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM licenses WHERE status = 'active' AND expires_at < $1")
            .bind(soon)
            .fetch_one(&s.pool)
            .await?;
    let (stale,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM activations WHERE status = 'active' AND last_checkin_at < $1",
    )
    .bind(to_i64(s.now().saturating_sub(30 * 86_400)))
    .fetch_one(&s.pool)
    .await?;
    Ok(Json(json!({
        "customers": customers, "active_licenses": active, "active_devices": devices, "seats": seats.unwrap_or(0),
        "expiring_within_30_days": expiring, "devices_not_seen_30_days": stale,
    })))
}

/// Admin routes.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/admin/login", post(login))
        .route("/admin/overview", get(overview))
        .route("/admin/plans", get(list_plans))
        .route(
            "/admin/customers",
            post(create_customer).get(list_customers),
        )
        .route("/admin/licenses", post(create_license).get(list_licenses))
        .route("/admin/licenses/{id}", get(get_license))
        .route("/admin/licenses/{id}/status", post(set_status))
        .route("/admin/licenses/{id}/renew", post(renew))
        .route(
            "/admin/activations/{id}/deactivate",
            post(deactivate_device),
        )
        .route("/admin/releases", post(create_release))
        .route("/admin/revocations", post(upload_revocations))
        .route("/admin/audit", get(audit_log))
}
