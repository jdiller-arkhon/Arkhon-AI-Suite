//! Device-facing endpoints. Inputs are license metadata only.

use std::collections::{BTreeMap, BTreeSet};

use arkhon_crypto::release::SignedReleaseManifest;
use arkhon_license::{
    wrap_cek, License, LicenseBody, RenewalRequest, RenewalResponse, RevocationList,
};
use arkhon_tpm::{
    parse_sec1, BindingKind, HardwareFingerprint, FINGERPRINT_LEN, SEC1_UNCOMPRESSED_LEN,
};
use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::Json;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::{FromRow, PgPool};

use crate::{audit, b64, to_i64, to_u64, unb64, ApiError, ApiResult, AppState};

/// Hash of a normalized activation key (keys are never stored).
#[must_use]
pub fn key_hash(activation_key: &str) -> Vec<u8> {
    let norm: String = activation_key
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_uppercase())
        .collect();
    Sha256::digest(norm.as_bytes()).to_vec()
}

/// A license row.
#[derive(Debug, Clone, FromRow)]
pub struct LicenseRow {
    /// Id.
    pub id: String,
    /// Customer.
    pub customer_id: String,
    /// Plan.
    pub plan: String,
    /// Seats.
    pub seats: i32,
    /// Max active devices.
    pub max_devices: i32,
    /// Workspaces.
    pub workspaces: Vec<String>,
    /// Engines.
    pub engines: Vec<String>,
    /// Packs.
    pub packs: Vec<String>,
    /// Software binding allowed.
    pub allow_software_binding: bool,
    /// Valid from.
    pub starts_at: i64,
    /// Valid until.
    pub expires_at: i64,
    /// Update window end.
    pub update_window_end: i64,
    /// Offline grace days.
    pub offline_grace_days: i32,
    /// Lifetime of each device license before renewal (days).
    pub license_term_days: i32,
    /// active | suspended | revoked.
    pub status: String,
    /// Created.
    pub created_at: i64,
}

pub(crate) const LICENSE_COLS: &str =
    "id, customer_id, plan, seats, max_devices, workspaces, engines, packs, \
     allow_software_binding, starts_at, expires_at, update_window_end, offline_grace_days, \
     license_term_days, status, created_at";

/// Device description sent on activation and check-in.
#[derive(Debug, Deserialize)]
pub struct DeviceInfo {
    /// Uncompressed SEC1 P-256 public key, base64.
    pub device_public_key: String,
    /// 160-byte salted fingerprint, base64.
    pub fingerprint: String,
    /// `tpm`, `secure-enclave` or `software`.
    pub binding: String,
}

/// `POST /v1/activate` body.
#[derive(Debug, Deserialize)]
pub struct ActivateRequest {
    /// The activation key the customer typed.
    pub activation_key: String,
    /// This device.
    #[serde(flatten)]
    pub device: DeviceInfo,
}

/// Activation/check-in response.
#[derive(Debug, Serialize)]
pub struct LicenseResponse {
    /// License id.
    pub license_id: String,
    /// Signed license bytes (base64).
    pub license: String,
    /// Current root-signed revocation list (base64).
    pub revocation_list: String,
}

struct Device {
    public_key: [u8; SEC1_UNCOMPRESSED_LEN],
    fingerprint: HardwareFingerprint,
    binding: BindingKind,
}

fn parse_binding(s: &str) -> ApiResult<BindingKind> {
    match s {
        "tpm" => Ok(BindingKind::Tpm),
        "secure-enclave" => Ok(BindingKind::SecureEnclave),
        "software" => Ok(BindingKind::Software),
        _ => Err(ApiError::bad(
            "binding must be tpm, secure-enclave or software.",
        )),
    }
}

fn binding_name(b: BindingKind) -> &'static str {
    match b {
        BindingKind::Tpm => "tpm",
        BindingKind::SecureEnclave => "secure-enclave",
        BindingKind::Software => "software",
    }
}

fn parse_device(d: &DeviceInfo) -> ApiResult<Device> {
    let pk = unb64(&d.device_public_key, "device_public_key")?;
    let public_key: [u8; SEC1_UNCOMPRESSED_LEN] = pk
        .try_into()
        .map_err(|_| ApiError::bad("device_public_key must be a 65-byte P-256 key."))?;
    parse_sec1(&public_key)
        .map_err(|_| ApiError::bad("device_public_key isn't a valid P-256 key."))?;
    let fp = unb64(&d.fingerprint, "fingerprint")?;
    let fp: [u8; FINGERPRINT_LEN] = fp
        .try_into()
        .map_err(|_| ApiError::bad(format!("fingerprint must be {FINGERPRINT_LEN} bytes.")))?;
    Ok(Device {
        public_key,
        fingerprint: HardwareFingerprint::from_bytes(&fp),
        binding: parse_binding(&d.binding)?,
    })
}

pub(crate) async fn current_revocations(pool: &PgPool) -> ApiResult<RevocationList> {
    let row: Option<(Vec<u8>,)> =
        sqlx::query_as("SELECT list FROM revocation_lists ORDER BY version DESC LIMIT 1")
            .fetch_optional(pool)
            .await?;
    let bytes = row.ok_or_else(|| {
        ApiError(
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "Licensing isn't set up yet: upload a revocation list first.".into(),
        )
    })?;
    RevocationList::from_bytes(&bytes.0)
        .map_err(|_| ApiError::bad("The stored revocation list is damaged."))
}

fn check_license_usable(lic: &LicenseRow, now: u64) -> ApiResult<()> {
    match lic.status.as_str() {
        "active" => {}
        "suspended" => {
            return Err(ApiError::forbidden(
                "This license is paused. Contact your Arkhon administrator or check billing.",
            ))
        }
        _ => return Err(ApiError::forbidden("This license has been revoked.")),
    }
    if now < to_u64(lic.starts_at) {
        return Err(ApiError::forbidden("This license hasn't started yet."));
    }
    if now >= to_u64(lic.expires_at) {
        return Err(ApiError::forbidden(
            "This license has expired. Renew it to keep using Arkhon.",
        ));
    }
    Ok(())
}

/// Sign a device license for `lic`, wrapping the newest permitted release CEK of each engine.
async fn issue(state: &AppState, lic: &LicenseRow, device: &Device) -> ApiResult<License> {
    let now = state.now();
    let device_pub = parse_sec1(&device.public_key).map_err(|_| ApiError::bad("bad device key"))?;
    let releases: Vec<(String, String, Vec<u8>)> = sqlx::query_as(
        "SELECT DISTINCT ON (engine) id, engine, cek_sealed FROM releases \
         WHERE engine = ANY($1) AND released_at <= $2 ORDER BY engine, released_at DESC",
    )
    .bind(&lic.engines)
    .bind(lic.update_window_end)
    .fetch_all(&state.pool)
    .await?;
    let mut wrapped = BTreeMap::new();
    for (release_id, engine, sealed) in releases {
        let cek = state
            .vault
            .open(&release_id, &sealed)
            .map_err(ApiError::bad)?;
        wrapped.insert(
            engine.clone(),
            wrap_cek(&mut OsRng, &cek, &device_pub, &lic.id, &engine),
        );
    }
    let term = u64::try_from(lic.license_term_days).unwrap_or(30) * 86_400;
    let body = LicenseBody {
        license_id: lic.id.clone(),
        customer_id: lic.customer_id.clone(),
        workspaces: lic.workspaces.iter().cloned().collect(),
        engines: lic.engines.iter().cloned().collect(),
        packs: lic.packs.iter().cloned().collect::<BTreeSet<_>>(),
        update_window_end: to_u64(lic.update_window_end),
        seats: u32::try_from(lic.seats).unwrap_or(1),
        issued_at: now,
        expires_at: (now + term).min(to_u64(lic.expires_at)),
        offline_grace_days: u32::try_from(lic.offline_grace_days).unwrap_or(30),
        binding: device.binding,
        device_public_key: device.public_key,
        fingerprint: device.fingerprint.clone(),
        wrapped_ceks: wrapped,
    };
    License::sign(
        body,
        state.signer.certificate().clone(),
        state.signer.signing_key(),
    )
    .map_err(|e| ApiError::bad(e.to_string()))
}

async fn license_by(pool: &PgPool, clause: &str, value: &[u8]) -> ApiResult<Option<LicenseRow>> {
    Ok(sqlx::query_as::<_, LicenseRow>(&format!(
        "SELECT {LICENSE_COLS} FROM licenses WHERE {clause}"
    ))
    .bind(value)
    .fetch_optional(pool)
    .await?)
}

pub(crate) async fn license_by_id(pool: &PgPool, id: &str) -> ApiResult<LicenseRow> {
    sqlx::query_as::<_, LicenseRow>(&format!(
        "SELECT {LICENSE_COLS} FROM licenses WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| ApiError::not_found("No license with that id."))
}

fn respond(lic: &LicenseRow, license: &License, rl: &RevocationList) -> Json<LicenseResponse> {
    Json(LicenseResponse {
        license_id: lic.id.clone(),
        license: b64(&license.to_bytes()),
        revocation_list: b64(&rl.to_bytes()),
    })
}

/// `POST /v1/activate`.
///
/// # Errors
/// Unknown key, unusable license, binding not allowed, all devices in use.
pub async fn activate(
    State(s): State<AppState>,
    Json(req): Json<ActivateRequest>,
) -> ApiResult<Json<LicenseResponse>> {
    let now = s.now();
    let device = parse_device(&req.device)?;
    let lic = license_by(&s.pool, "key_hash = $1", &key_hash(&req.activation_key))
        .await?
        .ok_or_else(|| {
            ApiError::not_found("That activation key isn't recognized. Check it and try again.")
        })?;
    check_license_usable(&lic, now)?;
    if device.binding == BindingKind::Software && !lic.allow_software_binding {
        return Err(ApiError::forbidden(
            "This plan needs a computer with a TPM security chip. Turn on TPM in the computer's settings, or ask Arkhon about software activation.",
        ));
    }
    let rl = current_revocations(&s.pool).await?;
    let mut tx = s.pool.begin().await?;
    // Serialize activations per license so the device limit can't be raced.
    sqlx::query("SELECT id FROM licenses WHERE id = $1 FOR UPDATE")
        .bind(&lic.id)
        .execute(&mut *tx)
        .await?;
    let existing: Option<(i64,)> = sqlx::query_as(
        "SELECT id FROM activations WHERE license_id = $1 AND device_public_key = $2 AND status = 'active'",
    )
    .bind(&lic.id)
    .bind(device.public_key.as_slice())
    .fetch_optional(&mut *tx)
    .await?;
    if let Some((id,)) = existing {
        sqlx::query("UPDATE activations SET fingerprint = $1, last_checkin_at = $2 WHERE id = $3")
            .bind(device.fingerprint.to_bytes().as_slice())
            .bind(to_i64(now))
            .bind(id)
            .execute(&mut *tx)
            .await?;
    } else {
        let (active,): (i64,) = sqlx::query_as(
            "SELECT count(*) FROM activations WHERE license_id = $1 AND status = 'active'",
        )
        .bind(&lic.id)
        .fetch_one(&mut *tx)
        .await?;
        if active >= i64::from(lic.max_devices) {
            return Err(ApiError::conflict(format!(
                "All {} computers on this license are in use. Deactivate one in the Arkhon portal, then try again.",
                lic.max_devices
            )));
        }
        sqlx::query(
            "INSERT INTO activations (license_id, device_public_key, fingerprint, binding, status, activated_at, last_checkin_at) \
             VALUES ($1,$2,$3,$4,'active',$5,$5)",
        )
        .bind(&lic.id)
        .bind(device.public_key.as_slice())
        .bind(device.fingerprint.to_bytes().as_slice())
        .bind(binding_name(device.binding))
        .bind(to_i64(now))
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    let license = issue(&s, &lic, &device).await?;
    audit(
        &s.pool,
        now,
        "device",
        "activate",
        &lic.id,
        json!({ "binding": binding_name(device.binding) }),
    )
    .await?;
    Ok(respond(&lic, &license, &rl))
}

/// `POST /v1/checkin` body.
#[derive(Debug, Deserialize)]
pub struct CheckinRequest {
    /// License id.
    pub license_id: String,
    /// This device.
    #[serde(flatten)]
    pub device: DeviceInfo,
}

async fn renew_for_device(s: &AppState, lic: &LicenseRow, device: &Device) -> ApiResult<License> {
    let now = s.now();
    check_license_usable(lic, now)?;
    let row: Option<(i64, Vec<u8>, String)> = sqlx::query_as(
        "SELECT id, fingerprint, binding FROM activations WHERE license_id = $1 AND device_public_key = $2 AND status = 'active'",
    )
    .bind(&lic.id)
    .bind(device.public_key.as_slice())
    .fetch_optional(&s.pool)
    .await?;
    let (id, stored_fp, binding) = row.ok_or_else(|| {
        ApiError::forbidden("This computer isn't activated on this license. Activate it again.")
    })?;
    let stored: [u8; FINGERPRINT_LEN] = stored_fp
        .try_into()
        .map_err(|_| ApiError::bad("stored fingerprint damaged"))?;
    if !HardwareFingerprint::from_bytes(&stored).matches(&device.fingerprint) {
        return Err(ApiError::forbidden(
            "This computer's hardware changed too much since activation. Deactivate it in the portal and activate again.",
        ));
    }
    if binding != binding_name(device.binding) {
        return Err(ApiError::forbidden(
            "This computer's security binding changed. Activate it again.",
        ));
    }
    sqlx::query("UPDATE activations SET fingerprint = $1, last_checkin_at = $2 WHERE id = $3")
        .bind(device.fingerprint.to_bytes().as_slice())
        .bind(to_i64(now))
        .bind(id)
        .execute(&s.pool)
        .await?;
    issue(s, lic, device).await
}

/// `POST /v1/checkin`.
///
/// # Errors
/// Unknown/unusable license, device not activated or changed too much.
pub async fn checkin(
    State(s): State<AppState>,
    Json(req): Json<CheckinRequest>,
) -> ApiResult<Json<LicenseResponse>> {
    let device = parse_device(&req.device)?;
    let lic = license_by_id(&s.pool, &req.license_id).await?;
    let license = renew_for_device(&s, &lic, &device).await?;
    let rl = current_revocations(&s.pool).await?;
    Ok(respond(&lic, &license, &rl))
}

/// `POST /v1/deactivate` body.
#[derive(Debug, Deserialize)]
pub struct DeactivateRequest {
    /// License id.
    pub license_id: String,
    /// Device public key, base64.
    pub device_public_key: String,
}

/// `POST /v1/deactivate`: free this computer's slot (used before moving to a new computer).
///
/// # Errors
/// Not activated.
pub async fn deactivate(
    State(s): State<AppState>,
    Json(req): Json<DeactivateRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let pk = unb64(&req.device_public_key, "device_public_key")?;
    let now = s.now();
    let done = sqlx::query(
        "UPDATE activations SET status = 'deactivated', deactivated_at = $1 \
         WHERE license_id = $2 AND device_public_key = $3 AND status = 'active'",
    )
    .bind(to_i64(now))
    .bind(&req.license_id)
    .bind(&pk)
    .execute(&s.pool)
    .await?;
    if done.rows_affected() == 0 {
        return Err(ApiError::not_found(
            "This computer isn't activated on that license.",
        ));
    }
    audit(
        &s.pool,
        now,
        "device",
        "deactivate",
        &req.license_id,
        json!({}),
    )
    .await?;
    Ok(Json(
        json!({ "message": "This computer is deactivated. You can now activate Arkhon on another computer." }),
    ))
}

/// `POST /v1/offline/renew`: body is a `RenewalRequest` file; returns a `RenewalResponse` file.
///
/// # Errors
/// Malformed file, replayed request, or the same checks as check-in.
pub async fn offline_renew(State(s): State<AppState>, body: Bytes) -> ApiResult<Response> {
    let bytes = offline_exchange(&s, &body, None, "device").await?;
    Ok(([(header::CONTENT_TYPE, "application/octet-stream")], bytes).into_response())
}

/// Turn a `RenewalRequest` file into `RenewalResponse` bytes. Each request id works once.
///
/// With `customer`, the request's license must belong to that customer (checked before the
/// request id is spent, so a file uploaded to the wrong account can still be used).
pub(crate) async fn offline_exchange(
    s: &AppState,
    body: &[u8],
    customer: Option<&str>,
    actor: &str,
) -> ApiResult<Vec<u8>> {
    let req = RenewalRequest::from_bytes(body)
        .map_err(|_| ApiError::bad("That file isn't an Arkhon renewal request."))?;
    let now = s.now();
    let lic = license_by_id(&s.pool, &req.license_id).await?;
    if customer.is_some_and(|c| c != lic.customer_id) {
        return Err(ApiError::not_found("No license with that id."));
    }
    let fresh = sqlx::query("INSERT INTO seen_renewal_requests (request_id, seen_at) VALUES ($1,$2) ON CONFLICT DO NOTHING")
        .bind(req.request_id.as_slice())
        .bind(to_i64(now))
        .execute(&s.pool)
        .await?;
    if fresh.rows_affected() == 0 {
        return Err(ApiError::conflict(
            "This renewal request was already used. Export a new one from Arkhon.",
        ));
    }
    let binding: Option<(String,)> = sqlx::query_as(
        "SELECT binding FROM activations WHERE license_id = $1 AND device_public_key = $2 AND status = 'active'",
    )
    .bind(&lic.id)
    .bind(req.device_public_key.as_slice())
    .fetch_optional(&s.pool)
    .await?;
    let binding = parse_binding(&binding.map(|b| b.0).unwrap_or_default())
        .map_err(|_| ApiError::forbidden("This computer isn't activated on this license."))?;
    let device = Device {
        public_key: req.device_public_key,
        fingerprint: req.fingerprint.clone(),
        binding,
    };
    let license = renew_for_device(s, &lic, &device).await?;
    let resp = RenewalResponse {
        license,
        revocation_list: current_revocations(&s.pool).await?,
    };
    audit(&s.pool, now, actor, "offline-renew", &lic.id, json!({})).await?;
    Ok(resp.to_bytes())
}

/// `GET /v1/releases` query.
#[derive(Debug, Deserialize)]
pub struct ReleasesQuery {
    /// License id.
    pub license_id: String,
}

/// `GET /v1/releases`: signed manifests this license may install (within its update window).
///
/// # Errors
/// Unknown license.
pub async fn releases(
    State(s): State<AppState>,
    Query(q): Query<ReleasesQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    let lic = license_by_id(&s.pool, &q.license_id).await?;
    let rows: Vec<(String, String, i64, Vec<u8>)> = sqlx::query_as(
        "SELECT engine, version, released_at, manifest FROM releases \
         WHERE engine = ANY($1) AND released_at <= $2 ORDER BY engine, released_at DESC",
    )
    .bind(&lic.engines)
    .bind(lic.update_window_end)
    .fetch_all(&s.pool)
    .await?;
    let list: Vec<_> = rows
        .into_iter()
        .filter(|r| SignedReleaseManifest::from_bytes(&r.3).is_ok())
        .map(|(engine, version, released_at, manifest)| {
            json!({ "engine": engine, "version": version, "released_at": released_at, "manifest": b64(&manifest) })
        })
        .collect();
    Ok(Json(json!({ "license_id": lic.id, "releases": list })))
}
