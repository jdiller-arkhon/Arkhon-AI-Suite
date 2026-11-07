//! Customer portal API (`/portal/...`): people at a customer company manage their own licenses.
//!
//! * Portal users belong to exactly one customer and have a role: `owner` (can change things),
//!   `billing` (reads everything plus billing) or `viewer` (reads licenses, computers, downloads).
//! * Every query is scoped to the signed-in user's customer. Anything belonging to another
//!   customer answers 404, exactly as if it didn't exist.
//! * Accounts start from a one-time invite link (from Arkhon staff, an owner, or the trial
//!   sign-up). Email isn't wired yet, so links are returned in the API response and logged.
//! * Sign-in is email + password (argon2id), plus a 6-digit code once two-step sign-in is on.
//!   Sessions last two hours and live in their own table, apart from admin sessions.
//! * Every change is written to the audit log as `portal:<email>`.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use arkhon_crypto::release::SignedReleaseManifest;
use axum::body::Bytes;
use axum::extract::{FromRequestParts, Path, State};
use axum::http::request::Parts;
use axum::http::{header, Extensions, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use rand_core::{OsRng, RngCore};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::admin::{new_activation_key, plan_preset, random_id, totp};
use crate::public::{key_hash, LicenseRow, LICENSE_COLS};
use crate::{audit, b64, to_i64, to_u64, ApiError, ApiResult, AppState};

/// Portal sessions are short: two hours.
pub const SESSION_SECS: u64 = 2 * 3600;
/// Invite and reset links work for seven days, once.
pub const INVITE_SECS: u64 = 7 * 86_400;
const MIN_PASSWORD: usize = 12;
const ROLES: [&str; 3] = ["owner", "billing", "viewer"];

fn token_hash(token: &str) -> Vec<u8> {
    Sha256::digest(token.trim().as_bytes()).to_vec()
}

fn new_token() -> String {
    let mut t = [0u8; 32];
    OsRng.fill_bytes(&mut t);
    // URL-safe so it can sit in a link fragment.
    crate::hex(&t)
}

fn hash_password(password: &str) -> ApiResult<String> {
    if password.chars().count() < MIN_PASSWORD {
        return Err(ApiError::bad(format!(
            "Use a password of at least {MIN_PASSWORD} characters."
        )));
    }
    Argon2::default()
        .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
        .map(|h| h.to_string())
        .map_err(|_| ApiError::bad("Couldn't save that password. Try another."))
}

fn valid_email(email: &str) -> bool {
    let e = email.trim();
    e.len() <= 254
        && e.split_once('@')
            .is_some_and(|(a, b)| !a.is_empty() && b.contains('.') && !b.starts_with('.'))
        && !e.contains(char::is_whitespace)
}

/// A one-time link that was just created. Email isn't wired yet, so the caller shows it.
#[derive(Debug)]
pub struct Invite {
    /// Portal user id.
    pub user_id: String,
    /// The raw one-time token (only its hash is stored).
    pub token: String,
}

impl Invite {
    /// Path to open in a browser (`/portal#accept=<token>`).
    #[must_use]
    pub fn path(&self) -> String {
        format!("/portal#accept={}", self.token)
    }

    fn json(&self, email: &str) -> Value {
        json!({
            "user_id": self.user_id, "email": email, "invite_token": self.token, "invite_link": self.path(),
            "note": "Email isn't set up yet: send this link to the person yourself. It works once, for 7 days.",
        })
    }
}

async fn issue_link(s: &AppState, user_id: &str, purpose: &str, email: &str) -> ApiResult<String> {
    let token = new_token();
    sqlx::query(
        "INSERT INTO portal_invites (token_hash, user_id, purpose, expires_at) VALUES ($1,$2,$3,$4)",
    )
    .bind(token_hash(&token))
    .bind(user_id)
    .bind(purpose)
    .bind(to_i64(s.now() + INVITE_SECS))
    .execute(&s.pool)
    .await?;
    // Until SMTP is wired, the link is logged for Arkhon staff as well as returned.
    eprintln!("portal {purpose} link for {email}: /portal#accept={token}");
    Ok(token)
}

/// Invite `email` to `customer_id` with `role`. Re-inviting someone who is still invited (or was
/// removed) from the same company issues a fresh link. With `reset_active` (Arkhon staff only),
/// an active account of the same company is reset too: password and two-step sign-in are cleared
/// and its sessions end. An email that belongs to another company is always refused.
///
/// # Errors
/// Bad input, unknown customer, email already in use.
pub async fn invite_user(
    s: &AppState,
    customer_id: &str,
    email: &str,
    role: &str,
    actor: &str,
    reset_active: bool,
) -> ApiResult<Invite> {
    let email = email.trim().to_lowercase();
    if !valid_email(&email) {
        return Err(ApiError::bad("Enter a valid email address."));
    }
    if !ROLES.contains(&role) {
        return Err(ApiError::bad("role must be owner, billing or viewer."));
    }
    let exists: Option<(String,)> = sqlx::query_as("SELECT id FROM customers WHERE id = $1")
        .bind(customer_id)
        .fetch_optional(&s.pool)
        .await?;
    if exists.is_none() {
        return Err(ApiError::not_found("No customer with that id."));
    }
    let now = s.now();
    let mut tx = s.pool.begin().await?;
    let existing: Option<(String, String, String)> = sqlx::query_as(
        "SELECT id, customer_id, status FROM portal_users WHERE email = $1 FOR UPDATE",
    )
    .bind(&email)
    .fetch_optional(&mut *tx)
    .await?;
    let user_id = match existing {
        Some((id, cust, status)) if cust == customer_id && (status != "active" || reset_active) => {
            sqlx::query("DELETE FROM portal_sessions WHERE user_id = $1")
                .bind(&id)
                .execute(&mut *tx)
                .await?;
            sqlx::query(
                "UPDATE portal_users SET role = $1, status = 'invited', password_hash = NULL, totp_secret = NULL, totp_pending = NULL WHERE id = $2",
            )
            .bind(role)
            .bind(&id)
            .execute(&mut *tx)
            .await?;
            // Older links for this person stop working.
            sqlx::query(
                "UPDATE portal_invites SET used_at = $1 WHERE user_id = $2 AND used_at IS NULL",
            )
            .bind(to_i64(now))
            .bind(&id)
            .execute(&mut *tx)
            .await?;
            id
        }
        Some(_) => {
            return Err(ApiError::conflict(
                "That email already has an Arkhon portal account.",
            ))
        }
        None => {
            let id = random_id("pu");
            sqlx::query(
                "INSERT INTO portal_users (id, customer_id, email, role, status, created_at) VALUES ($1,$2,$3,$4,'invited',$5)",
            )
            .bind(&id)
            .bind(customer_id)
            .bind(&email)
            .bind(role)
            .bind(to_i64(now))
            .execute(&mut *tx)
            .await?;
            id
        }
    };
    tx.commit().await?;
    let token = issue_link(s, &user_id, "invite", &email).await?;
    audit(
        &s.pool,
        now,
        actor,
        "portal-invite",
        customer_id,
        json!({ "email": email, "role": role }),
    )
    .await?;
    Ok(Invite { user_id, token })
}

/// Invite JSON for API responses.
#[must_use]
pub fn invite_json(inv: &Invite, email: &str) -> Value {
    inv.json(&email.trim().to_lowercase())
}

/// The signed-in portal user (from `Authorization: Bearer <token>`).
#[derive(Debug, Clone)]
pub struct PortalUser {
    /// User id.
    pub id: String,
    /// Their company.
    pub customer_id: String,
    /// Email.
    pub email: String,
    /// owner | billing | viewer.
    pub role: String,
}

impl PortalUser {
    fn actor(&self) -> String {
        format!("portal:{}", self.email)
    }

    fn require(&self, roles: &[&str]) -> ApiResult<()> {
        if roles.contains(&self.role.as_str()) {
            Ok(())
        } else if roles == ["owner"] {
            Err(ApiError::forbidden(
                "Only an owner of your company's Arkhon account can do this.",
            ))
        } else {
            Err(ApiError::forbidden("Your role can't see this page."))
        }
    }
}

fn unauthorized(msg: &str) -> ApiError {
    ApiError(StatusCode::UNAUTHORIZED, msg.into())
}

impl FromRequestParts<AppState> for PortalUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, s: &AppState) -> Result<Self, Self::Rejection> {
        let token = parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or_else(|| unauthorized("Sign in first."))?;
        let row: Option<(String, String, String, String)> = sqlx::query_as(
            "SELECT u.id, u.customer_id, u.email, u.role FROM portal_sessions s JOIN portal_users u ON u.id = s.user_id \
             WHERE s.token_hash = $1 AND s.expires_at > $2 AND u.status = 'active'",
        )
        .bind(token_hash(token))
        .bind(to_i64(s.now()))
        .fetch_optional(&s.pool)
        .await?;
        row.map(|(id, customer_id, email, role)| PortalUser {
            id,
            customer_id,
            email,
            role,
        })
        .ok_or_else(|| unauthorized("Your session has ended. Sign in again."))
    }
}

async fn new_session(s: &AppState, user_id: &str) -> ApiResult<Value> {
    let token = new_token();
    let expires = s.now() + SESSION_SECS;
    sqlx::query("INSERT INTO portal_sessions (token_hash, user_id, expires_at) VALUES ($1,$2,$3)")
        .bind(token_hash(&token))
        .bind(user_id)
        .bind(to_i64(expires))
        .execute(&s.pool)
        .await?;
    Ok(json!({ "token": token, "expires_at": expires }))
}

// ---------------------------------------------------------------- sign-in, invites, two-step

/// `POST /portal/login` body.
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    /// Email.
    pub email: String,
    /// Password.
    pub password: String,
    /// 6-digit code (only once two-step sign-in is on).
    #[serde(default)]
    pub code: Option<String>,
}

async fn login(State(s): State<AppState>, Json(req): Json<LoginRequest>) -> ApiResult<Response> {
    let email = req.email.trim().to_lowercase();
    let now = s.now();
    let row: Option<(String, Option<String>, Option<Vec<u8>>)> = sqlx::query_as(
        "SELECT id, password_hash, totp_secret FROM portal_users WHERE email = $1 AND status = 'active'",
    )
    .bind(&email)
    .fetch_optional(&s.pool)
    .await?;
    let fail = || ApiError::forbidden("Email or password is wrong.");
    let Some((id, Some(hash), secret)) = row else {
        let _ = Argon2::default()
            .hash_password(req.password.as_bytes(), &SaltString::generate(&mut OsRng));
        audit(
            &s.pool,
            now,
            &format!("portal:{email}"),
            "portal-login-failed",
            "portal",
            json!({}),
        )
        .await?;
        return Err(fail());
    };
    let parsed = PasswordHash::new(&hash).map_err(|_| fail())?;
    if Argon2::default()
        .verify_password(req.password.as_bytes(), &parsed)
        .is_err()
    {
        audit(
            &s.pool,
            now,
            &format!("portal:{email}"),
            "portal-login-failed",
            "portal",
            json!({}),
        )
        .await?;
        return Err(fail());
    }
    if let Some(secret) = secret {
        let Some(code) = req.code.as_deref().map(str::trim).filter(|c| !c.is_empty()) else {
            return Ok((
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "Enter the 6-digit code from your authenticator app.", "totp_required": true })),
            )
                .into_response());
        };
        if !totp(&secret, &email)?.check(code, now) {
            audit(
                &s.pool,
                now,
                &format!("portal:{email}"),
                "portal-login-failed",
                "portal",
                json!({ "reason": "code" }),
            )
            .await?;
            return Err(ApiError::forbidden(
                "That code is wrong. Use the newest one.",
            ));
        }
    }
    let session = new_session(&s, &id).await?;
    audit(
        &s.pool,
        now,
        &format!("portal:{email}"),
        "portal-login",
        "portal",
        json!({}),
    )
    .await?;
    Ok(Json(session).into_response())
}

/// `POST /portal/invites/accept` body.
#[derive(Debug, Deserialize)]
pub struct AcceptRequest {
    /// Token from the invite or reset link.
    pub token: String,
    /// New password.
    pub password: String,
    /// Display name (optional).
    #[serde(default)]
    pub name: Option<String>,
}

async fn accept(
    State(s): State<AppState>,
    Json(req): Json<AcceptRequest>,
) -> ApiResult<Json<Value>> {
    let hash = hash_password(&req.password)?;
    let now = s.now();
    let mut tx = s.pool.begin().await?;
    let row: Option<(String, String, String)> = sqlx::query_as(
        "UPDATE portal_invites i SET used_at = $1 FROM portal_users u \
         WHERE i.token_hash = $2 AND i.used_at IS NULL AND i.expires_at > $1 AND u.id = i.user_id AND u.status <> 'removed' \
         RETURNING u.id, u.email, u.customer_id",
    )
    .bind(to_i64(now))
    .bind(token_hash(&req.token))
    .fetch_optional(&mut *tx)
    .await?;
    let (id, email, customer) = row.ok_or_else(|| {
        ApiError::not_found(
            "This link has expired or was already used. Ask your company's owner (or Arkhon) for a new one.",
        )
    })?;
    sqlx::query(
        "UPDATE portal_users SET password_hash = $1, status = 'active', name = COALESCE(NULLIF($2, ''), name) WHERE id = $3",
    )
    .bind(&hash)
    .bind(req.name.as_deref().map(str::trim).unwrap_or_default())
    .bind(&id)
    .execute(&mut *tx)
    .await?;
    // A new password ends every other session.
    sqlx::query("DELETE FROM portal_sessions WHERE user_id = $1")
        .bind(&id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    audit(
        &s.pool,
        now,
        &format!("portal:{email}"),
        "portal-set-password",
        &customer,
        json!({}),
    )
    .await?;
    Ok(Json(new_session(&s, &id).await?))
}

async fn logout(State(s): State<AppState>, parts: Parts) -> ApiResult<Json<Value>> {
    if let Some(t) = parts
        .headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    {
        sqlx::query("DELETE FROM portal_sessions WHERE token_hash = $1")
            .bind(token_hash(t))
            .execute(&s.pool)
            .await?;
    }
    Ok(Json(json!({ "signed_out": true })))
}

async fn me(State(s): State<AppState>, u: PortalUser) -> ApiResult<Json<Value>> {
    let (name, company, totp_on): (String, String, bool) = sqlx::query_as(
        "SELECT u.name, c.name, u.totp_secret IS NOT NULL FROM portal_users u JOIN customers c ON c.id = u.customer_id WHERE u.id = $1",
    )
    .bind(&u.id)
    .fetch_one(&s.pool)
    .await?;
    Ok(Json(json!({
        "id": u.id, "email": u.email, "name": name, "role": u.role, "customer_id": u.customer_id,
        "company": company, "two_step": totp_on,
    })))
}

async fn totp_start(State(s): State<AppState>, u: PortalUser) -> ApiResult<Json<Value>> {
    let mut secret = vec![0u8; 20];
    OsRng.fill_bytes(&mut secret);
    let t = totp(&secret, &u.email)?;
    sqlx::query("UPDATE portal_users SET totp_pending = $1 WHERE id = $2")
        .bind(&secret)
        .bind(&u.id)
        .execute(&s.pool)
        .await?;
    Ok(Json(json!({
        "otpauth_url": t.get_url(), "secret": t.get_secret_base32(),
        "next": "Add this to your authenticator app, then confirm with the 6-digit code it shows.",
    })))
}

/// `POST /portal/me/totp/confirm` body.
#[derive(Debug, Deserialize)]
pub struct CodeRequest {
    /// 6-digit code.
    pub code: String,
}

async fn totp_confirm(
    State(s): State<AppState>,
    u: PortalUser,
    Json(c): Json<CodeRequest>,
) -> ApiResult<Json<Value>> {
    let (pending,): (Option<Vec<u8>>,) =
        sqlx::query_as("SELECT totp_pending FROM portal_users WHERE id = $1")
            .bind(&u.id)
            .fetch_one(&s.pool)
            .await?;
    let pending = pending.ok_or_else(|| ApiError::bad("Start two-step sign-in first."))?;
    if !totp(&pending, &u.email)?.check(c.code.trim(), s.now()) {
        return Err(ApiError::bad("That code is wrong. Use the newest one."));
    }
    sqlx::query(
        "UPDATE portal_users SET totp_secret = totp_pending, totp_pending = NULL WHERE id = $1",
    )
    .bind(&u.id)
    .execute(&s.pool)
    .await?;
    audit(
        &s.pool,
        s.now(),
        &u.actor(),
        "portal-two-step-on",
        &u.customer_id,
        json!({}),
    )
    .await?;
    Ok(Json(json!({ "two_step": true })))
}

// ---------------------------------------------------------------- licenses and computers

fn plan_label(plan: &str) -> &'static str {
    plan_preset(plan).map_or("Custom", |p| p.label)
}

/// Plain-language status for a non-technical owner.
fn status_text(l: &LicenseRow, now: u64) -> (&'static str, String) {
    let ends = to_u64(l.expires_at);
    match l.status.as_str() {
        "suspended" => (
            "paused",
            "Paused. Computers keep working for a short while, then stop. Check billing or contact Arkhon.".into(),
        ),
        "revoked" => ("ended", "This license has been cancelled.".into()),
        _ if now >= ends => ("ended", "This license has ended. Renew it to keep using Arkhon.".into()),
        _ if now < to_u64(l.starts_at) => ("not-started", "This license hasn't started yet.".into()),
        _ => {
            let days = (ends - now) / 86_400;
            if days <= 30 {
                ("ending-soon", format!("Working. Ends in {days} day{}: renew to keep going.", if days == 1 { "" } else { "s" }))
            } else {
                ("ok", "Working normally.".into())
            }
        }
    }
}

async fn licenses_for(s: &AppState, customer: &str) -> ApiResult<Vec<LicenseRow>> {
    Ok(sqlx::query_as(&format!(
        "SELECT {LICENSE_COLS} FROM licenses WHERE customer_id = $1 ORDER BY created_at DESC"
    ))
    .bind(customer)
    .fetch_all(&s.pool)
    .await?)
}

async fn own_license(s: &AppState, customer: &str, id: &str) -> ApiResult<LicenseRow> {
    sqlx::query_as(&format!(
        "SELECT {LICENSE_COLS} FROM licenses WHERE id = $1 AND customer_id = $2"
    ))
    .bind(id)
    .bind(customer)
    .fetch_optional(&s.pool)
    .await?
    .ok_or_else(|| ApiError::not_found("No license with that id."))
}

async fn in_use(s: &AppState, license: &str) -> ApiResult<i64> {
    let (n,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM activations WHERE license_id = $1 AND status = 'active'",
    )
    .bind(license)
    .fetch_one(&s.pool)
    .await?;
    Ok(n)
}

async fn license_summary(s: &AppState, l: &LicenseRow) -> ApiResult<Value> {
    let now = s.now();
    let (state, text) = status_text(l, now);
    Ok(json!({
        "id": l.id, "plan": l.plan, "plan_label": plan_label(&l.plan), "status": l.status,
        "state": state, "status_text": text, "seats": l.seats,
        "computers_in_use": in_use(s, &l.id).await?, "max_computers": l.max_devices,
        "starts_at": l.starts_at, "expires_at": l.expires_at, "update_window_end": l.update_window_end,
        "days_left": to_u64(l.expires_at).saturating_sub(now) / 86_400,
    }))
}

async fn overview(State(s): State<AppState>, u: PortalUser) -> ApiResult<Json<Value>> {
    let (company,): (String,) = sqlx::query_as("SELECT name FROM customers WHERE id = $1")
        .bind(&u.customer_id)
        .fetch_one(&s.pool)
        .await?;
    let lics = licenses_for(&s, &u.customer_id).await?;
    let mut list = Vec::new();
    let (mut seats, mut computers, mut max) = (0i64, 0i64, 0i64);
    let mut next_renewal: Option<i64> = None;
    for l in &lics {
        let v = license_summary(&s, l).await?;
        if l.status == "active" && to_u64(l.expires_at) > s.now() {
            seats += i64::from(l.seats);
            max += i64::from(l.max_devices);
            computers += v["computers_in_use"].as_i64().unwrap_or(0);
            next_renewal = Some(next_renewal.map_or(l.expires_at, |n| n.min(l.expires_at)));
        }
        list.push(v);
    }
    let headline = if lics.is_empty() {
        "You don't have a license yet. Start a free trial or contact Arkhon.".to_owned()
    } else if list.iter().any(|v| v["state"] == "paused") {
        "A license is paused. Check billing or contact Arkhon.".to_owned()
    } else if list.iter().any(|v| v["state"] == "ending-soon") {
        "Everything works. A license ends soon: renew it to keep going.".to_owned()
    } else if list.iter().all(|v| v["state"] == "ended") {
        "Your licenses have ended. Contact Arkhon to renew.".to_owned()
    } else {
        "Everything is working.".to_owned()
    };
    Ok(Json(json!({
        "company": company, "headline": headline, "seats": seats, "computers_in_use": computers,
        "max_computers": max, "next_renewal": next_renewal, "licenses": list,
    })))
}

async fn list_licenses(State(s): State<AppState>, u: PortalUser) -> ApiResult<Json<Value>> {
    let mut out = Vec::new();
    for l in licenses_for(&s, &u.customer_id).await? {
        out.push(license_summary(&s, &l).await?);
    }
    Ok(Json(json!(out)))
}

async fn get_license(
    State(s): State<AppState>,
    u: PortalUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let l = own_license(&s, &u.customer_id, &id).await?;
    let mut v = license_summary(&s, &l).await?;
    v["workspaces"] = json!(l.workspaces);
    v["engines"] = json!(l.engines);
    v["packs"] = json!(l.packs);
    v["allow_software_binding"] = json!(l.allow_software_binding);
    v["offline_grace_days"] = json!(l.offline_grace_days);
    v["computers"] = json!(computers_for(&s, &u.customer_id, Some(&l.id)).await?);
    v["activation_key_note"] = json!(
        "For your security Arkhon keeps only a fingerprint of your activation key, so it can't be shown again. An owner can request a new one."
    );
    Ok(Json(v))
}

async fn new_key(
    State(s): State<AppState>,
    u: PortalUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    u.require(&["owner"])?;
    let l = own_license(&s, &u.customer_id, &id).await?;
    if l.status == "revoked" {
        return Err(ApiError::conflict("This license has been cancelled."));
    }
    let key = new_activation_key();
    sqlx::query("UPDATE licenses SET key_hash = $1 WHERE id = $2 AND customer_id = $3")
        .bind(key_hash(&key))
        .bind(&l.id)
        .bind(&u.customer_id)
        .execute(&s.pool)
        .await?;
    audit(
        &s.pool,
        s.now(),
        &u.actor(),
        "portal-new-activation-key",
        &l.id,
        json!({}),
    )
    .await?;
    Ok(Json(json!({
        "license_id": l.id, "activation_key": key,
        "note": "Copy this key now: it won't be shown again. The old key no longer activates new computers. Computers already running Arkhon are not affected.",
    })))
}

type ComputerRow = (i64, String, String, String, i64, i64, Option<i64>);

async fn computers_for(
    s: &AppState,
    customer: &str,
    license: Option<&str>,
) -> ApiResult<Vec<Value>> {
    let rows: Vec<ComputerRow> = sqlx::query_as(
        "SELECT a.id, a.license_id, a.binding, a.status, a.activated_at, a.last_checkin_at, a.deactivated_at \
         FROM activations a JOIN licenses l ON l.id = a.license_id \
         WHERE l.customer_id = $1 AND ($2::text IS NULL OR l.id = $2) \
         ORDER BY (a.status = 'active') DESC, a.activated_at DESC LIMIT 500",
    )
    .bind(customer)
    .bind(license)
    .fetch_all(&s.pool)
    .await?;
    let now = s.now();
    Ok(rows
        .into_iter()
        .map(|(id, lic, binding, status, at, seen, off)| {
            let security = match binding.as_str() {
                "tpm" => "Security chip (TPM)",
                "secure-enclave" => "Apple Secure Enclave",
                _ => "Software key (no security chip)",
            };
            let stale = status == "active" && now.saturating_sub(to_u64(seen)) > 30 * 86_400;
            json!({
                "id": id, "license_id": lic, "binding": binding, "security": security, "status": status,
                "activated_at": at, "last_seen_at": seen, "deactivated_at": off, "not_seen_30_days": stale,
            })
        })
        .collect())
}

async fn list_computers(State(s): State<AppState>, u: PortalUser) -> ApiResult<Json<Value>> {
    Ok(Json(json!(computers_for(&s, &u.customer_id, None).await?)))
}

async fn deactivate_computer(
    State(s): State<AppState>,
    u: PortalUser,
    Path(id): Path<i64>,
) -> ApiResult<Json<Value>> {
    u.require(&["owner"])?;
    let row: Option<(String,)> = sqlx::query_as(
        "UPDATE activations a SET status = 'deactivated', deactivated_at = $1 FROM licenses l \
         WHERE a.id = $2 AND a.status = 'active' AND l.id = a.license_id AND l.customer_id = $3 RETURNING a.license_id",
    )
    .bind(to_i64(s.now()))
    .bind(id)
    .bind(&u.customer_id)
    .fetch_optional(&s.pool)
    .await?;
    let lic = row
        .ok_or_else(|| ApiError::not_found("No computer with that id is using your licenses."))?
        .0;
    audit(
        &s.pool,
        s.now(),
        &u.actor(),
        "portal-deactivate-computer",
        &lic,
        json!({ "activation": id }),
    )
    .await?;
    Ok(Json(json!({
        "deactivated": id,
        "message": "Done. That slot is free: you can activate Arkhon on another computer. The old computer stops at its next check-in.",
    })))
}

async fn offline_renew(
    State(s): State<AppState>,
    u: PortalUser,
    body: Bytes,
) -> ApiResult<Response> {
    u.require(&["owner"])?;
    let bytes =
        crate::public::offline_exchange(&s, &body, Some(&u.customer_id), &u.actor()).await?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"arkhon-renewal-response.bin\"",
            ),
        ],
        bytes,
    )
        .into_response())
}

async fn downloads(State(s): State<AppState>, u: PortalUser) -> ApiResult<Json<Value>> {
    let mut out = Vec::new();
    for l in licenses_for(&s, &u.customer_id).await? {
        if l.status == "revoked" {
            continue;
        }
        let rows: Vec<(String, String, i64, Vec<u8>)> = sqlx::query_as(
            "SELECT engine, version, released_at, manifest FROM releases \
             WHERE engine = ANY($1) AND released_at <= $2 ORDER BY engine, released_at DESC",
        )
        .bind(&l.engines)
        .bind(l.update_window_end)
        .fetch_all(&s.pool)
        .await?;
        let mut releases = Vec::new();
        for (engine, version, released_at, manifest) in rows {
            let Ok(m) = SignedReleaseManifest::from_bytes(&manifest) else {
                continue;
            };
            let files: Vec<Value> = m
                .manifest
                .files
                .iter()
                .map(|(name, f)| json!({ "name": name, "size": f.size, "sha256": crate::hex(&f.sha256) }))
                .collect();
            releases.push(json!({
                "engine": engine, "version": version, "released_at": released_at, "files": files,
                "manifest": b64(&manifest),
            }));
        }
        out.push(json!({
            "license_id": l.id, "plan_label": plan_label(&l.plan), "update_window_end": l.update_window_end,
            "releases": releases,
        }));
    }
    Ok(Json(json!({
        "licenses": out,
        "note": "Arkhon installs and updates engines for you. The checksums let your IT team verify files they copy by hand (for example to an offline site).",
    })))
}

// ---------------------------------------------------------------- team

async fn team(State(s): State<AppState>, u: PortalUser) -> ApiResult<Json<Value>> {
    let rows: Vec<(String, String, String, String, String, bool, i64)> = sqlx::query_as(
        "SELECT id, email, name, role, status, totp_secret IS NOT NULL, created_at FROM portal_users \
         WHERE customer_id = $1 AND status <> 'removed' ORDER BY created_at",
    )
    .bind(&u.customer_id)
    .fetch_all(&s.pool)
    .await?;
    Ok(Json(json!(rows
        .into_iter()
        .map(|(id, email, name, role, status, two_step, created_at)| json!({
            "id": id, "email": email, "name": name, "role": role, "status": status, "two_step": two_step,
            "created_at": created_at, "you": id == u.id,
        }))
        .collect::<Vec<_>>())))
}

/// `POST /portal/team` body.
#[derive(Debug, Deserialize)]
pub struct TeamInvite {
    /// Email.
    pub email: String,
    /// owner | billing | viewer.
    pub role: String,
}

async fn team_invite(
    State(s): State<AppState>,
    u: PortalUser,
    Json(t): Json<TeamInvite>,
) -> ApiResult<Json<Value>> {
    u.require(&["owner"])?;
    let inv = invite_user(&s, &u.customer_id, &t.email, &t.role, &u.actor(), false).await?;
    Ok(Json(invite_json(&inv, &t.email)))
}

async fn team_member(
    s: &AppState,
    u: &PortalUser,
    id: &str,
) -> ApiResult<(String, String, String)> {
    let row: Option<(String, String, String)> = sqlx::query_as(
        "SELECT email, role, status FROM portal_users WHERE id = $1 AND customer_id = $2 AND status <> 'removed'",
    )
    .bind(id)
    .bind(&u.customer_id)
    .fetch_optional(&s.pool)
    .await?;
    row.ok_or_else(|| ApiError::not_found("No one with that id is on your team."))
}

async fn team_remove(
    State(s): State<AppState>,
    u: PortalUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    u.require(&["owner"])?;
    if id == u.id {
        return Err(ApiError::bad(
            "You can't remove yourself. Ask another owner.",
        ));
    }
    let (email, role, _) = team_member(&s, &u, &id).await?;
    if role == "owner" {
        let (owners,): (i64,) = sqlx::query_as(
            "SELECT count(*) FROM portal_users WHERE customer_id = $1 AND role = 'owner' AND status = 'active' AND id <> $2",
        )
        .bind(&u.customer_id)
        .bind(&id)
        .fetch_one(&s.pool)
        .await?;
        if owners == 0 {
            return Err(ApiError::conflict("Your company needs at least one owner."));
        }
    }
    let mut tx = s.pool.begin().await?;
    sqlx::query("UPDATE portal_users SET status = 'removed', password_hash = NULL, totp_secret = NULL WHERE id = $1")
        .bind(&id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM portal_sessions WHERE user_id = $1")
        .bind(&id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE portal_invites SET used_at = $1 WHERE user_id = $2 AND used_at IS NULL")
        .bind(to_i64(s.now()))
        .bind(&id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    audit(
        &s.pool,
        s.now(),
        &u.actor(),
        "portal-remove-user",
        &u.customer_id,
        json!({ "email": email }),
    )
    .await?;
    Ok(Json(json!({ "removed": id })))
}

async fn team_reset_link(
    State(s): State<AppState>,
    u: PortalUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    u.require(&["owner"])?;
    let (email, _, status) = team_member(&s, &u, &id).await?;
    let purpose = if status == "invited" {
        "invite"
    } else {
        "reset"
    };
    let token = issue_link(&s, &id, purpose, &email).await?;
    audit(
        &s.pool,
        s.now(),
        &u.actor(),
        "portal-reset-link",
        &u.customer_id,
        json!({ "email": email }),
    )
    .await?;
    Ok(Json(Invite { user_id: id, token }.json(&email)))
}

// ---------------------------------------------------------------- billing placeholder

async fn invoices(u: PortalUser) -> ApiResult<Json<Value>> {
    u.require(&["owner", "billing"])?;
    Ok(Json(json!({
        "status": "not-set-up",
        "title": "Billing is being set up",
        "message": "Online invoices and card payments are coming soon. Until then Arkhon sends invoices by email; reply to one if anything looks wrong.",
        "invoices": [],
        "payment_method": null,
    })))
}

// ---------------------------------------------------------------- free trial (public)

/// `POST /portal/trial` body.
#[derive(Debug, Deserialize)]
pub struct TrialRequest {
    /// Company name.
    pub company: String,
    /// Your name.
    pub name: String,
    /// Your work email.
    pub email: String,
}

async fn trial(
    State(s): State<AppState>,
    ext: Extensions,
    Json(t): Json<TrialRequest>,
) -> ApiResult<Json<Value>> {
    if !s.trial_limiter.allow(crate::client_ip(&ext)) {
        return Err(ApiError(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many trial sign-ups from here. Try again in an hour, or contact Arkhon.".into(),
        ));
    }
    let company = t.company.trim();
    let name = t.name.trim();
    let email = t.email.trim().to_lowercase();
    if company.is_empty() || name.is_empty() || company.len() > 200 || name.len() > 200 {
        return Err(ApiError::bad("Enter your company name and your name."));
    }
    if !valid_email(&email) {
        return Err(ApiError::bad("Enter a valid work email address."));
    }
    let taken: Option<(String,)> = sqlx::query_as("SELECT id FROM portal_users WHERE email = $1")
        .bind(&email)
        .fetch_optional(&s.pool)
        .await?;
    if taken.is_some() {
        return Err(ApiError::conflict(
            "That email already has an Arkhon account. Sign in instead.",
        ));
    }
    let preset = plan_preset("trial").ok_or_else(|| ApiError::bad("No trial plan."))?;
    let now = s.now();
    let cust = random_id("cust");
    let lic = random_id("lic");
    let key = new_activation_key();
    let own = |v: &[&str]| v.iter().map(|x| (*x).to_owned()).collect::<Vec<_>>();
    let mut tx = s.pool.begin().await?;
    sqlx::query("INSERT INTO customers (id, name, email, created_at) VALUES ($1,$2,$3,$4)")
        .bind(&cust)
        .bind(company)
        .bind(&email)
        .bind(to_i64(now))
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO licenses (id, customer_id, key_hash, plan, seats, max_devices, workspaces, engines, packs, \
         allow_software_binding, starts_at, expires_at, update_window_end, offline_grace_days, license_term_days, status, created_at) \
         VALUES ($1,$2,$3,'trial',$4,2,$5,$6,'{}',$7,$8,$9,$10,30,30,'active',$8)",
    )
    .bind(&lic)
    .bind(&cust)
    .bind(key_hash(&key))
    .bind(preset.seats)
    .bind(own(preset.workspaces))
    .bind(own(preset.engines))
    .bind(preset.allow_software_binding)
    .bind(to_i64(now))
    .bind(to_i64(now + preset.days * 86_400))
    .bind(to_i64(now + preset.update_window_days * 86_400))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    audit(
        &s.pool,
        now,
        &format!("portal:{email}"),
        "portal-trial-signup",
        &cust,
        json!({ "company": company, "license": lic }),
    )
    .await?;
    let inv = invite_user(&s, &cust, &email, "owner", "system", false).await?;
    sqlx::query("UPDATE portal_users SET name = $1 WHERE id = $2")
        .bind(name)
        .bind(&inv.user_id)
        .execute(&s.pool)
        .await?;
    let mut v = inv.json(&email);
    v["customer_id"] = json!(cust);
    v["license_id"] = json!(lic);
    v["activation_key"] = json!(key);
    v["trial_ends_at"] = json!(now + preset.days * 86_400);
    v["note"] = json!("Your 14-day trial is ready. Copy your activation key now: it's shown once. Open the link to set your password. (Email isn't set up yet, so the link is shown here.)");
    Ok(Json(v))
}

/// Portal routes.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/portal/trial", post(trial))
        .route("/portal/login", post(login))
        .route("/portal/logout", post(logout))
        .route("/portal/invites/accept", post(accept))
        .route("/portal/me", get(me))
        .route("/portal/me/totp", post(totp_start))
        .route("/portal/me/totp/confirm", post(totp_confirm))
        .route("/portal/overview", get(overview))
        .route("/portal/licenses", get(list_licenses))
        .route("/portal/licenses/{id}", get(get_license))
        .route("/portal/licenses/{id}/new-key", post(new_key))
        .route("/portal/computers", get(list_computers))
        .route(
            "/portal/computers/{id}/deactivate",
            post(deactivate_computer),
        )
        .route("/portal/offline/renew", post(offline_renew))
        .route("/portal/downloads", get(downloads))
        .route("/portal/team", get(team).post(team_invite))
        .route("/portal/team/{id}/remove", post(team_remove))
        .route("/portal/team/{id}/reset-link", post(team_reset_link))
        .route("/portal/invoices", get(invoices))
}
