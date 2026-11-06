//! Arkhon License Manager.
//!
//! Holds license and activation **metadata only**. Devices send a license key, a P-256 device
//! public key, salted fingerprint hashes and a binding kind. Nothing a customer's staff writes,
//! reads or uploads ever reaches this server (N1).
//!
//! Public API (`/v1/...`, used by the runtime):
//! * `POST /v1/activate`: activation key + device → signed license with CEKs wrapped to the device
//! * `POST /v1/checkin`: renew a license, return the current revocation list
//! * `POST /v1/deactivate`: free a device slot (transfer = deactivate + activate elsewhere)
//! * `POST /v1/offline/renew`: offline file exchange (`RenewalRequest` → `RenewalResponse`)
//! * `GET  /v1/releases?license_id=…`: signed manifests the license may install
//!
//! Admin API (`/admin/...`, bearer session after password + TOTP sign-in) manages customers,
//! licenses, activations, releases, revocation lists and the audit log. See `openapi.yaml`.

pub mod admin;
pub mod keys;
pub mod public;

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use arkhon_crypto::ed25519_dalek::VerifyingKey;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use serde_json::json;
use sqlx::PgPool;

pub use keys::{CekVault, FileIssuingSigner, IssuingSigner};

/// Embedded schema migrations.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Shared state.
#[derive(Clone)]
pub struct AppState {
    /// Database.
    pub pool: PgPool,
    /// Issuing key + certificate.
    pub signer: Arc<dyn IssuingSigner>,
    /// CEK-at-rest encryption.
    pub vault: Arc<CekVault>,
    /// Root public key (verifies uploaded revocation lists).
    pub root: VerifyingKey,
    /// Clock (tests inject a fixed one).
    pub clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    limiter: Arc<RateLimiter>,
}

impl AppState {
    /// New state with the wall clock and default rate limits.
    #[must_use]
    pub fn new(
        pool: PgPool,
        signer: Arc<dyn IssuingSigner>,
        vault: Arc<CekVault>,
        root: VerifyingKey,
    ) -> Self {
        Self {
            pool,
            signer,
            vault,
            root,
            clock: Arc::new(|| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs())
            }),
            limiter: Arc::new(RateLimiter::new(60, Duration::from_secs(60))),
        }
    }

    /// Replace the clock.
    #[must_use]
    pub fn with_clock(mut self, clock: impl Fn() -> u64 + Send + Sync + 'static) -> Self {
        self.clock = Arc::new(clock);
        self
    }

    /// Replace the rate limit (requests per window per client IP).
    #[must_use]
    pub fn with_rate_limit(mut self, max: u32, window: Duration) -> Self {
        self.limiter = Arc::new(RateLimiter::new(max, window));
        self
    }

    /// Current time (Unix seconds).
    #[must_use]
    pub fn now(&self) -> u64 {
        (self.clock)()
    }
}

/// An API error: HTTP status plus a sentence for the person on the other end.
#[derive(Debug)]
pub struct ApiError(pub StatusCode, pub String);

impl ApiError {
    /// 400.
    pub fn bad(msg: impl Into<String>) -> Self {
        Self(StatusCode::BAD_REQUEST, msg.into())
    }
    /// 403.
    pub fn forbidden(msg: impl Into<String>) -> Self {
        Self(StatusCode::FORBIDDEN, msg.into())
    }
    /// 404.
    pub fn not_found(msg: impl Into<String>) -> Self {
        Self(StatusCode::NOT_FOUND, msg.into())
    }
    /// 409.
    pub fn conflict(msg: impl Into<String>) -> Self {
        Self(StatusCode::CONFLICT, msg.into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        // Never leak SQL details to clients.
        eprintln!("database error: {e}");
        Self(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Something went wrong on our side. Try again.".into(),
        )
    }
}

/// Result alias.
pub type ApiResult<T> = Result<T, ApiError>;

/// Base64 (standard) helpers for binary fields in JSON.
pub(crate) fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

pub(crate) fn unb64(s: &str, what: &str) -> ApiResult<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|_| ApiError::bad(format!("{what} isn't valid base64.")))
}

/// Append to the audit log.
///
/// # Errors
/// Database errors.
pub async fn audit(
    pool: &PgPool,
    at: u64,
    actor: &str,
    action: &str,
    target: &str,
    details: serde_json::Value,
) -> ApiResult<()> {
    sqlx::query(
        "INSERT INTO audit_log (at, actor, action, target, details) VALUES ($1,$2,$3,$4,$5)",
    )
    .bind(to_i64(at))
    .bind(actor)
    .bind(action)
    .bind(target)
    .bind(details)
    .execute(pool)
    .await?;
    Ok(())
}

/// Lower-case hex.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

pub(crate) fn to_i64(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

pub(crate) fn to_u64(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

/// Fixed-window rate limiter per client IP (in-process; put a shared limiter at the edge
/// when running more than one instance).
pub struct RateLimiter {
    max: u32,
    window: Duration,
    hits: Mutex<HashMap<IpAddr, (Instant, u32)>>,
}

impl RateLimiter {
    /// `max` requests per `window` per IP.
    #[must_use]
    pub fn new(max: u32, window: Duration) -> Self {
        Self {
            max,
            window,
            hits: Mutex::new(HashMap::new()),
        }
    }

    /// Record a hit; `false` when over the limit.
    pub fn allow(&self, ip: IpAddr) -> bool {
        let mut hits = self
            .hits
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = Instant::now();
        if hits.len() > 100_000 {
            hits.retain(|_, (start, _)| now.duration_since(*start) < self.window);
        }
        let entry = hits.entry(ip).or_insert((now, 0));
        if now.duration_since(entry.0) >= self.window {
            *entry = (now, 0);
        }
        entry.1 += 1;
        entry.1 <= self.max
    }
}

async fn rate_limit(State(s): State<AppState>, req: Request, next: Next) -> Response {
    let ip = req
        .extensions()
        .get::<ConnectInfo<std::net::SocketAddr>>()
        .map_or(IpAddr::from([0, 0, 0, 0]), |c| c.0.ip());
    if !s.limiter.allow(ip) {
        return ApiError(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many requests. Wait a minute and try again.".into(),
        )
        .into_response();
    }
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    h.insert("cache-control", "no-store".parse().expect("static header"));
    h.insert(
        "x-content-type-options",
        "nosniff".parse().expect("static header"),
    );
    res
}

/// The operator console: one static page that talks only to this server's `/admin` API.
#[allow(clippy::unused_async)] // axum handler signature
async fn console() -> Response {
    (
        [
            ("content-type", "text/html; charset=utf-8"),
            (
                "content-security-policy",
                "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; \
                 connect-src 'self'; img-src 'self' data:; form-action 'none'; base-uri 'none'; \
                 frame-ancestors 'none'",
            ),
            ("x-frame-options", "DENY"),
            ("referrer-policy", "no-referrer"),
        ],
        include_str!("../console/index.html"),
    )
        .into_response()
}

/// Build the router.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/console", get(console))
        .route(
            "/openapi.yaml",
            get(|| async { include_str!("../openapi.yaml") }),
        )
        .route("/v1/activate", post(public::activate))
        .route("/v1/checkin", post(public::checkin))
        .route("/v1/deactivate", post(public::deactivate))
        .route("/v1/offline/renew", post(public::offline_renew))
        .route("/v1/releases", get(public::releases))
        .merge(admin::routes())
        .layer(middleware::from_fn_with_state(state.clone(), rate_limit))
        .with_state(state)
}

#[cfg(test)]
mod tests;
