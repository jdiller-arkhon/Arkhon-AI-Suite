//! Local development server for Arkhon Suite.
//!
//! Serves the prototype UI (`suite/app/design`) and the engine's command API:
//!
//! | Method | Path | Body | Returns |
//! |---|---|---|---|
//! | GET | `/api/view` | — | [`arkhon_engine::View`] for the acting person |
//! | POST | `/api/command` | [`arkhon_engine::Command`] | `{ "message": "..." }` and the new view |
//! | GET | `/api/activity` | — | activity log (admins) |
//! | GET | `/api/people` | — | `[{id, name, role}]` for the dev "View as" switcher |
//!
//! **Dev-only identity:** the acting person is chosen with the `x-arkhon-as` header (a member id).
//! The desktop app replaces this with the signed-in local session (Phase 5). Because of that, this
//! server must never be reachable from other machines or other websites:
//!
//! * it binds to `127.0.0.1` only;
//! * it rejects requests whose `Host` isn't `127.0.0.1`/`localhost` (DNS rebinding);
//! * it rejects requests carrying a foreign `Origin` (cross-site requests);
//! * state-changing requests need `content-type: application/json` **and** `x-arkhon-as`, which a
//!   cross-site page can't send without a CORS preflight that this server never approves.

use std::path::PathBuf;
use std::sync::Arc;

use arkhon_engine::{Command, Refusal, Store, Suite};
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::json;
use tokio::sync::Mutex;
use tower_http::services::ServeDir;

/// Shared server state.
#[derive(Clone)]
pub struct AppState {
    suite: Arc<Mutex<Suite>>,
    store: Option<Store>,
    default_actor: u64,
}

impl AppState {
    /// New state. `store = None` keeps everything in memory (tests).
    #[must_use]
    pub fn new(suite: Suite, store: Option<Store>, default_actor: u64) -> Self {
        AppState {
            suite: Arc::new(Mutex::new(suite)),
            store,
            default_actor,
        }
    }
}

/// Build the router. `static_dir` is the folder holding `dashboard.html`.
pub fn router(state: AppState, static_dir: PathBuf, port: u16) -> Router {
    let api = Router::new()
        .route("/api/view", get(view))
        .route("/api/command", post(command))
        .route("/api/activity", get(activity))
        .route("/api/people", get(people))
        .with_state(state);
    Router::new()
        .merge(api)
        .fallback_service(ServeDir::new(static_dir).append_index_html_on_directories(false))
        .layer(middleware::from_fn(move |req, next| guard(req, next, port)))
}

fn err(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}

/// Host/Origin/content checks (see module docs).
async fn guard(req: Request, next: Next, port: u16) -> Response {
    let allowed_hosts = [format!("127.0.0.1:{port}"), format!("localhost:{port}")];
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    if !allowed_hosts.iter().any(|h| h == host) {
        return err(
            StatusCode::FORBIDDEN,
            "This server only answers on this computer.",
        );
    }
    if let Some(origin) = req.headers().get(header::ORIGIN) {
        let ok = origin
            .to_str()
            .ok()
            .is_some_and(|o| allowed_hosts.iter().any(|h| o == format!("http://{h}")));
        if !ok {
            return err(
                StatusCode::FORBIDDEN,
                "Requests from other websites are blocked.",
            );
        }
    }
    if req.method() == axum::http::Method::POST {
        let json = req
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("application/json"));
        if !json || !req.headers().contains_key("x-arkhon-as") {
            return err(
                StatusCode::BAD_REQUEST,
                "Send JSON with the x-arkhon-as header.",
            );
        }
    }
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    h.insert(
        header::CACHE_CONTROL,
        "no-store".parse().expect("static header"),
    );
    h.insert(
        "x-content-type-options",
        "nosniff".parse().expect("static header"),
    );
    h.insert("x-frame-options", "DENY".parse().expect("static header"));
    h.insert(
        "referrer-policy",
        "no-referrer".parse().expect("static header"),
    );
    res
}

fn actor(headers: &HeaderMap, default: u64) -> u64 {
    headers
        .get("x-arkhon-as")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

async fn view(State(s): State<AppState>, headers: HeaderMap) -> Response {
    let suite = s.suite.lock().await;
    Json(suite.view(actor(&headers, s.default_actor))).into_response()
}

async fn people(State(s): State<AppState>) -> Response {
    let suite = s.suite.lock().await;
    let list: Vec<_> = suite
        .state()
        .org
        .members()
        .map(|m| json!({ "id": m.id, "name": m.name, "role": m.role.to_string() }))
        .collect();
    Json(list).into_response()
}

async fn activity(State(s): State<AppState>, headers: HeaderMap) -> Response {
    let suite = s.suite.lock().await;
    match suite.activity(actor(&headers, s.default_actor)) {
        Ok(log) => Json(log).into_response(),
        Err(r) => refusal(&r),
    }
}

fn refusal(r: &Refusal) -> Response {
    let status = if r.forbidden {
        StatusCode::FORBIDDEN
    } else {
        StatusCode::BAD_REQUEST
    };
    err(status, &r.message)
}

async fn command(State(s): State<AppState>, headers: HeaderMap, body: String) -> Response {
    let Ok(cmd) = serde_json::from_str::<Command>(&body) else {
        return err(StatusCode::BAD_REQUEST, "That request wasn't understood.");
    };
    let who = actor(&headers, s.default_actor);
    let mut suite = s.suite.lock().await;
    let result = suite.execute(who, cmd);
    // The attempt is in the activity log either way, so persist either way.
    if let Some(store) = &s.store {
        if let Err(e) = store.save(suite.state()) {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Couldn't save your change ({e}). Check free disk space and try again."),
            );
        }
    }
    match result {
        Ok(message) => Json(json!({ "message": message, "view": suite.view(who) })).into_response(),
        Err(r) => refusal(&r),
    }
}

#[cfg(test)]
mod tests;
