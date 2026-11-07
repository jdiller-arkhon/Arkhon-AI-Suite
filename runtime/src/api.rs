//! Local inference API, shaped like the `OpenAI` API.
//!
//! * Binds `127.0.0.1` by default. In that mode every request must carry `Host: 127.0.0.1:<port>`
//!   or `localhost:<port>` (blocks DNS rebinding), and a browser `Origin` must be one of those
//!   (blocks other websites), the same pattern as the suite's dev server.
//! * LAN mode (`--lan`) listens on all interfaces and requires `Authorization: Bearer <token>` on
//!   every request (compared in constant time). Browser `Origin`s are refused in LAN mode.
//! * `POST` bodies must be JSON (multipart for audio), so plain HTML forms can't reach it.
//! * Models answer only while the license allows it ([`Gate`]); the router picks an entitled
//!   engine for every request.

use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::json;
use subtle::ConstantTimeEq;

use crate::backend::{Backend, BackendRequest, Endpoint};
use crate::router::{ModelRouter, Task};

/// Largest request body (audio uploads): 64 MiB.
pub const MAX_BODY: usize = 64 << 20;

/// Whether models may answer right now (updated by the licensing loop).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gate {
    /// Models may run.
    pub may_load_models: bool,
    /// Plain-language notes (warnings, or why models are locked).
    pub messages: Vec<String>,
}

/// Who may call the API.
#[derive(Debug, Clone)]
pub struct Access {
    /// Listening port (for the Host check).
    pub port: u16,
    /// Listen on all interfaces (requires `token`).
    pub lan: bool,
    /// Bearer token (required in LAN mode, optional locally).
    pub token: Option<String>,
}

impl Access {
    /// Local-only access on `port`.
    #[must_use]
    pub fn local(port: u16) -> Self {
        Self {
            port,
            lan: false,
            token: None,
        }
    }

    /// The socket address to bind.
    ///
    /// # Errors
    /// LAN mode without a token of at least 32 characters.
    pub fn bind_addr(&self) -> Result<SocketAddr, String> {
        if self.lan {
            if self.token.as_ref().is_none_or(|t| t.len() < 32) {
                return Err(
                    "LAN mode needs an access token of at least 32 characters (--token-file)."
                        .into(),
                );
            }
            Ok(SocketAddr::from(([0, 0, 0, 0], self.port)))
        } else {
            Ok(SocketAddr::from(([127, 0, 0, 1], self.port)))
        }
    }

    fn local_hosts(&self) -> [String; 3] {
        let p = self.port;
        [
            format!("127.0.0.1:{p}"),
            format!("localhost:{p}"),
            format!("[::1]:{p}"),
        ]
    }
}

/// Shared API state.
#[derive(Clone)]
pub struct ApiState {
    /// Engine router (entitled engines only).
    pub router: Arc<ModelRouter>,
    /// Inference backend.
    pub backend: Arc<dyn Backend>,
    /// License gate.
    pub gate: Arc<RwLock<Gate>>,
    /// Access rules.
    pub access: Arc<Access>,
}

fn error(status: StatusCode, kind: &str, message: &str) -> Response {
    (
        status,
        Json(json!({ "error": { "message": message, "type": kind } })),
    )
        .into_response()
}

fn bearer_ok(headers: &HeaderMap, token: &str) -> bool {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .is_some_and(|given| bool::from(given.as_bytes().ct_eq(token.as_bytes())))
}

async fn guard(State(access): State<Arc<Access>>, req: Request, next: Next) -> Response {
    let headers = req.headers();
    if !access.lan {
        let host = headers
            .get(header::HOST)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
        let hosts = access.local_hosts();
        if !hosts.iter().any(|h| h == host) {
            return error(
                StatusCode::FORBIDDEN,
                "forbidden",
                "This server only answers on this computer.",
            );
        }
        if let Some(origin) = headers.get(header::ORIGIN) {
            let ok = origin
                .to_str()
                .is_ok_and(|o| hosts.iter().any(|h| o == format!("http://{h}")));
            if !ok {
                return error(
                    StatusCode::FORBIDDEN,
                    "forbidden",
                    "Requests from other websites are blocked.",
                );
            }
        }
    } else if headers.contains_key(header::ORIGIN) {
        return error(
            StatusCode::FORBIDDEN,
            "forbidden",
            "Requests from websites are blocked in network mode.",
        );
    }
    if let Some(token) = &access.token {
        if !bearer_ok(headers, token) {
            return error(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "Missing or wrong access token.",
            );
        }
    }
    if req.method() == axum::http::Method::POST {
        let ct = headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let audio = req.uri().path() == "/v1/audio/transcriptions";
        let ok =
            ct.starts_with("application/json") || (audio && ct.starts_with("multipart/form-data"));
        if !ok {
            return error(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "invalid_request_error",
                "Send JSON (or multipart form data for audio).",
            );
        }
    }
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    h.insert("x-frame-options", HeaderValue::from_static("DENY"));
    h.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    res
}

async fn run(
    state: ApiState,
    endpoint: Endpoint,
    default: Task,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let gate = state
        .gate
        .read()
        .map_or_else(|p| p.into_inner().clone(), |g| g.clone());
    if !gate.may_load_models {
        let msg =
            gate.messages.first().cloned().unwrap_or_else(|| {
                "Arkhon's license needs attention before models can run.".into()
            });
        return error(StatusCode::SERVICE_UNAVAILABLE, "license", &msg);
    }
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json")
        .to_owned();
    let model = if content_type.starts_with("application/json") {
        match serde_json::from_slice::<serde_json::Value>(&body) {
            Ok(v) => v.get("model").and_then(|m| m.as_str()).map(str::to_owned),
            Err(_) => {
                return error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request_error",
                    "The request body isn't valid JSON.",
                )
            }
        }
    } else {
        None
    };
    let route = match state.router.route_model(model.as_deref(), default) {
        Ok(r) => r,
        Err(e) => return error(StatusCode::FORBIDDEN, "not_entitled", &e.to_string()),
    };
    let backend = state.backend.clone();
    let engine = route.engine.clone();
    let req = BackendRequest {
        engine: engine.clone(),
        endpoint,
        content_type,
        body: body.to_vec(),
    };
    let result = tokio::task::spawn_blocking(move || backend.forward(req)).await;
    let resp = match result {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            return error(
                StatusCode::BAD_GATEWAY,
                "engine_unavailable",
                &e.to_string(),
            )
        }
        Err(_) => {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                "Something went wrong inside Arkhon. Try again.",
            )
        }
    };
    let status = StatusCode::from_u16(resp.status).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut out = (status, resp.body).into_response();
    let h = out.headers_mut();
    if let Ok(v) = HeaderValue::from_str(&resp.content_type) {
        h.insert(header::CONTENT_TYPE, v);
    }
    if let Ok(v) = HeaderValue::from_str(&engine) {
        h.insert("x-arkhon-engine", v);
    }
    if let Ok(v) = HeaderValue::from_str(&route.reason) {
        h.insert("x-arkhon-route", v);
    }
    out
}

macro_rules! endpoint {
    ($name:ident, $ep:expr, $task:expr) => {
        async fn $name(State(s): State<ApiState>, headers: HeaderMap, body: Bytes) -> Response {
            run(s, $ep, $task, headers, body).await
        }
    };
}

endpoint!(chat, Endpoint::ChatCompletions, Task::Chat);
endpoint!(completions, Endpoint::Completions, Task::Chat);
endpoint!(embeddings, Endpoint::Embeddings, Task::Embedding);
endpoint!(rerank, Endpoint::Rerank, Task::Rerank);
endpoint!(
    transcribe,
    Endpoint::AudioTranscriptions,
    Task::Transcription
);

async fn models(State(s): State<ApiState>) -> Json<serde_json::Value> {
    let data: Vec<_> = s
        .router
        .entitled()
        .iter()
        .filter(|e| {
            s.router
                .route_model(Some(e), Task::Chat)
                .is_ok_and(|r| &r.engine == *e)
        })
        .map(|e| json!({ "id": e, "object": "model", "owned_by": "arkhon" }))
        .collect();
    Json(json!({ "object": "list", "data": data }))
}

async fn status(State(s): State<ApiState>) -> Json<serde_json::Value> {
    let gate = s
        .gate
        .read()
        .map_or_else(|p| p.into_inner().clone(), |g| g.clone());
    Json(json!({
        "may_load_models": gate.may_load_models,
        "messages": gate.messages,
        "tier": s.router.tier().as_str(),
    }))
}

/// Build the router.
pub fn app(state: ApiState) -> Router {
    let access = state.access.clone();
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/status", get(status))
        .route("/v1/models", get(models))
        .route("/v1/chat/completions", post(chat))
        .route("/v1/completions", post(completions))
        .route("/v1/embeddings", post(embeddings))
        .route("/v1/rerank", post(rerank))
        .route("/v1/audio/transcriptions", post(transcribe))
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .with_state(state)
        .layer(middleware::from_fn_with_state(access, guard))
}

/// Bind and serve until `shutdown` resolves.
///
/// # Errors
/// Bind failures, or LAN mode without a token.
pub async fn serve(
    state: ApiState,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    let addr = state.access.bind_addr().map_err(std::io::Error::other)?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app(state))
        .with_graceful_shutdown(shutdown)
        .await
}

#[cfg(test)]
mod tests;
