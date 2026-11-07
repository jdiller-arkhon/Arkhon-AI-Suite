//! Inference backends behind the local API.
//!
//! The API never talks to an inference engine directly; it calls a [`Backend`]. Production uses
//! [`HttpBackend`], which forwards to `llama-server` / `whisper.cpp` server processes the runtime
//! launched on 127.0.0.1 from sealed memfds (see `launch`, Linux). Tests and demos use
//! [`EchoBackend`], which needs no model.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

/// Which OpenAI-shaped endpoint is being called.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endpoint {
    /// `/v1/chat/completions`.
    ChatCompletions,
    /// `/v1/completions`.
    Completions,
    /// `/v1/embeddings`.
    Embeddings,
    /// `/v1/rerank`.
    Rerank,
    /// `/v1/audio/transcriptions`.
    AudioTranscriptions,
}

impl Endpoint {
    /// The path on the backend server.
    #[must_use]
    pub fn path(self) -> &'static str {
        match self {
            Endpoint::ChatCompletions => "/v1/chat/completions",
            Endpoint::Completions => "/v1/completions",
            Endpoint::Embeddings => "/v1/embeddings",
            Endpoint::Rerank => "/v1/rerank",
            // whisper.cpp's server exposes `/inference`; llama.cpp doesn't do audio.
            Endpoint::AudioTranscriptions => "/inference",
        }
    }
}

/// A request for one engine.
#[derive(Debug, Clone)]
pub struct BackendRequest {
    /// Engine chosen by the router.
    pub engine: String,
    /// Endpoint.
    pub endpoint: Endpoint,
    /// Request content type.
    pub content_type: String,
    /// Request body, passed through unchanged.
    pub body: Vec<u8>,
}

/// The engine's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendResponse {
    /// HTTP status.
    pub status: u16,
    /// Content type.
    pub content_type: String,
    /// Body.
    pub body: Vec<u8>,
}

/// Why a backend couldn't answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendError {
    /// The engine isn't running.
    NotRunning(String),
    /// The engine process didn't answer.
    Unavailable(String),
}

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BackendError::NotRunning(e) => write!(
                f,
                "The \"{e}\" engine isn't running. Restart Arkhon, or check that its update is installed."
            ),
            BackendError::Unavailable(e) => write!(
                f,
                "The AI engine didn't answer. Try again in a moment. ({e})"
            ),
        }
    }
}

impl std::error::Error for BackendError {}

/// Something that can run inference requests. Implementations block; the API calls them on a
/// blocking thread.
pub trait Backend: Send + Sync {
    /// Forward one request.
    ///
    /// # Errors
    /// [`BackendError`].
    fn forward(&self, req: BackendRequest) -> Result<BackendResponse, BackendError>;
}

/// Forwards to engine servers listening on 127.0.0.1.
#[derive(Debug, Clone)]
pub struct HttpBackend {
    upstreams: BTreeMap<String, String>,
    agent: ureq::Agent,
}

/// Largest engine response accepted (64 MiB).
const MAX_RESPONSE: u64 = 64 << 20;

impl HttpBackend {
    /// A backend forwarding each engine to its base URL (e.g. `http://127.0.0.1:8091`).
    #[must_use]
    pub fn new(upstreams: BTreeMap<String, String>, timeout: Duration) -> Self {
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(timeout))
            .http_status_as_error(false)
            .build();
        Self {
            upstreams,
            agent: config.into(),
        }
    }
}

impl Backend for HttpBackend {
    fn forward(&self, req: BackendRequest) -> Result<BackendResponse, BackendError> {
        let base = self
            .upstreams
            .get(&req.engine)
            .ok_or_else(|| BackendError::NotRunning(req.engine.clone()))?;
        let mut resp = self
            .agent
            .post(format!(
                "{}{}",
                base.trim_end_matches('/'),
                req.endpoint.path()
            ))
            .content_type(&req.content_type)
            .send(&req.body[..])
            .map_err(|e| BackendError::Unavailable(e.to_string()))?;
        let status = resp.status().as_u16();
        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/json")
            .to_owned();
        let body = resp
            .body_mut()
            .with_config()
            .limit(MAX_RESPONSE)
            .read_to_vec()
            .map_err(|e| BackendError::Unavailable(e.to_string()))?;
        Ok(BackendResponse {
            status,
            content_type,
            body,
        })
    }
}

/// A model-free backend for tests and demos: answers in the `OpenAI` response shapes with
/// deterministic content that names the engine it was routed to.
#[derive(Debug, Clone, Copy, Default)]
pub struct EchoBackend;

fn last_user_text(body: &serde_json::Value) -> String {
    if let Some(msgs) = body.get("messages").and_then(|m| m.as_array()) {
        if let Some(text) = msgs
            .iter()
            .rev()
            .find(|m| m.get("role").and_then(|r| r.as_str()) == Some("user"))
            .and_then(|m| m.get("content"))
            .and_then(|c| c.as_str())
        {
            return text.to_owned();
        }
    }
    body.get("prompt")
        .and_then(|p| p.as_str())
        .unwrap_or("")
        .to_owned()
}

impl Backend for EchoBackend {
    fn forward(&self, req: BackendRequest) -> Result<BackendResponse, BackendError> {
        let json = |v: serde_json::Value| BackendResponse {
            status: 200,
            content_type: "application/json".into(),
            body: v.to_string().into_bytes(),
        };
        let parsed: serde_json::Value =
            serde_json::from_slice(&req.body).unwrap_or(serde_json::Value::Null);
        let engine = req.engine.as_str();
        Ok(match req.endpoint {
            Endpoint::ChatCompletions => json(serde_json::json!({
                "id": "chatcmpl-echo",
                "object": "chat.completion",
                "model": engine,
                "choices": [{
                    "index": 0,
                    "message": {"role": "assistant", "content": format!("[{engine}] {}", last_user_text(&parsed))},
                    "finish_reason": "stop"
                }],
                "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
            })),
            Endpoint::Completions => json(serde_json::json!({
                "id": "cmpl-echo",
                "object": "text_completion",
                "model": engine,
                "choices": [{"index": 0, "text": format!("[{engine}] {}", last_user_text(&parsed)), "finish_reason": "stop"}]
            })),
            Endpoint::Embeddings => {
                let inputs = match parsed.get("input") {
                    Some(serde_json::Value::Array(a)) => a.len(),
                    _ => 1,
                };
                json(serde_json::json!({
                    "object": "list",
                    "model": engine,
                    "data": (0..inputs).map(|i| serde_json::json!({"object": "embedding", "index": i, "embedding": [0.0, 0.5, 1.0]})).collect::<Vec<_>>()
                }))
            }
            Endpoint::Rerank => {
                let docs = parsed
                    .get("documents")
                    .and_then(|d| d.as_array())
                    .map_or(0, Vec::len);
                json(serde_json::json!({
                    "model": engine,
                    "results": (0..docs).map(|i| serde_json::json!({"index": i, "relevance_score": 1.0 / (1.0 + f64::from(u32::try_from(i).unwrap_or(u32::MAX)))})).collect::<Vec<_>>()
                }))
            }
            Endpoint::AudioTranscriptions => json(serde_json::json!({
                "text": format!("[{engine}] transcribed {} bytes", req.body.len())
            })),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(endpoint: Endpoint, body: &str) -> BackendRequest {
        BackendRequest {
            engine: "core".into(),
            endpoint,
            content_type: "application/json".into(),
            body: body.as_bytes().to_vec(),
        }
    }

    #[test]
    fn echo_shapes() {
        let b = EchoBackend;
        let chat = b
            .forward(req(
                Endpoint::ChatCompletions,
                r#"{"messages":[{"role":"system","content":"s"},{"role":"user","content":"hi"}]}"#,
            ))
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&chat.body).unwrap();
        assert_eq!(v["choices"][0]["message"]["content"], "[core] hi");
        let v: serde_json::Value = serde_json::from_slice(
            &b.forward(req(Endpoint::Completions, r#"{"prompt":"p"}"#))
                .unwrap()
                .body,
        )
        .unwrap();
        assert_eq!(v["choices"][0]["text"], "[core] p");
        let v: serde_json::Value = serde_json::from_slice(
            &b.forward(req(Endpoint::Embeddings, r#"{"input":["a","b"]}"#))
                .unwrap()
                .body,
        )
        .unwrap();
        assert_eq!(v["data"].as_array().unwrap().len(), 2);
        let v: serde_json::Value = serde_json::from_slice(
            &b.forward(req(
                Endpoint::Rerank,
                r#"{"query":"q","documents":["a","b","c"]}"#,
            ))
            .unwrap()
            .body,
        )
        .unwrap();
        assert_eq!(v["results"].as_array().unwrap().len(), 3);
        let v: serde_json::Value = serde_json::from_slice(
            &b.forward(req(Endpoint::AudioTranscriptions, "xyz"))
                .unwrap()
                .body,
        )
        .unwrap();
        assert!(v["text"].as_str().unwrap().contains("3 bytes"));
        for e in [
            Endpoint::ChatCompletions,
            Endpoint::Completions,
            Endpoint::Embeddings,
            Endpoint::Rerank,
            Endpoint::AudioTranscriptions,
        ] {
            assert!(e.path().starts_with('/'));
        }
    }

    #[test]
    fn http_backend_errors() {
        let b = HttpBackend::new(
            [("core".to_owned(), "http://127.0.0.1:9".to_owned())].into(),
            Duration::from_secs(2),
        );
        assert!(matches!(
            b.forward(BackendRequest {
                engine: "pro".into(),
                ..req(Endpoint::ChatCompletions, "{}")
            }),
            Err(BackendError::NotRunning(_))
        ));
        let e = b.forward(req(Endpoint::ChatCompletions, "{}")).unwrap_err();
        assert!(matches!(e, BackendError::Unavailable(_)));
        assert_ne!(e.to_string().len(), 0);
        assert!(BackendError::NotRunning("x".into())
            .to_string()
            .contains("\"x\""));
    }
}
