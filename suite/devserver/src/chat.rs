//! `/api/chat`: the general chat page.
//!
//! Replies stream back as server-sent events:
//!
//! ```text
//! event: meta     data: {"mode":"demo"|"runtime","label":"..."}   (always first)
//! event: token    data: {"t":"..."}                               (repeated)
//! event: sources  data: {"sources":[{"label":"..."}]}             (company answers only)
//! event: error    data: {"message":"..."}
//! event: done     data: {}
//! ```
//!
//! **Where the conversation goes.** With `ARKHON_RUNTIME_URL` set (it must point at this computer:
//! `http://127.0.0.1:PORT`, `http://localhost:PORT` or `http://[::1]:PORT`), the conversation is
//! forwarded to the Arkhon runtime's `/v1/chat/completions` and its reply is passed through. Any
//! other address is refused, so chat content never leaves the computer. Without a runtime the
//! server runs in **demo mode**: it answers from the company's own files when it can (with
//! sources), and otherwise says plainly that a real model replies once the runtime is running.

use std::convert::Infallible;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::{actor, err, AppState};

/// Most messages forwarded per request (the newest are kept).
const MAX_MESSAGES: usize = 40;
/// Longest single message accepted, in characters.
const MAX_CHARS: usize = 60_000;

/// Label shown on the chat page in demo mode.
pub const DEMO_LABEL: &str = "Demo replies";
/// Label shown when a local model answers.
pub const RUNTIME_LABEL: &str = "Running on this computer";

/// A local Arkhon runtime address, checked to be on this computer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeUrl {
    host: String,
    port: u16,
    base: String,
}

impl RuntimeUrl {
    /// Parse `http://127.0.0.1:PORT[/base]` (or `localhost` / `[::1]`). Anything that isn't
    /// plain HTTP on this computer returns `None`: chat content must not leave the machine.
    #[must_use]
    pub fn parse(url: &str) -> Option<Self> {
        let rest = url.trim().strip_prefix("http://")?;
        let (authority, base) = match rest.find('/') {
            Some(i) => (&rest[..i], rest[i..].trim_end_matches('/')),
            None => (rest, ""),
        };
        if authority.contains('@') {
            return None;
        }
        let (host, port) = authority.rsplit_once(':')?;
        if !matches!(host, "127.0.0.1" | "localhost" | "[::1]") {
            return None;
        }
        let port: u16 = port.parse().ok().filter(|p| *p != 0)?;
        Some(RuntimeUrl {
            host: host.to_owned(),
            port,
            base: base.to_owned(),
        })
    }

    fn connect_addr(&self) -> String {
        let ip = if self.host == "[::1]" {
            "[::1]"
        } else {
            "127.0.0.1"
        };
        format!("{ip}:{}", self.port)
    }
}

/// Chat settings.
#[derive(Debug, Clone, Default)]
pub struct ChatConfig {
    /// The local runtime to forward to; `None` means demo mode.
    pub runtime: Option<RuntimeUrl>,
    /// Bearer token for the runtime, if it needs one.
    pub token: Option<String>,
    /// Model name to ask for; `None` lets the runtime choose.
    pub model: Option<String>,
    /// Pause between demo tokens, so the page can show replies arriving.
    pub demo_delay: Duration,
}

impl ChatConfig {
    /// Read `ARKHON_RUNTIME_URL`, `ARKHON_RUNTIME_TOKEN` and `ARKHON_CHAT_MODEL`.
    ///
    /// # Errors
    /// The runtime URL is set but isn't on this computer.
    pub fn from_env() -> Result<Self, String> {
        let var = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
        let runtime = match var("ARKHON_RUNTIME_URL") {
            None => None,
            Some(u) => Some(RuntimeUrl::parse(&u).ok_or_else(|| {
                format!("ARKHON_RUNTIME_URL must be http://127.0.0.1:PORT (this computer); got {u}")
            })?),
        };
        Ok(ChatConfig {
            runtime,
            token: var("ARKHON_RUNTIME_TOKEN"),
            model: var("ARKHON_CHAT_MODEL"),
            demo_delay: Duration::from_millis(28),
        })
    }

    fn mode(&self) -> (&'static str, &'static str) {
        if self.runtime.is_some() {
            ("runtime", RUNTIME_LABEL)
        } else {
            ("demo", DEMO_LABEL)
        }
    }
}

#[derive(Deserialize)]
struct ChatBody {
    messages: Vec<Msg>,
}

#[derive(Deserialize, serde::Serialize, Clone)]
struct Msg {
    role: String,
    content: String,
}

/// `GET /api/chat`: which mode replies come from.
pub async fn status(State(s): State<AppState>) -> Response {
    let (mode, label) = s.chat.mode();
    Json(json!({ "mode": mode, "label": label })).into_response()
}

/// `POST /api/chat`: stream a reply.
pub async fn chat(State(s): State<AppState>, headers: HeaderMap, body: String) -> Response {
    let Ok(parsed) = serde_json::from_str::<ChatBody>(&body) else {
        return err(StatusCode::BAD_REQUEST, "That request wasn't understood.");
    };
    let mut messages: Vec<Msg> = parsed
        .messages
        .into_iter()
        .filter(|m| matches!(m.role.as_str(), "user" | "assistant" | "system"))
        .collect();
    if messages
        .iter()
        .any(|m| m.content.chars().count() > MAX_CHARS)
    {
        return err(
            StatusCode::BAD_REQUEST,
            "That message is too long. Try a shorter one or a smaller file.",
        );
    }
    if messages.len() > MAX_MESSAGES {
        messages.drain(..messages.len() - MAX_MESSAGES);
    }
    let Some(last) = messages
        .iter()
        .rev()
        .find(|m| m.role == "user")
        .map(|m| m.content.trim().to_owned())
        .filter(|q| !q.is_empty())
    else {
        return err(StatusCode::BAD_REQUEST, "Type a message first.");
    };

    let (tx, rx) = mpsc::channel::<Bytes>(64);
    let (mode, label) = s.chat.mode();
    let _ = tx
        .send(event("meta", &json!({ "mode": mode, "label": label })))
        .await;

    if let Some(rt) = s.chat.runtime.clone() {
        let cfg = s.chat.clone();
        tokio::spawn(async move {
            if let Err(message) = forward(&rt, &cfg, &messages, &tx).await {
                let _ = tx
                    .send(event("error", &json!({ "message": message })))
                    .await;
            }
            let _ = tx.send(event("done", &json!({}))).await;
        });
    } else {
        // Demo mode: the company's own answer when there is one, otherwise an honest demo reply.
        let found = {
            let suite = s.suite.lock().await;
            suite
                .ask(actor(&headers, s.default_actor), &last)
                .ok()
                .filter(|a| a.found)
        };
        let delay = s.chat.demo_delay;
        tokio::spawn(async move {
            let (text, sources) = match found {
                Some(a) => (a.answer, a.sources),
                None => (demo_reply(&last), Vec::new()),
            };
            for piece in split_tokens(&text) {
                if tx
                    .send(event("token", &json!({ "t": piece })))
                    .await
                    .is_err()
                {
                    return; // The page stopped reading (Stop button).
                }
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
            }
            if !sources.is_empty() {
                let cited: Vec<_> = sources
                    .iter()
                    .map(|x| json!({ "label": x.label }))
                    .collect();
                let _ = tx
                    .send(event("sources", &json!({ "sources": cited })))
                    .await;
            }
            let _ = tx.send(event("done", &json!({}))).await;
        });
    }

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream; charset=utf-8")
        .body(Body::from_stream(RxStream(rx)))
        .unwrap_or_else(|_| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Couldn't start the reply.",
            )
        })
}

fn demo_reply(question: &str) -> String {
    let short: String = question.chars().take(140).collect();
    let more = if question.chars().count() > 140 {
        "…"
    } else {
        ""
    };
    format!(
        "**This is a demo reply.** A real model writes answers here once the Arkhon runtime is \
         running on this computer.\n\nYou asked: “{short}{more}”\n\nWhat works right now:\n\n\
         - Questions your company files answer (try *What is our warranty on new installs?*) are \
         answered from those files, with sources.\n- Your conversations are saved in this browser \
         only. They never leave this computer.\n\nTo get real replies, start the Arkhon runtime \
         and restart the suite with `ARKHON_RUNTIME_URL` pointing at it."
    )
}

/// Split into word-sized pieces that keep their whitespace, so joining them restores the text.
fn split_tokens(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for ch in text.chars() {
        cur.push(ch);
        if ch == ' ' || ch == '\n' {
            out.push(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn event(name: &str, data: &serde_json::Value) -> Bytes {
    Bytes::from(format!("event: {name}\ndata: {data}\n\n"))
}

/// Forward to the local runtime and pass its reply through as `token` events.
async fn forward(
    rt: &RuntimeUrl,
    cfg: &ChatConfig,
    messages: &[Msg],
    tx: &mpsc::Sender<Bytes>,
) -> Result<(), String> {
    let unreachable =
        "The Arkhon runtime isn't answering. Check that it's running on this computer.";
    let mut body = json!({ "messages": messages, "stream": true });
    if let Some(m) = &cfg.model {
        body["model"] = json!(m);
    }
    let body = body.to_string();
    let auth = cfg
        .token
        .as_ref()
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    let request = format!(
        "POST {}/v1/chat/completions HTTP/1.0\r\nHost: {}:{}\r\nContent-Type: application/json\r\n\
         Accept: text/event-stream, application/json\r\n{auth}Content-Length: {}\r\n\r\n{body}",
        rt.base,
        rt.host,
        rt.port,
        body.len()
    );
    let mut stream = tokio::time::timeout(
        Duration::from_secs(5),
        TcpStream::connect(rt.connect_addr()),
    )
    .await
    .map_err(|_| unreachable.to_owned())?
    .map_err(|_| unreachable.to_owned())?;
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|_| unreachable.to_owned())?;

    // Read the head.
    let mut buf = Vec::new();
    let mut chunk = vec![0u8; 8192];
    let head_end = loop {
        if let Some(i) = find(&buf, b"\r\n\r\n") {
            break i;
        }
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|_| unreachable.to_owned())?;
        if n == 0 {
            return Err(unreachable.to_owned());
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_ascii_lowercase();
    let status: u16 = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let sse = head.contains("content-type: text/event-stream");
    let mut rest = buf[head_end + 4..].to_vec();

    if sse && (200..300).contains(&status) {
        return pass_through(&mut stream, rest, tx).await;
    }

    // Whole reply at once: read it, then send it in word-sized pieces.
    stream
        .read_to_end(&mut rest)
        .await
        .map_err(|_| unreachable.to_owned())?;
    let v: serde_json::Value = serde_json::from_slice(&rest).unwrap_or(serde_json::Value::Null);
    if !(200..300).contains(&status) {
        let why = v["error"]["message"]
            .as_str()
            .or_else(|| v["error"].as_str())
            .unwrap_or("no details");
        return Err(format!(
            "The Arkhon runtime couldn't answer (status {status}): {why}"
        ));
    }
    let Some(text) = v["choices"][0]["message"]["content"].as_str() else {
        return Err("The Arkhon runtime sent a reply this page doesn't understand.".to_owned());
    };
    for piece in split_tokens(text) {
        if tx
            .send(event("token", &json!({ "t": piece })))
            .await
            .is_err()
        {
            return Ok(());
        }
    }
    Ok(())
}

/// Pass a streaming (SSE) reply through, token by token, as it arrives.
async fn pass_through(
    stream: &mut TcpStream,
    mut rest: Vec<u8>,
    tx: &mpsc::Sender<Bytes>,
) -> Result<(), String> {
    let mut chunk = vec![0u8; 8192];
    loop {
        while let Some(i) = find(&rest, b"\n") {
            let line = String::from_utf8_lossy(&rest[..i]).trim().to_owned();
            rest.drain(..=i);
            let Some(data) = line.strip_prefix("data:").map(str::trim) else {
                continue;
            };
            if data == "[DONE]" {
                return Ok(());
            }
            let Ok(v) = serde_json::from_str::<serde_json::Value>(data) else {
                continue;
            };
            if let Some(t) = v["choices"][0]["delta"]["content"].as_str() {
                if !t.is_empty() && tx.send(event("token", &json!({ "t": t }))).await.is_err() {
                    return Ok(()); // The page stopped reading.
                }
            }
        }
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|_| "The Arkhon runtime stopped answering partway through.".to_owned())?;
        if n == 0 {
            return Ok(());
        }
        rest.extend_from_slice(&chunk[..n]);
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// An mpsc receiver as a body stream.
struct RxStream(mpsc::Receiver<Bytes>);

impl futures_core::Stream for RxStream {
    type Item = Result<Bytes, Infallible>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.0.poll_recv(cx).map(|o| o.map(Ok))
    }
}
