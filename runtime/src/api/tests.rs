use std::collections::BTreeSet;
use std::sync::Mutex;

use axum::body::Body;
use http_body_util::BodyExt;
use tower::ServiceExt;

use super::*;
use crate::backend::{BackendError, BackendResponse, EchoBackend};
use crate::hardware::Tier;
use crate::router::Registry;

const PORT: u16 = 4318;

/// Records which engine each request was sent to.
#[derive(Default)]
struct Recorder(Mutex<Vec<(String, Endpoint)>>);

impl Backend for Recorder {
    fn forward(&self, req: BackendRequest) -> Result<BackendResponse, BackendError> {
        self.0
            .lock()
            .unwrap()
            .push((req.engine.clone(), req.endpoint));
        EchoBackend.forward(req)
    }
}

fn state_with(
    tier: Tier,
    entitled: &[&str],
    backend: Arc<dyn Backend>,
    access: Access,
) -> ApiState {
    ApiState {
        router: Arc::new(ModelRouter::new(
            Registry::bundled(),
            tier,
            entitled
                .iter()
                .map(|s| (*s).to_owned())
                .collect::<BTreeSet<_>>(),
        )),
        backend,
        gate: Arc::new(RwLock::new(Gate {
            may_load_models: true,
            messages: vec![],
        })),
        access: Arc::new(access),
    }
}

fn state(entitled: &[&str]) -> ApiState {
    state_with(
        Tier::L,
        entitled,
        Arc::new(EchoBackend),
        Access::local(PORT),
    )
}

fn post(path: &str, body: &str) -> axum::http::request::Builder {
    let _ = body;
    Request::builder()
        .method("POST")
        .uri(path)
        .header("host", format!("127.0.0.1:{PORT}"))
        .header("content-type", "application/json")
}

async fn send(app: Router, req: Request<Body>) -> (StatusCode, HeaderMap, serde_json::Value) {
    let res = app.oneshot(req).await.unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let v = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, headers, v)
}

async fn chat_req(app: Router, model: &str) -> (StatusCode, HeaderMap, serde_json::Value) {
    let body = format!(r#"{{"model":"{model}","messages":[{{"role":"user","content":"hello"}}]}}"#);
    send(
        app,
        post("/v1/chat/completions", &body)
            .body(Body::from(body))
            .unwrap(),
    )
    .await
}

#[tokio::test]
async fn chat_completion_round_trip() {
    let (s, h, v) = chat_req(app(state(&["core", "lite"])), "core").await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["choices"][0]["message"]["content"], "[core] hello");
    assert_eq!(h["x-arkhon-engine"], "core");
    assert_eq!(h["cache-control"], "no-store");
    assert_eq!(h["x-frame-options"], "DENY");
}

#[tokio::test]
async fn every_endpoint_routes_to_the_right_task() {
    let rec = Arc::new(Recorder::default());
    let st = state_with(
        Tier::L,
        &["core", "embed", "rerank", "scribe"],
        rec.clone(),
        Access::local(PORT),
    );
    for (path, body) in [
        ("/v1/completions", r#"{"prompt":"x"}"#),
        ("/v1/embeddings", r#"{"input":"x"}"#),
        ("/v1/rerank", r#"{"query":"q","documents":["a"]}"#),
    ] {
        let (s, _, v) = send(
            app(st.clone()),
            post(path, body).body(Body::from(body)).unwrap(),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{path} {v}");
    }
    let audio = Request::builder()
        .method("POST")
        .uri("/v1/audio/transcriptions")
        .header("host", format!("localhost:{PORT}"))
        .header("content-type", "multipart/form-data; boundary=x")
        .body(Body::from("--x\r\n\r\nRIFF....\r\n--x--"))
        .unwrap();
    let (s, _, v) = send(app(st.clone()), audio).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let got = rec.0.lock().unwrap().clone();
    assert_eq!(
        got,
        [
            ("core".to_owned(), Endpoint::Completions),
            ("embed".to_owned(), Endpoint::Embeddings),
            ("rerank".to_owned(), Endpoint::Rerank),
            ("scribe".to_owned(), Endpoint::AudioTranscriptions),
        ]
    );
}

#[tokio::test]
async fn gate_unlicensed_engine_never_reaches_backend() {
    let rec = Arc::new(Recorder::default());
    let st = state_with(Tier::L, &["lite"], rec.clone(), Access::local(PORT));
    for model in ["pro", "core", "code", "chat", "reason"] {
        let (s, h, _) = chat_req(app(st.clone()), model).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(h["x-arkhon-engine"], "lite", "{model}");
    }
    // Embeddings aren't licensed and have no fallback: refused, backend never called for it.
    let body = r#"{"input":"x"}"#;
    let (s, _, v) = send(
        app(st.clone()),
        post("/v1/embeddings", body).body(Body::from(body)).unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(v["error"]["message"]
        .as_str()
        .unwrap()
        .contains("isn't in your plan"));
    assert!(rec.0.lock().unwrap().iter().all(|(e, _)| e == "lite"));
    // /v1/models lists only what's licensed.
    let req = Request::builder()
        .uri("/v1/models")
        .header("host", format!("127.0.0.1:{PORT}"))
        .body(Body::empty())
        .unwrap();
    let (_, _, v) = send(app(st), req).await;
    let ids: Vec<_> = v["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["id"].clone())
        .collect();
    assert_eq!(ids, [serde_json::json!("lite")]);
}

#[tokio::test]
async fn locked_license_refuses_models() {
    let st = state(&["core"]);
    *st.gate.write().unwrap() = Gate {
        may_load_models: false,
        messages: vec!["Arkhon needs to check your license.".into()],
    };
    let (s, _, v) = chat_req(app(st.clone()), "core").await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(v["error"]["type"], "license");
    let req = Request::builder()
        .uri("/v1/status")
        .header("host", format!("127.0.0.1:{PORT}"))
        .body(Body::empty())
        .unwrap();
    let (_, _, v) = send(app(st), req).await;
    assert_eq!(v["may_load_models"], false);
    assert_eq!(v["tier"], "L");
}

#[tokio::test]
async fn foreign_host_origin_and_content_type_blocked() {
    let body = "{}";
    let mut r = post("/v1/chat/completions", body)
        .body(Body::from(body))
        .unwrap();
    r.headers_mut()
        .insert("host", "evil.example:4318".parse().unwrap());
    assert_eq!(
        send(app(state(&["core"])), r).await.0,
        StatusCode::FORBIDDEN
    );
    let r = post("/v1/chat/completions", body)
        .header("origin", "https://evil.example")
        .body(Body::from(body))
        .unwrap();
    assert_eq!(
        send(app(state(&["core"])), r).await.0,
        StatusCode::FORBIDDEN
    );
    let r = post("/v1/chat/completions", body)
        .header("origin", format!("http://localhost:{PORT}"))
        .body(Body::from(r#"{"messages":[]}"#))
        .unwrap();
    assert_eq!(send(app(state(&["core"])), r).await.0, StatusCode::OK);
    let r = Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header("host", format!("127.0.0.1:{PORT}"))
        .header("content-type", "text/plain")
        .body(Body::from("{}"))
        .unwrap();
    assert_eq!(
        send(app(state(&["core"])), r).await.0,
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
    let r = post("/v1/chat/completions", "")
        .body(Body::from("{not json"))
        .unwrap();
    assert_eq!(
        send(app(state(&["core"])), r).await.0,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn lan_mode_requires_token() {
    let token = "t".repeat(40);
    let access = Access {
        port: PORT,
        lan: true,
        token: Some(token.clone()),
    };
    assert_eq!(
        access.bind_addr().unwrap().to_string(),
        format!("0.0.0.0:{PORT}")
    );
    let st = state_with(Tier::L, &["core"], Arc::new(EchoBackend), access);
    let body = r#"{"messages":[]}"#;
    let lan_req = |auth: Option<&str>| {
        let mut b = Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header("host", "192.168.1.20:4318")
            .header("content-type", "application/json");
        if let Some(a) = auth {
            b = b.header("authorization", a);
        }
        b.body(Body::from(body)).unwrap()
    };
    assert_eq!(
        send(app(st.clone()), lan_req(None)).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        send(app(st.clone()), lan_req(Some("Bearer wrong"))).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        send(app(st.clone()), lan_req(Some(&format!("Bearer {token}"))))
            .await
            .0,
        StatusCode::OK
    );
    let mut with_origin = lan_req(Some(&format!("Bearer {token}")));
    with_origin
        .headers_mut()
        .insert("origin", "http://192.168.1.20:4318".parse().unwrap());
    assert_eq!(send(app(st), with_origin).await.0, StatusCode::FORBIDDEN);
    // LAN without a (long enough) token refuses to start.
    for token in [None, Some("short".to_owned())] {
        assert!(Access {
            port: 1,
            lan: true,
            token
        }
        .bind_addr()
        .is_err());
    }
    assert_eq!(
        Access::local(5).bind_addr().unwrap().to_string(),
        "127.0.0.1:5"
    );
}

#[tokio::test]
async fn backend_failure_is_plain() {
    struct Down;
    impl Backend for Down {
        fn forward(&self, req: BackendRequest) -> Result<BackendResponse, BackendError> {
            Err(BackendError::NotRunning(req.engine))
        }
    }
    let st = state_with(Tier::L, &["core"], Arc::new(Down), Access::local(PORT));
    let (s, _, v) = chat_req(app(st), "core").await;
    assert_eq!(s, StatusCode::BAD_GATEWAY);
    assert!(v["error"]["message"]
        .as_str()
        .unwrap()
        .contains("isn't running"));
}

#[tokio::test]
async fn serves_over_tcp_and_forwards_with_http_backend() {
    // Upstream "engine": the API itself with the echo backend on an ephemeral port.
    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let up_port = upstream.local_addr().unwrap().port();
    let up_state = state_with(
        Tier::L,
        &["core"],
        Arc::new(EchoBackend),
        Access::local(up_port),
    );
    tokio::spawn(async move { axum::serve(upstream, app(up_state)).await });
    // HttpBackend must send the upstream's Host; ureq sets it from the URL.
    let backend = crate::backend::HttpBackend::new(
        [("core".to_owned(), format!("http://127.0.0.1:{up_port}"))].into(),
        std::time::Duration::from_secs(10),
    );
    let st = state_with(Tier::L, &["core"], Arc::new(backend), Access::local(PORT));
    let (s, h, v) = chat_req(app(st), "core").await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["choices"][0]["message"]["content"], "[core] hello");
    assert!(h["content-type"]
        .to_str()
        .unwrap()
        .starts_with("application/json"));
}
