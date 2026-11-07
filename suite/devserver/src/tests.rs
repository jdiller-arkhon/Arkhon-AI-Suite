use super::*;
use arkhon_engine::{demo_state, SystemClock};
use axum::body::Body;
use axum::http::Request as HttpRequest;
use http_body_util::BodyExt;
use tower::ServiceExt;

const PORT: u16 = 4317;

fn app() -> (Router, arkhon_engine::DemoIds) {
    let (state, ids) = demo_state();
    let s = AppState::new(Suite::new(state, Box::new(SystemClock)), None, ids.owner);
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../app/design");
    (router(s, dir, PORT), ids)
}

fn req(method: &str, uri: &str, as_: Option<u64>, body: Option<&str>) -> HttpRequest<Body> {
    let mut b = HttpRequest::builder()
        .method(method)
        .uri(uri)
        .header("host", "127.0.0.1:4317");
    if let Some(a) = as_ {
        b = b.header("x-arkhon-as", a.to_string());
    }
    if body.is_some() {
        b = b.header("content-type", "application/json");
    }
    b.body(body.map_or_else(Body::empty, |s| Body::from(s.to_owned())))
        .unwrap()
}

async fn send(app: &Router, r: HttpRequest<Body>) -> (StatusCode, serde_json::Value) {
    let res = app.clone().oneshot(r).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

#[tokio::test]
async fn view_is_shaped_for_the_viewer() {
    let (app, ids) = app();
    let (s, v) = send(&app, req("GET", "/api/view", Some(ids.tech), None)).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["viewer"]["name"], "Tia Alvarez");
    assert_eq!(v["can"]["manage_people"], false);
    let (_, v) = send(&app, req("GET", "/api/view", Some(ids.owner), None)).await;
    assert_eq!(v["can"]["manage_billing"], true);
    assert_eq!(v["seats_used"], 8);
}

#[tokio::test]
async fn commands_run_the_real_rules() {
    let (app, ids) = app();
    let ok = r#"{"command":"invite","email":"new@coastline.com","role":"Member"}"#;
    let (s, v) = send(&app, req("POST", "/api/command", Some(ids.admin), Some(ok))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(v["message"].as_str().unwrap().contains("Invite sent"));
    assert_eq!(v["view"]["seats_used"], 9);

    let (s, v) = send(&app, req("POST", "/api/command", Some(ids.tech), Some(ok))).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(v["error"]
        .as_str()
        .unwrap()
        .contains("Invite and remove people"));

    let bad = r#"{"command":"invite","email":"x@coastline.com","role":"Wizard"}"#;
    let (s, _) = send(
        &app,
        req("POST", "/api/command", Some(ids.owner), Some(bad)),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    let (s, _) = send(
        &app,
        req("POST", "/api/command", Some(ids.owner), Some("{nope")),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn activity_records_and_is_admin_only() {
    let (app, ids) = app();
    let c = r#"{"command":"set-app-policy","app":"gmail","policy":"off"}"#;
    send(&app, req("POST", "/api/command", Some(ids.tech), Some(c))).await;
    let (s, log) = send(&app, req("GET", "/api/activity", Some(ids.owner), None)).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(log[0]["actor"], "Tia Alvarez");
    assert!(log[0]["refused"].is_string());
    let (s, _) = send(&app, req("GET", "/api/activity", Some(ids.tech), None)).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn foreign_hosts_and_origins_are_blocked() {
    let (app, ids) = app();
    let mut r = req("GET", "/api/view", Some(ids.owner), None);
    r.headers_mut()
        .insert("host", "evil.example:4317".parse().unwrap());
    assert_eq!(send(&app, r).await.0, StatusCode::FORBIDDEN);

    let mut r = req(
        "POST",
        "/api/command",
        Some(ids.owner),
        Some(r#"{"command":"set-seats","seats":50}"#),
    );
    r.headers_mut()
        .insert("origin", "https://evil.example".parse().unwrap());
    assert_eq!(send(&app, r).await.0, StatusCode::FORBIDDEN);

    let mut r = req("GET", "/api/view", Some(ids.owner), None);
    r.headers_mut()
        .insert("origin", "http://127.0.0.1:4317".parse().unwrap());
    assert_eq!(send(&app, r).await.0, StatusCode::OK);
}

#[tokio::test]
async fn simple_cross_site_posts_are_rejected() {
    // A form post (no JSON content type, no custom header) never reaches the engine.
    let (app, _) = app();
    let r = HttpRequest::builder()
        .method("POST")
        .uri("/api/command")
        .header("host", "127.0.0.1:4317")
        .header("content-type", "text/plain")
        .body(Body::from(r#"{"command":"set-seats","seats":50}"#))
        .unwrap();
    assert_eq!(send(&app, r).await.0, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn serves_the_prototype_with_safe_headers() {
    let (app, _) = app();
    let res = app
        .clone()
        .oneshot(req("GET", "/dashboard.html", None, None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers()["x-frame-options"], "DENY");
    assert_eq!(res.headers()["cache-control"], "no-store");
}

#[tokio::test]
async fn people_list_for_view_as() {
    let (app, _) = app();
    let (s, v) = send(&app, req("GET", "/api/people", None, None)).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v.as_array().unwrap().len(), 9);
}

#[test]
fn embedded_preview_snapshot_matches_the_engine() {
    // The static preview must show exactly what the engine produces. Regenerate with:
    // cargo run -q -p arkhon-suite-dev -- --dump-view  (and paste into dashboard.html#snapshot)
    let html = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../app/design/dashboard.html"),
    )
    .unwrap();
    let start = html
        .find(r#"<script type="application/json" id="snapshot">"#)
        .unwrap();
    let body = &html[start..];
    let json = &body[body.find('>').unwrap() + 1..body.find("</script>").unwrap()];
    let embedded: serde_json::Value = serde_json::from_str(json).expect("snapshot is JSON");
    let (state, ids) = demo_state();
    let view = Suite::new(state, Box::new(SystemClock)).view(ids.owner);
    assert_eq!(
        embedded,
        serde_json::to_value(view).unwrap(),
        "snapshot is stale; regenerate it"
    );
}

#[tokio::test]
async fn approving_from_home_updates_needs_you_and_this_week() {
    let (app, ids) = app();
    let (_, v) = send(&app, req("GET", "/api/view", Some(ids.owner), None)).await;
    assert_eq!(v["needs_you"]["total"], 5);
    let first = &v["needs_you"]["items"][0];
    assert_eq!(first["title"], "Reply to Marisol Vega");
    let drafts = v["this_week"]["totals"]["drafts"].as_u64().unwrap();
    let cmd = format!(r#"{{"command":"approve","item":{}}}"#, first["id"]);
    // Someone else can't approve Dana's item.
    let (s, _) = send(
        &app,
        req("POST", "/api/command", Some(ids.tech), Some(&cmd)),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, v) = send(
        &app,
        req("POST", "/api/command", Some(ids.owner), Some(&cmd)),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["view"]["needs_you"]["total"], 4);
    assert_eq!(v["view"]["this_week"]["totals"]["drafts"], drafts + 1);
}

#[tokio::test]
async fn monthly_report_is_scoped_to_the_viewer() {
    let (app, ids) = app();
    let (s, r) = send(
        &app,
        req("GET", "/api/report?month=2026-11", Some(ids.owner), None),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(r["scope"], "company");
    assert_eq!(r["days"].as_array().unwrap().len(), 30);
    let (_, r) = send(&app, req("GET", "/api/report", Some(ids.tech), None)).await;
    assert_eq!(r["scope"], "you");
    assert_eq!(r["month"], "2026-11");
    let (s, _) = send(
        &app,
        req("GET", "/api/report?month=nope", Some(ids.owner), None),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn mail_passwords_go_to_the_vault_and_are_never_echoed() {
    let dir = tempfile::tempdir().unwrap();
    let (state, ids) = demo_state();
    let vault = arkhon_engine::TokenVault::new(
        dir.path().join("vault.json"),
        Box::new(arkhon_engine::vault::DevFileKeyProvider::new(
            dir.path().join("vault.dev-key"),
        )),
    );
    let store = Store::new(dir.path().join("org.json"));
    let s = AppState::new(
        Suite::new(state, Box::new(SystemClock)).with_vault(vault),
        Some(store.clone()),
        ids.owner,
    );
    let app = router(
        s,
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../app/design"),
        PORT,
    );
    let secret = "correct-horse-battery-staple";
    let cmd = format!(
        r#"{{"command":"connect","app":"other-email","account":"dana@example.com","for":{{"type":"me"}},
            "credentials":{{"imap_host":"imap.example.com","smtp_host":"smtp.example.com","username":"dana","password":"{secret}"}}}}"#
    );
    let (s, v) = send(
        &app,
        req("POST", "/api/command", Some(ids.owner), Some(&cmd)),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(!v.to_string().contains(secret));
    let (_, log) = send(&app, req("GET", "/api/activity", Some(ids.owner), None)).await;
    assert!(!log.to_string().contains(secret));
    let saved = std::fs::read_to_string(store.path()).unwrap();
    assert!(!saved.contains(secret));
    let vault = std::fs::read_to_string(dir.path().join("vault.json")).unwrap();
    assert!(!vault.contains(secret));
}

#[tokio::test]
async fn ask_answers_from_files_or_says_not_found() {
    let (app, ids) = app();
    let (s, a) = send(
        &app,
        req(
            "GET",
            "/api/ask?q=How%20much%20is%20a%20diagnostic%20visit",
            Some(ids.tech),
            None,
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(a["found"], true);
    assert_eq!(a["sources"][0]["label"], "Price list 2026");
    let (_, a) = send(
        &app,
        req("GET", "/api/ask?q=wifi%20password", Some(ids.tech), None),
    )
    .await;
    assert_eq!(a["found"], false);
    let (s, _) = send(&app, req("GET", "/api/ask?q=", Some(ids.tech), None)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn workspace_pages_and_delete_all_follow_the_rules() {
    let (app, ids) = app();
    let (_, v) = send(&app, req("GET", "/api/view", Some(ids.tech), None)).await;
    assert!(v["desk"].is_null(), "Tia has no Customer replies workspace");
    assert!(v["docs"]["documents"].is_array());
    let del = r#"{"command":"delete-all-data","confirm":"Coastline Mechanical"}"#;
    let (s, _) = send(&app, req("POST", "/api/command", Some(ids.tech), Some(del))).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, v) = send(
        &app,
        req("POST", "/api/command", Some(ids.owner), Some(del)),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["view"]["needs_you"]["total"], 0);
    assert_eq!(v["view"]["connections"].as_array().unwrap().len(), 0);
}

/* ---------- /api/chat ---------- */

fn chat_app(cfg: chat::ChatConfig) -> (Router, arkhon_engine::DemoIds) {
    let (state, ids) = demo_state();
    let s = AppState::new(Suite::new(state, Box::new(SystemClock)), None, ids.owner).with_chat(cfg);
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../app/design");
    (router(s, dir, PORT), ids)
}

/// Parsed SSE stream: (event name, data JSON) in order.
async fn chat_events(
    app: &Router,
    as_: u64,
    text: &str,
) -> (StatusCode, Vec<(String, serde_json::Value)>) {
    let body = json!({ "messages": [{ "role": "user", "content": text }] }).to_string();
    let res = app
        .clone()
        .oneshot(req("POST", "/api/chat", Some(as_), Some(&body)))
        .await
        .unwrap();
    let status = res.status();
    let ct = res
        .headers()
        .get(header::CONTENT_TYPE)
        .map(|v| v.to_str().unwrap().to_owned())
        .unwrap_or_default();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let raw = String::from_utf8(bytes.to_vec()).unwrap();
    if status != StatusCode::OK {
        return (status, Vec::new());
    }
    assert!(ct.starts_with("text/event-stream"), "{ct}");
    let events = raw
        .split("\n\n")
        .filter(|b| !b.trim().is_empty())
        .map(|b| {
            let name = b.lines().find_map(|l| l.strip_prefix("event: ")).unwrap();
            let data = b.lines().find_map(|l| l.strip_prefix("data: ")).unwrap();
            (name.to_owned(), serde_json::from_str(data).unwrap())
        })
        .collect();
    (status, events)
}

fn joined(events: &[(String, serde_json::Value)]) -> String {
    events
        .iter()
        .filter(|(n, _)| n == "token")
        .map(|(_, d)| d["t"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn chat_demo_mode_streams_a_labelled_reply() {
    let (app, ids) = chat_app(chat::ChatConfig::default());
    let (s, v) = send(&app, req("GET", "/api/chat", None, None)).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["mode"], "demo");
    assert_eq!(v["label"], chat::DEMO_LABEL);

    let (s, ev) = chat_events(&app, ids.owner, "Write me a haiku about pipes").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(ev[0].0, "meta", "mode comes first");
    assert_eq!(ev[0].1["mode"], "demo");
    assert_eq!(ev[0].1["label"], "Demo replies");
    assert!(
        ev.iter().filter(|(n, _)| n == "token").count() > 10,
        "streams in pieces"
    );
    assert_eq!(ev.last().unwrap().0, "done");
    let text = joined(&ev);
    assert!(text.contains("demo reply"), "{text}");
    assert!(text.contains("Write me a haiku about pipes"));
    assert!(!ev.iter().any(|(n, _)| n == "sources"), "nothing to cite");

    // Empty and malformed requests are refused plainly.
    let (s, _) = chat_events(&app, ids.owner, "   ").await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = send(
        &app,
        req("POST", "/api/chat", Some(ids.owner), Some("{nope")),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn chat_demo_mode_answers_from_company_files_with_sources() {
    let (app, ids) = chat_app(chat::ChatConfig::default());
    let (_, ev) = chat_events(&app, ids.tech, "What's the warranty on new installs?").await;
    assert_eq!(ev[0].1["mode"], "demo");
    let text = joined(&ev);
    assert!(text.contains("10 years"), "{text}");
    let src = ev.iter().find(|(n, _)| n == "sources").expect("sources");
    assert_eq!(src.1["sources"][0]["label"], "Warranty policy");
    assert_eq!(ev.last().unwrap().0, "done");
}

/// A tiny stand-in for the runtime on 127.0.0.1: answers one request with `reply`
/// and hands back what it received.
async fn fake_runtime(reply: String) -> (u16, tokio::task::JoinHandle<String>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let h = tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        let mut got = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = s.read(&mut buf).await.unwrap();
            got.extend_from_slice(&buf[..n]);
            let text = String::from_utf8_lossy(&got).to_string();
            if let Some(i) = text.find("\r\n\r\n") {
                let len: usize = text
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .map(|v| v.trim().parse().unwrap())
                    })
                    .unwrap();
                if got.len() >= i + 4 + len {
                    break;
                }
            }
            if n == 0 {
                break;
            }
        }
        s.write_all(reply.as_bytes()).await.unwrap();
        s.shutdown().await.unwrap();
        String::from_utf8(got).unwrap()
    });
    (port, h)
}

fn runtime_at(url: &str) -> chat::ChatConfig {
    chat::ChatConfig {
        runtime: chat::RuntimeUrl::parse(url),
        ..Default::default()
    }
}

#[tokio::test]
async fn chat_forwards_to_the_local_runtime_and_passes_tokens_through() {
    // Streaming runtime.
    let sse = "HTTP/1.0 200 OK\r\ncontent-type: text/event-stream\r\n\r\n\
        data: {\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}\n\n\
        data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n\n\
        data: {\"choices\":[{\"delta\":{\"content\":\" from the runtime.\"}}]}\n\n\
        data: [DONE]\n\n";
    let (port, upstream) = fake_runtime(sse.to_owned()).await;
    let (app, ids) = chat_app(runtime_at(&format!("http://127.0.0.1:{port}")));
    let (_, v) = send(&app, req("GET", "/api/chat", None, None)).await;
    assert_eq!(v["mode"], "runtime");
    let (s, ev) = chat_events(&app, ids.owner, "Say hello").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(ev[0].1["mode"], "runtime");
    assert_eq!(ev[0].1["label"], chat::RUNTIME_LABEL);
    assert_eq!(joined(&ev), "Hello from the runtime.");
    assert_eq!(
        ev.iter().filter(|(n, _)| n == "token").count(),
        2,
        "passed through as sent"
    );
    assert_eq!(ev.last().unwrap().0, "done");
    let got = upstream.await.unwrap();
    assert!(
        got.starts_with("POST /v1/chat/completions HTTP/1.0\r\n"),
        "{got}"
    );
    assert!(got.contains(&format!("Host: 127.0.0.1:{port}")));
    assert!(got.contains("\"content\":\"Say hello\""));
    assert!(got.contains("\"stream\":true"));

    // A runtime that answers all at once is chunked for the page.
    let body = r#"{"choices":[{"message":{"role":"assistant","content":"One two three four."}}]}"#;
    let whole = format!(
        "HTTP/1.0 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
        body.len()
    );
    let (port, upstream) = fake_runtime(whole).await;
    let (app, ids) = chat_app(runtime_at(&format!("http://localhost:{port}")));
    let (_, ev) = chat_events(&app, ids.owner, "Count").await;
    assert_eq!(joined(&ev), "One two three four.");
    assert_eq!(ev.iter().filter(|(n, _)| n == "token").count(), 4);
    upstream.await.unwrap();

    // Errors from the runtime are shown honestly.
    let bad = r#"{"error":{"message":"No model is loaded."}}"#;
    let resp =
        format!("HTTP/1.0 503 Service Unavailable\r\ncontent-type: application/json\r\n\r\n{bad}");
    let (port, upstream) = fake_runtime(resp).await;
    let (app, ids) = chat_app(runtime_at(&format!("http://127.0.0.1:{port}")));
    let (_, ev) = chat_events(&app, ids.owner, "Hi").await;
    let e = ev.iter().find(|(n, _)| n == "error").expect("error event");
    assert!(e.1["message"]
        .as_str()
        .unwrap()
        .contains("No model is loaded"));
    assert_eq!(ev.last().unwrap().0, "done");
    upstream.await.unwrap();
}

#[test]
fn chat_runtime_must_be_on_this_computer() {
    assert!(chat::RuntimeUrl::parse("http://127.0.0.1:8080").is_some());
    assert!(chat::RuntimeUrl::parse("http://localhost:8080/").is_some());
    assert!(chat::RuntimeUrl::parse("http://[::1]:8080").is_some());
    for bad in [
        "https://api.example.com:443",
        "http://10.0.0.5:8080",
        "http://example.com:80",
        "http://127.0.0.1.evil.com:80",
        "http://user@127.0.0.1:80",
        "http://127.0.0.1",
        "ftp://127.0.0.1:21",
    ] {
        assert!(chat::RuntimeUrl::parse(bad).is_none(), "{bad}");
    }
}

#[tokio::test]
async fn chat_keeps_host_and_origin_protections() {
    let (app, ids) = chat_app(chat::ChatConfig::default());
    let body = r#"{"messages":[{"role":"user","content":"hi"}]}"#;
    let mut r = req("POST", "/api/chat", Some(ids.owner), Some(body));
    r.headers_mut()
        .insert("host", "evil.example:4317".parse().unwrap());
    assert_eq!(send(&app, r).await.0, StatusCode::FORBIDDEN);
    let mut r = req("POST", "/api/chat", Some(ids.owner), Some(body));
    r.headers_mut()
        .insert("origin", "https://evil.example".parse().unwrap());
    assert_eq!(send(&app, r).await.0, StatusCode::FORBIDDEN);
    let mut r = req("GET", "/api/chat", None, None);
    r.headers_mut()
        .insert("origin", "https://evil.example".parse().unwrap());
    assert_eq!(send(&app, r).await.0, StatusCode::FORBIDDEN);
    // No x-arkhon-as header: a cross-site form can't post a chat.
    assert_eq!(
        send(&app, req("POST", "/api/chat", None, Some(body)))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    // Not JSON.
    let mut r = req("POST", "/api/chat", Some(ids.owner), Some(body));
    r.headers_mut()
        .insert("content-type", "text/plain".parse().unwrap());
    assert_eq!(send(&app, r).await.0, StatusCode::BAD_REQUEST);
}
