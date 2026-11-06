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
