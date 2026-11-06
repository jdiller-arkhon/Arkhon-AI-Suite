//! Phase 1 spike: load a model into a sealed memfd and serve one completion through llama-server.
//!
//! ```text
//! p1-spike --server <llama-server> --model <file.gguf> [--port 8089]
//! ```
//! Prints timings as JSON lines so runs can be saved as evidence.

#[cfg(target_os = "linux")]
fn main() -> std::io::Result<()> {
    use std::io::{Read, Write};
    use std::time::{Duration, Instant};

    use arkhon_runtime::memload::{harden_process, SealedModel};

    let mut server = None;
    let mut model = None;
    let mut port: u16 = 8089;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--server" => server = args.next(),
            "--model" => model = args.next(),
            "--port" => port = args.next().and_then(|p| p.parse().ok()).unwrap_or(port),
            other => eprintln!("ignoring {other}"),
        }
    }
    let (Some(server), Some(model)) = (server, model) else {
        eprintln!("usage: p1-spike --server <llama-server> --model <file.gguf> [--port N]");
        std::process::exit(2);
    };

    harden_process()?;
    let t0 = Instant::now();
    let sealed = SealedModel::create("arkhon-model", |w| {
        let mut f = std::fs::File::open(&model)?;
        std::io::copy(&mut f, w).map(|_| ())
    })?;
    let load_ms = t0.elapsed().as_millis();
    let path = sealed.share_with_child()?;
    println!(
        "{{\"step\":\"memfd_loaded\",\"bytes\":{},\"ms\":{load_ms}}}",
        sealed.len()
    );

    let t1 = Instant::now();
    let mut child = std::process::Command::new(&server)
        .args(["-m"])
        .arg(&path)
        .args([
            "--load-mode",
            "mmap+mlock",
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "-c",
            "2048",
            "-t",
            "3",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::fs::File::create(
            std::env::temp_dir().join("arkhon-p1-llama.log"),
        )?)
        .spawn()?;

    let addr = format!("127.0.0.1:{port}");
    let http = |method: &str, path: &str, body: &str| -> std::io::Result<String> {
        let mut s = std::net::TcpStream::connect(&addr)?;
        s.set_read_timeout(Some(Duration::from_secs(120)))?;
        write!(
            s,
            "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )?;
        let mut out = String::new();
        s.read_to_string(&mut out)?;
        Ok(out)
    };
    let ready = loop {
        if t1.elapsed() > Duration::from_secs(180) {
            break false;
        }
        if http("GET", "/health", "").is_ok_and(|r| r.starts_with("HTTP/1.1 200")) {
            break true;
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    println!(
        "{{\"step\":\"server_ready\",\"ok\":{ready},\"ms\":{}}}",
        t1.elapsed().as_millis()
    );

    if ready {
        let t2 = Instant::now();
        let body = r#"{"model":"local","messages":[{"role":"user","content":"Reply with one short sentence: what is an HVAC system? /no_think"}],"max_tokens":48,"temperature":0}"#;
        let resp = http("POST", "/v1/chat/completions", body)?;
        let json = resp.split("\r\n\r\n").nth(1).unwrap_or("");
        println!(
            "{{\"step\":\"completion\",\"ms\":{},\"http_ok\":{}}}",
            t2.elapsed().as_millis(),
            resp.starts_with("HTTP/1.1 200")
        );
        println!("{json}");
    }
    child.kill().ok();
    child.wait().ok();
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("p1-spike currently supports Linux only (see ADR-0008).");
}
