//! `arkhon-license-server`: the Arkhon License Manager.
//!
//! ```text
//! arkhon-license-server serve                                  # run the API
//! arkhon-license-server create-admin --email ops@… --password '…' # prints the authenticator link
//! ```
//!
//! Configuration (environment):
//! * `DATABASE_URL`: Postgres URL
//! * `ARKHON_BIND`: listen address (default `127.0.0.1:8443`; terminate TLS at the proxy)
//! * `ARKHON_ROOT_PUBLIC_KEY`: root public key, hex (from `arkhon-keygen root`)
//! * `ARKHON_ISSUING_KEY_FILE`, `ARKHON_ISSUING_CERT_FILE`: from `arkhon-keygen issuing`
//! * `ARKHON_CEK_KEK_FILE`: 32 random bytes as hex, which encrypt release keys at rest
//!
//! Key files are read once at start-up. In production, mount them from a secret store or replace
//! `FileIssuingSigner` / `CekVault` with KMS-backed implementations.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use arkhon_crypto::ed25519_dalek::{SigningKey, VerifyingKey};
use arkhon_license::IssuingCertificate;
use arkhon_license_server::{admin, router, AppState, CekVault, FileIssuingSigner, MIGRATOR};
use sqlx::postgres::PgPoolOptions;

fn env(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("Set {name} (see server/README.md)."))
}

fn hex32(s: &str, what: &str) -> Result<[u8; 32], String> {
    let s = s.trim();
    let bytes: Option<Vec<u8>> = (0..s.len())
        .step_by(2)
        .map(|i| s.get(i..i + 2).and_then(|h| u8::from_str_radix(h, 16).ok()))
        .collect();
    bytes
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| format!("{what} must be 64 hex characters."))
}

fn read(path: &str) -> Result<String, String> {
    std::fs::read_to_string(Path::new(path)).map_err(|e| format!("Couldn't read {path}: {e}"))
}

async fn state() -> Result<AppState, String> {
    let pool = PgPoolOptions::new()
        .max_connections(20)
        .connect(&env("DATABASE_URL")?)
        .await
        .map_err(|e| format!("Couldn't connect to the database: {e}"))?;
    MIGRATOR
        .run(&pool)
        .await
        .map_err(|e| format!("Database migration failed: {e}"))?;
    let root = VerifyingKey::from_bytes(&hex32(
        &env("ARKHON_ROOT_PUBLIC_KEY")?,
        "ARKHON_ROOT_PUBLIC_KEY",
    )?)
    .map_err(|_| "ARKHON_ROOT_PUBLIC_KEY isn't a valid key.".to_owned())?;
    let issuing = SigningKey::from_bytes(&hex32(
        &read(&env("ARKHON_ISSUING_KEY_FILE")?)?,
        "issuing key",
    )?);
    let cert_bytes = std::fs::read(env("ARKHON_ISSUING_CERT_FILE")?).map_err(|e| e.to_string())?;
    let cert = IssuingCertificate::from_bytes(&cert_bytes)
        .map_err(|_| "The issuing certificate file is damaged.".to_owned())?;
    cert.verify(&root).map_err(|_| {
        "The issuing certificate isn't signed by ARKHON_ROOT_PUBLIC_KEY.".to_owned()
    })?;
    let kek = hex32(&read(&env("ARKHON_CEK_KEK_FILE")?)?, "ARKHON_CEK_KEK_FILE")?;
    Ok(AppState::new(
        pool,
        Arc::new(FileIssuingSigner::new(issuing, cert)?),
        Arc::new(CekVault::new(kek)),
        root,
    ))
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result: Result<(), String> = async {
        match args.first().map(String::as_str) {
            Some("serve") | None => {
                let s = state().await?;
                let bind: SocketAddr = std::env::var("ARKHON_BIND")
                    .unwrap_or_else(|_| "127.0.0.1:8443".into())
                    .parse()
                    .map_err(|_| "ARKHON_BIND must look like 127.0.0.1:8443".to_owned())?;
                let listener = tokio::net::TcpListener::bind(bind)
                    .await
                    .map_err(|e| e.to_string())?;
                println!("Arkhon License Manager listening on {bind}");
                axum::serve(
                    listener,
                    router(s).into_make_service_with_connect_info::<SocketAddr>(),
                )
                .await
                .map_err(|e| e.to_string())
            }
            Some("create-admin") => {
                let s = state().await?;
                let email = flag(&args, "--email").ok_or("Missing --email")?;
                let password = flag(&args, "--password").ok_or("Missing --password")?;
                let url = admin::create_admin(&s, &email, &password)
                    .await
                    .map_err(|e| e.1)?;
                println!("Admin created. Add this to an authenticator app, then sign in:\n{url}");
                Ok(())
            }
            Some(other) => Err(format!(
                "Unknown command {other}. Use serve or create-admin."
            )),
        }
    }
    .await;
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            std::process::ExitCode::FAILURE
        }
    }
}
