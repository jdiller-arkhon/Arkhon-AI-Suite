//! `arkhon-runtime`: the Arkhon process on a customer's computer.
//!
//! ```text
//! arkhon-runtime [--data-dir DIR] <command>
//!   detect [--json]                       hardware, accelerator memory and tier
//!   activate --server URL --key KEY       activate this computer (online)
//!   status                                where the license stands (offline)
//!   checkin [--server URL]                check in now (online)
//!   deactivate [--server URL]             free this computer's seat, delete local license data
//!   renewal-export FILE                   write an offline renewal request
//!   renewal-import FILE                   import an offline renewal response
//!   route MODEL_OR_TASK                   show which engine would answer, and why
//!   serve [--port 4318] [--lan --token-file F] [--fake-backend] [--upstream ENGINE=URL]...
//!         [--tier S|M|L]                  local OpenAI-shaped API
//! ```
//!
//! The root public key is embedded at build time from `ARKHON_ROOT_PUBLIC_KEY` (hex). Debug builds
//! also accept it from the environment at run time, for tests and demos; release builds never do.
//!
//! The device key is the TPM when built with `--features tpm` and `ARKHON_TPM_TCTI` is set
//! (e.g. `device:/dev/tpmrm0`); otherwise a software key in the data directory (weaker; the
//! license records which).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use arkhon_runtime::api::{self, Access, ApiState, Gate};
use arkhon_runtime::backend::{Backend, EchoBackend, HttpBackend};
use arkhon_runtime::client::HttpLicenseServer;
use arkhon_runtime::hardware::{self, Tier};
use arkhon_runtime::licensing::{CheckinOutcome, LicenseManager, Status, FINGERPRINT_SALT};
use arkhon_runtime::router::{Memory, ModelRouter, Registry, Task};
use arkhon_tpm::{DeviceKey, HardwareFingerprint, SoftwareDeviceKey};
use ed25519_dalek::VerifyingKey;
use rand_core::{OsRng, RngCore};

type R<T> = Result<T, String>;

const HTTP_TIMEOUT: Duration = Duration::from_secs(30);
const CHECK_INTERVAL: Duration = Duration::from_secs(3600);

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

fn flags(args: &[String], name: &str) -> Vec<String> {
    args.windows(2)
        .filter(|w| w[0] == name)
        .map(|w| w[1].clone())
        .collect()
}

fn has(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn default_data_dir() -> PathBuf {
    let env = |k: &str| std::env::var_os(k).map(PathBuf::from);
    if cfg!(windows) {
        env("LOCALAPPDATA")
            .unwrap_or_else(std::env::temp_dir)
            .join("Arkhon")
    } else if cfg!(target_os = "macos") {
        env("HOME")
            .unwrap_or_else(std::env::temp_dir)
            .join("Library/Application Support/Arkhon")
    } else {
        env("XDG_DATA_HOME")
            .or_else(|| env("HOME").map(|h| h.join(".local/share")))
            .unwrap_or_else(std::env::temp_dir)
            .join("arkhon")
    }
}

fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

fn root_key() -> R<VerifyingKey> {
    let embedded = option_env!("ARKHON_ROOT_PUBLIC_KEY").map(str::to_owned);
    let runtime = if cfg!(debug_assertions) {
        std::env::var("ARKHON_ROOT_PUBLIC_KEY").ok()
    } else {
        None
    };
    let hex = runtime
        .or(embedded)
        .ok_or("This build of Arkhon has no license root key. Install an official Arkhon build.")?;
    let bytes = parse_hex32(&hex).ok_or("The license root key in this build is damaged.")?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|_| "The license root key in this build is damaged.".into())
}

/// Per-install secret protecting the software device key file (owner-only file). An OS keychain
/// (DPAPI / Keychain / Secret Service) is the planned replacement.
fn storage_secret(dir: &Path) -> R<Vec<u8>> {
    let path = dir.join("device.secret");
    match std::fs::read(&path) {
        Ok(s) if s.len() == 32 => Ok(s),
        Ok(_) => Err("Arkhon's device secret is damaged. Activate Arkhon again.".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut s = vec![0u8; 32];
            OsRng.fill_bytes(&mut s);
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            opts.open(&path)
                .and_then(|mut f| std::io::Write::write_all(&mut f, &s))
                .map_err(|e| format!("Couldn't create Arkhon's device secret: {e}"))?;
            Ok(s)
        }
        Err(e) => Err(format!("Couldn't read Arkhon's device secret: {e}")),
    }
}

fn device_key(dir: &Path) -> R<Box<dyn DeviceKey>> {
    #[cfg(feature = "tpm")]
    if let Ok(tcti) = std::env::var("ARKHON_TPM_TCTI") {
        return arkhon_tpm::tpm::TpmDeviceKey::open(&tcti)
            .map(|k| Box::new(k) as Box<dyn DeviceKey>)
            .map_err(|e| e.to_string());
    }
    let secret = storage_secret(dir)?;
    SoftwareDeviceKey::open_or_create(&dir.join("device.key"), &secret)
        .map(|k| Box::new(k) as Box<dyn DeviceKey>)
        .map_err(|e| e.to_string())
}

fn manager(dir: &Path) -> R<LicenseManager> {
    std::fs::create_dir_all(dir).map_err(|e| format!("Couldn't create {}: {e}", dir.display()))?;
    Ok(LicenseManager::new(
        dir,
        root_key()?,
        device_key(dir)?,
        HardwareFingerprint::collect(&FINGERPRINT_SALT),
    ))
}

fn print_status(s: &Status) {
    println!(
        "License      : {} (customer {})",
        s.license_id, s.customer_id
    );
    println!(
        "Engines      : {}",
        s.engines.iter().cloned().collect::<Vec<_>>().join(", ")
    );
    println!("Security key : {}", s.binding.label());
    println!(
        "Models       : {}",
        if s.may_load_models {
            "allowed"
        } else {
            "locked"
        }
    );
    println!(
        "Expires (unix) {}; offline until {}; next check-in {}",
        s.expires_at, s.offline_deadline, s.checkin_due_at
    );
    for m in &s.messages {
        println!("Note         : {m}");
    }
}

fn server_for(args: &[String]) -> R<HttpLicenseServer> {
    let url = flag(args, "--server")
        .or_else(|| std::env::var("ARKHON_LICENSE_SERVER").ok())
        .ok_or("Give the license server address with --server.")?;
    Ok(HttpLicenseServer::new(&url, HTTP_TIMEOUT))
}

/// The router for this computer: detected tier and memory, or a `--tier` override (demos).
fn router_for(args: &[String], engines: std::collections::BTreeSet<String>) -> R<ModelRouter> {
    if let Some(t) = flag(args, "--tier") {
        let tier = Tier::parse(&t).ok_or("--tier must be S, M or L.")?;
        return Ok(ModelRouter::new(Registry::bundled(), tier, engines));
    }
    let hw = hardware::detect();
    let accel_mib = hardware::best_gpu(&hw.gpus).map_or(0, |g| g.vram_mib);
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let ram_mib = (hw.ram_gib * 1024.0) as u64;
    Ok(ModelRouter::new(Registry::bundled(), hw.tier, engines)
        .with_memory(Memory { accel_mib, ram_mib }))
}

fn gate_from(status: Result<Status, String>) -> (Gate, std::collections::BTreeSet<String>) {
    match status {
        Ok(s) => (
            Gate {
                may_load_models: s.may_load_models,
                messages: s.messages.clone(),
            },
            s.engines,
        ),
        Err(e) => (
            Gate {
                may_load_models: false,
                messages: vec![e],
            },
            std::collections::BTreeSet::new(),
        ),
    }
}

fn serve(dir: &Path, args: &[String]) -> R<()> {
    let m = manager(dir)?;
    let port: u16 = flag(args, "--port")
        .map_or(Ok(4318), |p| p.parse())
        .map_err(|_| "--port must be a number.")?;
    let token = flag(args, "--token-file")
        .map(|f| std::fs::read_to_string(f).map(|t| t.trim().to_owned()))
        .transpose()
        .map_err(|e| format!("Couldn't read the token file: {e}"))?;
    let access = Access {
        port,
        lan: has(args, "--lan"),
        token,
    };
    access.bind_addr()?;
    #[cfg(target_os = "linux")]
    let mut engines_alive: Vec<Running> = Vec::new();
    let backend: Arc<dyn Backend> = if has(args, "--fake-backend") {
        eprintln!("Using the test backend: answers are canned, no model runs.");
        Arc::new(EchoBackend)
    } else {
        let mut ups = BTreeMap::new();
        for u in flags(args, "--upstream") {
            let (engine, url) = u.split_once('=').ok_or("--upstream takes ENGINE=URL.")?;
            ups.insert(engine.to_owned(), url.to_owned());
        }
        #[cfg(target_os = "linux")]
        launch_engines(&m, args, &mut ups, &mut engines_alive)?;
        Arc::new(HttpBackend::new(ups, Duration::from_secs(600)))
    };
    let (gate, engines) = gate_from(m.status().map_err(|e| e.to_string()));
    for msg in &gate.messages {
        eprintln!("Note: {msg}");
    }
    let router = router_for(args, engines)?;
    let tier = router.tier();
    let state = ApiState {
        router: Arc::new(router),
        backend,
        gate: Arc::new(RwLock::new(gate)),
        access: Arc::new(access.clone()),
    };
    let gate = state.gate.clone();
    let server = std::thread::spawn(move || -> R<()> {
        let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
        rt.block_on(async move {
            let addr = state.access.bind_addr()?;
            eprintln!("Arkhon local API on http://{addr} (tier {tier})");
            api::serve(state, async {
                let _ = tokio::signal::ctrl_c().await;
            })
            .await
            .map_err(|e| format!("The local API stopped: {e}"))
        })
    });
    // Licensing loop on this thread (the device key stays here).
    let license_server = server_for(args).ok();
    let mut waited = Duration::ZERO;
    while !server.is_finished() {
        std::thread::sleep(Duration::from_millis(250));
        waited += Duration::from_millis(250);
        if waited < CHECK_INTERVAL {
            continue;
        }
        waited = Duration::ZERO;
        if let Some(ls) = &license_server {
            match m.checkin_if_due(ls) {
                Ok(CheckinOutcome::Offline(e)) => eprintln!("Note: {e}"),
                Err(e) => eprintln!("Note: {e}"),
                Ok(_) => {}
            }
        }
        let (g, _) = gate_from(m.status().map_err(|e| e.to_string()));
        if let Ok(mut w) = gate.write() {
            *w = g;
        }
    }
    let result = server
        .join()
        .map_err(|_| "The local API crashed.".to_owned())?;
    #[cfg(target_os = "linux")]
    for mut r in engines_alive {
        let _ = r.child.kill();
        let _ = r.child.wait();
    }
    result
}

/// An engine server started from a sealed memfd; the memfd must outlive the child.
#[cfg(target_os = "linux")]
struct Running {
    child: std::process::Child,
    _model: arkhon_runtime::memload::SealedModel,
}

/// Linux: `--launch ENGINE` (repeatable) decrypts `<models-dir>/<engine>/model.arkm` into a
/// sealed memfd and starts `--llama-server` / `--whisper-server` from it on 127.0.0.1.
#[cfg(target_os = "linux")]
fn launch_engines(
    m: &LicenseManager,
    args: &[String],
    ups: &mut BTreeMap<String, String>,
    alive: &mut Vec<Running>,
) -> R<()> {
    use arkhon_runtime::launch::{load_engine, spawn_server};
    let engines = flags(args, "--launch");
    if engines.is_empty() {
        return Ok(());
    }
    arkhon_runtime::memload::harden_process().map_err(|e| e.to_string())?;
    let models = PathBuf::from(flag(args, "--models-dir").ok_or("Give --models-dir.")?);
    let registry = Registry::bundled();
    for (port, engine) in (8100u16..).zip(engines) {
        let spec = registry
            .engines
            .get(&engine)
            .ok_or_else(|| format!("\"{engine}\" isn't a known engine."))?;
        let runtime = spec.runtime.clone().unwrap_or_else(|| "llama.cpp".into());
        let bin_flag = if runtime == "whisper.cpp" {
            "--whisper-server"
        } else {
            "--llama-server"
        };
        let binary =
            PathBuf::from(flag(args, bin_flag).ok_or_else(|| format!("Give {bin_flag}."))?);
        let model = load_engine(m, &models, &engine).map_err(|e| e.to_string())?;
        let child = spawn_server(
            &binary,
            &runtime,
            &engine,
            &model,
            port,
            Duration::from_secs(300),
        )
        .map_err(|e| format!("Couldn't start \"{engine}\": {e}"))?;
        ups.insert(engine, format!("http://127.0.0.1:{port}"));
        alive.push(Running {
            child,
            _model: model,
        });
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // one arm per command, kept flat for readability
fn run(args: &[String]) -> R<()> {
    let dir = flag(args, "--data-dir").map_or_else(default_data_dir, PathBuf::from);
    let cmd = args
        .iter()
        .enumerate()
        .find(|(i, a)| !a.starts_with("--") && (*i == 0 || !args[i - 1].starts_with("--")))
        .map(|(_, a)| a.as_str());
    let arg = || -> R<&String> {
        let pos = args
            .iter()
            .position(|a| Some(a.as_str()) == cmd)
            .ok_or("Missing argument.")?;
        args.get(pos + 1)
            .filter(|a| !a.starts_with("--"))
            .ok_or_else(|| "Missing argument. See the runtime README.".to_owned())
    };
    match cmd {
        Some("detect") => {
            let r = hardware::detect();
            if has(args, "--json") {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&r).map_err(|e| e.to_string())?
                );
            } else {
                println!("OS      : {} ({})", r.os, r.arch);
                println!("RAM     : {} GiB", r.ram_gib);
                for g in &r.gpus {
                    println!(
                        "GPU     : {} [{}/{}] {} MiB{}",
                        g.name,
                        g.vendor,
                        g.backend,
                        g.vram_mib,
                        if g.unified_memory { " unified" } else { "" }
                    );
                }
                println!("Backend : {}", r.accel_backend);
                println!("Tier    : {} - {}", r.tier, r.tier_reason);
            }
            Ok(())
        }
        Some("activate") => {
            let key = flag(args, "--key").ok_or("Give the activation key with --key.")?;
            let server = server_for(args)?;
            let url = flag(args, "--server");
            let s = manager(&dir)?
                .activate(&server, &key, url)
                .map_err(|e| e.to_string())?;
            println!("Arkhon is activated on this computer.");
            print_status(&s);
            Ok(())
        }
        Some("status") => {
            let s = manager(&dir)?.status().map_err(|e| e.to_string())?;
            print_status(&s);
            Ok(())
        }
        Some("checkin") => {
            let s = manager(&dir)?
                .checkin(&server_for(args)?)
                .map_err(|e| e.to_string())?;
            print_status(&s);
            Ok(())
        }
        Some("deactivate") => {
            manager(&dir)?
                .deactivate(&server_for(args)?)
                .map_err(|e| e.to_string())?;
            println!(
                "This computer is deactivated. You can now activate Arkhon on another computer."
            );
            Ok(())
        }
        Some("renewal-export") => {
            let out = arg()?;
            let req = manager(&dir)?
                .export_renewal_request()
                .map_err(|e| e.to_string())?;
            std::fs::write(out, req).map_err(|e| e.to_string())?;
            println!("Wrote {out}. Take it to a computer with internet access and upload it in the Arkhon portal.");
            Ok(())
        }
        Some("renewal-import") => {
            let file = arg()?;
            let data = std::fs::read(file).map_err(|e| e.to_string())?;
            let s = manager(&dir)?
                .import_renewal(&data)
                .map_err(|e| e.to_string())?;
            println!("Renewal imported.");
            print_status(&s);
            Ok(())
        }
        Some("route") => {
            let what = arg()?;
            let engines = manager(&dir)?.status().map_err(|e| e.to_string())?.engines;
            let router = router_for(args, engines)?;
            match router.route_model(Some(what), Task::Chat) {
                Ok(r) => println!(
                    "{} ({}, quant {}): {}",
                    r.engine,
                    r.runtime,
                    r.quant.as_deref().unwrap_or("not measured yet"),
                    r.reason
                ),
                Err(e) => println!("{e}"),
            }
            Ok(())
        }
        Some("serve") => serve(&dir, args),
        Some("version") | None => {
            println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some(other) => Err(format!(
            "Unknown command \"{other}\". See the runtime README."
        )),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| (*x).to_owned()).collect()
    }

    #[test]
    fn flags_and_hex() {
        let args = a(&[
            "serve",
            "--port",
            "1",
            "--upstream",
            "core=u1",
            "--upstream",
            "lite=u2",
            "--lan",
        ]);
        assert_eq!(flag(&args, "--port").as_deref(), Some("1"));
        assert_eq!(flags(&args, "--upstream"), ["core=u1", "lite=u2"]);
        assert!(has(&args, "--lan") && !has(&args, "--fake-backend"));
        assert_eq!(parse_hex32(&"ab".repeat(32)), Some([0xab; 32]));
        assert_eq!(parse_hex32("ab"), None);
        assert_eq!(parse_hex32(&"zz".repeat(32)), None);
        assert_ne!(default_data_dir().as_os_str().len(), 0);
        assert!(run(&a(&["no-such-command"])).is_err());
        run(&a(&["version"])).unwrap();
    }
}
