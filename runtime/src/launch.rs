//! Linux: decrypt an engine into a sealed memfd and launch its server process from it
//! (ADR-0009). Windows and macOS loaders are open (in-process loading; see the gate doc).

use std::io;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use arkhon_crypto::model::decrypt_model;

use crate::licensing::{LicenseManager, RuntimeError};
use crate::memload::SealedModel;

/// Where an engine's encrypted model lives: `<models_dir>/<engine>/model.arkm`.
#[must_use]
pub fn model_path(models_dir: &Path, engine: &str) -> PathBuf {
    models_dir.join(engine).join("model.arkm")
}

/// Why an engine couldn't be loaded.
#[derive(Debug)]
pub enum LoadError {
    /// The license refused (locked, not entitled, wrong device, …).
    License(RuntimeError),
    /// Reading, decrypting or sealing failed.
    Io(io::Error),
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::License(e) => e.fmt(f),
            LoadError::Io(e) => write!(f, "Couldn't load the AI engine: {e}"),
        }
    }
}

impl std::error::Error for LoadError {}

/// Unlock the engine's key through the license and decrypt its model into a sealed memfd.
/// The plaintext never touches a named file.
///
/// # Errors
/// [`LoadError`].
pub fn load_engine(
    manager: &LicenseManager,
    models_dir: &Path,
    engine: &str,
) -> Result<SealedModel, LoadError> {
    let cek = manager.unlock_engine(engine).map_err(LoadError::License)?;
    let path = model_path(models_dir, engine);
    SealedModel::create(&format!("arkhon-{engine}"), |mut w| {
        let file = std::fs::File::open(&path)?;
        let mut input = io::BufReader::with_capacity(1 << 20, file);
        decrypt_model(&cek, &mut input, &mut w)
            .map(|_| ())
            .map_err(|e| io::Error::other(e.to_string()))
    })
    .map_err(LoadError::Io)
}

/// Command-line arguments for an engine server reading the model from `model_path`.
#[must_use]
pub fn server_args(runtime: &str, engine: &str, model_path: &Path, port: u16) -> Vec<String> {
    let mut args = vec![
        "-m".to_owned(),
        model_path.to_string_lossy().into_owned(),
        "--host".to_owned(),
        "127.0.0.1".to_owned(),
        "--port".to_owned(),
        port.to_string(),
    ];
    if runtime == "llama.cpp" {
        // Pinned llama.cpp (ADR-0009): mapped pages locked in RAM, never swapped.
        args.extend(["--load-mode".to_owned(), "mmap+mlock".to_owned()]);
        match engine {
            "embed" => args.push("--embedding".to_owned()),
            "rerank" => args.push("--reranking".to_owned()),
            _ => {}
        }
    }
    args
}

/// Spawn the engine server with the sealed memfd inherited, and wait until `/health` answers.
///
/// # Errors
/// Spawn failures, or the server not becoming ready within `ready_timeout` (it is killed).
pub fn spawn_server(
    binary: &Path,
    runtime: &str,
    engine: &str,
    model: &SealedModel,
    port: u16,
    ready_timeout: Duration,
) -> io::Result<Child> {
    let path = model.share_with_child()?;
    let mut child = Command::new(binary)
        .args(server_args(runtime, engine, &path, port))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(2)))
        .build()
        .into();
    let start = Instant::now();
    loop {
        if agent
            .get(format!("http://127.0.0.1:{port}/health"))
            .call()
            .is_ok()
        {
            return Ok(child);
        }
        if let Some(status) = child.try_wait()? {
            return Err(io::Error::other(format!("engine server exited: {status}")));
        }
        if start.elapsed() > ready_timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::other("engine server didn't become ready"));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsutil::test_dir::TestDir;
    use crate::testkit::{fingerprint, FakeServer};
    use arkhon_crypto::model::encrypt_model;
    use arkhon_tpm::SoftwareDeviceKey;

    #[test]
    fn args() {
        let a = server_args("llama.cpp", "embed", Path::new("/proc/self/fd/7"), 8100);
        assert_eq!(a[..2], ["-m", "/proc/self/fd/7"]);
        assert!(a.contains(&"mmap+mlock".to_owned()) && a.contains(&"--embedding".to_owned()));
        assert!(server_args("llama.cpp", "rerank", Path::new("x"), 1)
            .contains(&"--reranking".to_owned()));
        let w = server_args("whisper.cpp", "scribe", Path::new("x"), 1);
        assert!(!w.contains(&"--load-mode".to_owned()));
    }

    #[test]
    fn license_gated_decrypt_into_memfd() {
        let server = FakeServer::new(&["core"]);
        let dir = TestDir::new("launch");
        let m = LicenseManager::new(
            dir.path(),
            server.authority.borrow().root_public(),
            Box::new(SoftwareDeviceKey::generate()),
            fingerprint("m"),
        )
        .with_clock(|| crate::testkit::T0);
        m.activate(&server, "GOOD-KEY", None).unwrap();
        let models = dir.path().join("models");
        std::fs::create_dir_all(models.join("core")).unwrap();
        std::fs::create_dir_all(models.join("pro")).unwrap();
        let plain = b"GGUF fake weights for the test".repeat(1000);
        let cek = server.authority.borrow_mut().cek("core");
        let mut enc = Vec::new();
        encrypt_model(&cek, &plain[..], &mut enc, 4096).unwrap();
        std::fs::write(model_path(&models, "core"), &enc).unwrap();
        let sealed = load_engine(&m, &models, "core").unwrap();
        assert_eq!(sealed.read_all().unwrap(), plain);
        assert!(sealed.is_write_sealed());
        // Not entitled: refused before any file is read.
        std::fs::write(model_path(&models, "pro"), &enc).unwrap();
        assert!(matches!(
            load_engine(&m, &models, "pro"),
            Err(LoadError::License(_))
        ));
        // Corrupted ciphertext: refused.
        let mut bad = enc.clone();
        let n = bad.len() - 1;
        bad[n] ^= 1;
        std::fs::write(model_path(&models, "core"), &bad).unwrap();
        let e = load_engine(&m, &models, "core").unwrap_err();
        assert!(matches!(e, LoadError::Io(_)) && !e.to_string().is_empty());
    }

    #[test]
    fn spawn_failure_reported() {
        let m = SealedModel::create("arkhon-test", |w| std::io::Write::write_all(w, b"x")).unwrap();
        assert!(spawn_server(
            Path::new("/nonexistent/llama-server"),
            "llama.cpp",
            "core",
            &m,
            1,
            Duration::from_secs(1)
        )
        .is_err());
        // A binary that exits at once.
        let e = spawn_server(
            Path::new("true"),
            "llama.cpp",
            "core",
            &m,
            9,
            Duration::from_secs(5),
        )
        .unwrap_err();
        assert!(
            e.to_string().contains("exited") || e.to_string().contains("ready"),
            "{e}"
        );
    }
}
