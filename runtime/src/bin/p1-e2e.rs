//! Phase 1 end-to-end: encrypted model → TPM-bound license → TPM unwrap → sealed memfd → llama-server.
//!
//! ```text
//! # customer machine: print the device public key + fingerprint (what activation sends)
//! p1-e2e device --tcti swtpm:host=127.0.0.1,port=2321 --out device.bin
//! # Arkhon side (test keys only): encrypt the model and issue a license bound to that device
//! p1-e2e vendor --model model.gguf --device device.bin --dir release/
//! # customer machine: verify, unwrap via TPM, decrypt into memory, serve one completion
//! p1-e2e run --dir release/ --tcti ... --server llama-server
//! ```
//! Requires `--features tpm`. Test keys are generated per run and never written outside `--dir`.

#[cfg(all(target_os = "linux", feature = "tpm"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    imp::main()
}

#[cfg(not(all(target_os = "linux", feature = "tpm")))]
fn main() {
    eprintln!("p1-e2e needs Linux and `--features tpm`.");
}

#[cfg(all(target_os = "linux", feature = "tpm"))]
mod imp {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    use std::io::{Read, Write};
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use arkhon_crypto::ed25519_dalek::{SigningKey, VerifyingKey};
    use arkhon_crypto::model::{decrypt_model, encrypt_model, DEFAULT_CHUNK_SIZE};
    use arkhon_crypto::Cek;
    use arkhon_license::{
        verify, wrap_cek, IssuingCertificate, License, LicenseBody, RevocationList,
    };
    use arkhon_runtime::memload::{harden_process, SealedModel};
    use arkhon_tpm::tpm::TpmDeviceKey;
    use arkhon_tpm::{
        parse_sec1, BindingKind, DeviceKey, FingerprintSalt, HardwareFingerprint, FINGERPRINT_LEN,
        SEC1_UNCOMPRESSED_LEN,
    };
    use rand_core::OsRng;

    type R<T> = Result<T, Box<dyn std::error::Error>>;
    const ENGINE: &str = "lite";
    const SALT: FingerprintSalt = FingerprintSalt(*b"arkhon-phase1-demo-salt-00000000");

    fn arg(args: &[String], name: &str) -> R<String> {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1).cloned())
            .ok_or_else(|| format!("missing {name}").into())
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }

    fn step(name: &str, start: Instant, extra: &str) {
        println!(
            "{{\"step\":\"{name}\",\"ms\":{}{extra}}}",
            start.elapsed().as_millis()
        );
    }

    pub fn main() -> R<()> {
        let args: Vec<String> = std::env::args().skip(1).collect();
        match args.first().map(String::as_str) {
            Some("device") => device(&args),
            Some("vendor") => vendor(&args),
            Some("run") => run(&args),
            _ => Err("usage: p1-e2e device|vendor|run ...".into()),
        }
    }

    fn device(args: &[String]) -> R<()> {
        let tpm = TpmDeviceKey::open(&arg(args, "--tcti")?)?;
        let fp = HardwareFingerprint::collect(&SALT);
        let mut out = tpm.public_key_sec1().to_vec();
        out.extend_from_slice(&fp.to_bytes());
        fs::write(arg(args, "--out")?, out)?;
        println!("device key + fingerprint written (binding: TPM)");
        Ok(())
    }

    fn vendor(args: &[String]) -> R<()> {
        let dir = PathBuf::from(arg(args, "--dir")?);
        fs::create_dir_all(&dir)?;
        let dev = fs::read(arg(args, "--device")?)?;
        let (pk, fp) = dev.split_at(SEC1_UNCOMPRESSED_LEN);
        let device_public_key: [u8; SEC1_UNCOMPRESSED_LEN] = pk.try_into()?;
        let fp: [u8; FINGERPRINT_LEN] = fp.try_into()?;
        let device_pub = parse_sec1(&device_public_key)?;

        let t = Instant::now();
        let cek = Cek::generate();
        let info = encrypt_model(
            &cek,
            fs::File::open(arg(args, "--model")?)?,
            std::io::BufWriter::new(fs::File::create(dir.join("model.arkm"))?),
            DEFAULT_CHUNK_SIZE,
        )?;
        step(
            "encrypted",
            t,
            &format!(",\"plaintext_bytes\":{}", info.plaintext_len),
        );

        // Throwaway test hierarchy for the demo; production keys come from tools/keygen.
        let root = SigningKey::generate(&mut OsRng);
        let issuing = SigningKey::generate(&mut OsRng);
        let n = now();
        let cert =
            IssuingCertificate::issue(&root, 1, &issuing.verifying_key(), n - 60, n + 86_400)?;
        let revocations = RevocationList::sign(&root, 1, n, BTreeSet::new());
        let license_id = "lic-phase1-demo";
        let body = LicenseBody {
            license_id: license_id.into(),
            customer_id: "cust-coastline".into(),
            workspaces: ["inbox".to_owned()].into(),
            engines: [ENGINE.to_owned()].into(),
            packs: BTreeSet::new(),
            update_window_end: n + 365 * 86_400,
            seats: 10,
            issued_at: n,
            expires_at: n + 90 * 86_400,
            offline_grace_days: 90,
            binding: BindingKind::Tpm,
            device_public_key,
            fingerprint: HardwareFingerprint::from_bytes(&fp),
            wrapped_ceks: BTreeMap::from([(
                ENGINE.to_owned(),
                wrap_cek(&mut OsRng, &cek, &device_pub, license_id, ENGINE),
            )]),
        };
        let license = License::sign(body, cert, &issuing)?;
        fs::write(dir.join("license.bin"), license.to_bytes())?;
        fs::write(dir.join("revocations.bin"), revocations.to_bytes())?;
        fs::write(dir.join("root.pub"), root.verifying_key().to_bytes())?;
        println!(
            "license issued: {} bytes, engine {ENGINE}, binding TPM",
            license.to_bytes().len()
        );
        Ok(())
    }

    fn run(args: &[String]) -> R<()> {
        let dir = PathBuf::from(arg(args, "--dir")?);
        harden_process()?;
        let total = Instant::now();

        let t = Instant::now();
        let root =
            VerifyingKey::from_bytes(&fs::read(dir.join("root.pub"))?.as_slice().try_into()?)?;
        let license = License::from_bytes(&fs::read(dir.join("license.bin"))?)?;
        let revocations = RevocationList::from_bytes(&fs::read(dir.join("revocations.bin"))?)?;
        let fp = HardwareFingerprint::collect(&SALT);
        let verified = verify(&license, &root, &revocations, now(), &fp)?;
        let tpm = TpmDeviceKey::open(&arg(args, "--tcti")?)?;
        let cek = verified.unwrap_cek(ENGINE, &tpm)?;
        step("license_verified_and_cek_unwrapped_via_tpm", t, "");

        let t = Instant::now();
        let model_path = dir.join("model.arkm");
        let sealed = SealedModel::create("arkhon-model", |mut w| {
            let mut input =
                std::io::BufReader::with_capacity(1 << 20, fs::File::open(&model_path)?);
            decrypt_model(&cek, &mut input, &mut w)
                .map(|_| ())
                .map_err(|e| std::io::Error::other(e.to_string()))
        })?;
        drop(cek);
        step(
            "decrypted_into_sealed_memfd",
            t,
            &format!(",\"bytes\":{}", sealed.len()),
        );

        serve(&sealed, &arg(args, "--server")?, total)
    }

    fn serve(sealed: &SealedModel, server: &str, total: Instant) -> R<()> {
        let path = sealed.share_with_child()?;
        let port = "8091";
        let t = Instant::now();
        let mut child = std::process::Command::new(server)
            .arg("-m")
            .arg(&path)
            .args([
                "--load-mode",
                "mmap+mlock",
                "--host",
                "127.0.0.1",
                "--port",
                port,
                "-c",
                "2048",
                "-t",
                "3",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(fs::File::create(
                std::env::temp_dir().join("arkhon-p1-e2e-llama.log"),
            )?)
            .spawn()?;
        let addr = format!("127.0.0.1:{port}");
        let http = |method: &str, p: &str, body: &str| -> std::io::Result<String> {
            let mut s = std::net::TcpStream::connect(&addr)?;
            s.set_read_timeout(Some(Duration::from_secs(120)))?;
            write!(s, "{method} {p} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())?;
            let mut out = String::new();
            s.read_to_string(&mut out)?;
            Ok(out)
        };
        let ready = loop {
            if t.elapsed() > Duration::from_secs(180) {
                break false;
            }
            if http("GET", "/health", "").is_ok_and(|r| r.starts_with("HTTP/1.1 200")) {
                break true;
            }
            std::thread::sleep(Duration::from_millis(200));
        };
        step("server_ready", t, &format!(",\"ok\":{ready}"));
        if ready {
            let maps = fs::read_to_string(format!("/proc/{}/maps", child.id())).unwrap_or_default();
            let memfd_mapped = maps.lines().any(|l| l.contains("/memfd:arkhon-model"));
            println!("{{\"step\":\"child_maps_model_from_memfd\",\"ok\":{memfd_mapped}}}");
            let t2 = Instant::now();
            let body = r#"{"messages":[{"role":"user","content":"Reply with one short sentence: what does an HVAC technician do? /no_think"}],"max_tokens":48,"temperature":0}"#;
            let resp = http("POST", "/v1/chat/completions", body)?;
            step(
                "completion",
                t2,
                &format!(",\"http_ok\":{}", resp.starts_with("HTTP/1.1 200")),
            );
            println!("{}", resp.split("\r\n\r\n").nth(1).unwrap_or(""));
        }
        step("total", total, "");
        child.kill().ok();
        child.wait().ok();
        let _ = Path::new(server);
        Ok(())
    }
}
