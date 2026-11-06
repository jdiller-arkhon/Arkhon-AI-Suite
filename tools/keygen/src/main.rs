//! `arkhon-keygen` — offline key tooling.
//!
//! ```text
//! arkhon-keygen root    --out root.key
//! arkhon-keygen issuing --root root.key --out issuing.key --cert issuing.cert --serial 1 --days 365
//! arkhon-keygen revoke  --root root.key --version 2 --serials 1,4 --out revocations.bin
//! ```

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use arkhon_keygen::{generate_issuing, generate_root, sign_revocations};

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn run(args: &[String]) -> Result<(), String> {
    let need = |n: &str| flag(args, n).ok_or_else(|| format!("Missing {n}. Run with --help."));
    match args.first().map(String::as_str) {
        Some("root") => {
            eprintln!("Generating the ROOT key. Do this on an offline machine and store the file offline.");
            let pk = generate_root(&PathBuf::from(need("--out")?)).map_err(|e| e.to_string())?;
            println!("root public key: {pk}");
            Ok(())
        }
        Some("issuing") => {
            let days: u64 = need("--days")?
                .parse()
                .map_err(|_| "--days must be a number")?;
            let serial: u64 = need("--serial")?
                .parse()
                .map_err(|_| "--serial must be a number")?;
            let start = now();
            let (_, pk) = generate_issuing(
                &PathBuf::from(need("--root")?),
                &PathBuf::from(need("--out")?),
                &PathBuf::from(need("--cert")?),
                serial,
                start,
                start + days * 86_400,
            )
            .map_err(|e| e.to_string())?;
            println!("issuing public key: {pk} (serial {serial}, valid {days} days)");
            Ok(())
        }
        Some("revoke") => {
            let version: u64 = need("--version")?
                .parse()
                .map_err(|_| "--version must be a number")?;
            let serials: BTreeSet<u64> = need("--serials")?
                .split(',')
                .filter(|s| !s.trim().is_empty())
                .map(|s| {
                    s.trim()
                        .parse()
                        .map_err(|_| format!("{s} isn't a serial number"))
                })
                .collect::<Result<_, _>>()?;
            sign_revocations(
                &PathBuf::from(need("--root")?),
                version,
                now(),
                serials.clone(),
                &PathBuf::from(need("--out")?),
            )
            .map_err(|e| e.to_string())?;
            println!("revocation list v{version} signed: {serials:?}");
            Ok(())
        }
        _ => {
            Err("usage: arkhon-keygen root|issuing|revoke ... (see tools/keygen/README.md)".into())
        }
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
