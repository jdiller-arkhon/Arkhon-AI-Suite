//! Offline key tooling for the Arkhon key hierarchy (brief §6).
//!
//! * `root` — generate the **root** Ed25519 key. Run this on an offline machine. The private key
//!   file is written with owner-only permissions and never overwritten.
//! * `issuing` — generate an **issuing** key and a certificate for it, signed by the root key.
//! * `revoke` — sign a revocation list of issuing-certificate serials with the root key.
//!
//! Key files hold the 32-byte Ed25519 seed as one line of hex. Nothing here talks to a network.
//! Private keys must never be committed: `.gitignore` and gitleaks both guard against it.

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use arkhon_license::{IssuingCertificate, RevocationList};
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use zeroize::Zeroizing;

/// Tool error with a plain sentence.
#[derive(Debug)]
pub struct KeygenError(pub String);

impl std::fmt::Display for KeygenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for KeygenError {}

fn err(msg: impl Into<String>) -> KeygenError {
    KeygenError(msg.into())
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// Write a private key file: create-new (never overwrite), owner read/write only.
fn write_secret(path: &Path, key: &SigningKey) -> Result<(), KeygenError> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            err(format!(
                "{} already exists. Refusing to overwrite a key.",
                path.display()
            ))
        } else {
            err(format!("Couldn't create {}: {e}", path.display()))
        }
    })?;
    let line = Zeroizing::new(format!("{}\n", hex(&key.to_bytes())));
    f.write_all(line.as_bytes())
        .and_then(|()| f.sync_all())
        .map_err(|e| err(format!("Couldn't write {}: {e}", path.display())))
}

/// Read a private key file written by this tool.
///
/// # Errors
/// Unreadable or malformed file.
pub fn read_secret(path: &Path) -> Result<SigningKey, KeygenError> {
    let text = Zeroizing::new(
        fs::read_to_string(path)
            .map_err(|e| err(format!("Couldn't read {}: {e}", path.display())))?,
    );
    let bytes = Zeroizing::new(
        unhex(&text).ok_or_else(|| err(format!("{} isn't a key file.", path.display())))?,
    );
    let seed: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| err(format!("{} isn't a key file.", path.display())))?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Generate the root key. Returns the public key as hex.
///
/// # Errors
/// The file exists or can't be written.
pub fn generate_root(out: &Path) -> Result<String, KeygenError> {
    let key = SigningKey::generate(&mut OsRng);
    write_secret(out, &key)?;
    Ok(hex(key.verifying_key().as_bytes()))
}

/// Generate an issuing key and its root-signed certificate. Returns the certificate bytes
/// (also written to `cert_out`) and the issuing public key as hex.
///
/// # Errors
/// Key files, validity window or output errors.
pub fn generate_issuing(
    root_key: &Path,
    out: &Path,
    cert_out: &Path,
    serial: u64,
    not_before: u64,
    not_after: u64,
) -> Result<(Vec<u8>, String), KeygenError> {
    let root = read_secret(root_key)?;
    if cert_out.exists() {
        return Err(err(format!(
            "{} already exists. Refusing to overwrite.",
            cert_out.display()
        )));
    }
    let issuing = SigningKey::generate(&mut OsRng);
    let cert = IssuingCertificate::issue(
        &root,
        serial,
        &issuing.verifying_key(),
        not_before,
        not_after,
    )
    .map_err(|e| err(e.to_string()))?;
    write_secret(out, &issuing)?;
    let bytes = cert.to_bytes();
    fs::write(cert_out, &bytes)
        .map_err(|e| err(format!("Couldn't write {}: {e}", cert_out.display())))?;
    Ok((bytes, hex(issuing.verifying_key().as_bytes())))
}

/// Sign a revocation list. Returns the encoded list (also written to `out`).
///
/// # Errors
/// Key file or output errors.
pub fn sign_revocations(
    root_key: &Path,
    version: u64,
    issued_at: u64,
    serials: BTreeSet<u64>,
    out: &Path,
) -> Result<Vec<u8>, KeygenError> {
    let root = read_secret(root_key)?;
    let bytes = RevocationList::sign(&root, version, issued_at, serials).to_bytes();
    fs::write(out, &bytes).map_err(|e| err(format!("Couldn't write {}: {e}", out.display())))?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::VerifyingKey;

    fn dir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("arkhon-keygen-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn root_pub(hex_str: &str) -> VerifyingKey {
        let b: [u8; 32] = unhex(hex_str).unwrap().try_into().unwrap();
        VerifyingKey::from_bytes(&b).unwrap()
    }

    #[test]
    fn root_then_issuing_chain_verifies() {
        let d = dir("chain");
        let pub_hex = generate_root(&d.join("root.key")).unwrap();
        let (cert, issuing_hex) = generate_issuing(
            &d.join("root.key"),
            &d.join("issuing.key"),
            &d.join("issuing.cert"),
            7,
            1_700_000_000,
            1_800_000_000,
        )
        .unwrap();
        let parsed = IssuingCertificate::from_bytes(&cert).unwrap();
        let issuing = parsed.verify(&root_pub(&pub_hex)).unwrap();
        assert_eq!(hex(issuing.as_bytes()), issuing_hex);
        assert_eq!(parsed.serial, 7);
        assert_eq!(
            read_secret(&d.join("issuing.key")).unwrap().verifying_key(),
            issuing
        );
        fs::remove_dir_all(d).ok();
    }

    #[test]
    fn refuses_to_overwrite_keys() {
        let d = dir("overwrite");
        generate_root(&d.join("root.key")).unwrap();
        let before = fs::read(d.join("root.key")).unwrap();
        let e = generate_root(&d.join("root.key")).unwrap_err();
        assert!(e.to_string().contains("Refusing to overwrite"));
        assert_eq!(fs::read(d.join("root.key")).unwrap(), before);
        fs::remove_dir_all(d).ok();
    }

    #[cfg(unix)]
    #[test]
    fn key_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let d = dir("perms");
        generate_root(&d.join("root.key")).unwrap();
        let mode = fs::metadata(d.join("root.key"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        fs::remove_dir_all(d).ok();
    }

    #[test]
    fn revocation_list_verifies_and_lists_serials() {
        let d = dir("revoke");
        let pub_hex = generate_root(&d.join("root.key")).unwrap();
        let bytes = sign_revocations(
            &d.join("root.key"),
            3,
            1_750_000_000,
            [7, 9].into(),
            &d.join("rl.bin"),
        )
        .unwrap();
        let list = RevocationList::from_bytes(&bytes).unwrap();
        list.verify(&root_pub(&pub_hex)).unwrap();
        assert!(list.is_revoked(7) && list.is_revoked(9) && !list.is_revoked(8));
        fs::remove_dir_all(d).ok();
    }

    #[test]
    fn bad_inputs_explain_themselves() {
        let d = dir("bad");
        fs::write(d.join("junk.key"), "not hex").unwrap();
        assert!(read_secret(&d.join("junk.key"))
            .unwrap_err()
            .to_string()
            .contains("isn't a key file"));
        generate_root(&d.join("root.key")).unwrap();
        let e = generate_issuing(
            &d.join("root.key"),
            &d.join("i.key"),
            &d.join("i.cert"),
            1,
            10,
            5,
        )
        .unwrap_err();
        assert_ne!(e.to_string(), "");
        assert!(
            !d.join("i.key").exists(),
            "no issuing key left behind on failure"
        );
        fs::remove_dir_all(d).ok();
    }
}
