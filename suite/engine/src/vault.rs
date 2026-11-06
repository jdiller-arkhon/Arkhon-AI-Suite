//! Encrypted local token store (N1, ADR-0006).
//!
//! Sign-in secrets for connected accounts (OAuth refresh tokens, IMAP/SMTP passwords) live here
//! and **nowhere else**: never in [`crate::State`], views, the activity log or logs. The vault is
//! its own file, separate from the organization JSON, and every entry is sealed with
//! AES-256-GCM under a 32-byte vault key. The connection id is bound as associated data, so an
//! entry copied onto another connection fails to open.
//!
//! The vault key comes from a [`VaultKeyProvider`]. Production will provide it from the TPM or
//! the operating system's key store (Phase 5); [`DevFileKeyProvider`] is for development only.
//!
//! Secrets are held in [`Zeroizing`] buffers and wiped from memory when dropped.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit, OsRng, Payload};
use aes_gcm::{AeadCore, Aes256Gcm, Key, Nonce};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

/// A secret string: redacted in `Debug`, never serialized, wiped on drop.
///
/// It can be *deserialized* (credentials arrive in a command from the UI) but serializing it
/// always writes `null`, so a secret can't slip into saved state or a response by accident.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Secret(Zeroizing<String>);

impl Secret {
    /// Wrap a value.
    #[must_use]
    pub fn new(s: impl Into<String>) -> Self {
        Secret(Zeroizing::new(s.into()))
    }

    /// The secret itself. Use only to hand it to the remote service.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Whether it's empty or only spaces.
    #[must_use]
    pub fn is_blank(&self) -> bool {
        self.0.trim().is_empty()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([redacted])")
    }
}

impl Serialize for Secret {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_none()
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d).map(Secret::new)
    }
}

/// Sign-in details for one connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Credential {
    /// OAuth refresh token (Microsoft 365, Google, `QuickBooks`...).
    OAuthRefreshToken {
        /// The token.
        token: Secret,
    },
    /// Mailbox password for IMAP/SMTP ("Other email").
    Mail(MailLogin),
}

/// IMAP + SMTP sign-in for a mailbox.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct MailLogin {
    /// IMAP server, e.g. `imap.example.com`.
    pub imap_host: String,
    /// IMAP port (TLS). Defaults to 993.
    #[serde(default = "default_imap_port")]
    pub imap_port: u16,
    /// SMTP server, e.g. `smtp.example.com`.
    pub smtp_host: String,
    /// SMTP port (STARTTLS). Defaults to 587.
    #[serde(default = "default_smtp_port")]
    pub smtp_port: u16,
    /// Sign-in name, usually the email address.
    pub username: String,
    /// Password or app password.
    pub password: Secret,
}

fn default_imap_port() -> u16 {
    993
}
fn default_smtp_port() -> u16 {
    587
}

// Plaintext shape inside a sealed entry. Only ever lives in a `Zeroizing` buffer.
#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
enum Sealed {
    OAuth {
        token: String,
    },
    Mail {
        imap_host: String,
        imap_port: u16,
        smtp_host: String,
        smtp_port: u16,
        username: String,
        password: String,
    },
}

impl Drop for Sealed {
    fn drop(&mut self) {
        match self {
            Sealed::OAuth { token } => token.zeroize(),
            Sealed::Mail { password, .. } => password.zeroize(),
        }
    }
}

/// Why the vault couldn't do something.
#[derive(Debug)]
pub enum VaultError {
    /// The vault key isn't available.
    Key(String),
    /// Reading or writing the vault file failed.
    Io(std::io::Error),
    /// The vault file or an entry is damaged, or was sealed with another key.
    Corrupt,
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VaultError::Key(why) => write!(f, "The sign-in vault is locked ({why})."),
            VaultError::Io(e) => write!(f, "Couldn't read or save sign-ins ({e})."),
            VaultError::Corrupt => f.write_str(
                "Saved sign-ins couldn't be opened. Reconnect the account to sign in again.",
            ),
        }
    }
}

impl std::error::Error for VaultError {}

impl From<std::io::Error> for VaultError {
    fn from(e: std::io::Error) -> Self {
        VaultError::Io(e)
    }
}

/// Supplies the 32-byte vault key.
///
/// Implementations: the TPM-sealed key and the OS keystore (Phase 5), and
/// [`DevFileKeyProvider`] for development.
pub trait VaultKeyProvider: Send + Sync {
    /// The key. Called for each vault operation; don't cache it in plain memory.
    ///
    /// # Errors
    /// [`VaultError::Key`] when the key can't be obtained.
    fn vault_key(&self) -> Result<Zeroizing<[u8; 32]>, VaultError>;
}

/// **Development only.** Keeps the vault key in a plain file next to the data.
///
/// Anyone who can read that file can open the vault, so this gives no protection against
/// someone with access to the disk. It exists so the dev server and tests can run without a TPM
/// or OS key store. Shipping builds must use a hardware- or OS-backed provider (ADR-0006).
#[derive(Debug, Clone)]
pub struct DevFileKeyProvider {
    path: PathBuf,
}

impl DevFileKeyProvider {
    /// Use (and create on first use) the key file at `path`.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        DevFileKeyProvider { path: path.into() }
    }
}

impl VaultKeyProvider for DevFileKeyProvider {
    fn vault_key(&self) -> Result<Zeroizing<[u8; 32]>, VaultError> {
        match fs::read(&self.path) {
            Ok(bytes) => {
                let bytes = Zeroizing::new(bytes);
                let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                    VaultError::Key("the development key file has the wrong size".into())
                })?;
                Ok(Zeroizing::new(arr))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let key = Aes256Gcm::generate_key(OsRng);
                let mut arr = Zeroizing::new([0u8; 32]);
                arr.copy_from_slice(&key);
                write_private(&self.path, arr.as_slice())?;
                Ok(arr)
            }
            Err(e) => Err(VaultError::Key(e.to_string())),
        }
    }
}

/// A fixed key, for tests.
#[derive(Clone)]
pub struct StaticKeyProvider(pub [u8; 32]);

impl fmt::Debug for StaticKeyProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StaticKeyProvider([redacted])")
    }
}

impl VaultKeyProvider for StaticKeyProvider {
    fn vault_key(&self) -> Result<Zeroizing<[u8; 32]>, VaultError> {
        Ok(Zeroizing::new(self.0))
    }
}

#[derive(Serialize, Deserialize, Default)]
struct VaultFile {
    version: u32,
    /// Connection id -> sealed entry.
    entries: BTreeMap<u64, Entry>,
}

#[derive(Serialize, Deserialize, Clone)]
struct Entry {
    /// 12-byte nonce, hex.
    nonce: String,
    /// Ciphertext + tag, hex.
    sealed: String,
}

/// Encrypted per-connection sign-in store.
pub struct TokenVault {
    path: PathBuf,
    keys: Box<dyn VaultKeyProvider>,
}

impl fmt::Debug for TokenVault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenVault")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl TokenVault {
    /// Vault stored at `path` (created on first write).
    #[must_use]
    pub fn new(path: impl Into<PathBuf>, keys: Box<dyn VaultKeyProvider>) -> Self {
        TokenVault {
            path: path.into(),
            keys,
        }
    }

    /// Where the sealed file lives.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn read(&self) -> Result<VaultFile, VaultError> {
        match fs::read(&self.path) {
            Ok(b) => serde_json::from_slice(&b).map_err(|_| VaultError::Corrupt),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(VaultFile {
                version: 1,
                ..VaultFile::default()
            }),
            Err(e) => Err(e.into()),
        }
    }

    fn write(&self, file: &VaultFile) -> Result<(), VaultError> {
        let bytes = serde_json::to_vec(file).map_err(|_| VaultError::Corrupt)?;
        write_private(&self.path, &bytes)
    }

    fn cipher(&self) -> Result<Aes256Gcm, VaultError> {
        let key = self.keys.vault_key()?;
        Ok(Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_slice())))
    }

    /// Seal and store `credential` for connection `id`, replacing any earlier one.
    ///
    /// # Errors
    /// Key or disk errors.
    pub fn put(&self, id: u64, credential: &Credential) -> Result<(), VaultError> {
        let sealed = match credential {
            Credential::OAuthRefreshToken { token } => Sealed::OAuth {
                token: token.expose().to_owned(),
            },
            Credential::Mail(m) => Sealed::Mail {
                imap_host: m.imap_host.clone(),
                imap_port: m.imap_port,
                smtp_host: m.smtp_host.clone(),
                smtp_port: m.smtp_port,
                username: m.username.clone(),
                password: m.password.expose().to_owned(),
            },
        };
        let plain = Zeroizing::new(serde_json::to_vec(&sealed).map_err(|_| VaultError::Corrupt)?);
        drop(sealed);
        let cipher = self.cipher()?;
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let aad = id.to_be_bytes();
        let ct = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: &plain,
                    aad: &aad,
                },
            )
            .map_err(|_| VaultError::Corrupt)?;
        let mut file = self.read()?;
        file.entries.insert(
            id,
            Entry {
                nonce: hex(&nonce),
                sealed: hex(&ct),
            },
        );
        self.write(&file)
    }

    /// Open the sign-in for connection `id`, if there is one.
    ///
    /// # Errors
    /// Key, disk or tamper errors.
    pub fn get(&self, id: u64) -> Result<Option<Credential>, VaultError> {
        let file = self.read()?;
        let Some(e) = file.entries.get(&id) else {
            return Ok(None);
        };
        let nonce = unhex(&e.nonce).ok_or(VaultError::Corrupt)?;
        if nonce.len() != 12 {
            return Err(VaultError::Corrupt);
        }
        let ct = unhex(&e.sealed).ok_or(VaultError::Corrupt)?;
        let aad = id.to_be_bytes();
        let plain = Zeroizing::new(
            self.cipher()?
                .decrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: &ct,
                        aad: &aad,
                    },
                )
                .map_err(|_| VaultError::Corrupt)?,
        );
        let sealed: Sealed = serde_json::from_slice(&plain).map_err(|_| VaultError::Corrupt)?;
        Ok(Some(match &sealed {
            Sealed::OAuth { token } => Credential::OAuthRefreshToken {
                token: Secret::new(token.as_str()),
            },
            Sealed::Mail {
                imap_host,
                imap_port,
                smtp_host,
                smtp_port,
                username,
                password,
            } => Credential::Mail(MailLogin {
                imap_host: imap_host.clone(),
                imap_port: *imap_port,
                smtp_host: smtp_host.clone(),
                smtp_port: *smtp_port,
                username: username.clone(),
                password: Secret::new(password.as_str()),
            }),
        }))
    }

    /// Forget the sign-in for connection `id`. Missing entries are fine.
    ///
    /// # Errors
    /// Disk errors.
    pub fn remove(&self, id: u64) -> Result<(), VaultError> {
        let mut file = self.read()?;
        if file.entries.remove(&id).is_some() {
            self.write(&file)?;
        }
        Ok(())
    }

    /// Whether connection `id` has a stored sign-in.
    ///
    /// # Errors
    /// Disk errors.
    pub fn contains(&self, id: u64) -> Result<bool, VaultError> {
        Ok(self.read()?.entries.contains_key(&id))
    }
}

/// Atomic write, readable only by the current user on Unix.
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), VaultError> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    b.iter()
        .fold(String::with_capacity(b.len() * 2), |mut s, x| {
            let _ = write!(s, "{x:02x}");
            s
        })
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}
