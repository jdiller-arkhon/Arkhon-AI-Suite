//! Sealed "last seen" time for clock-rollback detection.
//!
//! The runtime calls [`SoftwareClockStore::check_and_record`] with the system time at every start
//! and periodically. If the clock is earlier than the last time seen minus a small tolerance, the
//! clock was turned back (e.g. to stretch an expired license) and the check fails.
//!
//! The software store is a file holding `last_seen` and an HMAC-SHA256 tag keyed from the caller's
//! storage secret, so it can't be edited without the secret. Limits, stated plainly:
//!
//! * **Deleting the file resets it.** A missing file reads as "first run". `arkhon-license` bounds
//!   the damage: a license is never accepted before its own issue time, and the runtime should
//!   treat a missing store after activation as suspicious and require an online check.
//! * **Restoring an older copy of the file** (with its valid tag) rolls it back. A TPM NV counter
//!   (`TPM2_NV_Increment`, monotonic by hardware) closes this; planned for the `tpm` backend.

use std::fmt;
use std::path::{Path, PathBuf};

use hmac::Mac;
use zeroize::Zeroizing;

use crate::{fsutil, keys};

const MAGIC: &[u8; 8] = b"ARKCLK01";
const FILE_LEN: usize = 8 + 8 + 32;
const MAC_INFO: &[u8] = b"arkhon/v1/clock-store-mac";

/// Default tolerance for small backwards clock adjustments (NTP, DST bugs): 5 minutes.
pub const DEFAULT_TOLERANCE_SECS: u64 = 300;

/// Why the clock check failed.
#[derive(Debug)]
pub enum ClockError {
    /// The clock is earlier than a time already seen on this computer.
    RolledBack {
        /// Latest time seen before (Unix seconds).
        last_seen: u64,
        /// The time given now (Unix seconds).
        now: u64,
    },
    /// The stored time was changed or belongs to another installation.
    Tampered,
    /// Reading or writing failed.
    Io(std::io::Error),
}

impl fmt::Display for ClockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClockError::RolledBack { .. } => f.write_str(
                "This computer's clock is set earlier than before. Set the correct date and time, then try again.",
            ),
            ClockError::Tampered => f.write_str(
                "Arkhon's saved time check was changed. Connect to the internet so Arkhon can check your license.",
            ),
            ClockError::Io(e) => write!(f, "Couldn't read or save Arkhon's time check: {e}"),
        }
    }
}

impl std::error::Error for ClockError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ClockError::Io(e) => Some(e),
            _ => None,
        }
    }
}

/// Software implementation of the sealed monotonic time store.
pub struct SoftwareClockStore {
    path: PathBuf,
    mac_key: Zeroizing<[u8; 32]>,
    tolerance_secs: u64,
}

impl fmt::Debug for SoftwareClockStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SoftwareClockStore")
            .field("path", &self.path)
            .field("tolerance_secs", &self.tolerance_secs)
            .finish_non_exhaustive()
    }
}

impl SoftwareClockStore {
    /// A store at `path`, keyed from `storage_secret`, with [`DEFAULT_TOLERANCE_SECS`].
    #[must_use]
    pub fn new(path: impl Into<PathBuf>, storage_secret: &[u8]) -> Self {
        let mac_key = keys::hkdf32(MAGIC, storage_secret, MAC_INFO);
        Self {
            path: path.into(),
            mac_key,
            tolerance_secs: DEFAULT_TOLERANCE_SECS,
        }
    }

    /// Change the backwards tolerance.
    #[must_use]
    pub fn with_tolerance(mut self, secs: u64) -> Self {
        self.tolerance_secs = secs;
        self
    }

    /// Where the store lives.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn tag(&self, last_seen: u64) -> [u8; 32] {
        let mut mac = keys::hmac(self.mac_key.as_ref());
        mac.update(MAGIC);
        mac.update(&last_seen.to_be_bytes());
        mac.finalize().into_bytes().into()
    }

    /// The last time recorded, or `None` if nothing has been recorded yet.
    ///
    /// # Errors
    /// [`ClockError::Tampered`] or [`ClockError::Io`].
    pub fn last_seen(&self) -> Result<Option<u64>, ClockError> {
        let data = match std::fs::read(&self.path) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(ClockError::Io(e)),
        };
        if data.len() != FILE_LEN || &data[..8] != MAGIC {
            return Err(ClockError::Tampered);
        }
        let mut raw = [0u8; 8];
        raw.copy_from_slice(&data[8..16]);
        let last_seen = u64::from_be_bytes(raw);
        let mut mac = keys::hmac(self.mac_key.as_ref());
        mac.update(MAGIC);
        mac.update(&raw);
        mac.verify_slice(&data[16..])
            .map_err(|_| ClockError::Tampered)?;
        Ok(Some(last_seen))
    }

    /// Check `now` (Unix seconds) against the last time seen and record `max(last_seen, now)`.
    /// Returns the time now recorded.
    ///
    /// # Errors
    /// [`ClockError::RolledBack`] if `now < last_seen - tolerance`, or as [`Self::last_seen`].
    pub fn check_and_record(&self, now: u64) -> Result<u64, ClockError> {
        let last = self.last_seen()?;
        if let Some(last_seen) = last {
            if now.saturating_add(self.tolerance_secs) < last_seen {
                return Err(ClockError::RolledBack { last_seen, now });
            }
            if now <= last_seen {
                return Ok(last_seen);
            }
        }
        let file = [&MAGIC[..], &now.to_be_bytes(), &self.tag(now)].concat();
        fsutil::replace_private(&self.path, &file).map_err(ClockError::Io)?;
        Ok(now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsutil::test_dir::TestDir;

    #[test]
    fn records_and_detects_rollback() {
        let dir = TestDir::new("clk");
        let store = SoftwareClockStore::new(dir.path().join("clock"), b"secret");
        assert!(store.path().ends_with("clock"));
        assert_eq!(store.last_seen().unwrap(), None);
        assert_eq!(store.check_and_record(10_000).unwrap(), 10_000);
        assert_eq!(store.check_and_record(20_000).unwrap(), 20_000);
        // Small backwards step within tolerance: accepted, last_seen kept.
        assert_eq!(store.check_and_record(19_800).unwrap(), 20_000);
        let err = store.check_and_record(19_000).unwrap_err();
        assert!(matches!(
            err,
            ClockError::RolledBack {
                last_seen: 20_000,
                now: 19_000
            }
        ));
        assert_eq!(store.last_seen().unwrap(), Some(20_000));
    }

    #[test]
    fn custom_tolerance() {
        let dir = TestDir::new("clk2");
        let store = SoftwareClockStore::new(dir.path().join("c"), b"s").with_tolerance(0);
        store.check_and_record(100).unwrap();
        assert!(store.check_and_record(99).is_err());
        assert!(format!("{store:?}").contains("tolerance_secs: 0"));
    }

    #[test]
    fn tamper_and_wrong_secret_detected() {
        let dir = TestDir::new("clk3");
        let path = dir.path().join("c");
        let store = SoftwareClockStore::new(&path, b"s");
        store.check_and_record(5_000_000).unwrap();
        let other = SoftwareClockStore::new(&path, b"other");
        assert!(matches!(other.last_seen(), Err(ClockError::Tampered)));
        let mut data = std::fs::read(&path).unwrap();
        data[15] ^= 1;
        std::fs::write(&path, &data).unwrap();
        assert!(matches!(
            store.check_and_record(1),
            Err(ClockError::Tampered)
        ));
        std::fs::write(&path, b"short").unwrap();
        assert!(matches!(store.last_seen(), Err(ClockError::Tampered)));
    }

    #[test]
    fn io_errors_and_messages() {
        use std::error::Error;
        let dir = TestDir::new("clk4");
        let store = SoftwareClockStore::new(dir.path(), b"s");
        assert!(matches!(store.last_seen(), Err(ClockError::Io(_))));
        let missing = SoftwareClockStore::new(dir.path().join("x").join("y"), b"s");
        assert!(matches!(
            missing.check_and_record(1),
            Err(ClockError::Io(_))
        ));
        let errs = [
            ClockError::RolledBack {
                last_seen: 2,
                now: 1,
            },
            ClockError::Tampered,
            ClockError::Io(std::io::Error::other("x")),
        ];
        for e in &errs {
            assert_ne!(e.to_string(), "");
        }
        assert!(errs[2].source().is_some());
        assert!(errs[0].source().is_none());
    }
}
