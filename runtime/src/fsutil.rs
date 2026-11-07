//! Private, atomic file writes (owner-only permissions on Unix; on Windows the file inherits the
//! per-user ACL of the data directory, which the installer creates under the user's profile).

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use rand_core::{OsRng, RngCore};

fn temp_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".tmp-{:016x}", OsRng.next_u64()));
    path.with_file_name(name)
}

fn create_private(path: &Path) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// Atomically replace `path` with `data`. Readers see the old or the new file, never a mix.
pub(crate) fn replace_private(path: &Path, data: &[u8]) -> io::Result<()> {
    let tmp = temp_path(path);
    let mut f = create_private(&tmp)?;
    let res = f.write_all(data).and_then(|()| f.sync_all());
    drop(f);
    if let Err(e) = res {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    // `std::fs::rename` replaces an existing destination on Unix and on Windows
    // (`MoveFileExW` with `MOVEFILE_REPLACE_EXISTING`).
    fs::rename(&tmp, path).inspect_err(|_| {
        let _ = fs::remove_file(&tmp);
    })
}

/// Remove `path`; a missing file is not an error.
pub(crate) fn remove_if_exists(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

#[cfg(test)]
pub(crate) mod test_dir {
    use std::path::{Path, PathBuf};

    use rand_core::RngCore;

    /// A unique temporary directory removed on drop.
    pub(crate) struct TestDir(PathBuf);

    impl TestDir {
        pub(crate) fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!(
                "arkhon-rt-{tag}-{:016x}",
                rand_core::OsRng.next_u64()
            ));
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }

        pub(crate) fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_dir::TestDir;
    use super::*;

    #[test]
    fn replace_and_remove() {
        let d = TestDir::new("fs");
        let p = d.path().join("f");
        replace_private(&p, b"one").unwrap();
        replace_private(&p, b"two").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"two");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&p).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        remove_if_exists(&p).unwrap();
        remove_if_exists(&p).unwrap();
        assert!(!p.exists());
        assert!(replace_private(&d.path().join("no/such/dir"), b"x").is_err());
    }
}
