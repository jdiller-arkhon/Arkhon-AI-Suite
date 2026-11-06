//! Small file helpers: private (0600) atomic writes.

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

fn write_temp(path: &Path, data: &[u8]) -> io::Result<PathBuf> {
    let tmp = temp_path(path);
    let mut f = create_private(&tmp)?;
    let res = f.write_all(data).and_then(|()| f.sync_all());
    if let Err(e) = res {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(tmp)
}

/// Write `data` to `path` with owner-only permissions, never replacing an existing file.
/// The file appears complete or not at all.
pub(crate) fn write_new_private(path: &Path, data: &[u8]) -> io::Result<()> {
    let tmp = write_temp(path, data)?;
    let res = fs::hard_link(&tmp, path);
    let _ = fs::remove_file(&tmp);
    res
}

/// Atomically replace `path` with `data` (owner-only permissions).
pub(crate) fn replace_private(path: &Path, data: &[u8]) -> io::Result<()> {
    let tmp = write_temp(path, data)?;
    fs::rename(&tmp, path).inspect_err(|_| {
        let _ = fs::remove_file(&tmp);
    })
}

#[cfg(test)]
pub(crate) mod test_dir {
    use std::path::{Path, PathBuf};

    /// A unique temporary directory removed on drop.
    pub(crate) struct TestDir(PathBuf);

    impl TestDir {
        pub(crate) fn new(tag: &str) -> Self {
            use rand_core::RngCore;
            let p = std::env::temp_dir().join(format!(
                "arkhon-tpm-{tag}-{:016x}",
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
    fn write_new_refuses_overwrite_and_is_private() {
        let dir = TestDir::new("fs");
        let p = dir.path().join("f");
        write_new_private(&p, b"one").unwrap();
        let err = write_new_private(&p, b"two").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&p).unwrap(), b"one");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&p).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        replace_private(&p, b"three").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"three");
        // Only the target file remains (no temp files left behind).
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn errors_when_directory_missing() {
        let dir = TestDir::new("fs2");
        let p = dir.path().join("missing").join("f");
        assert!(write_new_private(&p, b"x").is_err());
        assert!(replace_private(&p, b"x").is_err());
    }
}
