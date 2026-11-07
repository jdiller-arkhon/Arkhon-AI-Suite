//! Linux in-memory model loading via sealed `memfd`.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::path::PathBuf;

use nix::fcntl::{fcntl, FcntlArg, FdFlag, SealFlag};
use nix::sys::memfd::{memfd_create, MFdFlags};
use nix::sys::prctl;
use nix::sys::resource::{setrlimit, Resource};

fn io_err(e: nix::Error) -> io::Error {
    io::Error::from_raw_os_error(e as i32)
}

/// Make this process resistant to memory inspection: non-dumpable (no core files, no same-user
/// ptrace or `/proc/<pid>/mem` access) and a zero core-size limit. Children inherit the limit;
/// `llama-server` re-exec resets dumpability, so it is launched with the same rlimit and the
/// runtime should run under a dedicated service account in production.
///
/// # Errors
/// OS errors from `prctl` or `setrlimit`.
pub fn harden_process() -> io::Result<()> {
    prctl::set_dumpable(false).map_err(io_err)?;
    setrlimit(Resource::RLIMIT_CORE, 0, 0).map_err(io_err)?;
    Ok(())
}

/// Model weights held in a sealed, anonymous, RAM-backed file.
#[derive(Debug)]
pub struct SealedModel {
    file: File,
    len: u64,
}

impl SealedModel {
    /// Create a memfd, let `write_plaintext` write the plaintext into it (e.g. a streaming decryptor),
    /// then seal it. The plaintext never exists in a named file.
    ///
    /// # Errors
    /// OS errors, or any error returned by `write_plaintext`.
    pub fn create(
        name: &str,
        write_plaintext: impl FnOnce(&mut dyn Write) -> io::Result<()>,
    ) -> io::Result<Self> {
        let fd: OwnedFd = memfd_create(name, MFdFlags::MFD_CLOEXEC | MFdFlags::MFD_ALLOW_SEALING)
            .map_err(io_err)?;
        let mut file = File::from(fd);
        {
            let mut buffered = io::BufWriter::with_capacity(1 << 20, &mut file);
            write_plaintext(&mut buffered)?;
            buffered.flush()?;
        }
        let len = file.seek(SeekFrom::End(0))?;
        file.seek(SeekFrom::Start(0))?;
        fcntl(
            file.as_fd(),
            FcntlArg::F_ADD_SEALS(
                SealFlag::F_SEAL_WRITE
                    | SealFlag::F_SEAL_GROW
                    | SealFlag::F_SEAL_SHRINK
                    | SealFlag::F_SEAL_SEAL,
            ),
        )
        .map_err(io_err)?;
        Ok(SealedModel { file, len })
    }

    /// Size in bytes.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Whether the model is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Allow a child process to inherit the fd and return the path the child should open
    /// (`/proc/self/fd/N` resolves inside the child to the same memfd).
    ///
    /// # Errors
    /// OS errors from `fcntl`.
    pub fn share_with_child(&self) -> io::Result<PathBuf> {
        fcntl(self.file.as_fd(), FcntlArg::F_SETFD(FdFlag::empty())).map_err(io_err)?;
        Ok(PathBuf::from(format!(
            "/proc/self/fd/{}",
            self.file.as_raw_fd()
        )))
    }

    /// Read the whole model back (tests and in-process loaders).
    ///
    /// # Errors
    /// I/O errors.
    pub fn read_all(&self) -> io::Result<Vec<u8>> {
        let mut f = self.file.try_clone()?;
        f.seek(SeekFrom::Start(0))?;
        let mut v = Vec::with_capacity(usize::try_from(self.len).unwrap_or(0));
        f.read_to_end(&mut v)?;
        Ok(v)
    }

    /// Whether a write to the sealed file is refused (it must be).
    #[must_use]
    pub fn is_write_sealed(&self) -> bool {
        let Ok(mut f) = self.file.try_clone() else {
            return false;
        };
        f.write_all(b"x").is_err()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_model_round_trips_and_refuses_writes() {
        let m = SealedModel::create("arkhon-test", |w| w.write_all(b"GGUF-test-weights")).unwrap();
        assert_eq!(m.len(), 17);
        assert_eq!(m.read_all().unwrap(), b"GGUF-test-weights");
        assert!(m.is_write_sealed());
        // No path on any filesystem: the fd link names an anonymous memfd.
        let link = std::fs::read_link(format!("/proc/self/fd/{}", m.file.as_raw_fd())).unwrap();
        assert!(
            link.to_string_lossy().starts_with("/memfd:arkhon-test"),
            "{link:?}"
        );
    }

    #[test]
    fn fill_errors_propagate() {
        let e = SealedModel::create("arkhon-test", |_| Err(io::Error::other("decrypt failed")))
            .unwrap_err();
        assert_eq!(e.to_string(), "decrypt failed");
    }

    #[test]
    fn child_can_read_shared_fd() {
        let m = SealedModel::create("arkhon-test", |w| w.write_all(b"hello")).unwrap();
        let path = m.share_with_child().unwrap();
        let out = std::process::Command::new("cat")
            .arg(&path)
            .output()
            .unwrap();
        assert_eq!(out.stdout, b"hello");
    }
}
