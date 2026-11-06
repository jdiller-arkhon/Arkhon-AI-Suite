//! Arkhon Runtime library.
//!
//! Phase 1 scope: load decrypted model weights **into memory only** and hand them to the
//! inference engine without plaintext ever touching disk, swap or core dumps.
//!
//! Linux strategy (see `docs/decisions/0008-in-memory-model-loading.md`):
//! 1. [`harden_process`]: mark the process non-dumpable (blocks same-user `ptrace` and
//!    `/proc/<pid>/mem` reads) and set the core-dump limit to zero.
//! 2. [`SealedModel::create`]: decrypt straight into an anonymous `memfd` (RAM-backed, no
//!    filesystem path), then seal it against writes, growth and shrinking.
//! 3. Pass the fd to `llama-server` as `/proc/self/fd/N` with `--mlock`, so the mapped pages
//!    are locked in RAM and never written to swap.

#[cfg(target_os = "linux")]
pub mod memload;

/// Crate version, exposed for build/diagnostic reporting.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    #[test]
    fn version_is_set() {
        assert_ne!(super::VERSION, "");
    }
}
