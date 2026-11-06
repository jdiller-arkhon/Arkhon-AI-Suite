//! Suite engine: workflows, review queue, retrieval index, value metrics, audit log.
//!
//! Phase 0 scaffold. Implementation lands in a later gated phase; see
//! `docs/architecture.md`.

/// Crate version, exposed for build/diagnostic reporting.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    #[test]
    fn version_is_set() {
        assert!(!super::VERSION.is_empty());
    }
}
