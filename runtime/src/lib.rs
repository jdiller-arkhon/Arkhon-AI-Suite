//! Arkhon Runtime library: the process on a customer's computer.
//!
//! * [`client`]: the License Manager's device API (activate, check-in, deactivate, offline renewal,
//!   releases). Only license metadata is ever sent.
//! * [`store`]: sealed local storage, encrypted to this computer's device key.
//! * [`licensing`]: activation and the licensing state machine (offline verification, check-in,
//!   offline grace, clock-rollback detection, forward-only revocation lists, release gating).
//! * [`hardware`]: vendor-neutral hardware detection and S/M/L tiering (port of env-check).
//! * [`router`]: engine choice per task from `models/registry.yaml`, with fallback chains,
//!   restricted to licensed engines.
//! * [`api`] + [`backend`]: the local OpenAI-shaped API and the inference backends behind it.
//! * Linux only: [`memload`] (sealed memfd, ADR-0009) and [`launch`] (decrypt an engine into a
//!   memfd and start its server from it).

pub mod api;
pub mod backend;
pub mod client;
mod fsutil;
pub mod hardware;
#[cfg(target_os = "linux")]
pub mod launch;
pub mod licensing;
#[cfg(target_os = "linux")]
pub mod memload;
pub mod router;
pub mod store;
#[cfg(test)]
mod testkit;

/// Crate version, exposed for build/diagnostic reporting.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    #[test]
    fn version_is_set() {
        assert_ne!(super::VERSION, "");
    }
}
