#![no_main]
//! Signed release-manifest parser: no panics; accepted input is canonical.

use arkhon_crypto::release::SignedReleaseManifest;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(m) = SignedReleaseManifest::from_bytes(data) {
        assert_eq!(m.to_bytes(), data, "accepted a non-canonical manifest");
    }
});
