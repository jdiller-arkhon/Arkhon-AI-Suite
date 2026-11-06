#![no_main]
//! License parser: must never panic, and anything accepted must re-encode to the same bytes.

use arkhon_license::License;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(license) = License::from_bytes(data) {
        assert_eq!(license.to_bytes(), data, "accepted a non-canonical license");
    }
});
