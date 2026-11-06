#![no_main]
//! Revocation-list parser: no panics; accepted input is canonical.

use arkhon_license::RevocationList;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(list) = RevocationList::from_bytes(data) {
        assert_eq!(list.to_bytes(), data, "accepted a non-canonical revocation list");
    }
});
