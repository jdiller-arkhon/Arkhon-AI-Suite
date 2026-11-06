#![no_main]
//! Offline-renewal request/response parsers: no panics; accepted input is canonical.

use arkhon_license::{RenewalRequest, RenewalResponse};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(req) = RenewalRequest::from_bytes(data) {
        assert_eq!(req.to_bytes(), data);
    }
    if let Ok(resp) = RenewalResponse::from_bytes(data) {
        assert_eq!(resp.to_bytes(), data);
    }
});
