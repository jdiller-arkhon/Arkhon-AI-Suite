#![no_main]
//! Issuing-certificate parser: no panics; accepted input is canonical.

use arkhon_license::IssuingCertificate;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(cert) = IssuingCertificate::from_bytes(data) {
        assert_eq!(cert.to_bytes(), data, "accepted a non-canonical certificate");
    }
});
