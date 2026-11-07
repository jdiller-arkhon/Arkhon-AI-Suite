#![no_main]
//! Model-file header parser: no panics; accepted headers round-trip.

use arkhon_crypto::model::{ModelHeader, HEADER_LEN};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(h) = ModelHeader::parse(data) {
        assert_eq!(&h.to_bytes()[..], &data[..HEADER_LEN]);
        let _ = h.ciphertext_len(data.len() as u64);
    }
});
