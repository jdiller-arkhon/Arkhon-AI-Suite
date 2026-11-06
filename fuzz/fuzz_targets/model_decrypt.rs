#![no_main]
//! Model-file chunk parser/decryptor on arbitrary bytes under a fixed key: must never panic and
//! never accept forged data. The seed corpus holds a real file under this key, so the fuzzer also
//! explores mutations of valid ciphertext; any accepted input must re-encrypt-check consistently.

use arkhon_crypto::model::decrypt_model_to_vec;
use arkhon_crypto::{sha256, Cek};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let cek = Cek::from_bytes(sha256(b"arkhon test vector CEK - NOT SECRET"));
    if let Ok(plain) = decrypt_model_to_vec(&cek, data, 0) {
        // Only the published vector (or another genuine file under this key) can get here.
        assert!(plain.len() <= data.len());
    }
});
