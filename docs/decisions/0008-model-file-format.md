# ADR-0008: Encrypted model-file format (chunked AES-256-GCM)

- Status: Accepted (Phase 2) · Implementation: `arkhon_crypto::model`

## Decision
- **Header (34 bytes):** magic `ARKHMDL\0`, version, chunk size (1 B to 16 MiB, default 1 MiB), a random 16-byte file id and a random 4-byte nonce prefix.
- **Per-file key:** `HKDF-SHA256(CEK, salt = SHA-256(header), info = "arkhon/v1/model-file-key")`.
- **Nonce for chunk i:** `prefix || u64 i`.
- **AAD for chunk i:** `header digest || u64 i || final flag`.

These choices defeat the following, and a property test and a fuzz target cover each one:
- **header tampering:** the digest changes, so every chunk fails;
- **reordering:** the chunk index is authenticated;
- **mixing chunks between files:** each file has a different digest and key;
- **truncation and appended data:** the final flag catches both.

Decryption writes each authenticated chunk to an in-memory sink (`decrypt_model_to_vec`, or a
`Write` the caller owns, such as the runtime's sealed memfd). On any error the caller throws away
everything written so far.

Encrypted files may be downloaded freely; they are useless without a license that unwraps the CEK.
