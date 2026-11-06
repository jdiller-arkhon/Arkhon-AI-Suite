# Phase 2 security self-review: crypto, device binding, licensing

Date: 2026-11-06 · Crates: `arkhon-crypto`, `arkhon-tpm`, `arkhon-license`, `tools/keygen`

## What each crate guarantees
| Crate | Guarantee | Evidence |
|---|---|---|
| arkhon-crypto | **Model files:** confidentiality and integrity per chunk. Tampering, reordering, cross-file splicing and truncation are all detected. | Property tests (single-bit flips, truncation, reordering); fuzz `model_header`, `model_decrypt`; test vector `model-file-v1.hex` |
| arkhon-crypto | **Codec:** exactly one accepted encoding per value. | Re-encode check in every decoder; 5 parser fuzz targets assert canonicality |
| arkhon-crypto | **Content keys (`Cek`):** zeroized on drop; `Debug` never prints the key. | Unit tests |
| arkhon-tpm | **Device keys:** P-256, where the TPM key can't be exported (primary key, `fixedTPM`). The software key is encrypted at rest and flagged `binding: software`. | swtpm integration test (ECDH matches a software peer; the key is deterministic across reopen); negative control fails with no TPM |
| arkhon-tpm | **Hardware fingerprint:** salted HMAC of 5 components, matching with at most 1 changed. No raw serials are kept. | Unit and property tests |
| arkhon-tpm | **Clock-rollback check:** an HMAC-protected last-seen time; a clock earlier than that, beyond the tolerance, is refused. | Unit tests |
| arkhon-license | **Chain:** root → issuing cert → license and manifest. Includes revocation, validity windows, domain-separated signatures, expiry, offline grace, fingerprint binding and update-window gating for releases. | 29 tests; fuzz `license_decode`, `cert_decode`, `revocation_decode`, `renewal_decode`, `manifest_decode`; 6 published test vectors |
| arkhon-license | **CEK wrapping:** ECDH + HKDF + GCM, bound to the license id and engine name. | Tests: wrong device, wrong engine and moved license all fail |
| tools/keygen | **Key files:** created new, never overwritten, mode 0600. The root key is generated locally with OS randomness. | 5 tests |

## Measured
- **Coverage** (`cargo llvm-cov -p arkhon-crypto -p arkhon-tpm -p arkhon-license --summary-only`): **98.99% lines, 97.12% regions, 98.52% functions**.
- **Fuzzing:** see `docs/security/phase-2-fuzzing.md` for each target's duration and result.

## Misuse risks (things callers must get right)
1. **Partial plaintext on error.** `decrypt_model` writes authenticated chunks as it goes. A caller that keeps a partially written sink after an error is holding unverified-to-the-end plaintext; it must throw it away. The runtime's sealed-memfd path drops the memfd on error.
2. **Software binding is a deterrent, not a hard control.** The key exists in process memory during ECDH. The server must decide, per plan, whether to accept it.
3. **The rollback store** is HMAC-protected, but someone who deletes the file resets it to "first run". In production this moves to a TPM NV monotonic counter (Phase 4).
4. **Revocation freshness.** The runtime must keep the highest revocation-list version it has seen, in sealed storage, and refuse older lists (`verify_update` enforces this when given the stored list).
5. **Root key handling.** It must be generated offline and stored offline. Only the root *public* key is compiled into the runtime.

## Not yet verified
- Physical TPMs. Only `swtpm` has been tested. TPM owner-hierarchy auth and lockout handling are deferred to Phase 4.
- Apple Secure Enclave and the Windows TBS path, which need macOS and Windows hardware.
- An independent cryptographic review. This is a self-review; an external audit is recommended before GA.
