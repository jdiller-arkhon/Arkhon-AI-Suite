# ADR-0007: Canonical encoding and license format

- Status: Accepted (Phase 2) · Implementation: `arkhon_crypto::codec`, `crates/arkhon-license`

## Context
Licenses, issuing-key certificates, revocation lists and release manifests are signed. A signature
is only meaningful if the signed bytes have exactly one valid encoding. Otherwise an attacker can
re-encode a signed document so that parsers disagree about what was signed.

## Decision
**A hand-rolled, deterministic, length-prefixed binary format** (`arkhon_crypto::codec`), rather than
deterministic CBOR:
- Every document starts with a 4-byte kind tag and a `u16` format version.
- Integers are fixed-width big-endian, with no varints. Booleans are exactly `0` or `1`.
- Strings and byte strings are a `u32` length followed by the bytes. Strings are capped at 4096 bytes.
- Sets and maps are written in strictly ascending key order. Unsorted or duplicate entries are rejected.
- Fields come in a fixed order, there are no optional fields, and trailing bytes are rejected.
- Every decoder also re-encodes its input and compares, so **a successful parse means the input was canonical**.

**Domain separation:** each signature covers `domain-tag || canonical bytes` (`arkhon/v1/license\0`,
`…/issuing-certificate\0`, `…/revocation-list\0`, `…/release-manifest\0`). A signature on one kind of
document can never be replayed as another.

**Chain:** the root Ed25519 key signs `IssuingCertificate` (serial, issuing public key, validity
window) and `RevocationList` (monotonic version, revoked serials). Issuing keys sign `License` and
`SignedReleaseManifest`. `verify()` takes the embedded root public key, the newest revocation list it
has seen, the time and the device fingerprint, and checks all of the following:
- the certificate, against the root key;
- that the certificate isn't revoked;
- that the license was issued inside the certificate's validity window;
- the license signature, the expiry and the fingerprint (tolerating one changed component).

Revocation lists only move forward (`verify_update`).

**CEK wrapping** (`wrap.rs`):
1. An ephemeral P-256 ECDH exchange with the device's non-exportable key.
2. HKDF-SHA256 derives the key-wrapping key, with context bound to both public keys, the license id and the engine name.
3. AES-256-GCM encrypts the CEK, using that same context as AAD.

P-256, not X25519, because TPM 2.0 and Apple's Secure Enclave only do ECDH on NIST curves.

## Why not CBOR
Deterministic CBOR needs a library we would have to trust to be canonical, on both encode and
decode. The custom format is about 400 lines, fully fuzzed, and simple enough to specify in
one paragraph. The trade-off is that third-party tools can't read it directly. The admin CLI decodes
it instead.

## Consequences
Format changes bump the version. Old runtimes reject new versions with a plain message telling the
user to update.
