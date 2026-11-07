# Phase 4 gate report: Arkhon Runtime + model router

Date: 2026-11-07 · Branch: `claude/kind-mendel-jsavoh` · Code: `runtime/` (see `runtime/README.md`)

## Built
- **Activation client** (`runtime/src/client.rs`): `/v1/activate`, `/v1/checkin`, `/v1/deactivate`,
  `/v1/offline/renew`, `/v1/releases`, per `server/openapi.yaml`. Blocking `ureq` 3.5.1 with rustls
  (no OpenSSL), 30 s timeouts, 4 MiB response cap. Requests carry license metadata only; a test pins
  the exact JSON field set of every request and checks that raw hardware identifiers never appear.
- **Sealed local storage** (`store.rs`): license, revocation list and state are encrypted to this
  computer's own device key. Each write uses a fresh P-256 key, ECDH with the device key,
  HKDF-SHA256 and AES-256-GCM, with both public keys in the AAD. Reading needs the device key's
  ECDH, which is the TPM when there is one. A copy on another computer can't be opened.
- **Licensing state machine** (`licensing.rs`):
  1. Open the sealed store.
  2. Check trusted time with `SoftwareClockStore`, keyed by a secret inside the sealed store. A
     clock earlier than the last time seen, or earlier than the last online check, is refused.
  3. Verify offline: root → issuing cert → license, plus the revocation list, the device key and
     binding, and the fingerprint.
  4. Check offline grace: warnings in the last 3 days, then models are locked.
  5. Check in when due: at half the term, or 3 days before the offline deadline if that's sooner.

  Also:
  - A missing clock record keeps models locked until the next online check or renewal import.
  - Revocation lists only move forward, both on update and on check-in.
  - `check_release` uses `verify_release` and `may_install` (entitlement and update window).
  - Offline renewal can be exported and imported as files. Deactivation deletes local data only
    after the server confirms.
- **Hardware + router** (`hardware.rs`, `router.rs`):
  - Hardware tiering is a port of `tools/env-check`, with the same thresholds and test cases
    (NVIDIA `nvidia-smi`, Linux sysfs DRM, Windows display-class registry, Apple unified-memory
    budget).
  - The router reads `models/registry.yaml` with `serde_norway` =0.9.42, a maintained fork of
    `serde_yaml`.
  - It follows fallback chains (pro → core → lite) and only picks engines that are licensed and fit
    the tier. Quants are chosen by measured `vram_mib`/`ram_mib` once the registry has them. Every
    decision comes with a plain reason.
- **Local API** (`api.rs`, `backend.rs`):
  - axum, serving `/v1/chat/completions`, `/v1/completions`, `/v1/embeddings`, `/v1/rerank`,
    `/v1/audio/transcriptions`, `/v1/models` and `/v1/status`.
  - Binds 127.0.0.1 with the dev server's Host/Origin checks. `--lan` needs a bearer token of at
    least 32 characters, compared in constant time, and refuses browser Origins.
  - POST bodies must be JSON (multipart for audio).
  - The `Backend` trait has two implementations:
    - `HttpBackend` forwards to engine servers.
    - `EchoBackend` is model-free, for tests and demos.
  - On Linux, `launch.rs` gets the engine key through the license, decrypts the model into a sealed
    memfd, and starts llama-server or whisper.cpp from `/proc/self/fd/N` with `mmap+mlock`
    (`serve --launch`).
- **CLI** `arkhon-runtime`: `detect`, `activate`, `status`, `checkin`, `deactivate`,
  `renewal-export`, `renewal-import`, `route`, `serve`.
  - The root public key is embedded at build time from `ARKHON_ROOT_PUBLIC_KEY`. Only debug builds
    accept it from the environment.
  - The device key is the TPM (feature `tpm` + `ARKHON_TPM_TCTI`), or a software key otherwise.
- **Demo License Manager stand-in** (`runtime/examples/demo-license-server.rs`): uses throwaway
  keys, needs no Postgres, and is only for local demos.
- **CI**: new `rust-windows-macos` matrix job. Linux swtpm step now also runs
  `cargo test -p arkhon-runtime --features tpm`.

## Phase 4 gate tests (all pass locally)
| Gate requirement | Test(s) |
|---|---|
| Copied install fails | `gate_copied_install_fails_with_other_device_key` (store can't be unsealed), `gate_copied_install_fails_on_other_hardware` (device key copied too → `WrongMachine`), `gate_license_for_another_device_key_is_refused` |
| Tampered license fails | `gate_tampered_license_fails` (engine added + expiry extended → `BadSignature`), `gate_tampered_store_bytes_fail` |
| Forged license fails | `gate_forged_by_other_root_fails_activation`, `gate_forged_certificate_not_root_signed_fails` (`UntrustedIssuer`), `gate_forged_with_wrong_issuing_key_fails` (`BadSignature`), `gate_revoked_issuing_key_fails` (`IssuerRevoked`, also at check-in) |
| Clock rollback detected and refused | `gate_clock_rollback_refused`, `gate_clock_rollback_refused_even_if_clock_file_deleted`; plus `deleted_clock_file_locks_models_until_online_check`, `tampered_clock_file_refused` |
| Expired offline grace refuses to load models | `gate_offline_grace_expiry_refuses_models` (day 3 OK, day 5 "2 more days" warning, under 1 day warning, day 8 `OfflineTooLong` on unlock; check-in restores) |
| Router never picks an unlicensed engine | `gate_entitlement_filtering_never_picks_unlicensed_engine` (exhaustive over all engine subsets × tiers), `gate_unlicensed_engine_never_reaches_backend` (API level) |

All keys are throwaway, generated per test (`runtime/src/testkit.rs`). The TPM variant
`tpm_bound_activation_and_copy_refusal` activates with a TPM-bound key on swtpm, re-opens the
store with the same TPM, and refuses a copy opened with any other key.

## Verification (local, Linux x86_64, rustc 1.99.1)
| Command | Result |
|---|---|
| `cargo fmt --all --check` | pass |
| `cargo clippy --workspace --all-targets -- -D warnings` | pass |
| `cargo clippy -p arkhon-runtime --all-targets --features tpm -- -D warnings` | pass |
| `cargo test -p arkhon-runtime` | **62 passed** (61 lib + 1 bin), 0 failed |
| `cargo test -p arkhon-runtime gate_` | **14 passed** |
| `ARKHON_TEST_TCTI=swtpm:host=127.0.0.1,port=2321 cargo test -p arkhon-runtime --features tpm -- --nocapture` | **63 passed** (62 lib + 1 bin); prints "TPM-bound licensing verified against swtpm:…" |
| `ARKHON_TEST_DATABASE_URL=postgresql://arkhon@127.0.0.1:5433/postgres cargo test --workspace` | **261 passed**, 0 failed (all crates, server DB tests included) |
| `cargo clippy --workspace --all-targets --target {x86_64-pc-windows-gnu,x86_64-apple-darwin} -- -D warnings` (excluding the ring-dependent suite crates, with ureq's TLS feature temporarily off because no C cross-toolchain is installed here; not committed) | pass: the runtime and crates type-check for Windows and macOS |

swtpm was started with
`swtpm socket --tpmstate dir=<scratch>/swtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear --daemon`.

### Manual demo (fake backend, demo License Manager over real HTTP)
```text
$ cargo run -p arkhon-runtime --example demo-license-server -- 8455 core,lite,embed
ARKHON_ROOT_PUBLIC_KEY=872076e9…94ae            (throwaway, regenerated each start)
$ arkhon-runtime activate --server http://127.0.0.1:8455 --key WRONG
That activation key isn't valid.
exit=1
$ arkhon-runtime activate --server http://127.0.0.1:8455 --key DEMO-KEY
Arkhon is activated on this computer.
License      : lic-demo-1 (customer cust-demo)
Engines      : core, embed, lite
Security key : Software key (less secure)
Models       : allowed
Expires (unix) 1796601652; offline until 1795219252; next check-in 1794960052
Note         : This computer uses a software security key (no security chip found). That is less secure.
$ arkhon-runtime route pro --tier M
core (llama.cpp, quant not measured yet): Using "core" because "pro" isn't in your plan.
$ arkhon-runtime serve --port 4318 --fake-backend --tier M
Using the test backend: answers are canned, no model runs.
Arkhon local API on http://127.0.0.1:4318 (tier M)
$ curl -s -i http://127.0.0.1:4318/v1/chat/completions -H "content-type: application/json" \
    -d '{"model":"pro","messages":[{"role":"user","content":"Summarize this invoice."}]}'
HTTP/1.1 200 OK
content-type: application/json
x-arkhon-engine: core
x-arkhon-route: Using "core" because "pro" isn't in your plan.
cache-control: no-store
x-content-type-options: nosniff
x-frame-options: DENY
referrer-policy: no-referrer

{"choices":[{"finish_reason":"stop","index":0,"message":{"content":"[core] Summarize this invoice.","role":"assistant"}}],"id":"chatcmpl-echo","model":"core","object":"chat.completion","usage":{"completion_tokens":0,"prompt_tokens":0,"total_tokens":0}}
$ curl -s http://127.0.0.1:4318/v1/models
{"data":[{"id":"core",…},{"id":"embed",…},{"id":"lite",…}],"object":"list"}
$ curl -s http://127.0.0.1:4318/v1/rerank -H "content-type: application/json" -d '{"model":"rerank","query":"q","documents":["a"]}'
{"error":{"message":"Arkhon can't do \"rerank\" on this computer with your plan: \"rerank\" isn't in your plan.","type":"not_entitled"}}
$ curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:4318/v1/models -H "Host: evil.example:4318"
403
$ curl -s http://127.0.0.1:4318/v1/models -H "Origin: https://evil.example"
{"error":{"message":"Requests from other websites are blocked.","type":"forbidden"}}
$ arkhon-runtime checkin --server http://127.0.0.1:8455          → Models : allowed
# copy license.sealed + clock.sealed to a fresh data dir (= new software device key)
$ arkhon-runtime --data-dir data2 status
Arkhon's saved license on this computer can't be opened. It was copied from another computer or damaged. Activate Arkhon again.
$ arkhon-runtime deactivate --server http://127.0.0.1:8455
This computer is deactivated. You can now activate Arkhon on another computer.
```

## CI changes
- New job `rust-windows-macos` (`windows-latest`, `macos-latest`, `fail-fast: false`): runs
  `cargo build --workspace --all-targets` and
  `cargo test --workspace --exclude arkhon-license-server`.
  - The server is still built on both OSes. Its DB tests assert when `CI` is set, and service
    containers only exist on Linux runners, so they stay in the Linux `rust` job, which has
    Postgres. This is explained in a comment in `ci.yml`.
- The Linux swtpm step adds `cargo test -p arkhon-runtime --features tpm`.
- **The Windows and macOS jobs are unverified until CI runs.** Locally only cross-target
  type-checking was possible (see above).

## Open risks
1. **Physical TPM not tested.** Only swtpm. Secure Enclave binding (macOS) isn't implemented:
   macOS uses the software key. A TPM NV monotonic counter (to stop someone restoring an older
   clock or store file on the same computer) is planned but not built.
2. **Windows and macOS loaders are open** (ADR-0009). `launch` is Linux-only. On Windows and macOS,
   `serve` can only forward to `--upstream` servers, and there is no plaintext-free model loading
   yet. In-process loading is the recommended next step.
3. **Fingerprint on Windows/macOS** (in `crates/arkhon-tpm`, not changed here):
   `RawComponents::collect()` returns no components off Linux. So all Windows and Mac computers
   share the same fingerprint, and "different hardware" detection there rests on the device key
   alone. Reported to the crate owners.
4. **Software device key strength.** Off-TPM, the device key file is protected by a random
   per-install secret file next to it (owner-only on Unix; on Windows it relies on the profile
   ACL). Copying the whole data directory *plus* matching hardware would move a software-bound
   install. OS keychain storage (DPAPI, Keychain, Secret Service) is the planned replacement. The
   license records the binding, and the server can refuse software binding per plan.
5. **CRLF on Windows checkouts.** The registry YAML (parsed fine either way) and the hex test
   vectors (trimmed by `from_hex`) tolerate CRLF. Other suite tests that compare text files are
   unverified on Windows.
6. **No end-to-end test against the real License Manager.** This optional item wasn't done. The
   HTTP client is exercised against a local axum stub (unit test) and the demo server above.
   The response formats are the shared `arkhon-license` types.
7. Quantization choice is wired to the registry's `vram_mib`/`ram_mib`. Those fields are empty
   until measured runs land, so routes report "quant not measured yet".
