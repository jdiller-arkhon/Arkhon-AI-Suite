# runtime

Arkhon Runtime: the process on a customer's computer. It activates and keeps the license valid,
detects the hardware tier, routes each request to a licensed engine, and serves a local
OpenAI-shaped API. Gate record: [`docs/gates/phase-4.md`](../docs/gates/phase-4.md).

## Modules (`src/`)
| Module | What it does |
|---|---|
| `client` | Device API of the License Manager (`server/openapi.yaml`): activate, check-in, deactivate, offline renew, releases. Blocking `ureq` + rustls, 30 s timeouts. Sends license metadata only (a test pins every request's exact field set). |
| `store` | Sealed local storage. License, revocation list and licensing state are encrypted to this computer's own device key (ECIES-style: ephemeral P-256 → ECDH with the device key → HKDF-SHA256 → AES-256-GCM, AAD binds both public keys). A copy on another computer can't be opened. |
| `licensing` | State machine: open store → sealed clock (rollback refused) → offline verification (root → issuing cert → license, revocation list, device key, binding, fingerprint) → offline grace (warnings in the last 3 days, models locked after) → check-in when due. Revocation lists only move forward. Releases gated by entitlement and update window. Offline renewal export/import. |
| `hardware` | Rust port of `tools/env-check` tiering (same thresholds and test cases): `nvidia-smi`, Linux sysfs DRM (AMD/Intel), Windows display-class registry, Apple unified memory. |
| `router` | Reads `models/registry.yaml` (`serde_norway`); picks engine + quant per task along fallback chains (pro → core → lite), only among licensed engines that fit the tier; plain reason strings. |
| `api` | axum, `127.0.0.1` by default with Host/Origin checks; `--lan` needs a ≥32-char bearer token. `/v1/chat/completions`, `/v1/completions`, `/v1/embeddings`, `/v1/rerank`, `/v1/audio/transcriptions`, `/v1/models`, `/v1/status`. |
| `backend` | `Backend` trait. `HttpBackend` forwards to engine servers on 127.0.0.1; `EchoBackend` is a model-free test/demo backend. |
| `memload`, `launch` (Linux) | Decrypt an engine straight into a sealed memfd (ADR-0009) after the license unlocks its key, then start `llama-server` / whisper.cpp from `/proc/self/fd/N` with `mmap+mlock`. |

## CLI
```text
arkhon-runtime [--data-dir DIR] <command>
  detect [--json]
  activate --server URL --key KEY
  status | checkin [--server URL] | deactivate [--server URL]
  renewal-export FILE | renewal-import FILE
  route ENGINE_OR_TASK [--tier S|M|L]
  serve [--port 4318] [--lan --token-file F] [--tier S|M|L]
        [--fake-backend | --upstream ENGINE=URL ... | --launch ENGINE --models-dir D --llama-server BIN [--whisper-server BIN]]
```
The command comes first, then its flags. Data lives in `%LOCALAPPDATA%\Arkhon`,
`~/Library/Application Support/Arkhon` or `$XDG_DATA_HOME/arkhon` unless `--data-dir` is given.

**Root key.** The license root public key is embedded at build time from `ARKHON_ROOT_PUBLIC_KEY`
(hex). Debug builds also read it from the environment at run time (tests, demos); release builds
never do.

**Device key.** Built with `--features tpm` and `ARKHON_TPM_TCTI` set (e.g. `device:/dev/tpmrm0`),
the TPM holds the key. Otherwise a software key in the data directory, encrypted with a random
per-install secret file (weaker; the license records the binding, and `status` says so).

## Demo without Postgres
```bash
cargo run -p arkhon-runtime --example demo-license-server -- 8455 core,lite,embed   # prints ARKHON_ROOT_PUBLIC_KEY=…
export ARKHON_ROOT_PUBLIC_KEY=<printed hex>
cargo run -p arkhon-runtime -- --data-dir /tmp/ark activate --server http://127.0.0.1:8455 --key DEMO-KEY
cargo run -p arkhon-runtime -- --data-dir /tmp/ark serve --fake-backend --tier M &
curl -s http://127.0.0.1:4318/v1/chat/completions -H 'content-type: application/json' \
  -d '{"model":"pro","messages":[{"role":"user","content":"hi"}]}'
```
The demo server makes throwaway keys on every start. Never use them for anything else.

## Tests
```bash
cargo test -p arkhon-runtime                     # all unit + gate tests (gate tests are named gate_*)
cargo test -p arkhon-runtime gate_               # just the Phase 4 gate tests
ARKHON_TEST_TCTI=swtpm:host=127.0.0.1,port=2321 cargo test -p arkhon-runtime --features tpm   # + TPM-bound licensing
```
Phase 1 demos (`src/bin/p1-spike.rs`, `p1-e2e.rs`) are Linux-only.
