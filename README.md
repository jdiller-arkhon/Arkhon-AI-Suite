# Arkhon Suite

A private AI suite for small and mid-sized businesses that runs entirely on the customer's own
computer. It drafts email replies, answers customer questions, files bills, writes up meetings,
prepares quotes and answers questions about the company, all grounded in the company's own data,
with citations and human approval. Customer data never leaves the customer's machine (**N1**).

```bash
make            # list every command
make check      # format, lint and test everything (what CI runs)
make suite      # customer app on the real engine: http://127.0.0.1:4317/dashboard.html
make license-server   # License Manager + Operator Console: http://127.0.0.1:8443/console
```

## Two sides

| | Who uses it | Where |
|---|---|---|
| **Arkhon Suite** | The customer's staff: Home, Needs you, Company settings (people, roles, teams, connections, activity) | `suite/` + `runtime/` on the customer's computer |
| **Operator Console + License Manager** | Arkhon staff: customers, licenses, devices, releases, audit | `server/` (with `server/console/`), run by Arkhon |

They share only signed licenses and release manifests (`crates/arkhon-license`). No customer content
crosses between them.

## Repository map

| Path | What | Status |
|---|---|---|
| `crates/arkhon-crypto` | Encrypted model files, canonical encoding, release signing | Phase 2 ✓ (98.99% coverage, fuzzed) |
| `crates/arkhon-tpm` | TPM 2.0 / software device keys, fingerprints, clock-rollback store | Phase 2 ✓ (swtpm-tested) |
| `crates/arkhon-license` | License format, key chain, revocation, CEK wrapping, offline renewal | Phase 2 ✓ |
| `crates/arkhon-org` | People, roles, teams, connected-app rules | ✓ |
| `runtime/` | In-memory model loading (sealed memfd), Phase 1 demos | Phase 1 ✓ on Linux |
| `suite/engine` | One command surface: org, review queue, value metrics, token vault, activity log | ✓ |
| `suite/connectors` | Connector framework + IMAP/SMTP (sends only with approval) | ✓ |
| `suite/devserver` | Local dev server for the prototype (127.0.0.1 only) | ✓ |
| `suite/app/design` | Customer app prototype (`dashboard.html`) + brand tokens | ✓ (Tauri shell: Phase 5) |
| `server/` | License Manager API (axum + Postgres) + Operator Console | Phase 3 ✓ |
| `tools/keygen` | Offline root / issuing keys, revocation lists | ✓ |
| `tools/env-check` | Hardware tier detection (any GPU vendor, TPM) | ✓ |
| `fuzz/` | cargo-fuzz targets for every parser | ✓ |
| `models/` | Engine registry, measured run logs | Registry ✓, training: Phase 7 |
| `deploy/` | Docker Compose for the License Manager | ✓ |
| `docs/` | Everything written down. Start at [docs/README.md](docs/README.md) | |

## Hard rules
- No secrets, weights or customer data in git. See [SECURITY.md](SECURITY.md); gitleaks runs on every PR.
- No hand-authored or Claude-generated training data. See [`models/data/LICENSES.md`](models/data/LICENSES.md).
- Only Apache-2.0 or MIT model bases. See [ADR-0001](docs/decisions/0001-engine-selection.md).
- Every benchmark or result in the repo comes from a saved run under `models/evals/runs/`.
