# Arkhon Suite

A private AI suite that runs entirely on a small or mid-sized business's own hardware. It does
inbox triage and drafting, support replies, document intake, company Q&A, meeting notes, growth
content, and insights, all grounded in the customer's own data with citations and human approval.
Customer data never leaves the customer's machine (**N1**).

> Status: **Phase 0 — bootstrap**. See [`docs/gates/phase-0.md`](docs/gates/phase-0.md).

| Path | What |
|------|------|
| `crates/arkhon-license` | License format, canonical encoding, signing, verification, CEK wrapping |
| `crates/arkhon-tpm` | TPM 2.0 abstraction with software fallback |
| `crates/arkhon-crypto` | Chunked AES-256-GCM model encryption, release signing |
| `runtime/` | Arkhon Runtime: activation, in-memory loading, local inference API, model router |
| `suite/app` | Tauri 2 + React desktop app (Phase 5) |
| `suite/engine` | Workflows, review queue, retrieval, value metrics, audit log |
| `suite/connectors` | Email, file, accounting and CRM connectors |
| `suite/packs` | Industry Packs (config + templates + eval sets) |
| `server/` | License Manager API (axum + sqlx + Postgres) |
| `portal/` | Admin and customer portals (Next.js, Phase 9) |
| `models/` | Engine registry, data/eval/train/package pipelines |
| `tools/` | env-check, keygen, release, trace CLIs |
| `docs/` | Product needs, architecture, [threat model](docs/threat-model.md), ADRs, discovery kit, gate reports |
| `docs/legal` | [EULA template](docs/legal/eula-template.md) (draft for attorney review, not for use as-is) |

## Developer setup

```bash
pipx install pre-commit && pre-commit install   # gitleaks + fmt hooks
cargo test --workspace
pip install pyyaml jsonschema pytest ruff && pytest -q
python tools/env-check/arkhon_envcheck/check.py   # hardware/TPM report
```

## Hard rules
- No secrets, weights or customer data in git. See [SECURITY.md](SECURITY.md).
- No hand-authored or Claude-generated training data. See [`models/data/LICENSES.md`](models/data/LICENSES.md).
- Only Apache-2.0 or MIT model bases, as recorded in [ADR-0001](docs/decisions/0001-engine-selection.md).
