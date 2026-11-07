# Phase 0 gate report — Bootstrap, verification, discovery kit

Date: 2026-11-06 · Branch: `claude/kind-mendel-jsavoh` · Needs: N1, N2, N10, N11 (all, via the needs doc)

## Built
- Monorepo in `jdiller-arkhon/Arkhon-AI-Suite` with the full Section 3 layout. The Rust workspace has 6 crates (stubs that compile and are linted with `clippy -D warnings` and `unsafe_code = deny`).
- CI (`.github/workflows/ci.yml`): Rust fmt, clippy and test; Python ruff and pytest; env-check on Windows, macOS and Linux; gitleaks over full history.
- Secret hygiene: `.gitignore` covers keys, weights and customer data; `.gitleaks.toml` adds Arkhon key and CEK rules; the pre-commit config includes gitleaks; `SECURITY.md` is written.
- `docs/product/customer-needs.md` lists N1–N11 with a component traceability table.
- ADR-0001 re-verifies every engine base against primary sources: all are Apache-2.0 or MIT. Parakeet and Sortformer are rejected. ADR-0002 records the repo and branch decision.
- `models/registry.yaml` with a JSON schema. Tests enforce permissive-only licenses, acyclic fallbacks, and text plus embed coverage on every tier. The `quants` field requires a run log, so no benchmark numbers can be fabricated.
- `tools/env-check` is a stdlib, cross-platform, **vendor-neutral** detector (NVIDIA CUDA, AMD ROCm/Vulkan, Intel Arc, Apple Metal unified memory, CPU) covering TPM and tier, with unit tests. It becomes the runtime's auto-detect (N2). See ADR-0004.
- Discovery kit: a 30-minute interview script, a scoring sheet and method, and a design-partner agreement outline marked for attorney review.
- `models/data/LICENSES.md` dataset ledger; NOTICE; architecture and threat-model skeletons.

## Verification
| Check | Result |
|---|---|
| `cargo fmt --check && cargo clippy --all-targets -D warnings && cargo test` | pass (local) |
| `ruff check && ruff format --check && pytest` | pass, 12 tests (local) |
| gitleaks | **not run locally** (sandbox blocked the binary download). The first run happens in CI on the PR. |
| CI on GitHub | pending the first PR run |

## Open risks
1. **No reference hardware measured yet.** env-check runs on every vendor (NVIDIA/AMD/Intel/Apple/CPU), but real machines are needed for each backend (see `docs/hardware-matrix.md`).
2. The minimum llama.cpp build for `qwen35` / `qwen35moe` is UNVERIFIED. Phase 1 pins a commit.
3. No diarization with an Apache or MIT license is confirmed. pyannote 3.1 is MIT but gated, and its dependency license is unverified.
4. Blackwell (sm_120) needs a recent CUDA toolchain. The Windows in-memory load path is the biggest Phase 1 unknown.

## Decisions needed
1. ~~Launch Industry Pack~~ → **Trades & field services** (ADR-0003, decided 2026-11-06).
2. ~~Approve ADR-0001~~ → **Approved 2026-11-06**, including Vision = Core + LoRA.
3. Approve the reference hardware matrix sourcing plan (`docs/hardware-matrix.md`, ADR-0004). This means per-backend self-hosted runners, not one dev machine.
4. Branch naming: the session can only push `claude/kind-mendel-jsavoh`. Rename to `phase-0-bootstrap` when opening the PR, or accept the name as-is.
