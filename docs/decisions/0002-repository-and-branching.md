# ADR-0002: Repository location and branching

- Status: Accepted · Date: 2026-11-06

## Context
The brief specified `arkhon-industries/arkhon-platform`. The owner had already created the private
repository `jdiller-arkhon/Arkhon-AI-Suite` and asked that it be used. The build agent runs in a
sandbox scoped to that repository and to an assigned working branch.

## Decision
- The monorepo lives in `jdiller-arkhon/Arkhon-AI-Suite`, using the Section 3 layout unchanged.
- Phase 0 work is pushed to the branch assigned to the agent session (`claude/kind-mendel-jsavoh`).
  From Phase 1 on, a `phase-N-name` branch is used per phase if the session can push it; otherwise the
  owner renames the branch when opening the PR.
- `main` is protected; the owner merges at each gate.

## Consequences
Transferring the repository to an `arkhon-industries` org later is a GitHub transfer that keeps
history; update `workspace.package.repository` in `Cargo.toml` when that happens.
