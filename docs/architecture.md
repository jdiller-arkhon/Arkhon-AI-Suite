# Architecture (Phase 0 overview)

```
 Customer machine (everything customer-specific stays here — N1)
 ┌──────────────────────────────────────────────────────────────────────┐
 │ Suite app (Tauri)  ── workspaces: Inbox, Desk, Docs, Knowledge, ...   │
 │      │ IPC                                                            │
 │ Suite engine: workflows · review queue · retrieval index · audit log │
 │      │                · value metrics · connectors (OAuth tokens enc.)│
 │      │ 127.0.0.1 only                                                 │
 │ Arkhon Runtime: activation · sealed license · model router ·          │
 │   in-memory decrypt (memfd / buffer load) → llama.cpp / whisper.cpp   │
 │      │ TPM 2.0 (or software keystore, flagged)                        │
 └──────┼───────────────────────────────────────────────────────────────┘
        │ license metadata only (license key, TPM pubkey, HW fingerprint)
        ▼
 Arkhon License Manager (axum + Postgres) ── Admin/Customer portals ── Stripe (test mode first)
```

Key hierarchy: offline **root** Ed25519 → online, rotatable **issuing** key → licenses and release
manifests. The runtime embeds the root public key and an issuing-key revocation list. Model releases
use chunked AES-256-GCM under per-release CEKs, which are wrapped to the activating machine's TPM key.

| Phase | Builds |
|------|--------|
| 0 | Repo, CI, gitleaks, ADR-0001, env check, needs, discovery kit |
| 1 | Risk spike: encrypted GGUF → TPM unwrap → in-memory llama.cpp, no plaintext on disk |
| 2 | license / crypto / tpm crates (≥90% cov, fuzzing) |
| 3 | License Manager server |
| 4 | Runtime + router |
| 5 | Suite foundation, Inbox, Knowledge (base engines) |
| 6 | Docs, Desk, Meetings, Growth, Insights, launch pack |
| 7 | Training pipeline, fine-tunes, packaging |
| 8 | Arkhon Tune |
| 9 | Portals + Stripe |
| 10 | Installers, hardening, RC |
