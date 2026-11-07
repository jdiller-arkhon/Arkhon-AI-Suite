# Threat model

- Status: **Draft v1** (Phase 0). Re-reviewed at the Phase 2 gate (crypto crates) and Phase 10 (RC hardening).
- Needs: N1 (privacy), N9 (supervised automation), N10 (flat licensing), N4 (trust).
- Method: STRIDE per component (Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege).
- Inputs: [`architecture.md`](architecture.md), [ADR-0005](decisions/0005-organizations-and-roles.md), [ADR-0006](decisions/0006-connections.md), [`SECURITY.md`](../SECURITY.md), `crates/arkhon-org`, `suite/engine`, `suite/devserver`.

### How to read the status markers

| Marker | Meaning |
|---|---|
| **Implemented** | Code exists in this repo and a named test passes today. |
| **Planned** | The design is decided; the code and test come in the phase named. |
| **Unverified** | It's an assumption or depends on a platform behavior we haven't tested. Don't rely on it until a spike or test closes it. |

Today `crates/arkhon-crypto`, `crates/arkhon-license` and `crates/arkhon-tpm` are placeholders, so
**every licensing and model-protection control below is Planned**. The only Implemented controls are
the organization rules (`crates/arkhon-org`, `suite/engine`) and the devserver's local API hardening.
Test names marked *(planned)* are where the proof will live. They don't exist yet.

---

## 1. What we protect (assets)

| ID | Asset | Owner | Why it matters |
|---|---|---|---|
| A1 | Customer content: mail, documents, indexes, drafts, meeting audio, adapters, logs | Customer | N1, the #1 adoption barrier. A leak ends trust in the product. |
| A2 | Connector OAuth tokens (mailboxes, books, CRM, drives) | Customer | A stolen token reads or changes the customer's systems directly. |
| A3 | Fine-tuned engine weights and Industry Pack assets | Arkhon | Core IP and the reason a license has value. |
| A4 | Root signing key (Ed25519) | Arkhon owner | Signs the trust anchor. Losing it means re-shipping every runtime. |
| A5 | Issuing signing key (Ed25519) | Arkhon | Signs licenses and release manifests. |
| A6 | Licenses and activation state | Arkhon and customer | Seat and site entitlement (N10). |
| A7 | License Manager database: customers, activations, billing references | Arkhon | Holds customer PII (contact, company) and payment references. |
| A8 | Organization state: people, roles, approvals, activity log | Customer | Who may do what (N9). The audit trail for disputes. |
| A9 | Update channel and installers | Arkhon | A malicious update runs as the customer, everywhere. |

## 2. Attackers

| ID | Attacker | Capability we assume |
|---|---|---|
| T1 | Remote internet attacker | Can reach public Arkhon services. Can send email and documents to customers. |
| T2 | Malicious web page in the customer's browser | Can make cross-site requests and use DNS rebinding against 127.0.0.1. |
| T3 | LAN peer on the customer's network | Can reach any port the machine exposes on the LAN. |
| T4 | Unprivileged local user or malware at user level | Reads the user's files, runs processes as the user. |
| T5 | Machine administrator (including a licensee who wants to pirate) | Root/Administrator. Can attach debuggers, read process memory, dump VRAM, patch binaries. |
| T6 | Insider at the customer | A legitimate member who abuses access. |
| T7 | Physical thief | Has the powered-off laptop or disk. |
| T8 | Supply-chain attacker | Compromises a dependency, model download, build machine or update host. |
| T9 | Arkhon insider or compromised Arkhon staff account | Has portal or server access. |

## 3. Components and trust boundaries

```
  OFFLINE (air-gapped, owner)            ARKHON CLOUD                          CUSTOMER MACHINE
 ┌───────────────────────┐   signs   ┌───────────────────────────┐  license  ┌──────────────────────────────┐
 │ Root Ed25519 key      │──────────▶│ Issuing Ed25519 key (KMS) │ metadata  │ Arkhon Runtime               │
 │ + revocation list     │  issuing  │ License Manager (axum)    │◀────────▶ │  activation, sealed storage, │
 └───────────────────────┘  pubkey   │ Postgres                  │   only    │  model router, TPM 2.0       │
                                     │ Admin / customer portals  │           │  in-memory decrypt → llama.cpp│
                                     │ Stripe (webhooks)         │           │        ▲ 127.0.0.1           │
                                     │ Update/release host       │──signed──▶│ Suite engine + app           │
                                     └───────────────────────────┘ manifests │  review queue, activity log, │
                                                                             │  connectors + token vault    │
                                                                             └──────────┬───────────────────┘
                                                                                        │ OAuth (customer's own
                                                                                        ▼ accounts, never Arkhon)
                                                                             M365, Google, QuickBooks, ...
```

| Boundary | Crosses | What may cross |
|---|---|---|
| B1 Offline → online | Root key ceremony | Signed issuing-key certificates and revocation lists. Never the root private key. |
| B2 Arkhon cloud ↔ customer | HTTPS to License Manager; portal file exchange when offline | License key, TPM public key, hardware fingerprint hash, seat counts, hashed member IDs, versions. **No content.** |
| B3 Update host → customer | HTTPS download | Installers, release manifests (issuing-key signed), encrypted model chunks. |
| B4 Runtime ↔ suite | 127.0.0.1 IPC/HTTP | Prompts and outputs. Same machine, same user. |
| B5 Suite ↔ LAN (opt-in) | LAN mode flag + token | Inference and suite calls from other office machines. |
| B6 Suite ↔ third-party apps | OAuth via connectors | The customer's own data, between the customer's machine and the customer's accounts. |
| B7 User ↔ untrusted content | Email bodies, attachments, shared documents | Text the model reads. Treated as data, never as instructions. |

## 4. Key hierarchy (as specified)

| Key | Algorithm | Where it lives | Signs or protects | Rotation and revocation |
|---|---|---|---|---|
| Root | Ed25519 | Generated by the owner on an air-gapped machine. Offline backups (location is owner process). | Issuing-key certificates and the issuing-key revocation list | Never rotated in normal life. Compromise means a new runtime build with a new embedded public key. |
| Issuing | Ed25519 | Online, in a KMS or secrets manager. Never in git (`SECURITY.md`, gitleaks). | Licenses and release manifests | Rotatable. A compromised key is added to the root-signed revocation list, which ships with updates and activation responses. |
| Runtime trust anchor | Root **public** key | Embedded in the runtime binary | Verifies issuing certs, then licenses and manifests | Changes only with a root change. |
| Release CEK | AES-256-GCM, one per release | Generated at packaging. Stored wrapped, never in plaintext outside the packaging host. | Model weights, chunked AES-256-GCM | New per release. |
| Machine key | TPM 2.0 P-256, non-exportable | Created inside the customer's TPM at activation | Unwraps the CEK: ECDH + HKDF + AES-GCM | New on each activation or transfer. |
| Software fallback | OS keystore or software key | Machines without a usable TPM | Same role as the machine key | License records `binding: software`. Each tier may refuse it. |
| Vault key | Symmetric | Sealed to the TPM (or OS keystore fallback) | Connector OAuth tokens (A2) and, planned, local suite state | Rotates on re-activation. |

Other specified mechanisms:
- **In-memory weights only.** Weights are decrypted into memory and handed to llama.cpp. On Linux this is a `memfd` with seals (no write, no grow, no shrink after load). The Windows approach is **TBD in Phase 1** (Unverified).
- **Clock rollback.** The runtime keeps a sealed monotonic "last seen" timestamp. A wall clock behind it is treated as tampering.
- **Offline sites.** They get 90-day licenses, renewed by exchanging a request file and a signed license file through the customer portal.
- **Traceability.** Each customer's engines carry a per-customer fingerprinted LoRA watermark. `tools/trace` (planned) identifies the customer from a leaked weight file or from model outputs.

## 5. STRIDE per component

Each row lists the threat, the attacker, the mitigation, the residual risk and the test that proves the mitigation.

### 5.1 Offline root key and issuing key

| # | STRIDE | Threat | Attacker | Mitigation | Residual | Proof |
|---|---|---|---|---|---|---|
| K1 | S/E | Root private key stolen, so attacker can mint issuing keys | T9, T8 | Generated and kept offline by the owner. Repo holds tooling only. gitleaks in pre-commit and CI. | Depends on the owner's physical process. **Owner process.** | Key-ceremony checklist signed at the Phase 3 gate *(planned: `docs/runbooks/key-ceremony.md`)*. gitleaks CI job (Implemented). |
| K2 | S | Issuing key stolen from KMS, so attacker signs licenses | T9, T1 | KMS with signing-only API and no export. Root-signed revocation list. Short-lived licenses for offline sites (90 days). | Licenses signed before revocation stay valid until the runtime gets the new list. | `license::revoked_issuer_rejected` *(planned, Phase 2)*. |
| K3 | T | Forged or edited license or manifest | T5 | Ed25519 over a canonical encoding. Chain: root → issuing → license. | Low. | `license::tampered_field_rejected`, `license::wrong_chain_rejected`, cargo-fuzz target `fuzz_license_parse` *(planned, Phase 2)*. |
| K4 | R | Arkhon can't show which key signed what | T9 | Signing log in the License Manager with key ID per license. | Low. | `server::every_license_has_key_id` *(planned, Phase 3)*. |

### 5.2 License Manager server, Postgres, portals, Stripe

| # | STRIDE | Threat | Attacker | Mitigation | Residual | Proof |
|---|---|---|---|---|---|---|
| L1 | S | Account takeover of a customer portal login | T1 | Email verification, MFA for owners, rate-limited login. | Phishing. | Portal auth tests *(planned, Phase 9)*. |
| L2 | E | Arkhon staff abuse the admin portal (free licenses, data browsing) | T9 | Role-based admin portal, MFA, every admin action logged and reviewed. | Insider with KMS access. | `server::admin_actions_logged` *(planned, Phase 3)*. |
| L3 | I | SQL injection or DB dump exposes customer PII (A7) | T1 | sqlx with bound parameters only. Least-privilege DB role. Encryption at rest. **No customer content exists in this DB** (N1). | PII of account contacts. | `server::no_content_fields_in_schema` schema test *(planned, Phase 3)*. |
| L4 | T | Forged Stripe webhook marks an invoice paid | T1 | Verify the Stripe signature on every webhook. Act only on events fetched back from Stripe. Test mode first. | Low. | `server::stripe_webhook_bad_sig_rejected` *(planned, Phase 9)*. |
| L5 | D | License server outage blocks customers | T1 | Runtime keeps working on a valid sealed license. Only activation and renewal need the server. Offline file exchange as a fallback. | Activation delays during outage. | `runtime::works_offline_with_valid_license` *(planned, Phase 4)*. |
| L6 | S | One license activated on many machines | T5 | Server activation count per license. TPM public key recorded per activation. Transfers deactivate the old key. | Software-bound activations are easier to clone (see R2). | `server::activation_limit_enforced` *(planned, Phase 3)*. |
| L7 | I | Activation payload leaks customer content | — | Fixed allow-list of fields (§7). The request type has no free-text field. | Low. | `runtime::activation_payload_allowlist` and the outbound-traffic test N1-T1 *(planned, Phase 4)*. |

### 5.3 Customer runtime: activation, sealed storage, in-memory decryption, router

| # | STRIDE | Threat | Attacker | Mitigation | Residual | Proof |
|---|---|---|---|---|---|---|
| R1 | I | Copy encrypted model files to another machine | T4, T5 | CEK is wrapped to a non-exportable TPM P-256 key. The files are useless without that TPM. | Low with TPM binding. | `tpm::unwrap_fails_on_other_tpm` *(planned, Phase 2, swtpm in CI)*. |
| R2 | I/S | Software binding (`binding: software`) key copied with the files | T5 | Flagged in the license. Each tier may refuse software binding. Fingerprint and activation count apply. | **Medium.** A software key is extractable by an admin. Accepted for tiers that allow it. | `license::tier_rejects_software_binding` *(planned, Phase 2)*. |
| R3 | I | Plaintext weights written to disk (swap, temp files, crash dumps) | T4, T7 | Decrypt into `memfd` with seals on Linux. Lock pages where possible. Disable core dumps for the runtime. | Windows path **TBD (Unverified)**. Hibernation files may hold memory pages (Unverified, guidance: disk encryption). | Phase 1 spike `spike::no_plaintext_on_disk` scans the filesystem and swap after load *(planned, Phase 1)*. |
| R4 | I | **Admin dumps RAM or VRAM during inference and recovers plaintext weights** | T5 | **Cannot be fully prevented** on hardware the customer controls. See §6 for how the gap is covered. | **Accepted.** | Trace CLI recovers the customer ID from a dumped file: `trace::identifies_customer_from_weights` *(planned, Phase 7)*. |
| R5 | T | Roll the clock back to extend a license | T5 | Sealed monotonic timestamp. Clock behind it means "license paused, fix the clock". | Admin with TPM reset can clear state, which forces re-activation (visible on the server). | `license::clock_rollback_detected` *(planned, Phase 2)*. |
| R6 | T | Patch the runtime to skip the license check | T5 | Signed binaries. The CEK only unwraps after a successful check (the check and the key release are one step). | **Medium.** A determined admin can patch the binary. Covered by §6. | Release signature test *(planned, Phase 10)*. |
| R7 | T | Malicious model file loaded through the router | T4, T8 | Router loads only models listed in an issuing-key-signed manifest, verified by hash. | Low. | `runtime::unsigned_model_refused` *(planned, Phase 4)*. |
| R8 | D | Local process exhausts GPU/RAM so the suite stalls | T4 | Router limits concurrent jobs. Graceful "busy" errors. | Local DoS by a local user is accepted. | Load test *(planned, Phase 4)*. |

### 5.4 Suite app, engine and local API

| # | STRIDE | Threat | Attacker | Mitigation | Residual | Proof |
|---|---|---|---|---|---|---|
| S1 | S | A web page calls the local API through DNS rebinding | T2 | **Implemented in devserver:** binds to 127.0.0.1, rejects any `Host` that isn't `127.0.0.1:<port>`/`localhost:<port>`. | Low. Must carry into the runtime API (Phase 4). | `suite/devserver/src/tests.rs::foreign_hosts_and_origins_are_blocked` (Implemented). |
| S2 | S/T | Cross-site POST (CSRF) runs a command | T2 | **Implemented:** foreign `Origin` rejected. State changes need `content-type: application/json` **and** the custom `x-arkhon-as` header, which forces a CORS preflight the server never approves. | Low. | `simple_cross_site_posts_are_rejected` (Implemented). |
| S3 | S | `x-arkhon-as` lets any local caller pick an identity | T4 | Dev-only. The desktop app replaces it with the signed-in local session (Phase 5). | **High in devserver if shipped.** It must never ship. | Release check that devserver isn't in installers *(planned, Phase 10)*. |
| S4 | S | Another LAN host calls inference or the suite | T3 | Binds to 127.0.0.1 by default. LAN mode needs an explicit flag **and** a token. | Token sent over plain HTTP on the LAN can be sniffed (Unverified: TLS for LAN mode is not decided). | `runtime::lan_requires_flag_and_token` *(planned, Phase 4)*. |
| S5 | E | A member performs admin actions or escalates their role | T6 | **Implemented:** permission checks in `arkhon-org`. No one can grant permissions they don't hold. Only owners touch owners. Last owner protected. Paused people have no permissions. | Low. | `crates/arkhon-org/src/tests.rs` (Implemented, ADR-0005 safety rules). |
| S6 | R | Someone denies doing an admin action | T6 | **Implemented:** the engine logs every command, including refusals. Only people with the activity permission can read the log. | The log is a local file an OS admin can edit (see S7). | `activity_records_and_is_admin_only` (Implemented). |
| S7 | I/T | Local suite state (org, activity log) read or edited on disk | T4, T7 | Today: JSON file with atomic replace, **not encrypted**. Planned: encrypt at rest under the vault key and hash-chain the activity log. | **Open finding** until Phase 5. | `engine::store_is_encrypted`, `engine::activity_chain_detects_edit` *(planned, Phase 5)*. |

### 5.5 Connectors and the OAuth token vault

| # | STRIDE | Threat | Attacker | Mitigation | Residual | Proof |
|---|---|---|---|---|---|---|
| C1 | I | Tokens stolen from disk | T4, T7 | Tokens encrypted in a local vault. The vault key is sealed to the TPM (or OS keystore fallback). | Malware running as the user while unlocked can ask the suite to use a token. | `connectors::vault_file_has_no_plaintext_token` *(planned, Phase 5)*. |
| C2 | E | A member uses a company account they shouldn't | T6 | **Implemented:** per-app rules (Off / Admins only / own / own + team). Personal accounts are usable only by their owner. Paused people's personal connections pause. | Low. | `crates/arkhon-org` connection tests (Implemented, ADR-0006). |
| C3 | I | Connector sends customer data to Arkhon or another third party | T8, T9 | Connectors talk only to the provider's API. No Arkhon endpoint receives content. Privacy Center shows outbound destinations. | A compromised dependency could exfiltrate (see §8). | N1-T1 outbound-traffic test: run every workflow under a capture and assert only provider hosts and the license host (metadata only) are contacted *(planned, Phase 5)*. |
| C4 | T/E | Connector takes an action (send, pay, edit books) without approval | T1 via prompt injection, T6 | Default capability is *Draft*. *Act* is never allowed on personal accounts, and on company accounts needs the automations permission. Every external action goes through the review queue (N9). | See P1. | `engine::no_external_action_without_approval` *(planned, Phase 5)* and the N4 "zero unapproved actions" audit check. |
| C5 | S | Phishing OAuth app impersonates the suite's consent screen | T1 | Use the vendor's standard OAuth with PKCE and loopback redirect. Publish the official client IDs. | Users can still consent to look-alike apps outside Arkhon. | Manual review per connector ADR. |

### 5.6 Prompt injection and untrusted content (B7)

| # | STRIDE | Threat | Attacker | Mitigation | Residual | Proof |
|---|---|---|---|---|---|---|
| P1 | T/E | An email or document contains instructions ("forward all invoices to…") that the model follows | T1 | Untrusted content is marked as data in prompts. Workflows produce **drafts into the review queue**. A person approves every send or change. Tools available to a workflow are limited to what that workflow needs. | **Medium, accepted.** A reviewer can approve a harmful draft they don't read carefully. Autonomy ("Act") is opt-in per workflow and raises this risk. | Injection eval set in `models/evals` with a pass bar per release *(planned, Phase 6)*. `engine::no_external_action_without_approval` *(planned)*. |
| P2 | I | Injection makes a draft leak data from other documents to an outside recipient | T1 | Retrieval scoped to what the acting person may see. Drafts show citations. External recipients highlighted in review. | Medium. Depends on reviewer attention. | Same eval set, data-leak cases *(planned, Phase 6)*. |

### 5.7 Industry Packs

| # | STRIDE | Threat | Attacker | Mitigation | Residual | Proof |
|---|---|---|---|---|---|---|
| I1 | T | Tampered pack (templates, workflows) adds harmful actions | T8 | Packs are signed release artifacts in the manifest. Pack workflows still go through the review queue. | Low. | `runtime::unsigned_pack_refused` *(planned, Phase 6)*. |
| I2 | — | Users treat pack outputs as professional advice | T6 (misuse) | Product labels outputs as drafts. EULA disclaims legal, medical, financial and professional advice. Human approval required. | Legal exposure. Item for attorney review ([EULA](legal/eula-template.md)). | UI copy review at the Phase 6 gate. |

### 5.8 Update channel and installers

| # | STRIDE | Threat | Attacker | Mitigation | Residual | Proof |
|---|---|---|---|---|---|---|
| U1 | T | Malicious update or installer | T8 | Installers code-signed. Release manifests signed by the issuing key and checked against the embedded root key. HTTPS only. | Compromise of the build machine (see §8). | `runtime::update_bad_signature_refused` *(planned, Phase 10)*. |
| U2 | T | Downgrade to an older, vulnerable or unprotected release | T5, T8 | Manifests carry a monotonic version. The runtime refuses versions below its sealed minimum. | Low. | `runtime::downgrade_refused` *(planned, Phase 10)*. |
| U3 | — | Licensee keeps using a cracked old build | T5 | **Update gating:** new engines, packs and fixes ship only to licenses in good standing. A cracked build freezes in time. | Accepted (see §6). | Server test that lapsed licenses get no manifests *(planned, Phase 3)*. |

## 6. The gap we accept: an admin dumping memory at inference time (R4, R6)

Weights have to exist in plaintext in RAM or VRAM for the GPU to use them. A machine administrator
can attach a debugger, read process memory, or read GPU memory. **No software design on
customer-owned hardware fully prevents this**, and this model doesn't claim it does. TPM binding
protects files at rest and in transit. It does not protect weights in use.

We cover the gap with three controls, so that extraction is detectable, attributable and costly:

| Control | How it covers the gap | Status |
|---|---|---|
| **Traceability** | Every customer's engines carry a per-customer fingerprinted LoRA watermark. `tools/trace` identifies which license a leaked weight file (or, with lower confidence, a model's outputs) came from. | Planned (Phase 7). Robustness to fine-tuning, quantization and merging is **Unverified** and must be measured. |
| **EULA** | Extracting, exporting or redistributing weights, circumventing encryption, and training competing models on outputs are explicit breaches. The customer is told about fingerprinting up front, which supports enforcement. | Template drafted, [attorney review pending](legal/eula-template.md). |
| **Update gating** | Extracted weights stop at the version they were taken from. New engines, Industry Packs, fixes and support go only to licenses in good standing. | Planned (Phase 3). |

Things that raise the cost but don't close the gap: in-memory-only decryption, sealed memfd,
disabled core dumps, signed binaries. Confidential-computing GPUs and hardware enclaves were not
considered for v1 because target customers run commodity hardware (ADR-0004).

## 7. Customer-data threats (N1)

What leaves the customer's machine, and to whom:

| Destination | Data | Never |
|---|---|---|
| Arkhon License Manager | License key, TPM public key, hashed hardware fingerprint, binding type, runtime and suite versions, seat counts, role names and counts, hashed member IDs (ADR-0005), activation timestamps | Prompts, outputs, documents, mail, indexes, adapters, names or emails of members, OAuth tokens |
| Update host | License ID (for update gating), current versions | Anything above |
| Customer's own connected apps | The customer's own data, through the customer's own OAuth grants | Arkhon never acts as a proxy |

| # | Threat | Attacker | Mitigation | Residual | Proof |
|---|---|---|---|---|---|
| N1-1 | Exfiltration via connectors | T1, T6, T8 | See C1–C4 and P1–P2. Draft-by-default. Review queue. Outbound-traffic test. | Medium via prompt injection plus careless approval. | N1-T1 outbound-traffic test *(planned, Phase 5)*. |
| N1-2 | Local API CSRF and DNS rebinding | T2 | Host and Origin checks, JSON + custom header. | Low. | Devserver tests (Implemented). Port the same tests to the runtime API *(planned, Phase 4)*. |
| N1-3 | Prompt injection from emails or documents causes unwanted actions | T1 | Review-queue approval (N9). Tool scoping. | **Medium, accepted.** Human approval is the last line. Opt-in "Act" increases risk. | Injection eval set *(planned, Phase 6)*. |
| N1-4 | Insider misuse | T6 | Roles and permissions (ADR-0005). Connection rules (ADR-0006). Activity log of every command and refusal. | An owner or admin can still see a lot. That is by design. The log is editable by an OS admin until S7 lands. | `arkhon-org` and engine tests (Implemented). Hash chain *(planned)*. |
| N1-5 | Lost or stolen laptop | T7 | Guidance: full-disk encryption (BitLocker, FileVault, LUKS) required by the onboarding checklist. Vault key sealed in the TPM. Weights never in plaintext on disk. | Unencrypted disk exposes suite state (S7) until Phase 5. Hibernation file (Unverified). | Env-check warns when disk encryption is off *(planned, `tools/env-check`)*. |
| N1-6 | Arkhon telemetry or crash reports carry content | T9 | No content telemetry. Crash reports are opt-in and stripped of prompts and paths. | Low. | N1-T1 outbound-traffic test *(planned)*. |

## 8. Supply chain

| # | Threat | Mitigation | Residual | Proof |
|---|---|---|---|---|
| SC1 | Tampered base model download | We convert from the base model's **official safetensors** ourselves. Pin and record hashes in `models/registry.yaml`. Never use third-party pre-quantized files. Licenses verified per ADR-0001. | Compromise of the official source. | Registry hash check in `models/tests` *(planned, Phase 7)*. |
| SC2 | Malicious or vulnerable Rust/Python/npm dependency | `cargo audit` and `cargo deny` (licenses and advisories), `pip-audit`, `npm audit` in CI. Lockfiles committed. New dependencies reviewed in PRs. | Zero-days in pinned dependencies. | CI audit jobs *(planned, Phase 2; `Cargo.lock` committed today)*. |
| SC3 | Unknown components in a release | SBOM (CycloneDX or SPDX) generated for every release and shipped with it. | Low. | Release pipeline step *(planned, Phase 10)*. |
| SC4 | Tampered installer | Code-signed installers (Windows Authenticode, macOS notarization). Manifest signatures (U1). | Theft of the code-signing certificate. | U1 test *(planned, Phase 10)*. |
| SC5 | Compromised build machine | **Goal:** reproducible builds, so an independent rebuild can confirm a release. Hardened CI with short-lived credentials. | Reproducibility is a goal, **not yet achieved**. | Rebuild comparison *(planned, Phase 10)*. |
| SC6 | Secrets committed to git | gitleaks pre-commit and CI over full history. Rotate first, then purge. | Low. | gitleaks CI job (Implemented). |

## 9. Open items

1. Windows in-memory loading approach (R3). Decide in the Phase 1 spike.
2. TLS for LAN mode (S4).
3. Encrypting local suite state and hash-chaining the activity log (S7). Phase 5.
4. Watermark robustness against fine-tuning, quantization and merging (§6). Measure in Phase 7.
5. Which tiers allow `binding: software` (R2). Product and pricing decision.
6. Hibernation and crash-dump behavior on each OS (R3, N1-5).
7. Key ceremony runbook and root-key backup locations (K1). Owner process.
8. Legal review of the EULA clauses this model relies on (§6, I2).
