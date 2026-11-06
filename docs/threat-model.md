# Threat model (skeleton — completed in Phase 2 and reviewed in Phase 10)

| Asset | Threat | Mitigation | Residual risk |
|-------|--------|-----------|---------------|
| Engine weights | Copying the encrypted files | CEK wrapped to a non-exportable TPM key | Low |
| Engine weights | Admin-level attacker dumps RAM/VRAM at inference time | Not fully preventable. Covered by per-customer fingerprinting + `tools/trace`, EULA, update gating | **Accepted, mitigated by traceability** |
| License | Forgery or tampering | Ed25519 over canonical encoding; root → issuing chain; revocation list | Low |
| License | Clock rollback to extend expiry | Monotonic sealed timestamp | Low |
| License | Sharing a license across machines | TPM binding + fingerprint + server activation count | Low–Med (software binding) |
| Customer data | Exfiltration to Arkhon or third parties | No content in any Arkhon API; outbound-traffic test; Privacy Center log | Low |
| Local API | Other LAN hosts calling inference | Binds to 127.0.0.1; LAN mode needs a flag + token | Low |
| Signing keys | Root key theft | Generated and kept offline by the owner; repo holds tooling only | Owner process |
