# ADR-0004: Hardware-neutral support — no single reference machine

- Status: Accepted (owner direction, 2026-11-06) · Needs: N2, N10

## Context
The brief named one development box (an RTX 5070, 12 GB) for benchmarks and local training. The owner
clarified that the product must not be built *for* that machine. Customers run whatever they already
own or buy (N10), and setup must be automatic on all of it (N2).

## Decision
1. **Tiers are defined by memory, not by a GPU model.** A tier is the largest accelerator memory pool: discrete VRAM, or the GPU-usable share of unified memory on Apple Silicon, together with system RAM. `tools/env-check` implements this for every vendor.
2. **Supported backends, all through llama.cpp/whisper.cpp:**

   | Platform | Backend | Binding root of trust |
   |---|---|---|
   | NVIDIA (Win/Linux) | CUDA | TPM 2.0 |
   | AMD Radeon (Linux) | ROCm, else Vulkan | TPM 2.0 |
   | AMD / Intel Arc (Windows) | Vulkan | TPM 2.0 |
   | Apple Silicon (macOS) | Metal (unified memory) | Secure Enclave (P-256; see below) |
   | Any x86-64 / arm64 CPU | CPU (AVX2 / NEON) | TPM 2.0 or OS keystore (`binding: software`) |

3. **Benchmarks come from a reference-hardware matrix, never from one box.** Every `models/registry.yaml` quant entry records `measured_on` (a machine ID from `docs/hardware-matrix.md`) plus a raw run log. A quant ships for a tier only once it has been measured on at least one machine per backend that tier claims.
4. **The model router chooses at runtime.** It picks engine and quant from the *measured* free memory and backend at startup, not from a lookup table keyed on GPU model.
5. **macOS has no TPM.** The Phase 2 `arkhon-tpm` crate gets a Secure Enclave provider: a non-exportable P-256 key, with ECDH + HKDF to unwrap the CEK. It is recorded as `binding: secure-enclave`, and the server policy treats it as hardware-bound. Any deviation from the brief's "TPM 2.0" wording is covered by this ADR.
6. **The owner's RTX 5070 is one machine in the matrix** (NVIDIA, tier M) and a convenient place for local training runs. Nothing is tuned to it specifically.

## Consequences
- CI needs hardware runners per backend (Phase 1/4): NVIDIA, AMD or Intel (Vulkan), and Apple Silicon (GitHub's hosted `macos-14+` arm64 runners cover Metal). Physical TPM tests need self-hosted machines, or `swtpm` in CI for logic tests.
- More quant/benchmark work per release. This is bounded by building quants once and *measuring* them per backend.
- Unverified until Phase 1 measurement: Vulkan and ROCm performance on the Qwen3.5 architectures, and the true Metal working-set limit (the runtime reads `recommendedMaxWorkingSetSize`; env-check's 2/3 or 3/4 rule is only an approximation).
