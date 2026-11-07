# Environment report — Phase 0

## Reference machines: **PENDING — see `docs/hardware-matrix.md`**
The product targets any customer hardware (ADR-0004). The owner's RTX 5070 is one reference machine (`ref-nv-12`).

### ref-nv-12 (owner dev box)
This build ran in a sandboxed cloud container. It cannot see the owner's machine, so no hardware
values are asserted here. Run this and attach the output to the gate PR:

```bash
cd tools/env-check && python -m arkhon_envcheck.check --json reports/ref-nv-12.json
```
On Windows, also run these in an elevated PowerShell: `nvidia-smi`, `Get-Tpm`, and `tpm.msc`
(confirm "Specification Version: 2.0").
Expected (to be confirmed, not assumed): RTX 5070, 12 GB VRAM, Blackwell compute capability 12.0 →
tier **M**. CUDA 12.8+ is needed for Blackwell (sm_120) builds of llama.cpp. Verify against the
NVIDIA release notes in Phase 1.

## Build container (measured 2026-11-06, `python -m arkhon_envcheck.check`)
```
OS        : Linux-6.18.44-fc-v242-x86_64-with-glibc2.39 (x86_64)
CPU       : Intel(R) Xeon(R) Processor @ 2.10GHz x4
RAM       : 15.7 GiB   free disk: 27.9 GiB
GPU       : none
TPM       : present=False (no /sys/class/tpm/tpm0)
Tier      : S
```
Toolchain: rustc 1.97.0, cargo 1.97.0, Python 3.13.18, Node 22.23.4, pnpm available.
Consequence: GPU and TPM work (Phase 1 onward) needs real hardware across backends. **Recommendation:**
self-hosted runners labelled by backend (`cuda`, `vulkan`, `rocm`, `tpm`), with Metal covered by GitHub's
hosted Apple Silicon runners. See `docs/hardware-matrix.md`.
