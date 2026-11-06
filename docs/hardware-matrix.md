# Reference hardware matrix

Benchmarks (`models/registry.yaml → quants[].measured_on`) must reference a machine ID listed here.
The goal is coverage per **backend × tier**. No single machine is "the" target (ADR-0004).

| ID | Class | Backend | Accel memory | RAM | Tier | Status |
|----|-------|---------|--------------|-----|------|--------|
| ref-cpu-16 | Office desktop/laptop, no GPU | CPU (AVX2) | — | 16 GB | S | needed |
| ref-nv-8 | Entry NVIDIA (e.g. RTX 4060/5060 8 GB) | CUDA | 8 GB | 16–32 GB | S | needed |
| ref-nv-12 | Owner dev box, RTX 5070 | CUDA | 12 GB | TBD (run env-check) | M | available |
| ref-nv-16 | Mid NVIDIA 16 GB (e.g. 4060 Ti/5060 Ti 16 GB) | CUDA | 16 GB | 32/64 GB | M/L | needed |
| ref-nv-24 | High NVIDIA 24 GB+ (e.g. 3090/4090/5090) | CUDA | 24–32 GB | 64 GB | L | needed (rent) |
| ref-amd-16 | AMD Radeon 16 GB (e.g. RX 7800 XT/9070) | ROCm/Vulkan | 16 GB | 32 GB | M | needed |
| ref-intel-12 | Intel Arc B580 12 GB | Vulkan | 12 GB | 32 GB | M | needed |
| ref-mac-16 | Apple Silicon 16 GB | Metal | ~10.7 GB usable | 16 GB | S | CI hosted runner (verify) |
| ref-mac-36 | Apple Silicon 36–64 GB | Metal | 24–48 GB usable | 36–64 GB | L | needed |

Sourcing plan, decided at the Phase 1 gate: borrow or buy the "needed" boxes, or rent cloud
instances where a matching GPU exists. Physical TPM tests need real machines; `swtpm` covers
protocol logic in CI.

Record each machine by running `python -m arkhon_envcheck.check --json` and committing a redacted
summary row here. Never commit the raw JSON (hostnames/serials are git-ignored).
