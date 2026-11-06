# env-check

Stdlib-only Python hardware report: OS, CPU, RAM, NVIDIA GPU/VRAM, CUDA, TPM 2.0, disk, and the
Arkhon tier (S/M/L). It sends nothing over the network.

```bash
cd tools/env-check
python -m arkhon_envcheck.check --json reports/$(hostname).json   # reports/*.json are git-ignored
```
On Windows, run it from an **elevated** PowerShell so the TPM query succeeds.
This tool becomes the basis for the runtime's automatic hardware detection (N2).
