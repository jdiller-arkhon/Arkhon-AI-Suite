# ADR-0009: In-memory model loading (Phase 1 result)

- Status: **Linux: Go** (verified 2026-11-06 with swtpm). **Windows and macOS: open**, needing hardware.
- Implementation: `runtime/src/memload.rs`; demos `runtime/src/bin/p1-spike.rs` and `p1-e2e.rs`
- Evidence: `models/evals/runs/2026-11-06-p1-*.txt`

## Linux design (verified)
1. `harden_process()`: non-dumpable, which blocks same-user ptrace and `/proc/<pid>/mem`, and `RLIMIT_CORE=0`.
2. Verify the license (`arkhon_license::verify`), then unwrap the engine CEK through the TPM's non-exportable P-256 key.
3. `SealedModel::create`: `memfd_create` (anonymous and RAM-backed, with no filesystem path). `decrypt_model` writes each authenticated chunk straight into it. Then it is sealed: `WRITE | GROW | SHRINK | SEAL`.
4. llama-server is spawned with the fd inherited, opening `/proc/self/fd/N`, and `--load-mode mmap+mlock`, so the mapped pages are locked in RAM and can't be swapped.

## Measured (4 vCPU Xeon, Qwen3-0.6B Q8_0, 639 MB, CPU only)
| | Plaintext → memfd (baseline) | **Encrypted → TPM unwrap → memfd** |
|---|---|---|
| License verify + TPM unwrap | — | 35 ms |
| Into memfd | 459 ms warm / 4,835 ms cold | **1,375 ms** (decrypt + write) |
| Server ready | 3,248 ms | 4,073 ms |
| 25–32 token completion | 679 ms | 772 ms |

Decryption overhead is about 1 s per 640 MB on this CPU. That's acceptable: a 9B Q4 engine (about 5.5 GB) should take around 10 s.

**No plaintext on disk.** The plaintext source was deleted before the run. Afterwards, every regular file on `/` (321,714 files, 25.6 GB) was scanned for 8 random 64-byte probes taken from the plaintext. The 7 probes from the weight region had **0 hits**. The only hits were for probe 0, which falls in public tokenizer strings that llama.cpp's own unmodified vocab test files also contain. There is no swap on this host. The server process mapped the model from `/memfd:arkhon-model`.

## Production requirements found
- `mlock` worked here because the process runs as root. A service account needs `LimitMEMLOCK=infinity` (systemd) or `CAP_IPC_LOCK`, set by the installer.
- Pin llama.cpp to an exact commit. This run used `6c01da6`. Its flag is `--load-mode mmap+mlock`, which replaced the old `--mlock`.
- The child llama-server process is dumpable again after `exec`. Run it under a dedicated user with the core-dump limit inherited, and consider linking llama.cpp in-process (Phase 4) to keep one hardened process.

## Windows and macOS (open, need hardware)
- **Windows options:**
  - (a) a llama.cpp buffer-loading patch;
  - (b) a pagefile-backed section mapping without a file name (`CreateFileMapping(INVALID_HANDLE_VALUE)` + `VirtualLock`), passed by handle to an in-process loader;
  - (c) in-process linking with `llama_model_load_from_buffer`-style loading.

  **Recommendation:** (c), in-process linking. It avoids the problem of handing a file to a child process entirely. Needs a Windows runner with a TPM (TBS).
- **macOS:** the Secure Enclave replaces the TPM. Loading uses an anonymous `mmap` and in-process loading.
