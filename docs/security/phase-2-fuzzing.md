# Phase 2 fuzzing results

Date: 2026-11-06. Host: 4 vCPU Xeon @ 2.1 GHz build container. Toolchain: nightly + cargo-fuzz (libFuzzer), `-O`.
Command per target: `cargo +nightly fuzz run -O <target> corpus/<target> -- -max_total_time=280 -rss_limit_mb=2048`.
Seed corpora are the published test vectors. Each target asserts **no panics**, and that any input it accepts is the **canonical encoding** (re-encodes byte-for-byte).

| Target | Runs | Seconds | Crashes / failures |
|---|---|---|---|
| `license_decode` | 14268691 | 281 | 0 |
| `cert_decode` | 55786313 | 282 | 0 |
| `revocation_decode` | 38139348 | 282 | 0 |
| `renewal_decode` | 34120823 | 282 | 0 |
| `manifest_decode` | 34039078 | 284 | 0 |
| `model_header` | 81151216 | 283 | 0 |
| `model_decrypt` | 9839128 | 281 | 0 |

**Total: 1,975 s (32.9 minutes), 0 crashes, 0 failed assertions, no crash artifacts.** Gate requirement: at least 30 minutes with no crashes. Met.

The first four targets ran in one session. A worker restart interrupted `manifest_decode`, so it was re-run in full with the last two targets. All logs ended with libFuzzer's `Done N runs` line.
