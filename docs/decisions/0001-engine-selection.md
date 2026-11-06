# ADR-0001: Engine base selection and license verification

- Status: **Accepted**. The owner approved the engine section on 2026-11-06, including Decision 2 (Vision = Core weights + Vision LoRA). The Phase 7 ship gate can still move Vision to its own weights if the LoRA doesn't beat the base model on document extraction.
- Date: 2026-11-06
- Needs served: N1 (local-only), N2 (automatic selection), N10 (no per-token cost)

## Context
Arkhon engines may only be built on **Apache-2.0 or MIT** bases (brief §5). The brief lists candidate
bases from earlier research; this ADR re-verifies each one against primary sources.

**Method.** On 2026-11-06 we read, for each repo, the Hugging Face model API
(`https://huggingface.co/api/models/<repo>`), `raw/main/config.json`, and the `LICENSE` file, plus
llama.cpp `src/llama-arch.cpp` on `master`. A claim is marked **UNVERIFIED** when no primary source
confirmed it.

## Verified findings (accessed 2026-11-06)

| Engine | Base (HF repo) | License (source) | Params | Context | Arch / GGUF | Verdict |
|---|---|---|---|---|---|---|
| Lite | `Qwen/Qwen3.5-4B` (2026-02-27) | Apache-2.0 (LICENSE file) | 4.66 B | 262,144 | `qwen35`, natively VL. GGUF: `unsloth/Qwen3.5-4B-GGUF` | ✅ Keep |
| Core | `Qwen/Qwen3.5-9B` (2026-02-27) | Apache-2.0 (LICENSE file) | 9.65 B | 262,144 | `qwen35`, natively VL. GGUF: `unsloth/Qwen3.5-9B-GGUF`. `Qwen/Qwen3.5-9B-GGUF` returns 404 | ✅ Keep |
| Vision | `Qwen/Qwen3.5-9B` (same checkpoint) | Apache-2.0 | 9.65 B | 262,144 | Same as Core | ✅ Keep. **Proposal below.** |
| Reason | `openai/gpt-oss-20b` (2025-08-04) | Apache-2.0 (LICENSE) + `USAGE_POLICY` | 20.9 B total; 32 experts, 4 active | 131,072 | `gpt-oss`, text only. Official `ggml-org/gpt-oss-20b-GGUF` | ✅ Keep. Ship USAGE_POLICY in NOTICE. |
| Pro | `Qwen/Qwen3.6-35B-A3B` (2026-04-15) | Apache-2.0 (LICENSE file) | 35.95 B total; 256 experts, 8 active (the "~3 B active" figure is UNVERIFIED) | 262,144 | `qwen35moe`, VL. GGUF: `unsloth/Qwen3.6-35B-A3B-GGUF` | ✅ Keep |
| Code | `Qwen/Qwen3.6-27B` (2026-04-21) | Apache-2.0 (LICENSE file) | 27.78 B dense | 262,144 | `qwen35`, VL. GGUF: `unsloth/Qwen3.6-27B-GGUF` | ✅ Keep |
| Embed | `Qwen/Qwen3-Embedding-0.6B` / `-4B` | Apache-2.0 | 0.60 B / 4.02 B | 32 K (model card; config not read, UNVERIFIED) | `qwen3`. Official `Qwen/Qwen3-Embedding-0.6B-GGUF` | ✅ Keep |
| Rerank | `Qwen/Qwen3-Reranker-0.6B` / `-4B` | Apache-2.0 | 0.60 B / 4.02 B | UNVERIFIED | `qwen3`. Official GGUF not found (UNVERIFIED) | ✅ Keep. Convert ourselves in Phase 1. |
| Scribe | `openai/whisper-large-v3-turbo` | **MIT** | 809 M | 30 s window | whisper.cpp (support UNVERIFIED this session) | ✅ Keep |
| Scribe (S tier) | `openai/whisper-small` | HF tag says Apache-2.0; upstream Whisper repo is MIT. LICENSE file not read | ~244 M (UNVERIFIED) | 30 s | whisper.cpp | ✅ Provisional. Read the LICENSE file in Phase 1. |

### Rejected or flagged speech options
| Model | License | Decision |
|---|---|---|
| `nvidia/parakeet-tdt-0.6b-v3` | CC-BY-4.0 | ❌ Not Apache-2.0 or MIT, so not allowed under the brief's rule (even though it permits commercial use with attribution). |
| `nvidia/diar_sortformer_4spk-v1` | CC-BY-NC-4.0 | ❌ Non-commercial. Never use. |
| `pyannote/speaker-diarization-community-1` | CC-BY-4.0, gated | ❌ Not Apache-2.0 or MIT. |
| `pyannote/speaker-diarization-3.1` | MIT, gated (click-through) | ⚠️ The only verified MIT diarization pipeline. Its `segmentation-3.0` dependency license is UNVERIFIED. Decide in Phase 6 after reading both LICENSE files and the gate terms. |

## Decisions
1. **Keep every base in the brief's lineup.** All are Apache-2.0 or MIT, all exist, and all LLMs have a llama.cpp architecture on master.
2. **Proposal: Vision = Core weights + Vision LoRA.** Qwen3.5-9B is natively vision-language, so the Vision and Core engines can share one encrypted base (plus the `mmproj` projector), with Docs-specific behavior in a LoRA. This saves about 5–6 GB of download and VRAM residency on tier M, and the router can hot-swap adapters. *Owner decision needed.*
3. **Lite also handles images on tier S.** Qwen3.5-4B is VL, so tier S gets degraded but working Docs extraction instead of none. Its quality will be measured before we claim it.
4. **Diarization is deferred to Phase 6.** Ship transcripts without speaker labels unless pyannote 3.1 and its dependencies all clear as MIT.
5. **Pin a llama.cpp build in Phase 1.** We couldn't find the minimum release tag that supports `qwen35` / `qwen35moe` (UNVERIFIED). Phase 1 pins an exact commit and records it here.

## Open items for later phases
- Measure VRAM, RAM, tok/s and quality deltas per quant on each backend in the reference hardware matrix (ADR-0004). `models/registry.yaml` `quants` stay empty until then, because the schema requires a saved run log.
- Check whether a Qwen3.5-generation embedding or reranker exists. Also check for 2026 Apache/MIT competitors (Gemma, Mistral, Granite). Not checked this session: UNVERIFIED.
- Third-party GGUFs (unsloth) are a convenience only. Release builds will **convert and quantize from the official safetensors ourselves**, so the supply chain is ours and checksums are reproducible.

## Consequences
- `NOTICE` must carry Apache-2.0 attribution for the Qwen and gpt-oss models, the MIT notice for Whisper, and gpt-oss's `USAGE_POLICY`.
- Public wording: "Arkhon engines, fine-tuned from [base]."

## Sources (all accessed 2026-11-06)
- https://huggingface.co/Qwen/Qwen3.5-4B · /Qwen/Qwen3.5-9B · /Qwen/Qwen3.6-35B-A3B · /Qwen/Qwen3.6-27B (API, config.json, LICENSE)
- https://huggingface.co/openai/gpt-oss-20b (LICENSE, USAGE_POLICY) · https://huggingface.co/ggml-org/gpt-oss-20b-GGUF
- https://huggingface.co/Qwen/Qwen3-Embedding-0.6B · /Qwen/Qwen3-Embedding-0.6B-GGUF · /Qwen/Qwen3-Reranker-0.6B
- https://huggingface.co/openai/whisper-large-v3-turbo · /openai/whisper-small
- https://huggingface.co/nvidia/parakeet-tdt-0.6b-v3 · /nvidia/diar_sortformer_4spk-v1 · /pyannote/speaker-diarization-3.1 · /pyannote/speaker-diarization-community-1
- https://raw.githubusercontent.com/ggml-org/llama.cpp/master/src/llama-arch.cpp
