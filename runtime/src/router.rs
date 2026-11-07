//! Model router: picks the engine (and quantization) for a task from `models/registry.yaml`,
//! following each engine's fallback chain (e.g. pro → core → lite), restricted to engines the
//! license entitles and that fit this computer's tier. Every decision carries a plain reason.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::Deserialize;

use crate::hardware::Tier;

/// The registry shipped in this repository (engine names, tiers, fallbacks, quants).
pub const BUNDLED_REGISTRY: &str = include_str!("../../models/registry.yaml");

/// One measured quantization of an engine.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct QuantSpec {
    /// Quantization name.
    #[serde(alias = "quant")]
    pub name: String,
    /// Tiers this quant is meant for (optional; empty: any tier the engine supports).
    #[serde(default)]
    pub tiers: Vec<String>,
    /// Measured accelerator memory needed (MiB), from the registry's run logs.
    #[serde(default)]
    pub vram_mib: Option<u64>,
    /// Measured system memory needed for CPU inference (MiB).
    #[serde(default)]
    pub ram_mib: Option<u64>,
}

/// Memory available for a model (MiB), when known.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Memory {
    /// Usable accelerator memory (0 if no GPU).
    pub accel_mib: u64,
    /// System RAM.
    pub ram_mib: u64,
}

impl QuantSpec {
    fn fits(&self, tier: Tier, mem: Option<Memory>) -> bool {
        let tier_ok =
            self.tiers.is_empty() || self.tiers.iter().any(|t| Tier::parse(t) == Some(tier));
        let mem_ok = match mem {
            None => true,
            Some(m) if m.accel_mib > 0 => self.vram_mib.is_none_or(|v| v <= m.accel_mib),
            Some(m) => self.ram_mib.is_none_or(|r| r <= m.ram_mib),
        };
        tier_ok && mem_ok
    }
}

/// An engine entry. Unknown registry fields are ignored.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct EngineSpec {
    /// What the engine is for.
    pub role: String,
    /// Tiers it runs on.
    pub tiers: Vec<String>,
    /// Next engine to try when this one can't be used.
    pub fallback: Option<String>,
    /// Inference runtime (`whisper.cpp`; default llama.cpp).
    #[serde(default)]
    pub runtime: Option<String>,
    /// Measured quantizations, best first.
    #[serde(default)]
    pub quants: Vec<QuantSpec>,
}

impl EngineSpec {
    fn fits(&self, tier: Tier) -> bool {
        self.tiers.iter().any(|t| Tier::parse(t) == Some(tier))
    }

    /// First quant (registry order: best first) that fits the tier and the measured memory.
    fn quant_for(&self, tier: Tier, mem: Option<Memory>) -> Option<String> {
        self.quants
            .iter()
            .find(|q| q.fits(tier, mem))
            .map(|q| q.name.clone())
    }
}

/// The engine registry.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Registry {
    /// Registry schema version.
    pub schema_version: u32,
    /// Engines by name.
    pub engines: BTreeMap<String, EngineSpec>,
}

impl Registry {
    /// Parse registry YAML.
    ///
    /// # Errors
    /// The parser's message if the YAML doesn't match the expected shape.
    pub fn from_yaml(yaml: &str) -> Result<Self, String> {
        let r: Registry = serde_norway::from_str(yaml).map_err(|e| e.to_string())?;
        if r.schema_version != 1 {
            return Err(format!("unsupported registry schema {}", r.schema_version));
        }
        Ok(r)
    }

    /// The registry bundled into this build.
    ///
    /// # Panics
    /// Never in a release that passed CI (the bundled file is parsed by a test).
    #[must_use]
    pub fn bundled() -> Self {
        Self::from_yaml(BUNDLED_REGISTRY).expect("bundled registry parses")
    }
}

/// What the caller wants done.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Task {
    /// Writing and grounded answers.
    Chat,
    /// Fast classification and triage.
    Triage,
    /// Long documents and complex drafting.
    LongDocument,
    /// Calculation and verification.
    Reasoning,
    /// Code.
    Code,
    /// Documents as images (OCR, forms).
    Vision,
    /// Retrieval embeddings.
    Embedding,
    /// Retrieval reranking.
    Rerank,
    /// Speech to text.
    Transcription,
}

impl Task {
    /// Every task.
    pub const ALL: [Task; 9] = [
        Task::Chat,
        Task::Triage,
        Task::LongDocument,
        Task::Reasoning,
        Task::Code,
        Task::Vision,
        Task::Embedding,
        Task::Rerank,
        Task::Transcription,
    ];

    /// The engine tried first.
    #[must_use]
    pub fn preferred_engine(self) -> &'static str {
        match self {
            Task::Chat => "core",
            Task::Triage => "lite",
            Task::LongDocument => "pro",
            Task::Reasoning => "reason",
            Task::Code => "code",
            Task::Vision => "vision",
            Task::Embedding => "embed",
            Task::Rerank => "rerank",
            Task::Transcription => "scribe",
        }
    }

    /// Stable name (accepted as the `model` field of API requests).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Task::Chat => "chat",
            Task::Triage => "triage",
            Task::LongDocument => "long-document",
            Task::Reasoning => "reasoning",
            Task::Code => "code-task",
            Task::Vision => "vision-task",
            Task::Embedding => "embedding",
            Task::Rerank => "rerank-task",
            Task::Transcription => "transcription",
        }
    }

    /// Inverse of [`Task::as_str`].
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.as_str() == s)
    }
}

/// A routing decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    /// Chosen engine.
    pub engine: String,
    /// Chosen quantization, if one has been measured for this tier.
    pub quant: Option<String>,
    /// `llama.cpp` or `whisper.cpp`.
    pub runtime: String,
    /// True if the first choice couldn't be used.
    pub fell_back: bool,
    /// Plain-language explanation.
    pub reason: String,
}

/// No engine could serve the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoEngine {
    /// What was asked for.
    pub requested: String,
    /// Why each candidate was skipped.
    pub skipped: Vec<String>,
}

impl fmt::Display for NoEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Arkhon can't do \"{}\" on this computer with your plan: {}.",
            self.requested,
            self.skipped.join("; ")
        )
    }
}

impl std::error::Error for NoEngine {}

/// Routes tasks to engines.
#[derive(Debug, Clone)]
pub struct ModelRouter {
    registry: Registry,
    tier: Tier,
    entitled: BTreeSet<String>,
    memory: Option<Memory>,
}

impl ModelRouter {
    /// A router for `tier`, allowed to choose only from `entitled` (the license's engines).
    #[must_use]
    pub fn new(registry: Registry, tier: Tier, entitled: BTreeSet<String>) -> Self {
        Self {
            registry,
            tier,
            entitled,
            memory: None,
        }
    }

    /// Also pick quantizations by measured memory needs (from hardware detection).
    #[must_use]
    pub fn with_memory(mut self, memory: Memory) -> Self {
        self.memory = Some(memory);
        self
    }

    /// This computer's tier.
    #[must_use]
    pub fn tier(&self) -> Tier {
        self.tier
    }

    /// Engines the license allows.
    #[must_use]
    pub fn entitled(&self) -> &BTreeSet<String> {
        &self.entitled
    }

    /// Route a task.
    ///
    /// # Errors
    /// [`NoEngine`] with the reason each candidate was skipped.
    pub fn route(&self, task: Task) -> Result<Route, NoEngine> {
        self.route_from(task.preferred_engine(), task.as_str())
    }

    /// Route an API `model` field: an engine name starts its fallback chain, a task name routes
    /// that task, and anything else (or nothing) routes `default`.
    ///
    /// # Errors
    /// [`NoEngine`].
    pub fn route_model(&self, model: Option<&str>, default: Task) -> Result<Route, NoEngine> {
        match model {
            Some(m) if self.registry.engines.contains_key(m) => self.route_from(m, m),
            Some(m) => match Task::parse(m) {
                Some(t) => self.route(t),
                None => self.route(default),
            },
            None => self.route(default),
        }
    }

    fn route_from(&self, start: &str, requested: &str) -> Result<Route, NoEngine> {
        let mut skipped = Vec::new();
        let mut seen = BTreeSet::new();
        let mut next = Some(start.to_owned());
        while let Some(name) = next.take() {
            if !seen.insert(name.clone()) {
                break; // a cycle in the registry
            }
            let Some(spec) = self.registry.engines.get(&name) else {
                skipped.push(format!("\"{name}\" isn't a known engine"));
                break;
            };
            next.clone_from(&spec.fallback);
            if !self.entitled.contains(&name) {
                skipped.push(format!("\"{name}\" isn't in your plan"));
                continue;
            }
            if !spec.fits(self.tier) {
                skipped.push(format!(
                    "\"{name}\" needs a more powerful computer (this one is tier {})",
                    self.tier
                ));
                continue;
            }
            let fell_back = name != start;
            let reason = if fell_back {
                format!("Using \"{name}\" because {}.", skipped.join(" and "))
            } else {
                format!("Using \"{name}\" ({}).", spec.role)
            };
            return Ok(Route {
                quant: spec.quant_for(self.tier, self.memory),
                runtime: spec.runtime.clone().unwrap_or_else(|| "llama.cpp".into()),
                engine: name,
                fell_back,
                reason,
            });
        }
        Err(NoEngine {
            requested: requested.to_owned(),
            skipped,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const YAML: &str = r"
schema_version: 1
engines:
  lite:   {role: fast, tiers: [S, M, L], fallback: null, quants: [{name: q-s, tiers: [S]}, {name: q-ml}]}
  core:   {role: workhorse, tiers: [M, L], fallback: lite, quants: []}
  pro:    {role: long docs, tiers: [L], fallback: core}
  loop-a: {role: x, tiers: [L], fallback: loop-b}
  loop-b: {role: x, tiers: [L], fallback: loop-a}
  scribe: {role: speech, tiers: [M, L], runtime: whisper.cpp, fallback: scribe-small}
  scribe-small: {role: speech small, tiers: [S, M, L], runtime: whisper.cpp, fallback: null}
";

    fn set(e: &[&str]) -> BTreeSet<String> {
        e.iter().map(|s| (*s).to_owned()).collect()
    }

    fn router(tier: Tier, ent: &[&str]) -> ModelRouter {
        ModelRouter::new(Registry::from_yaml(YAML).unwrap(), tier, set(ent))
    }

    #[test]
    fn bundled_registry_parses_and_chains_resolve() {
        let r = Registry::bundled();
        for (name, spec) in &r.engines {
            if let Some(fb) = &spec.fallback {
                assert!(r.engines.contains_key(fb), "{name} -> {fb}");
            }
            assert!(spec.tiers.iter().all(|t| Tier::parse(t).is_some()));
        }
        for t in Task::ALL {
            assert!(r.engines.contains_key(t.preferred_engine()), "{t:?}");
            assert_eq!(Task::parse(t.as_str()), Some(t));
        }
        // With everything entitled on an L machine every task routes to its first choice.
        let all: BTreeSet<String> = r.engines.keys().cloned().collect();
        let big = ModelRouter::new(r.clone(), Tier::L, all.clone());
        for t in Task::ALL {
            let route = big.route(t).unwrap();
            assert_eq!(route.engine, t.preferred_engine());
            assert!(!route.fell_back);
        }
        // pro → core → lite on smaller machines.
        let m = ModelRouter::new(r.clone(), Tier::M, all.clone());
        assert_eq!(m.route(Task::LongDocument).unwrap().engine, "core");
        let s = ModelRouter::new(r, Tier::S, all);
        assert_eq!(s.route(Task::LongDocument).unwrap().engine, "lite");
        assert_eq!(s.route(Task::Transcription).unwrap().engine, "scribe-small");
        assert_eq!(s.route(Task::Transcription).unwrap().runtime, "whisper.cpp");
    }

    #[test]
    fn falls_back_by_tier_with_reason() {
        let r = router(Tier::M, &["pro", "core", "lite"]);
        let route = r.route_model(Some("pro"), Task::Chat).unwrap();
        assert_eq!(route.engine, "core");
        assert!(route.fell_back);
        assert!(
            route.reason.contains("more powerful computer"),
            "{}",
            route.reason
        );
        let route = router(Tier::L, &["pro", "core", "lite"])
            .route_model(Some("pro"), Task::Chat)
            .unwrap();
        assert_eq!(route.engine, "pro");
        assert!(route.reason.contains("long docs"));
    }

    #[test]
    fn gate_entitlement_filtering_never_picks_unlicensed_engine() {
        // On the biggest machine, with only lite licensed, nothing else is ever chosen.
        let r = router(Tier::L, &["lite"]);
        for m in [
            Some("pro"),
            Some("core"),
            Some("lite"),
            Some("chat"),
            None,
            Some("nonsense"),
        ] {
            let route = r.route_model(m, Task::Chat).unwrap();
            assert_eq!(route.engine, "lite", "{m:?}");
        }
        let route = r.route_model(Some("pro"), Task::Chat).unwrap();
        assert!(
            route.reason.contains("isn't in your plan"),
            "{}",
            route.reason
        );
        // Exhaustively: for every subset of engines and every tier, the chosen engine is entitled.
        let names = ["lite", "core", "pro", "scribe", "scribe-small"];
        for mask in 0u32..(1 << names.len()) {
            let ent: Vec<&str> = names
                .iter()
                .enumerate()
                .filter(|(i, _)| mask & (1 << i) != 0)
                .map(|(_, n)| *n)
                .collect();
            for tier in [Tier::S, Tier::M, Tier::L] {
                let r = router(tier, &ent);
                for start in names {
                    if let Ok(route) = r.route_model(Some(start), Task::Chat) {
                        assert!(
                            ent.contains(&route.engine.as_str()),
                            "{start} {ent:?} {tier}"
                        );
                    }
                }
            }
        }
        // No entitled engine in the chain: a clear refusal.
        let err = router(Tier::L, &["scribe"])
            .route_model(Some("pro"), Task::Chat)
            .unwrap_err();
        assert!(err.to_string().contains("isn't in your plan"), "{err}");
    }

    #[test]
    fn quants_and_edges() {
        let s = router(Tier::S, &["lite"]).route(Task::Triage).unwrap();
        assert_eq!(s.quant.as_deref(), Some("q-s"));
        let l = router(Tier::L, &["lite"]).route(Task::Triage).unwrap();
        assert_eq!(l.quant.as_deref(), Some("q-ml"));
        assert_eq!(
            router(Tier::L, &["core"]).route(Task::Chat).unwrap().quant,
            None
        );
        // Cycles terminate.
        assert!(router(Tier::S, &["loop-a", "loop-b"])
            .route_model(Some("loop-a"), Task::Chat)
            .is_err());
        // Unknown engine in a chain.
        let err = router(Tier::L, &[]).route(Task::Embedding).unwrap_err();
        assert!(err.to_string().contains("isn't a known engine"));
        // Unsupported hardware fits nothing.
        assert!(router(Tier::Unsupported, &["lite"])
            .route(Task::Triage)
            .is_err());
        assert!(Registry::from_yaml("schema_version: 2\nengines: {}").is_err());
        assert!(Registry::from_yaml("::").is_err());
        let r = router(Tier::M, &["lite"]);
        assert_eq!(r.tier(), Tier::M);
        assert!(r.entitled().contains("lite"));
    }
}
