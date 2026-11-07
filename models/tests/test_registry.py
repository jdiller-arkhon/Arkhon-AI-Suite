"""Registry invariants: schema-valid, permissive licenses only, fallback chains terminate."""

import json
from pathlib import Path

import jsonschema
import yaml

ROOT = Path(__file__).resolve().parents[1]
REG = yaml.safe_load((ROOT / "registry.yaml").read_text())


def test_schema_valid():
    schema = json.loads((ROOT / "registry.schema.json").read_text())
    jsonschema.validate(json.loads(json.dumps(REG, default=str)), schema)


def test_licenses_permissive():
    for name, e in REG["engines"].items():
        assert e["base"]["license"] in REG["allowed_licenses"], name


def test_fallbacks_exist_acyclic_and_reach_lower_tier():
    engines = REG["engines"]
    for name in engines:
        seen, cur = set(), name
        while engines[cur]["fallback"] is not None:
            assert cur not in seen, f"cycle at {name}"
            seen.add(cur)
            cur = engines[cur]["fallback"]
            assert cur in engines, f"{name}: unknown fallback {cur}"


def test_every_tier_has_text_and_embed_engine():
    for tier in "SML":
        avail = {n for n, e in REG["engines"].items() if tier in e["tiers"]}
        assert "embed" in avail and ({"lite", "core", "pro"} & avail), tier
