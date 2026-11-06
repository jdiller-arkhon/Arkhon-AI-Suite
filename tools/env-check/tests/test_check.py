from arkhon_envcheck.check import Gpu, classify_tier, collect, parse_nvidia_smi


def test_parse_nvidia_smi_rtx5070():
    gpus = parse_nvidia_smi("NVIDIA GeForce RTX 5070, 12227, 581.57, 12.0\n")
    assert gpus == [Gpu("NVIDIA GeForce RTX 5070", 12227, "581.57", "12.0")]


def test_parse_ignores_garbage():
    assert parse_nvidia_smi("No devices were found") == []


def test_tiers():
    assert classify_tier(32, [Gpu("RTX 5070", 12227)])[0] == "M"
    assert classify_tier(32, [Gpu("RTX 4090", 24564)])[0] == "L"
    assert classify_tier(64, [Gpu("RTX 5070 Ti", 16303)])[0] == "L"
    assert classify_tier(32, [Gpu("RTX 5070 Ti", 16303)])[0] == "M"
    assert classify_tier(16, [])[0] == "S"
    assert classify_tier(8, [])[0] == "unsupported"


def test_collect_runs_here():
    rep = collect()
    assert rep.logical_cpus > 0
    assert rep.tier in {"S", "M", "L", "unsupported"}
