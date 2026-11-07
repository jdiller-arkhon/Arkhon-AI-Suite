import json

from arkhon_envcheck.check import (
    GIB,
    Gpu,
    apple_usable_gpu_mib,
    classify_tier,
    collect,
    parse_nvidia_smi,
    parse_nvidia_smi_cuda,
    parse_windows_adapters,
)


def nv(vram):
    return Gpu("NVIDIA GPU", vram, vendor="nvidia", backend="cuda")


def test_parse_nvidia_smi():
    gpus = parse_nvidia_smi("NVIDIA GeForce RTX 4060 Ti, 16380, 581.57, 8.9\n")
    assert gpus[0].name == "NVIDIA GeForce RTX 4060 Ti" and gpus[0].vram_mib == 16380


def test_parse_nvidia_garbage_and_cuda_header():
    assert parse_nvidia_smi("No devices were found") == []
    assert parse_nvidia_smi_cuda("| Driver Version: 581.57   CUDA Version: 13.0     |") == "13.0"
    assert parse_nvidia_smi_cuda("") is None


def test_parse_windows_adapters_amd_intel_and_skips():
    js = json.dumps(
        [
            {"name": "AMD Radeon RX 7800 XT", "mem": 16 * GIB, "driver": "32.0"},
            {"name": "Intel(R) Arc(TM) B580 Graphics", "mem": 12 * GIB, "driver": "32.1"},
            {"name": "Intel(R) UHD Graphics", "mem": 128 * 1024**2},  # iGPU carve-out
            {"name": "NVIDIA GeForce RTX 3060", "mem": 12 * GIB},  # handled by nvidia-smi
            {"name": "Microsoft Basic Display Adapter"},
        ]
    )
    gpus = parse_windows_adapters(js)
    assert [(g.vendor, g.vram_mib) for g in gpus] == [("amd", 16384), ("intel", 12288)]
    assert all(g.backend == "vulkan" for g in gpus)
    assert parse_windows_adapters("not json") == []
    assert len(parse_windows_adapters(json.dumps({"name": "AMD Radeon", "mem": 8 * GIB}))) == 1


def test_apple_unified_budget():
    assert apple_usable_gpu_mib(16 * GIB) == int(16 * 1024 * 2 / 3)
    assert apple_usable_gpu_mib(64 * GIB) == 48 * 1024


def test_tiers_vendor_neutral():
    assert classify_tier(32, [nv(12 * 1024)])[0] == "M"
    assert classify_tier(32, [nv(24 * 1024)])[0] == "L"
    assert classify_tier(64, [nv(16 * 1024)])[0] == "L"
    assert classify_tier(32, [nv(16 * 1024)])[0] == "M"
    assert classify_tier(32, [Gpu("RX 7800 XT", 16384, vendor="amd", backend="rocm")])[0] == "M"
    assert classify_tier(32, [Gpu("Arc B580", 12288, vendor="intel")])[0] == "M"
    assert classify_tier(16, [nv(8 * 1024)])[0] == "S"
    assert classify_tier(16, [])[0] == "S"
    assert classify_tier(8, [])[0] == "unsupported"


def test_tiers_apple():
    def mac(ram):
        return Gpu(
            "Apple M4",
            apple_usable_gpu_mib(ram * GIB),
            vendor="apple",
            backend="metal",
            unified_memory=True,
        )

    assert classify_tier(16, [mac(16)])[0] == "S"  # ~10.7 GiB GPU-usable
    assert classify_tier(24, [mac(24)])[0] == "M"
    assert classify_tier(36, [mac(36)])[0] == "L"
    assert classify_tier(64, [mac(64)])[0] == "L"


def test_best_gpu_wins_on_multi_gpu():
    tier, desc = classify_tier(32, [Gpu("iGPU-ish", 2048, vendor="intel"), nv(24 * 1024)])
    assert tier == "L" and "24 GiB" in desc


def test_collect_runs_here():
    rep = collect()
    assert rep.logical_cpus > 0
    assert rep.tier in {"S", "M", "L", "unsupported"}
    assert rep.accel_backend in {"cpu", "cuda", "rocm", "metal", "vulkan"}
