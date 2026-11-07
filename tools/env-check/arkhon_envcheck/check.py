"""Detect hardware relevant to Arkhon: OS, CPU, RAM, GPU/VRAM, CUDA, TPM 2.0, disk.

Stdlib only so it runs on a fresh machine before anything else is installed.
Never transmits anything: prints a report and optionally writes JSON locally.

Usage:
    python -m arkhon_envcheck.check            # human summary
    python -m arkhon_envcheck.check --json out.json
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import platform
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

GIB = 1024**3


@dataclass
class Gpu:
    name: str
    vram_mib: int
    driver: str | None = None
    compute_cap: str | None = None
    vendor: str = "unknown"  # nvidia | amd | intel | apple | unknown
    backend: str = "vulkan"  # llama.cpp backend: cuda | rocm | metal | vulkan
    unified_memory: bool = False  # True when "VRAM" is shared system RAM (Apple Silicon)


@dataclass
class Report:
    os: str
    os_version: str
    arch: str
    cpu: str
    logical_cpus: int
    ram_gib: float
    free_disk_gib: float
    gpus: list[Gpu] = field(default_factory=list)
    cuda_driver_version: str | None = None
    nvcc_version: str | None = None
    tpm_present: bool = False
    tpm_version: str | None = None
    tpm_detail: str | None = None
    accel_backend: str = "cpu"
    tier: str = "unsupported"
    tier_reason: str = ""
    notes: list[str] = field(default_factory=list)


def _run(cmd: list[str], timeout: float = 15.0) -> str | None:
    if shutil.which(cmd[0]) is None:
        return None
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return out.stdout.strip() if out.returncode == 0 else None


def ram_bytes() -> int:
    if sys.platform == "win32":

        class MemStatus(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        st = MemStatus()
        st.dwLength = ctypes.sizeof(MemStatus)
        ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(st))  # type: ignore[attr-defined]
        return int(st.ullTotalPhys)
    if sys.platform == "darwin":
        out = _run(["sysctl", "-n", "hw.memsize"])
        return int(out) if out and out.isdigit() else 0
    try:
        return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
    except (ValueError, OSError):
        return 0


def cpu_name() -> str:
    if sys.platform.startswith("linux"):
        try:
            for line in Path("/proc/cpuinfo").read_text().splitlines():
                if line.startswith("model name"):
                    return line.split(":", 1)[1].strip()
        except OSError:
            pass
    if sys.platform == "darwin":
        out = _run(["sysctl", "-n", "machdep.cpu.brand_string"])
        if out:
            return out
    return platform.processor() or platform.machine()


def parse_nvidia_smi(csv: str) -> list[Gpu]:
    gpus = []
    for line in csv.splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 2:
            continue
        try:
            vram = int(float(parts[1]))
        except ValueError:
            continue
        gpus.append(
            Gpu(
                name=parts[0],
                vram_mib=vram,
                driver=parts[2] if len(parts) > 2 else None,
                compute_cap=parts[3] if len(parts) > 3 else None,
            )
        )
    return gpus


def parse_nvidia_smi_cuda(header: str) -> str | None:
    if "CUDA Version:" not in header:
        return None
    return header.split("CUDA Version:", 1)[1].split()[0].strip("|")


def apple_usable_gpu_mib(ram_bytes_total: int) -> int:
    """Default macOS GPU wired-memory budget on Apple Silicon.

    macOS lets the GPU wire roughly 2/3 of RAM on machines with <=36 GiB and ~3/4 above.
    Approximation used only for tiering; the runtime measures the real limit
    (MTLDevice.recommendedMaxWorkingSetSize) at startup.
    """
    frac = 0.75 if ram_bytes_total > 36 * GIB else 2 / 3
    return int(ram_bytes_total * frac / 1024**2)


def _vendor_of(name: str) -> str:
    n = name.lower()
    for key, vendor in (
        ("nvidia", "nvidia"),
        ("geforce", "nvidia"),
        ("quadro", "nvidia"),
        ("radeon", "amd"),
        ("amd", "amd"),
        ("intel", "intel"),
        ("arc", "intel"),
        ("apple", "apple"),
    ):
        if key in n:
            return vendor
    return "unknown"


def _detect_nvidia(rep: Report) -> list[Gpu]:
    out = _run(
        [
            "nvidia-smi",
            "--query-gpu=name,memory.total,driver_version,compute_cap",
            "--format=csv,noheader,nounits",
        ]
    )
    if not out:
        return []
    gpus = parse_nvidia_smi(out)
    for g in gpus:
        g.vendor, g.backend = "nvidia", "cuda"
    hdr = _run(["nvidia-smi"])
    rep.cuda_driver_version = parse_nvidia_smi_cuda(hdr or "")
    nvcc = _run(["nvcc", "--version"])
    if nvcc:
        rep.nvcc_version = nvcc.strip().splitlines()[-1]
    return gpus


def _detect_linux_drm() -> list[Gpu]:
    """AMD (amdgpu) and Intel discrete GPUs expose VRAM size in sysfs without vendor tools."""
    gpus = []
    for card in sorted(Path("/sys/class/drm").glob("card[0-9]*")):
        dev = card / "device"
        vram = dev / "mem_info_vram_total"
        if not vram.exists():
            continue
        try:
            vram_mib = int(vram.read_text().strip()) // 1024**2
            vendor_id = (dev / "vendor").read_text().strip()
        except (OSError, ValueError):
            continue
        vendor = {"0x1002": "amd", "0x8086": "intel", "0x10de": "nvidia"}.get(vendor_id, "unknown")
        if vendor == "nvidia" or vram_mib < 1024:  # nvidia handled above; skip tiny iGPU carve-outs
            continue
        backend = "rocm" if vendor == "amd" and shutil.which("rocminfo") else "vulkan"
        gpus.append(Gpu(f"{vendor} GPU ({card.name})", vram_mib, vendor=vendor, backend=backend))
    return gpus


def _detect_windows_adapters() -> list[Gpu]:
    # Win32_VideoController.AdapterRAM is a uint32 (caps at 4 GiB); the registry qwMemorySize
    # value under the display class key holds the true 64-bit dedicated VRAM size.
    script = (
        "$k='HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Class\\"
        "{4d36e968-e325-11ce-bfc1-08002be10318}';"
        "Get-ChildItem $k -ErrorAction SilentlyContinue | ForEach-Object {"
        "$p=Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue;"
        "if($p.DriverDesc){[pscustomobject]@{name=$p.DriverDesc;"
        "mem=$p.'HardwareInformation.qwMemorySize';driver=$p.DriverVersion}}}"
        " | ConvertTo-Json"
    )
    out = _run(["powershell", "-NoProfile", "-Command", script])
    if not out:
        return []
    return parse_windows_adapters(out)


def parse_windows_adapters(js: str) -> list[Gpu]:
    try:
        data = json.loads(js)
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict):
        data = [data]
    gpus = []
    for d in data:
        name, mem = str(d.get("name") or ""), d.get("mem")
        vendor = _vendor_of(name)
        if vendor == "nvidia" or not isinstance(mem, int) or mem < GIB:
            continue  # nvidia via nvidia-smi; skip adapters with no dedicated VRAM
        gpus.append(
            Gpu(name, mem // 1024**2, driver=d.get("driver"), vendor=vendor, backend="vulkan")
        )
    return gpus


def detect_gpus(rep: Report, total_ram: int) -> None:
    gpus = _detect_nvidia(rep)
    if sys.platform == "darwin" and platform.machine() == "arm64":
        gpus.append(
            Gpu(
                cpu_name(),
                apple_usable_gpu_mib(total_ram),
                vendor="apple",
                backend="metal",
                unified_memory=True,
            )
        )
    elif sys.platform.startswith("linux"):
        gpus += _detect_linux_drm()
    elif sys.platform == "win32":
        gpus += _detect_windows_adapters()
    rep.gpus = gpus
    if not gpus:
        rep.notes.append("No discrete/unified GPU found: CPU inference (tier S at most).")
    rep.accel_backend = best_gpu(gpus).backend if gpus else "cpu"


def best_gpu(gpus: list[Gpu]) -> Gpu:
    rank = {"cuda": 3, "metal": 3, "rocm": 2, "vulkan": 1}
    return max(gpus, key=lambda g: (g.vram_mib, rank.get(g.backend, 0)))


def detect_tpm(rep: Report) -> None:
    if sys.platform.startswith("linux"):
        base = Path("/sys/class/tpm/tpm0")
        if base.exists():
            rep.tpm_present = True
            major = base / "tpm_version_major"
            rep.tpm_version = major.read_text().strip() + ".0" if major.exists() else "unknown"
            rep.tpm_detail = (
                "rm device /dev/tpmrm0 present"
                if Path("/dev/tpmrm0").exists()
                else "no /dev/tpmrm0 (resource manager) — tpm2-abrmd or kernel RM required"
            )
        else:
            rep.tpm_detail = "no /sys/class/tpm/tpm0"
    elif sys.platform == "win32":
        out = _run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-CimInstance -Namespace root/cimv2/security/microsofttpm "
                "-ClassName Win32_Tpm | Select-Object IsEnabled_InitialValue,"
                "IsActivated_InitialValue,SpecVersion | ConvertTo-Json",
            ]
        )
        if out:
            try:
                data = json.loads(out)
            except json.JSONDecodeError:
                data = {}
            spec = str(data.get("SpecVersion") or "")
            rep.tpm_present = bool(data.get("IsEnabled_InitialValue"))
            rep.tpm_version = spec.split(",")[0].strip() or None
            rep.tpm_detail = (
                f"enabled={data.get('IsEnabled_InitialValue')} "
                f"activated={data.get('IsActivated_InitialValue')} spec={spec}"
            )
        else:
            rep.tpm_detail = "Win32_Tpm query failed (run from an elevated PowerShell)"
    else:
        rep.tpm_detail = "TPM 2.0 not applicable on this OS (software binding fallback)"


def classify_tier(ram_gib: float, gpus: list[Gpu]) -> tuple[str, str]:
    """Map hardware to Arkhon tiers S/M/L (brief section 5), vendor-neutral.

    Uses the largest accelerator memory pool: discrete VRAM (CUDA/ROCm/Vulkan) or the
    GPU-usable share of unified memory (Apple Silicon). Backend quality is reported
    separately; tier only says which engines *fit*.
    """
    if gpus:
        g = best_gpu(gpus)
        mem_gib, kind = g.vram_mib / 1024, "unified" if g.unified_memory else "VRAM"
    else:
        mem_gib, kind = 0.0, "VRAM"
    desc = f"{mem_gib:.0f} GiB {kind}, {ram_gib:.0f} GiB RAM"
    if mem_gib >= 23 or (mem_gib >= 15 and ram_gib >= 62):
        return "L", desc
    if mem_gib >= 11:
        return "M", desc
    if mem_gib >= 7.5 or ram_gib >= 15:
        return "S", desc
    return "unsupported", f"needs >=16 GiB RAM or >=8 GiB GPU memory ({desc})"


def collect() -> Report:
    total_ram = ram_bytes()
    rep = Report(
        os=platform.system(),
        os_version=platform.platform(),
        arch=platform.machine(),
        cpu=cpu_name(),
        logical_cpus=os.cpu_count() or 0,
        ram_gib=round(total_ram / GIB, 1),
        free_disk_gib=round(shutil.disk_usage(Path.home()).free / GIB, 1),
    )
    detect_gpus(rep, total_ram)
    detect_tpm(rep)
    rep.tier, rep.tier_reason = classify_tier(rep.ram_gib, rep.gpus)
    return rep


def summary(rep: Report) -> str:
    gpu = (
        ", ".join(
            f"{g.name} [{g.vendor}/{g.backend}] {g.vram_mib} MiB"
            + (" unified" if g.unified_memory else "")
            for g in rep.gpus
        )
        or "none"
    )
    lines = [
        f"OS        : {rep.os_version} ({rep.arch})",
        f"CPU       : {rep.cpu} x{rep.logical_cpus}",
        f"RAM       : {rep.ram_gib} GiB   free disk: {rep.free_disk_gib} GiB",
        f"GPU       : {gpu}",
        f"Backend   : {rep.accel_backend}",
        f"CUDA      : driver {rep.cuda_driver_version or '-'}; nvcc {rep.nvcc_version or '-'}",
        f"TPM       : present={rep.tpm_present} v={rep.tpm_version or '-'} ({rep.tpm_detail})",
        f"Tier      : {rep.tier} — {rep.tier_reason}",
    ]
    lines += [f"note      : {n}" for n in rep.notes]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--json", type=Path, help="write the full report as JSON to this path")
    args = ap.parse_args(argv)
    rep = collect()
    print(summary(rep))
    if args.json:
        args.json.write_text(json.dumps(asdict(rep), indent=2))
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
