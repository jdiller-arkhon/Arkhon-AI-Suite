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


def detect_gpus(rep: Report) -> None:
    out = _run(
        [
            "nvidia-smi",
            "--query-gpu=name,memory.total,driver_version,compute_cap",
            "--format=csv,noheader,nounits",
        ]
    )
    if out:
        rep.gpus = parse_nvidia_smi(out)
        hdr = _run(["nvidia-smi"])
        if hdr and "CUDA Version:" in hdr:
            rep.cuda_driver_version = hdr.split("CUDA Version:", 1)[1].split()[0].strip("|")
    else:
        rep.notes.append("nvidia-smi not found: no NVIDIA GPU detected (or driver missing).")
    nvcc = _run(["nvcc", "--version"])
    if nvcc:
        rep.nvcc_version = nvcc.strip().splitlines()[-1]
    if sys.platform == "darwin" and platform.machine() == "arm64":
        rep.notes.append("Apple Silicon: unified memory; Metal backend applies (no TPM 2.0).")


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
    """Map hardware to Arkhon tiers S/M/L (see build brief section 5)."""
    vram_gib = max((g.vram_mib for g in gpus), default=0) / 1024
    if vram_gib >= 23 or (vram_gib >= 15 and ram_gib >= 62):
        return "L", f"{vram_gib:.0f} GiB VRAM, {ram_gib:.0f} GiB RAM"
    if vram_gib >= 11:
        return "M", f"{vram_gib:.0f} GiB VRAM"
    if vram_gib >= 7.5 or ram_gib >= 15:
        return "S", f"{vram_gib:.0f} GiB VRAM, {ram_gib:.0f} GiB RAM"
    return "unsupported", f"needs >=16 GiB RAM or >=8 GiB VRAM (have {ram_gib:.0f} GiB RAM)"


def collect() -> Report:
    rep = Report(
        os=platform.system(),
        os_version=platform.platform(),
        arch=platform.machine(),
        cpu=cpu_name(),
        logical_cpus=os.cpu_count() or 0,
        ram_gib=round(ram_bytes() / GIB, 1),
        free_disk_gib=round(shutil.disk_usage(Path.home()).free / GIB, 1),
    )
    detect_gpus(rep)
    detect_tpm(rep)
    rep.tier, rep.tier_reason = classify_tier(rep.ram_gib, rep.gpus)
    return rep


def summary(rep: Report) -> str:
    gpu = ", ".join(f"{g.name} ({g.vram_mib} MiB, cc {g.compute_cap})" for g in rep.gpus) or "none"
    lines = [
        f"OS        : {rep.os_version} ({rep.arch})",
        f"CPU       : {rep.cpu} x{rep.logical_cpus}",
        f"RAM       : {rep.ram_gib} GiB   free disk: {rep.free_disk_gib} GiB",
        f"GPU       : {gpu}",
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
