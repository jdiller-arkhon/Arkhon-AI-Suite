//! Hardware detection and tiering, vendor-neutral (ADR-0004).
//!
//! A Rust port of `tools/env-check/arkhon_envcheck/check.py`: same thresholds, same parsers, same
//! test cases. Only accelerator memory decides the tier:
//!
//! * NVIDIA via `nvidia-smi` (any OS);
//! * AMD / Intel discrete GPUs via sysfs on Linux (`mem_info_vram_total`) and the display-class
//!   registry key (`HardwareInformation.qwMemorySize`) on Windows;
//! * Apple Silicon unified memory: the default GPU wired-memory budget (≈2/3 of RAM up to 36 GiB,
//!   ≈3/4 above).
//!
//! Nothing detected here is ever sent anywhere.

use std::fmt;
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

const GIB: u64 = 1024 * 1024 * 1024;
const MIB: u64 = 1024 * 1024;

/// A GPU (or the GPU share of unified memory).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Gpu {
    /// Name as reported.
    pub name: String,
    /// Usable accelerator memory (MiB).
    pub vram_mib: u64,
    /// `nvidia`, `amd`, `intel`, `apple` or `unknown`.
    pub vendor: String,
    /// llama.cpp backend: `cuda`, `rocm`, `metal` or `vulkan`.
    pub backend: String,
    /// True when the memory is shared system RAM (Apple Silicon).
    pub unified_memory: bool,
}

impl Gpu {
    fn new(name: &str, vram_mib: u64, vendor: &str, backend: &str) -> Self {
        Self {
            name: name.to_owned(),
            vram_mib,
            vendor: vendor.to_owned(),
            backend: backend.to_owned(),
            unified_memory: false,
        }
    }
}

/// Hardware tier: which engines fit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Tier {
    /// Below the minimum.
    Unsupported,
    /// Small: ≥16 GiB RAM or ≥8 GiB GPU memory.
    S,
    /// Medium: ≥12 GiB GPU memory.
    M,
    /// Large: ≥24 GiB GPU memory, or ≥16 GiB with ≥64 GiB RAM.
    L,
}

impl Tier {
    /// `S`, `M`, `L` or `unsupported` (registry spelling).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Tier::Unsupported => "unsupported",
            Tier::S => "S",
            Tier::M => "M",
            Tier::L => "L",
        }
    }

    /// Parse the registry spelling.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "S" => Some(Tier::S),
            "M" => Some(Tier::M),
            "L" => Some(Tier::L),
            "unsupported" => Some(Tier::Unsupported),
            _ => None,
        }
    }
}

impl fmt::Display for Tier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What this computer has.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HardwareReport {
    /// `linux`, `windows`, `macos`, …
    pub os: String,
    /// CPU architecture.
    pub arch: String,
    /// Total RAM (GiB).
    pub ram_gib: f64,
    /// Accelerators found.
    pub gpus: Vec<Gpu>,
    /// Best backend (`cpu` if no GPU).
    pub accel_backend: String,
    /// Tier.
    pub tier: Tier,
    /// Plain description, e.g. `"16 GiB VRAM, 32 GiB RAM"`.
    pub tier_reason: String,
}

/// Run a command with a timeout; stdout on success.
fn run(cmd: &str, args: &[&str], timeout: Duration) -> Option<String> {
    let mut child = Command::new(cmd)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut out = String::new();
                child.stdout.take()?.read_to_string(&mut out).ok()?;
                return status.success().then(|| out.trim().to_owned());
            }
            Ok(None) if start.elapsed() < timeout => std::thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

const CMD_TIMEOUT: Duration = Duration::from_secs(15);

/// Parse `nvidia-smi --query-gpu=name,memory.total,driver_version,compute_cap
/// --format=csv,noheader,nounits`.
#[must_use]
pub fn parse_nvidia_smi(csv: &str) -> Vec<Gpu> {
    csv.lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split(',').map(str::trim).collect();
            if parts.len() < 2 {
                return None;
            }
            let vram: f64 = parts[1].parse().ok()?;
            if !vram.is_finite() || vram < 0.0 {
                return None;
            }
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let vram_mib = vram as u64;
            Some(Gpu::new(parts[0], vram_mib, "nvidia", "cuda"))
        })
        .collect()
}

/// The CUDA version from the `nvidia-smi` banner.
#[must_use]
pub fn parse_nvidia_smi_cuda(header: &str) -> Option<String> {
    let rest = header.split_once("CUDA Version:")?.1;
    rest.split_whitespace()
        .next()
        .map(|v| v.trim_matches('|').to_owned())
}

/// Default macOS GPU wired-memory budget on Apple Silicon (MiB), as in the Python tool.
#[must_use]
pub fn apple_usable_gpu_mib(ram_bytes_total: u64) -> u64 {
    // ram * 3/4 above 36 GiB, else ram * 2/3; integer math, truncated like Python's int().
    let scaled = if ram_bytes_total > 36 * GIB {
        u128::from(ram_bytes_total) * 3 / 4
    } else {
        u128::from(ram_bytes_total) * 2 / 3
    };
    u64::try_from(scaled / u128::from(MIB)).unwrap_or(u64::MAX)
}

fn vendor_of(name: &str) -> &'static str {
    let n = name.to_lowercase();
    for (key, vendor) in [
        ("nvidia", "nvidia"),
        ("geforce", "nvidia"),
        ("quadro", "nvidia"),
        ("radeon", "amd"),
        ("amd", "amd"),
        ("intel", "intel"),
        ("arc", "intel"),
        ("apple", "apple"),
    ] {
        if n.contains(key) {
            return vendor;
        }
    }
    "unknown"
}

/// Parse the PowerShell JSON listing of display adapters (name, mem, driver).
#[must_use]
pub fn parse_windows_adapters(js: &str) -> Vec<Gpu> {
    let Ok(data) = serde_json::from_str::<serde_json::Value>(js) else {
        return Vec::new();
    };
    let items = match data {
        serde_json::Value::Array(v) => v,
        obj @ serde_json::Value::Object(_) => vec![obj],
        _ => return Vec::new(),
    };
    items
        .iter()
        .filter_map(|d| {
            let name = d.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let mem = d.get("mem").and_then(serde_json::Value::as_u64)?;
            let vendor = vendor_of(name);
            // NVIDIA comes from nvidia-smi; skip adapters with no dedicated VRAM.
            if vendor == "nvidia" || mem < GIB {
                return None;
            }
            Some(Gpu::new(name, mem / MIB, vendor, "vulkan"))
        })
        .collect()
}

/// Read AMD/Intel discrete GPUs from a sysfs DRM directory (`/sys/class/drm` in production).
#[must_use]
pub fn detect_linux_drm(drm: &Path, rocm_available: bool) -> Vec<Gpu> {
    let Ok(entries) = std::fs::read_dir(drm) else {
        return Vec::new();
    };
    let mut cards: Vec<_> = entries
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| {
            n.strip_prefix("card")
                .is_some_and(|rest| !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()))
        })
        .collect();
    cards.sort();
    cards
        .into_iter()
        .filter_map(|card| {
            let dev = drm.join(&card).join("device");
            let vram: u64 = std::fs::read_to_string(dev.join("mem_info_vram_total"))
                .ok()?
                .trim()
                .parse()
                .ok()?;
            let vendor_id = std::fs::read_to_string(dev.join("vendor")).ok()?;
            let vendor = match vendor_id.trim() {
                "0x1002" => "amd",
                "0x8086" => "intel",
                "0x10de" => "nvidia",
                _ => "unknown",
            };
            let vram_mib = vram / MIB;
            if vendor == "nvidia" || vram_mib < 1024 {
                return None;
            }
            let backend = if vendor == "amd" && rocm_available {
                "rocm"
            } else {
                "vulkan"
            };
            Some(Gpu::new(
                &format!("{vendor} GPU ({card})"),
                vram_mib,
                vendor,
                backend,
            ))
        })
        .collect()
}

fn backend_rank(b: &str) -> u8 {
    match b {
        "cuda" | "metal" => 3,
        "rocm" => 2,
        "vulkan" => 1,
        _ => 0,
    }
}

/// The GPU with the most memory (backend quality breaks ties).
#[must_use]
pub fn best_gpu(gpus: &[Gpu]) -> Option<&Gpu> {
    gpus.iter()
        .max_by_key(|g| (g.vram_mib, backend_rank(&g.backend)))
}

/// Map hardware to tiers S/M/L, vendor-neutral. Same thresholds as the Python tool.
#[must_use]
#[allow(clippy::cast_precision_loss)]
pub fn classify_tier(ram_gib: f64, gpus: &[Gpu]) -> (Tier, String) {
    let (mem_gib, kind) = match best_gpu(gpus) {
        Some(g) => (
            g.vram_mib as f64 / 1024.0,
            if g.unified_memory { "unified" } else { "VRAM" },
        ),
        None => (0.0, "VRAM"),
    };
    let desc = format!("{mem_gib:.0} GiB {kind}, {ram_gib:.0} GiB RAM");
    if mem_gib >= 23.0 || (mem_gib >= 15.0 && ram_gib >= 62.0) {
        (Tier::L, desc)
    } else if mem_gib >= 11.0 {
        (Tier::M, desc)
    } else if mem_gib >= 7.5 || ram_gib >= 15.0 {
        (Tier::S, desc)
    } else {
        (
            Tier::Unsupported,
            format!("needs >=16 GiB RAM or >=8 GiB GPU memory ({desc})"),
        )
    }
}

fn parse_meminfo(text: &str) -> Option<u64> {
    let line = text.lines().find(|l| l.starts_with("MemTotal:"))?;
    let kib: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kib * 1024)
}

/// Total RAM in bytes (0 if unknown).
#[must_use]
pub fn ram_bytes() -> u64 {
    if cfg!(target_os = "linux") {
        std::fs::read_to_string("/proc/meminfo")
            .ok()
            .and_then(|t| parse_meminfo(&t))
            .unwrap_or(0)
    } else if cfg!(target_os = "macos") {
        run("sysctl", &["-n", "hw.memsize"], CMD_TIMEOUT)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    } else if cfg!(windows) {
        run(
            "powershell",
            &[
                "-NoProfile",
                "-Command",
                "(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory",
            ],
            CMD_TIMEOUT,
        )
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
    } else {
        0
    }
}

fn detect_nvidia() -> Vec<Gpu> {
    run(
        "nvidia-smi",
        &[
            "--query-gpu=name,memory.total,driver_version,compute_cap",
            "--format=csv,noheader,nounits",
        ],
        CMD_TIMEOUT,
    )
    .map(|out| parse_nvidia_smi(&out))
    .unwrap_or_default()
}

const WINDOWS_ADAPTERS_PS: &str = "$k='HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}';Get-ChildItem $k -ErrorAction SilentlyContinue | ForEach-Object {$p=Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue;if($p.DriverDesc){[pscustomobject]@{name=$p.DriverDesc;mem=$p.'HardwareInformation.qwMemorySize';driver=$p.DriverVersion}}} | ConvertTo-Json";

/// Detect accelerators on this computer.
#[must_use]
pub fn detect_gpus(total_ram: u64) -> Vec<Gpu> {
    let mut gpus = detect_nvidia();
    if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        gpus.push(Gpu {
            name: "Apple Silicon".into(),
            vram_mib: apple_usable_gpu_mib(total_ram),
            vendor: "apple".into(),
            backend: "metal".into(),
            unified_memory: true,
        });
    } else if cfg!(target_os = "linux") {
        let rocm = run("rocminfo", &[], CMD_TIMEOUT).is_some();
        gpus.extend(detect_linux_drm(Path::new("/sys/class/drm"), rocm));
    } else if cfg!(windows) {
        if let Some(out) = run(
            "powershell",
            &["-NoProfile", "-Command", WINDOWS_ADAPTERS_PS],
            CMD_TIMEOUT,
        ) {
            gpus.extend(parse_windows_adapters(&out));
        }
    }
    gpus
}

/// Detect everything and classify.
#[must_use]
#[allow(clippy::cast_precision_loss)]
pub fn detect() -> HardwareReport {
    let total = ram_bytes();
    let gpus = detect_gpus(total);
    let ram_gib = (total as f64 / GIB as f64 * 10.0).round() / 10.0;
    let (tier, tier_reason) = classify_tier(ram_gib, &gpus);
    HardwareReport {
        os: std::env::consts::OS.into(),
        arch: std::env::consts::ARCH.into(),
        ram_gib,
        accel_backend: best_gpu(&gpus).map_or_else(|| "cpu".into(), |g| g.backend.clone()),
        gpus,
        tier,
        tier_reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsutil::test_dir::TestDir;

    fn nv(vram: u64) -> Gpu {
        Gpu::new("NVIDIA GPU", vram, "nvidia", "cuda")
    }

    #[test]
    fn parse_nvidia() {
        let g = parse_nvidia_smi("NVIDIA GeForce RTX 4060 Ti, 16380, 581.57, 8.9\n");
        assert_eq!(g[0].name, "NVIDIA GeForce RTX 4060 Ti");
        assert_eq!(g[0].vram_mib, 16380);
        assert_eq!(parse_nvidia_smi("No devices were found").len(), 0);
        assert_eq!(parse_nvidia_smi("x, nan").len(), 0);
        assert_eq!(
            parse_nvidia_smi_cuda("| Driver Version: 581.57   CUDA Version: 13.0     |").as_deref(),
            Some("13.0")
        );
        assert_eq!(parse_nvidia_smi_cuda(""), None);
    }

    #[test]
    fn parse_windows() {
        let js = serde_json::json!([
            {"name": "AMD Radeon RX 7800 XT", "mem": 16 * GIB, "driver": "32.0"},
            {"name": "Intel(R) Arc(TM) B580 Graphics", "mem": 12 * GIB, "driver": "32.1"},
            {"name": "Intel(R) UHD Graphics", "mem": 128 * MIB},
            {"name": "NVIDIA GeForce RTX 3060", "mem": 12 * GIB},
            {"name": "Microsoft Basic Display Adapter"}
        ])
        .to_string();
        let g = parse_windows_adapters(&js);
        let got: Vec<_> = g.iter().map(|g| (g.vendor.as_str(), g.vram_mib)).collect();
        assert_eq!(got, [("amd", 16384), ("intel", 12288)]);
        assert!(g.iter().all(|g| g.backend == "vulkan"));
        assert_eq!(parse_windows_adapters("not json").len(), 0);
        assert_eq!(parse_windows_adapters("42").len(), 0);
        let one = serde_json::json!({"name": "AMD Radeon", "mem": 8 * GIB}).to_string();
        assert_eq!(parse_windows_adapters(&one).len(), 1);
    }

    #[test]
    fn apple_budget() {
        assert_eq!(apple_usable_gpu_mib(16 * GIB), 16 * 1024 * 2 / 3);
        assert_eq!(apple_usable_gpu_mib(64 * GIB), 48 * 1024);
    }

    #[test]
    fn tiers_vendor_neutral() {
        assert_eq!(classify_tier(32.0, &[nv(12 * 1024)]).0, Tier::M);
        assert_eq!(classify_tier(32.0, &[nv(24 * 1024)]).0, Tier::L);
        assert_eq!(classify_tier(64.0, &[nv(16 * 1024)]).0, Tier::L);
        assert_eq!(classify_tier(32.0, &[nv(16 * 1024)]).0, Tier::M);
        assert_eq!(
            classify_tier(32.0, &[Gpu::new("RX 7800 XT", 16384, "amd", "rocm")]).0,
            Tier::M
        );
        assert_eq!(
            classify_tier(32.0, &[Gpu::new("Arc B580", 12288, "intel", "vulkan")]).0,
            Tier::M
        );
        assert_eq!(classify_tier(16.0, &[nv(8 * 1024)]).0, Tier::S);
        assert_eq!(classify_tier(16.0, &[]).0, Tier::S);
        let (t, why) = classify_tier(8.0, &[]);
        assert_eq!(t, Tier::Unsupported);
        assert!(why.contains("needs"));
    }

    #[test]
    fn tiers_apple() {
        let mac = |ram: u64| Gpu {
            name: "Apple".into(),
            vram_mib: apple_usable_gpu_mib(ram * GIB),
            vendor: "apple".into(),
            backend: "metal".into(),
            unified_memory: true,
        };
        assert_eq!(classify_tier(16.0, &[mac(16)]).0, Tier::S);
        assert_eq!(classify_tier(24.0, &[mac(24)]).0, Tier::M);
        assert_eq!(classify_tier(36.0, &[mac(36)]).0, Tier::L);
        let (t, why) = classify_tier(64.0, &[mac(64)]);
        assert_eq!(t, Tier::L);
        assert!(why.contains("unified"));
    }

    #[test]
    fn best_gpu_wins() {
        let (t, d) = classify_tier(
            32.0,
            &[Gpu::new("iGPU-ish", 2048, "intel", "vulkan"), nv(24 * 1024)],
        );
        assert_eq!(t, Tier::L);
        assert!(d.contains("24 GiB"));
    }

    #[test]
    fn linux_drm_fake_sysfs() {
        let d = TestDir::new("drm");
        let card = |n: &str, vendor: &str, vram: u64| {
            let dev = d.path().join(n).join("device");
            std::fs::create_dir_all(&dev).unwrap();
            std::fs::write(dev.join("vendor"), format!("{vendor}\n")).unwrap();
            std::fs::write(dev.join("mem_info_vram_total"), vram.to_string()).unwrap();
        };
        card("card0", "0x1002", 16 * GIB);
        card("card1", "0x8086", 256 * MIB); // carve-out, skipped
        card("card2", "0x10de", 24 * GIB); // nvidia handled by nvidia-smi
        card("card3", "0x8086", 12 * GIB);
        std::fs::create_dir_all(d.path().join("card0-DP-1")).unwrap();
        let g = detect_linux_drm(d.path(), true);
        let got: Vec<_> = g
            .iter()
            .map(|g| (g.vendor.as_str(), g.backend.as_str(), g.vram_mib))
            .collect();
        assert_eq!(got, [("amd", "rocm", 16384), ("intel", "vulkan", 12288)]);
        assert_eq!(detect_linux_drm(d.path(), false)[0].backend, "vulkan");
        assert_eq!(detect_linux_drm(&d.path().join("missing"), false).len(), 0);
    }

    #[test]
    fn meminfo_and_tier_names() {
        assert_eq!(
            parse_meminfo("MemTotal:       16384 kB\nMemFree: 1 kB"),
            Some(16384 * 1024)
        );
        assert_eq!(parse_meminfo("nothing"), None);
        for t in [Tier::Unsupported, Tier::S, Tier::M, Tier::L] {
            assert_eq!(Tier::parse(t.as_str()), Some(t));
            assert_eq!(t.to_string(), t.as_str());
        }
        assert_eq!(Tier::parse("XL"), None);
        assert!(Tier::S < Tier::L);
    }

    #[test]
    fn detect_runs_here() {
        let r = detect();
        assert_ne!(r.os.len(), 0);
        assert!(["cpu", "cuda", "rocm", "metal", "vulkan"].contains(&r.accel_backend.as_str()));
        assert!(run(
            "definitely-not-a-command-arkhon",
            &[],
            Duration::from_secs(1)
        )
        .is_none());
    }
}
