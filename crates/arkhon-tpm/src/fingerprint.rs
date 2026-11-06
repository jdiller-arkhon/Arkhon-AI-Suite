//! Hardware fingerprint: salted hashes of five machine components.
//!
//! Raw identifiers (serial numbers, MAC addresses, machine id) are never stored or sent. Each one is
//! hashed as `HMAC-SHA256(key = product salt, label || 0x00 || value)` on the machine, and only the
//! hashes travel in license requests and licenses. The per-product salt keeps hashes from one
//! product (or anyone else's database) from being matched against ours.
//!
//! Two fingerprints *match* when at most one component differs, so replacing a disk or network card
//! doesn't break a license, but moving it to another machine does.
//!
//! Known limit: a component that can't be read hashes to a fixed "absent" value, so two machines
//! that both hide the same components (common in VMs) look alike for those components.

use std::fmt;

use hmac::Mac;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Number of components in a fingerprint.
pub const COMPONENT_COUNT: usize = 5;
/// Encoded fingerprint length in bytes.
pub const FINGERPRINT_LEN: usize = COMPONENT_COUNT * 32;
/// Most components that may differ for two fingerprints to still match.
pub const MAX_CHANGED_COMPONENTS: usize = 1;

/// The components, in encoding order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Component {
    /// OS machine id (`/etc/machine-id`, Windows `MachineGuid`, macOS `IOPlatformUUID`).
    MachineId,
    /// CPU model/family/stepping.
    Cpu,
    /// System disk serial.
    Disk,
    /// Motherboard serial / product UUID.
    Board,
    /// Primary physical network adapter MAC.
    Mac,
}

impl Component {
    /// Every component, in encoding order.
    pub const ALL: [Component; COMPONENT_COUNT] = [
        Component::MachineId,
        Component::Cpu,
        Component::Disk,
        Component::Board,
        Component::Mac,
    ];

    fn index(self) -> usize {
        match self {
            Component::MachineId => 0,
            Component::Cpu => 1,
            Component::Disk => 2,
            Component::Board => 3,
            Component::Mac => 4,
        }
    }

    fn label(self) -> &'static [u8] {
        match self {
            Component::MachineId => b"machine-id",
            Component::Cpu => b"cpu",
            Component::Disk => b"disk",
            Component::Board => b"board",
            Component::Mac => b"mac",
        }
    }
}

/// The per-product salt (public, embedded in the product; not a secret key).
#[derive(Clone)]
pub struct FingerprintSalt(pub [u8; 32]);

/// Raw component values as read from the machine. Wiped on drop; never persist or send these.
#[derive(Default, Zeroize, ZeroizeOnDrop)]
pub struct RawComponents {
    /// OS machine id.
    pub machine_id: Option<String>,
    /// CPU description.
    pub cpu: Option<String>,
    /// System disk serial.
    pub disk: Option<String>,
    /// Board serial or product UUID.
    pub board: Option<String>,
    /// Primary MAC address.
    pub mac: Option<String>,
}

impl fmt::Debug for RawComponents {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RawComponents(<redacted>)")
    }
}

impl RawComponents {
    fn get(&self, c: Component) -> Option<&str> {
        match c {
            Component::MachineId => self.machine_id.as_deref(),
            Component::Cpu => self.cpu.as_deref(),
            Component::Disk => self.disk.as_deref(),
            Component::Board => self.board.as_deref(),
            Component::Mac => self.mac.as_deref(),
        }
        .map(str::trim)
        .filter(|s| !s.is_empty())
    }

    /// Read what this machine exposes without admin rights (Linux today; other OSes return
    /// fewer components until their collectors land in Phase 4).
    #[must_use]
    pub fn collect() -> Self {
        #[cfg(target_os = "linux")]
        {
            linux::collect()
        }
        #[cfg(not(target_os = "linux"))]
        {
            Self::default()
        }
    }
}

/// Salted component hashes.
#[derive(Clone, PartialEq, Eq)]
pub struct HardwareFingerprint {
    components: [[u8; 32]; COMPONENT_COUNT],
}

impl fmt::Debug for HardwareFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut l = f.debug_list();
        for c in &self.components {
            l.entry(&format_args!(
                "{:02x}{:02x}{:02x}{:02x}..",
                c[0], c[1], c[2], c[3]
            ));
        }
        l.finish()
    }
}

impl HardwareFingerprint {
    /// Hash raw components with the product salt.
    #[must_use]
    pub fn from_raw(salt: &FingerprintSalt, raw: &RawComponents) -> Self {
        let mut components = [[0u8; 32]; COMPONENT_COUNT];
        for (slot, c) in components.iter_mut().zip(Component::ALL) {
            let mut mac = crate::keys::hmac(&salt.0);
            mac.update(c.label());
            match raw.get(c) {
                Some(v) => {
                    mac.update(&[0]);
                    mac.update(v.as_bytes());
                }
                None => mac.update(&[1]),
            }
            *slot = mac.finalize().into_bytes().into();
        }
        Self { components }
    }

    /// Collect and hash this machine's fingerprint.
    #[must_use]
    pub fn collect(salt: &FingerprintSalt) -> Self {
        Self::from_raw(salt, &RawComponents::collect())
    }

    /// The hash of one component.
    #[must_use]
    pub fn component(&self, c: Component) -> &[u8; 32] {
        &self.components[c.index()]
    }

    /// Fixed-length encoding (components in [`Component::ALL`] order).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; FINGERPRINT_LEN] {
        let mut out = [0u8; FINGERPRINT_LEN];
        for (chunk, c) in out.chunks_exact_mut(32).zip(&self.components) {
            chunk.copy_from_slice(c);
        }
        out
    }

    /// Inverse of [`HardwareFingerprint::to_bytes`].
    #[must_use]
    pub fn from_bytes(bytes: &[u8; FINGERPRINT_LEN]) -> Self {
        let mut components = [[0u8; 32]; COMPONENT_COUNT];
        for (c, chunk) in components.iter_mut().zip(bytes.chunks_exact(32)) {
            c.copy_from_slice(chunk);
        }
        Self { components }
    }

    /// How many components differ (each compared in constant time).
    #[must_use]
    pub fn changed_components(&self, other: &Self) -> usize {
        self.components
            .iter()
            .zip(&other.components)
            .filter(|(a, b)| !bool::from(a[..].ct_eq(&b[..])))
            .count()
    }

    /// True when at most [`MAX_CHANGED_COMPONENTS`] components differ.
    #[must_use]
    pub fn matches(&self, other: &Self) -> bool {
        self.changed_components(other) <= MAX_CHANGED_COMPONENTS
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::RawComponents;
    use std::fs;

    fn read(path: &str) -> Option<String> {
        fs::read_to_string(path)
            .ok()
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
    }

    fn cpu() -> Option<String> {
        let info = fs::read_to_string("/proc/cpuinfo").ok()?;
        let wanted = ["vendor_id", "cpu family", "model", "model name", "stepping"];
        let mut parts = Vec::new();
        for line in info.lines() {
            if line.trim().is_empty() {
                break; // first processor block only
            }
            if let Some((k, v)) = line.split_once(':') {
                if wanted.contains(&k.trim()) {
                    parts.push(format!("{}={}", k.trim(), v.trim()));
                }
            }
        }
        (!parts.is_empty()).then(|| parts.join(";"))
    }

    fn disk() -> Option<String> {
        let mut names: Vec<String> = fs::read_dir("/sys/block")
            .ok()?
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| !n.starts_with("loop") && !n.starts_with("ram") && !n.starts_with("zram"))
            .collect();
        names.sort();
        names.iter().find_map(|n| {
            read(&format!("/sys/block/{n}/device/serial"))
                .or_else(|| read(&format!("/sys/block/{n}/serial")))
                .or_else(|| read(&format!("/sys/block/{n}/device/wwid")))
        })
    }

    fn board() -> Option<String> {
        read("/sys/class/dmi/id/board_serial")
            .or_else(|| read("/sys/class/dmi/id/product_uuid"))
            .or_else(|| {
                let v = read("/sys/class/dmi/id/board_vendor")?;
                let n = read("/sys/class/dmi/id/board_name")?;
                Some(format!("{v}/{n}"))
            })
    }

    fn mac() -> Option<String> {
        let mut names: Vec<String> = fs::read_dir("/sys/class/net")
            .ok()?
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            // Physical adapters have a `device` link; skips lo, bridges, veth, docker.
            .filter(|n| fs::metadata(format!("/sys/class/net/{n}/device")).is_ok())
            .collect();
        names.sort();
        names
            .iter()
            .filter_map(|n| read(&format!("/sys/class/net/{n}/address")))
            .find(|a| a != "00:00:00:00:00:00")
    }

    pub(super) fn collect() -> RawComponents {
        RawComponents {
            machine_id: read("/etc/machine-id").or_else(|| read("/var/lib/dbus/machine-id")),
            cpu: cpu(),
            disk: disk(),
            board: board(),
            mac: mac(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn salt() -> FingerprintSalt {
        FingerprintSalt([9; 32])
    }

    fn raw() -> RawComponents {
        RawComponents {
            machine_id: Some("m".into()),
            cpu: Some("c".into()),
            disk: Some("d".into()),
            board: Some("b".into()),
            mac: Some("aa:bb".into()),
        }
    }

    #[test]
    fn tolerates_one_change_not_two() {
        let a = HardwareFingerprint::from_raw(&salt(), &raw());
        let mut r = raw();
        r.disk = Some("new disk".into());
        let one = HardwareFingerprint::from_raw(&salt(), &r);
        assert_eq!(a.changed_components(&one), 1);
        assert!(a.matches(&one));
        r.mac = None;
        let two = HardwareFingerprint::from_raw(&salt(), &r);
        assert_eq!(a.changed_components(&two), 2);
        assert!(!a.matches(&two));
        assert_ne!(a.component(Component::Disk), one.component(Component::Disk));
        assert_eq!(a.component(Component::Cpu), one.component(Component::Cpu));
    }

    #[test]
    fn salt_changes_everything_and_no_raw_values_leak() {
        let a = HardwareFingerprint::from_raw(&salt(), &raw());
        let b = HardwareFingerprint::from_raw(&FingerprintSalt([8; 32]), &raw());
        assert_eq!(a.changed_components(&b), COMPONENT_COUNT);
        let bytes = a.to_bytes();
        assert!(!bytes.windows(5).any(|w| w == b"aa:bb"));
        assert!(!format!("{a:?}").contains("aa:bb"));
        assert_eq!(format!("{:?}", raw()), "RawComponents(<redacted>)");
    }

    #[test]
    fn blank_and_absent_are_the_same_and_whitespace_trimmed() {
        let mut r = raw();
        r.cpu = Some("   ".into());
        let blank = HardwareFingerprint::from_raw(&salt(), &r);
        r.cpu = None;
        let absent = HardwareFingerprint::from_raw(&salt(), &r);
        assert_eq!(blank, absent);
        let mut r2 = raw();
        r2.cpu = Some(" c \n".into());
        assert_eq!(
            HardwareFingerprint::from_raw(&salt(), &r2),
            HardwareFingerprint::from_raw(&salt(), &raw())
        );
    }

    #[test]
    fn collect_runs_and_is_stable() {
        let a = HardwareFingerprint::collect(&salt());
        let b = HardwareFingerprint::collect(&salt());
        assert_eq!(a, b);
    }

    proptest! {
        #[test]
        fn prop_bytes_round_trip(bytes in prop::collection::vec(any::<u8>(), FINGERPRINT_LEN)) {
            let arr: [u8; FINGERPRINT_LEN] = bytes.try_into().unwrap();
            let fp = HardwareFingerprint::from_bytes(&arr);
            prop_assert_eq!(fp.to_bytes(), arr);
            prop_assert!(fp.matches(&fp));
        }

        #[test]
        fn prop_match_iff_at_most_one_change(changes in prop::collection::vec(any::<bool>(), COMPONENT_COUNT)) {
            let base = HardwareFingerprint::from_raw(&salt(), &raw());
            let mut r = raw();
            let fields = [&mut r.machine_id, &mut r.cpu, &mut r.disk, &mut r.board, &mut r.mac];
            for (f, change) in fields.into_iter().zip(&changes) {
                if *change {
                    *f = Some("changed".into());
                }
            }
            let other = HardwareFingerprint::from_raw(&salt(), &r);
            let n = changes.iter().filter(|c| **c).count();
            prop_assert_eq!(base.changed_components(&other), n);
            prop_assert_eq!(base.matches(&other), n <= 1);
        }
    }
}
