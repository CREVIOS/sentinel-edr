//! eBPF kernel-telemetry integration + capability detection and the fallback chain.
//!
//! The agent prefers in-kernel capture (real-time, no missed short-lived procs) but must run
//! everywhere, so it degrades gracefully:
//!
//!     eBPF (this module, --features ebpf)  →  auditd  →  netlink cn_proc  →  userspace polling
//!
//! Only the eBPF tip and the capability probe live here; the polling tier is always present
//! (collectors.rs). `detect_tier()` is compiled in every build so the agent logs which tier it
//! is using; the actual eBPF loader is behind `#[cfg(feature = "ebpf")]` so the default binary
//! needs no aya/bpf-linker.

/// Telemetry tiers in preference order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    Ebpf,
    Auditd,
    Netlink,
    Polling,
}

impl Tier {
    pub fn as_str(self) -> &'static str {
        match self {
            Tier::Ebpf => "ebpf",
            Tier::Auditd => "auditd",
            Tier::Netlink => "netlink",
            Tier::Polling => "polling",
        }
    }
}

/// Probe the host and return the best available telemetry tier. Pure capability inspection —
/// no side effects — so it is safe to call at startup and log the result.
pub fn detect_tier() -> Tier {
    #[cfg(all(feature = "ebpf", target_os = "linux"))]
    {
        if ebpf_supported() {
            return Tier::Ebpf;
        }
    }
    #[cfg(target_os = "linux")]
    {
        if auditd_present() {
            return Tier::Auditd;
        }
        if netlink_proc_available() {
            return Tier::Netlink;
        }
    }
    Tier::Polling
}

/// eBPF needs a BTF-enabled kernel and the privilege to load programs.
#[cfg(target_os = "linux")]
#[cfg_attr(not(feature = "ebpf"), allow(dead_code))]
fn ebpf_supported() -> bool {
    // CO-RE requires kernel BTF; CAP_BPF (5.8+) or CAP_SYS_ADMIN required to load.
    std::path::Path::new("/sys/kernel/btf/vmlinux").exists() && has_bpf_priv()
}

#[cfg(target_os = "linux")]
#[cfg_attr(not(feature = "ebpf"), allow(dead_code))]
fn has_bpf_priv() -> bool {
    // Effective uid 0 covers CAP_SYS_ADMIN/CAP_BPF in the common (root systemd) deployment.
    unsafe { libc::geteuid() == 0 }
}

#[cfg(target_os = "linux")]
fn auditd_present() -> bool {
    std::path::Path::new("/var/run/auditd.pid").exists()
        || std::path::Path::new("/sbin/auditctl").exists()
}

#[cfg(target_os = "linux")]
fn netlink_proc_available() -> bool {
    // cn_proc connector requires the kernel CONFIG_PROC_EVENTS; presence is best-effort here.
    std::path::Path::new("/proc/net/netlink").exists()
}

// The eBPF program loader moved to `bpf.rs` (C/libbpf-rs CO-RE). This module keeps only the
// capability/tier detection used by the agent loop.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_strings_stable() {
        assert_eq!(Tier::Ebpf.as_str(), "ebpf");
        assert_eq!(Tier::Polling.as_str(), "polling");
    }

    #[test]
    fn detect_returns_a_tier() {
        // On the test host (no BPF priv / non-linux) this must resolve to a valid lower tier,
        // never panic.
        let t = detect_tier();
        assert!(matches!(
            t,
            Tier::Ebpf | Tier::Auditd | Tier::Netlink | Tier::Polling
        ));
    }
}
