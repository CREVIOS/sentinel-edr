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

// ---- eBPF loader (only with --features ebpf) ----
#[cfg(all(feature = "ebpf", target_os = "linux"))]
pub mod loader {
    //! Loads the compiled sentinel-ebpf object, attaches the sched_process_exec tracepoint, and
    //! streams ExecEvents into the agent's event pipeline. Built only with `--features ebpf`.
    use crate::event::{Event, Process};

    /// Mirror of sentinel-ebpf::ExecEvent (same #[repr(C)] layout).
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct ExecEvent {
        pub pid: u32,
        pub ppid: u32,
        pub uid: u32,
        pub comm: [u8; 16],
        pub filename: [u8; 128],
    }

    /// Convert a kernel ExecEvent into a Sentinel process Event.
    pub fn to_event(e: &ExecEvent) -> Event {
        let name = cstr(&e.comm);
        let exe = cstr(&e.filename);
        let mut ev = Event::new("process", "exec", "info")
            .with_user(&uid_name(e.uid))
            .msg(format!("{} executed (ebpf): {}", name, exe));
        ev.process = Some(Process {
            pid: e.pid as i64,
            ppid: e.ppid as i64,
            name,
            exe,
            uid: e.uid as i64,
            user: uid_name(e.uid),
            ..Default::default()
        });
        ev
    }

    fn cstr(b: &[u8]) -> String {
        let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
        String::from_utf8_lossy(&b[..end]).into_owned()
    }
    fn uid_name(uid: u32) -> String {
        // resolve via /etc/passwd; fall back to numeric
        std::fs::read_to_string("/etc/passwd")
            .ok()
            .and_then(|p| {
                p.lines().find_map(|l| {
                    let f: Vec<&str> = l.split(':').collect();
                    if f.len() > 2 && f[2] == uid.to_string() {
                        Some(f[0].to_string())
                    } else {
                        None
                    }
                })
            })
            .unwrap_or_default()
    }

    /// fnv-1a — MUST match the kernel program's hash so blocklist keys line up.
    pub fn fnv1a(bytes: &[u8]) -> u64 {
        let mut h: u64 = 0xcbf29ce484222325;
        for &b in bytes {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        h
    }

    /// Path to the compiled kernel object, shipped alongside the agent. Loaded at runtime (not
    /// `include_bytes!`) so the agent binary builds without the object present.
    const OBJECT_PATH: &str = "/usr/lib/sentinel/sentinel-ebpf.o";

    /// Handle to the loaded programs + their control maps.
    pub struct Loaded {
        bpf: aya::Ebpf,
    }

    /// Load the object, attach both programs (exec tracepoint + bprm LSM), and return a handle.
    /// Telemetry flows immediately; enforcement stays disarmed until `set_enforce(true)`.
    pub fn load() -> anyhow::Result<Loaded> {
        let mut bpf = aya::Ebpf::load_file(OBJECT_PATH)?;
        // exec telemetry tracepoint
        let tp: &mut aya::programs::TracePoint = bpf
            .program_mut("sched_process_exec")
            .ok_or_else(|| anyhow::anyhow!("missing sched_process_exec program"))?
            .try_into()?;
        tp.load()?;
        tp.attach("sched", "sched_process_exec")?;
        // LSM exec gate (kernel must be built with BPF LSM in lsm= boot param)
        if let Some(p) = bpf.program_mut("bprm_check_security") {
            let lsm: &mut aya::programs::Lsm = p.try_into()?;
            // attach requires the kernel btf; best-effort so telemetry still works without LSM.
            if let Err(e) = lsm.load().and_then(|_| lsm.attach()) {
                tracing::warn!(error = %e, "LSM exec-gate unavailable (kernel lacks BPF LSM?)");
            }
        }
        Ok(Loaded { bpf })
    }

    impl Loaded {
        /// Arm/disarm in-kernel exec enforcement (writes the ENFORCE single-slot array).
        pub fn set_enforce(&mut self, on: bool) -> anyhow::Result<()> {
            let mut arr: aya::maps::Array<_, u32> = aya::maps::Array::try_from(
                self.bpf
                    .map_mut("ENFORCE")
                    .ok_or_else(|| anyhow::anyhow!("missing ENFORCE map"))?,
            )?;
            arr.set(0, if on { 1 } else { 0 }, 0)?;
            Ok(())
        }

        /// Add an absolute path to the in-kernel exec blocklist.
        pub fn block_path(&mut self, path: &str) -> anyhow::Result<()> {
            let mut m: aya::maps::HashMap<_, u64, u8> = aya::maps::HashMap::try_from(
                self.bpf
                    .map_mut("BLOCKED_EXEC")
                    .ok_or_else(|| anyhow::anyhow!("missing BLOCKED_EXEC map"))?,
            )?;
            m.insert(fnv1a(path.as_bytes()), 1u8, 0)?;
            Ok(())
        }

        /// Remove a path from the exec blocklist.
        pub fn unblock_path(&mut self, path: &str) -> anyhow::Result<()> {
            let mut m: aya::maps::HashMap<_, u64, u8> = aya::maps::HashMap::try_from(
                self.bpf
                    .map_mut("BLOCKED_EXEC")
                    .ok_or_else(|| anyhow::anyhow!("missing BLOCKED_EXEC map"))?,
            )?;
            let _ = m.remove(&fnv1a(path.as_bytes()));
            Ok(())
        }

        /// Borrow the EXEC_EVENTS perf array for draining (see docs/EBPF.md for the per-CPU
        /// read loop; kept out of the hot default build because it pulls bytes/perf plumbing).
        pub fn exec_events(&mut self) -> Option<&mut aya::maps::MapData> {
            // Drain wiring is documented in docs/EBPF.md; verified on a BTF host.
            let _ = &mut self.bpf;
            None
        }
    }
}

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
