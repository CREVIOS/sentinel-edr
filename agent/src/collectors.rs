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
use sysinfo::{Pid, ProcessesToUpdate, System};
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
    seen: HashSet<u32>,
    first: bool,
}

impl ProcessCollector {
    pub fn new() -> Self {
        ProcessCollector {
            sys: System::new(),
            seen: HashSet::new(),
            first: true,
        }
    }

    pub fn poll(&mut self) -> Vec<Event> {
        self.sys.refresh_processes(ProcessesToUpdate::All, true);
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
            let sev = if is_suspicious(&name, &cmdline) {
                "medium"
            } else {
                "info"
            };
            let ev = Event::new("process", "exec", sev).msg(format!(
                "{} executed: {}",
                name,
                truncate(&cmdline, 240)
            ));
            let mut ev = ev;
            ev.process = Some(Process {
                pid: pidu as i64,
                ppid: proc_.parent().map(|p| p.as_u32() as i64).unwrap_or(0),
                name,
                exe,
                cmdline,
                uid: 0,
                user: String::new(),
                parent,
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
                let mut ev = Event::new("network", "connect", "info").msg(format!(
                    "outbound {} connection to {}",
                    conn.proto, conn.remote
                ));
                ev.network = Some(NetInfo {
                    direction: "outbound".into(),
                    proto: conn.proto.clone(),
                    local_addr: conn.local.clone(),
                    remote: conn.remote.clone(),
                    category: conn.category(),
                    ..Default::default()
                });
                out.push(ev);
            }
        }
        self.seen = current;
        self.first = false;
        out
    }
}

#[derive(Clone)]
struct Conn {
    proto: String,
    local: String,
    remote: String,
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

fn established_connections() -> Vec<Conn> {
    #[cfg(target_os = "macos")]
    let cmd = ("lsof", vec!["-nP", "-iTCP", "-sTCP:ESTABLISHED"]);
    #[cfg(not(target_os = "macos"))]
    let cmd = ("ss", vec!["-tunp", "state", "established"]);

    let out = match Command::new(cmd.0).args(&cmd.1).output() {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };
    let text = String::from_utf8_lossy(&out.stdout);
    let mut set: HashMap<String, Conn> = HashMap::new();
    for line in text
        .lines()
        .filter(|l| !l.starts_with("Netid") && !l.starts_with("COMMAND"))
    {
        #[cfg(target_os = "macos")]
        {
            for tok in line.split_whitespace() {
                if let Some((local, remote)) = tok.split_once("->") {
                    if is_remote(remote) {
                        let c = Conn {
                            proto: "tcp".into(),
                            local: local.into(),
                            remote: remote.into(),
                        };
                        set.insert(c.key(), c);
                    }
                }
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 5 {
                continue;
            }
            let proto = fields[0].to_string();
            let local = fields[3].to_string();
            let remote = fields[4].to_string();
            if is_remote(&remote) {
                let c = Conn {
                    proto,
                    local,
                    remote,
                };
                set.insert(c.key(), c);
            }
        }
    }
    set.into_values().take(50).collect()
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
