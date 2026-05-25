//! Executes containment commands from the server. Design principles:
//!   * NO shell string interpolation — every action uses structured argv
//!     (`Command::new(bin).arg(..)`), so attacker-influenced fields cannot inject.
//!   * Targets are validated (pid bounds, username charset, server host must be an IP).
//!   * Network actions use a DEDICATED nftables table (`sentinel`/`sentinel_dlp`) applied
//!     atomically via `nft -f`; un-isolation deletes only our table and never flushes the
//!     host's global ruleset.
//!   * Network/USB-module actions (isolate, block_upload, block_usb) report success only
//!     after a verification step (nft table present / module unloaded) and set their
//!     enforcement flag only on that verified success. kill_process and disable_account
//!     report based on the command's exit status.
//!   * Every action is appended to a local access-restricted (0600) append-only audit log.
//! Enforcement is real on Linux; on other platforms the agent reports an honest
//! "unsupported" failure and does NOT set any enforcement flag (telemetry never claims a
//! block that did not happen).

use std::fs::OpenOptions;
use std::io::Write as _;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use chrono::Utc;
use sha2::{Digest, Sha256};

use crate::event::{Command as Cmd, CommandResult};

/// Enforcement flags shared with collectors so block decisions are reflected in telemetry.
#[derive(Clone, Default)]
pub struct Enforcement {
    pub upload_blocked: Arc<AtomicBool>,
    pub usb_blocked: Arc<AtomicBool>,
    pub isolated: Arc<AtomicBool>,
}

impl Enforcement {
    pub fn new() -> Self {
        Self::default()
    }
}

pub struct Responder {
    pub enforce: bool,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub server_host: String,
    pub flags: Enforcement,
    pub audit_path: PathBuf,
}

impl Responder {
    pub fn new(
        enforce: bool,
        server_host: String,
        flags: Enforcement,
        audit_path: PathBuf,
    ) -> Self {
        Responder {
            enforce,
            server_host,
            flags,
            audit_path,
        }
    }

    pub fn execute(&self, cmd: &Cmd) -> CommandResult {
        let res = match cmd.kind.as_str() {
            "kill_process" => self.kill_process(cmd),
            "isolate" => self.isolate(),
            "unisolate" => self.unisolate(),
            "disable_account" => self.disable_account(cmd),
            "block_upload" => self.block_upload(),
            "block_usb" => self.block_usb(),
            "kill_tree" => self.kill_tree(cmd),
            "freeze" => self.freeze(cmd, true),
            "unfreeze" => self.freeze(cmd, false),
            "quarantine_file" => self.quarantine_file(cmd),
            "live_triage" => self.live_triage(),
            other => Err(format!("unknown command: {other}")),
        };
        let ok = res.is_ok();
        let message = res.clone().unwrap_or_else(|e| e);
        self.audit(&cmd.kind, &cmd.target, ok, &message);
        CommandResult {
            id: cmd.id.clone(),
            ok,
            message,
        }
    }

    // -------- process --------
    fn kill_process(&self, cmd: &Cmd) -> Result<String, String> {
        let pid = cmd
            .target
            .get("pid")
            .and_then(|v| v.as_i64())
            .ok_or("missing pid")?;
        if pid <= 1 {
            return Err("refusing to kill pid <= 1".into());
        }
        let out = Command::new("kill")
            .arg("-9")
            .arg(pid.to_string())
            .output()
            .map_err(|e| format!("kill spawn: {e}"))?;
        if out.status.success() {
            Ok(format!("process {pid} terminated"))
        } else {
            Err(format!("kill failed: {}", stderr(&out.stderr)))
        }
    }

    // -------- whole-process-tree kill (cgroup.kill, else recursive SIGKILL) --------
    fn kill_tree(&self, cmd: &Cmd) -> Result<String, String> {
        let pid = cmd.target.get("pid").and_then(|v| v.as_i64()).ok_or("missing pid")? as i32;
        if pid <= 1 {
            return Err("refusing to kill pid <= 1".into());
        }
        #[cfg(target_os = "linux")]
        {
            // Prefer cgroup.kill: atomic, race-free against forks (kernel 5.14+).
            if let Some(dir) = cgroup_dir(pid) {
                let kf = std::path::Path::new(&dir).join("cgroup.kill");
                if kf.exists() && std::fs::write(&kf, "1").is_ok() {
                    return Ok(format!("process tree of {pid} killed via cgroup.kill ({dir})"));
                }
            }
            // Fallback: recursively SIGKILL pid + descendants (collected before killing).
            let mut victims = Vec::new();
            collect_descendants(pid, &mut victims);
            victims.push(pid);
            let mut killed = 0;
            for p in &victims {
                if unsafe { libc::kill(*p, libc::SIGKILL) } == 0 {
                    killed += 1;
                }
            }
            Ok(format!("process tree of {pid} killed ({killed}/{} pids, recursive SIGKILL)", victims.len()))
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err("process-tree kill requires Linux".into())
        }
    }

    // -------- cgroup freeze / thaw (forensic hold without killing) --------
    fn freeze(&self, cmd: &Cmd, freeze: bool) -> Result<String, String> {
        let pid = cmd.target.get("pid").and_then(|v| v.as_i64()).ok_or("missing pid")? as i32;
        if pid <= 1 {
            return Err("refusing to freeze pid <= 1".into());
        }
        #[cfg(target_os = "linux")]
        {
            let dir = cgroup_dir(pid).ok_or("process not in a cgroup v2 group")?;
            let f = std::path::Path::new(&dir).join("cgroup.freeze");
            if !f.exists() {
                return Err("cgroup.freeze unavailable (needs cgroup v2)".into());
            }
            std::fs::write(&f, if freeze { "1" } else { "0" }).map_err(|e| format!("write cgroup.freeze: {e}"))?;
            Ok(format!("process tree of {pid} {} ({dir})", if freeze { "frozen for forensics" } else { "thawed" }))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = freeze;
            Err("cgroup freeze requires Linux".into())
        }
    }

    // -------- quarantine a file (copy → 0000, hash, record for restore) --------
    fn quarantine_file(&self, cmd: &Cmd) -> Result<String, String> {
        let path = cmd.target.get("path").and_then(|v| v.as_str()).ok_or("missing path")?;
        if !valid_quarantine_path(path) {
            return Err(format!("refusing to quarantine protected path: {path}"));
        }
        let src = std::path::Path::new(path);
        if !src.is_file() {
            return Err(format!("not a regular file: {path}"));
        }
        let data = std::fs::read(src).map_err(|e| format!("read: {e}"))?;
        let mut h = Sha256::new();
        h.update(&data);
        let digest = h.finalize();
        let mut hash = String::with_capacity(64);
        for x in digest.iter() {
            hash.push_str(&format!("{:02x}", x));
        }
        let qdir = std::path::Path::new("/var/lib/sentinel/quarantine");
        std::fs::create_dir_all(qdir).map_err(|e| format!("mkdir quarantine: {e}"))?;
        let dest = qdir.join(&hash);
        write_private(&dest, &data).map_err(|e| format!("write quarantine: {e}"))?;
        // record original path + perms for restore
        #[cfg(unix)]
        let mode = {
            use std::os::unix::fs::MetadataExt;
            src.metadata().map(|m| m.mode()).unwrap_or(0)
        };
        #[cfg(not(unix))]
        let mode = 0u32;
        let meta = serde_json::json!({ "original": path, "sha256": hash, "mode": mode, "ts": Utc::now().to_rfc3339() });
        let _ = write_private(&qdir.join(format!("{hash}.json")), meta.to_string().as_bytes());
        // neutralize the original: chmod 000 then remove (copy is safe in quarantine)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(src, std::fs::Permissions::from_mode(0o000));
        }
        std::fs::remove_file(src).map_err(|e| format!("remove original: {e}"))?;
        Ok(format!("quarantined {path} (sha256 {}…) → /var/lib/sentinel/quarantine", &hash[..16]))
    }

    // -------- on-demand live triage snapshot --------
    fn live_triage(&self) -> Result<String, String> {
        let procs = Command::new("ps").args(["-eo", "pid,ppid,user,comm,args", "--sort=-%cpu"]).output().ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).lines().take(40).collect::<Vec<_>>().join("\n")).unwrap_or_default();
        #[cfg(target_os = "linux")]
        let socks = Command::new("ss").args(["-tunp"]).output().ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).lines().take(60).collect::<Vec<_>>().join("\n")).unwrap_or_default();
        #[cfg(not(target_os = "linux"))]
        let socks = String::new();
        let modules = std::fs::read_to_string("/proc/modules").unwrap_or_default()
            .lines().filter_map(|l| l.split_whitespace().next()).take(80).collect::<Vec<_>>().join(",");
        let summary = format!(
            "triage: {} procs sampled, {} socket rows, {} modules",
            procs.lines().count(), socks.lines().count(), modules.split(',').filter(|s| !s.is_empty()).count()
        );
        // write the full snapshot to the audit dir for retrieval; return a summary inline.
        let dir = std::path::Path::new("/var/lib/sentinel/triage");
        if std::fs::create_dir_all(dir).is_ok() {
            let f = dir.join(format!("triage-{}.txt", Utc::now().timestamp()));
            let _ = write_private(&f, format!("== PROCESSES ==\n{procs}\n\n== SOCKETS ==\n{socks}\n\n== MODULES ==\n{modules}\n").as_bytes());
        }
        Ok(summary)
    }

    // -------- isolation (dedicated nft table) --------
    fn isolate(&self) -> Result<String, String> {
        if !self.enforce {
            return Err("isolation disabled by policy (--enforce=false)".into());
        }
        #[cfg(target_os = "linux")]
        {
            let server_rule = match validated_ip(&self.server_host) {
                Some(ip) => format!(
                    "    ip saddr {ip} accept\n  }}\n  chain output {{ type filter hook output priority -1; policy drop;\n    oif \"lo\" accept\n    ct state established,related accept\n    ip daddr {ip} accept\n",
                    ip = ip
                ),
                None => "  }\n  chain output { type filter hook output priority -1; policy drop;\n    oif \"lo\" accept\n    ct state established,related accept\n".into(),
            };
            let ruleset = format!(
                "table inet sentinel {{\n  chain input {{ type filter hook input priority -1; policy drop;\n    iif \"lo\" accept\n    ct state established,related accept\n{server_rule}  }}\n}}\n"
            );
            apply_nft(&ruleset, "sentinel-isolate.nft")?;
            verify_nft_table("sentinel")?;
            // Flag only AFTER verified enforcement — telemetry must not claim "blocked"
            // unless the host is actually isolated.
            self.flags.isolated.store(true, Ordering::SeqCst);
            Ok("endpoint isolated (traffic restricted to management server)".into())
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err("network isolation requires Linux with nftables/NET_ADMIN".into())
        }
    }

    fn unisolate(&self) -> Result<String, String> {
        #[cfg(target_os = "linux")]
        {
            // delete only OUR table; never touch the host's global ruleset
            let _ = nft(&["delete", "table", "inet", "sentinel"]); // ok if already absent
            // Only clear the flag once the table is verifiably gone — otherwise telemetry
            // would claim the host is un-isolated while traffic is still blocked.
            if verify_nft_table("sentinel").is_ok() {
                return Err("failed to remove isolation table (still present)".into());
            }
            self.flags.isolated.store(false, Ordering::SeqCst);
            Ok("endpoint isolation lifted".into())
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.flags.isolated.store(false, Ordering::SeqCst);
            Ok("isolation flag cleared".into())
        }
    }

    // -------- account disable --------
    fn disable_account(&self, cmd: &Cmd) -> Result<String, String> {
        let user = cmd
            .target
            .get("user")
            .and_then(|v| v.as_str())
            .ok_or("missing user")?;
        if !valid_username(user) {
            return Err(format!("invalid username: {user:?}"));
        }
        if PROTECTED_USERS.contains(&user) {
            return Err(format!("refusing to disable protected account {user}"));
        }
        if !self.enforce {
            return Err("account disable disabled by policy (--enforce=false)".into());
        }
        #[cfg(target_os = "linux")]
        {
            let lock = Command::new("usermod").arg("--lock").arg(user).output();
            match lock {
                Ok(o) if o.status.success() => {}
                Ok(o) => return Err(format!("usermod failed: {}", stderr(&o.stderr))),
                Err(e) => return Err(format!("usermod spawn: {e}")),
            }
            // terminate active sessions (best-effort; ignore "no processes" exit code)
            let _ = Command::new("pkill")
                .arg("-KILL")
                .arg("-u")
                .arg(user)
                .output();
            Ok(format!("account {user} locked and sessions terminated"))
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err("account disable requires Linux".into())
        }
    }

    // -------- block uploads (dedicated nft egress table) --------
    fn block_upload(&self) -> Result<String, String> {
        if !self.enforce {
            return Err("upload block disabled by policy (--enforce=false)".into());
        }
        #[cfg(target_os = "linux")]
        {
            let server_allow = validated_ip(&self.server_host)
                .map(|ip| format!("    ip daddr {ip} accept\n"))
                .unwrap_or_default();
            let ruleset = format!(
                "table inet sentinel_dlp {{\n  chain output {{ type filter hook output priority -2; policy accept;\n    oif \"lo\" accept\n{server_allow}    ct state established,related accept\n    udp dport 53 accept\n    tcp dport {{ 80, 443, 21, 8080, 2049 }} ct state new drop\n  }}\n}}\n"
            );
            apply_nft(&ruleset, "sentinel-dlp.nft")?;
            verify_nft_table("sentinel_dlp")?;
            self.flags.upload_blocked.store(true, Ordering::SeqCst);
            Ok("outbound upload channels blocked (new web/ftp/nfs egress dropped)".into())
        }
        #[cfg(not(target_os = "linux"))]
        {
            // Do NOT set the flag — nothing is actually blocked on this platform, so
            // telemetry must not be annotated as "blocked".
            Err("upload enforcement requires Linux nftables".into())
        }
    }

    // -------- block USB mass storage --------
    fn block_usb(&self) -> Result<String, String> {
        if !self.enforce {
            return Err("usb block disabled by policy (--enforce=false)".into());
        }
        #[cfg(target_os = "linux")]
        {
            // Prefer USBGuard if installed; else unload the mass-storage kernel modules.
            if which("usbguard") {
                let out = Command::new("usbguard")
                    .args(["set-parameter", "ImplicitPolicyTarget", "block"])
                    .output();
                if let Ok(o) = out {
                    if o.status.success() {
                        self.flags.usb_blocked.store(true, Ordering::SeqCst);
                        return Ok("USBGuard implicit policy set to block".into());
                    }
                }
            }
            for module in ["usb_storage", "uas"] {
                let _ = Command::new("modprobe").arg("-r").arg(module).output();
            }
            if module_loaded("usb_storage") {
                return Err("failed to unload usb_storage (device busy?)".into());
            }
            self.flags.usb_blocked.store(true, Ordering::SeqCst);
            Ok("USB mass-storage modules unloaded; new removable media blocked".into())
        }
        #[cfg(not(target_os = "linux"))]
        {
            // Do NOT set the flag — nothing is actually blocked on this platform.
            Err("USB enforcement requires Linux (USBGuard/modprobe)".into())
        }
    }

    fn audit(
        &self,
        action: &str,
        target: &std::collections::BTreeMap<String, serde_json::Value>,
        ok: bool,
        msg: &str,
    ) {
        let rec = serde_json::json!({
            "ts": Utc::now().to_rfc3339(),
            "action": action,
            "target": target,
            "ok": ok,
            "result": msg,
        });
        if let Ok(mut f) = private_append(&self.audit_path) {
            let _ = writeln!(f, "{rec}");
        }
    }
}

const PROTECTED_USERS: [&str; 4] = ["root", "daemon", "sshd", "systemd"];

fn valid_username(u: &str) -> bool {
    if u.is_empty() || u.len() > 32 {
        return false;
    }
    let mut chars = u.chars();
    let first = chars.next().unwrap();
    if !(first.is_ascii_lowercase() || first == '_') {
        return false;
    }
    u.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn validated_ip(host: &str) -> Option<String> {
    host.parse::<IpAddr>().ok().map(|ip| ip.to_string())
}

fn stderr(b: &[u8]) -> String {
    String::from_utf8_lossy(b).trim().to_string()
}

#[cfg(target_os = "linux")]
fn nft(args: &[&str]) -> Result<(), String> {
    let out = Command::new("nft")
        .args(args)
        .output()
        .map_err(|e| format!("nft spawn: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!("nft {args:?} failed: {}", stderr(&out.stderr)))
    }
}

#[cfg(target_os = "linux")]
fn apply_nft(ruleset: &str, name: &str) -> Result<String, String> {
    use std::os::unix::fs::OpenOptionsExt;
    // Unpredictable name + O_EXCL + 0600: /tmp is world-writable, so a fixed path could be
    // symlink/replace-raced between write and `nft -f` to subvert the isolation ruleset.
    let stem = name.trim_end_matches(".nft");
    let path = std::env::temp_dir().join(format!("{stem}-{}.nft", uuid::Uuid::new_v4()));
    {
        let mut f = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| format!("create ruleset: {e}"))?;
        f.write_all(ruleset.as_bytes())
            .map_err(|e| format!("write ruleset: {e}"))?;
    }
    let out = Command::new("nft")
        .arg("-f")
        .arg(&path)
        .output()
        .map_err(|e| format!("nft spawn: {e}"))?;
    let _ = std::fs::remove_file(&path);
    if out.status.success() {
        Ok("applied".into())
    } else {
        Err(format!("nft apply failed: {}", stderr(&out.stderr)))
    }
}

#[cfg(target_os = "linux")]
fn verify_nft_table(table: &str) -> Result<(), String> {
    let out = Command::new("nft")
        .args(["list", "table", "inet", table])
        .output()
        .map_err(|e| format!("nft verify spawn: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "verification failed: table inet {table} not present"
        ))
    }
}

#[cfg(target_os = "linux")]
fn module_loaded(name: &str) -> bool {
    std::fs::read_to_string("/proc/modules")
        .map(|s| s.lines().any(|l| l.split_whitespace().next() == Some(name)))
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn which(bin: &str) -> bool {
    if bin.contains('/') {
        return std::path::Path::new(bin).is_file();
    }
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|p| p.join(bin).is_file()))
        .unwrap_or(false)
}

/// Resolve a pid's cgroup-v2 directory under /sys/fs/cgroup (for cgroup.kill/freeze).
#[cfg(target_os = "linux")]
fn cgroup_dir(pid: i32) -> Option<String> {
    let body = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    // cgroup v2 unified line: "0::/path"
    for line in body.lines() {
        if let Some(rest) = line.strip_prefix("0::") {
            let p = format!("/sys/fs/cgroup{}", rest.trim());
            if Path::new(&p).is_dir() {
                return Some(p);
            }
        }
    }
    None
}

/// Collect all descendant pids of `pid` (BFS over /proc/<pid>/task/*/children).
#[cfg(target_os = "linux")]
fn collect_descendants(pid: i32, out: &mut Vec<i32>) {
    let mut stack = vec![pid];
    let mut depth = 0;
    while let Some(p) = stack.pop() {
        depth += 1;
        if depth > 100_000 {
            break;
        }
        if let Ok(tasks) = std::fs::read_dir(format!("/proc/{p}/task")) {
            for t in tasks.flatten() {
                if let Ok(ch) = std::fs::read_to_string(t.path().join("children")) {
                    for c in ch.split_whitespace().filter_map(|s| s.parse::<i32>().ok()) {
                        if c > 1 && !out.contains(&c) {
                            out.push(c);
                            stack.push(c);
                        }
                    }
                }
            }
        }
    }
}

/// Guard quarantine targets: never touch system-critical paths.
fn valid_quarantine_path(path: &str) -> bool {
    if !path.starts_with('/') || path.contains("..") {
        return false;
    }
    const PROTECTED: [&str; 8] = ["/bin/", "/sbin/", "/usr/", "/lib/", "/lib64/", "/etc/", "/boot/", "/proc/"];
    !PROTECTED.iter().any(|p| path.starts_with(p))
}

/// Write a 0600 file (overwrite), for quarantine/triage artifacts.
#[cfg(unix)]
fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = OpenOptions::new().create(true).truncate(true).write(true).mode(0o600).open(path)?;
    f.write_all(data)
}
#[cfg(not(unix))]
fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, data)
}

#[cfg(unix)]
fn private_append(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn private_append(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    OpenOptions::new().create(true).append(true).open(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::BTreeMap;

    fn responder() -> Responder {
        Responder::new(true, "10.0.0.1".into(), Enforcement::new(), std::env::temp_dir().join("sentinel-test-audit.log"))
    }
    fn cmd(kind: &str, target: serde_json::Value) -> Cmd {
        let m: BTreeMap<String, serde_json::Value> =
            target.as_object().map(|o| o.clone().into_iter().collect()).unwrap_or_default();
        Cmd { id: "t".into(), kind: kind.into(), target: m }
    }

    #[test]
    fn username_validation() {
        assert!(valid_username("alice"));
        assert!(valid_username("app_1"));
        assert!(valid_username("_svc"));
        assert!(!valid_username(""));
        assert!(!valid_username("1abc"));        // leading digit
        assert!(!valid_username("Alice"));       // uppercase
        assert!(!valid_username("a;rm -rf"));    // injection chars
        assert!(!valid_username("a b"));         // space
        assert!(!valid_username(&"x".repeat(33))); // too long
    }

    #[test]
    fn server_host_must_be_ip() {
        assert_eq!(validated_ip("10.0.0.5"), Some("10.0.0.5".into()));
        assert!(validated_ip("evil.example.com").is_none());
        assert!(validated_ip("").is_none());
    }

    #[test]
    fn kill_process_rejects_pid_le_1() {
        let r = responder();
        assert!(!r.execute(&cmd("kill_process", json!({"pid": 1}))).ok);
        assert!(!r.execute(&cmd("kill_process", json!({"pid": 0}))).ok);
        assert!(!r.execute(&cmd("kill_process", json!({}))).ok); // missing pid
    }

    #[test]
    fn disable_account_protects_critical_and_validates() {
        let r = responder();
        assert!(!r.execute(&cmd("disable_account", json!({"user": "root"}))).ok);
        assert!(!r.execute(&cmd("disable_account", json!({"user": "a;rm"}))).ok);
        assert!(!r.execute(&cmd("disable_account", json!({}))).ok); // missing user
    }

    #[test]
    fn unknown_command_is_rejected() {
        assert!(!responder().execute(&cmd("nuke_everything", json!({}))).ok);
    }

    #[test]
    fn quarantine_guards_protected_paths() {
        assert!(!valid_quarantine_path("/etc/passwd"));
        assert!(!valid_quarantine_path("/usr/bin/ls"));
        assert!(!valid_quarantine_path("/bin/sh"));
        assert!(!valid_quarantine_path("../etc/shadow"));
        assert!(!valid_quarantine_path("relative/path"));
        assert!(valid_quarantine_path("/home/user/Downloads/malware.bin"));
        assert!(valid_quarantine_path("/tmp/dropper"));
    }

    #[test]
    fn tree_and_freeze_validate_pid() {
        let r = responder();
        assert!(!r.execute(&cmd("kill_tree", json!({"pid": 1}))).ok);
        assert!(!r.execute(&cmd("kill_tree", json!({}))).ok);
        assert!(!r.execute(&cmd("freeze", json!({"pid": 0}))).ok);
        assert!(!r.execute(&cmd("freeze", json!({}))).ok);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn enforcement_unsupported_off_linux_does_not_set_flag() {
        let enf = Enforcement::new();
        let r = Responder::new(true, "10.0.0.1".into(), enf.clone(), std::env::temp_dir().join("a.log"));
        // On non-Linux these must report failure AND leave the flag false (no faked block).
        assert!(!r.execute(&cmd("block_usb", json!({}))).ok);
        assert!(!enf.usb_blocked.load(std::sync::atomic::Ordering::SeqCst));
        assert!(!r.execute(&cmd("block_upload", json!({}))).ok);
        assert!(!enf.upload_blocked.load(std::sync::atomic::Ordering::SeqCst));
        assert!(!r.execute(&cmd("isolate", json!({}))).ok);
        assert!(!enf.isolated.load(std::sync::atomic::Ordering::SeqCst));
    }
}
