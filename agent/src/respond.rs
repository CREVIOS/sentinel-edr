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
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use chrono::Utc;

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
        self.flags.isolated.store(false, Ordering::SeqCst);
        #[cfg(target_os = "linux")]
        {
            // delete only OUR tables; never touch the host's global ruleset
            let _ = nft(&["delete", "table", "inet", "sentinel"]);
            Ok("endpoint isolation lifted".into())
        }
        #[cfg(not(target_os = "linux"))]
        {
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
    let path = std::env::temp_dir().join(name);
    std::fs::write(&path, ruleset).map_err(|e| format!("write ruleset: {e}"))?;
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
