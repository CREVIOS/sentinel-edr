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
    /// Live policy (shared with collectors). The `enforce` gate is read from here so a
    /// console `update_policy` can arm/disarm enforcement fleet-wide without a restart.
    pub policy: crate::config::SharedPolicy,
    /// Where to persist a pushed policy so it survives restart.
    pub policy_path: PathBuf,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub server_host: String,
    pub flags: Enforcement,
    pub audit_path: PathBuf,
}

impl Responder {
    pub fn new(
        policy: crate::config::SharedPolicy,
        policy_path: PathBuf,
        server_host: String,
        flags: Enforcement,
        audit_path: PathBuf,
    ) -> Self {
        Responder {
            policy,
            policy_path,
            server_host,
            flags,
            audit_path,
        }
    }

    /// Current enforcement gate (poisoned lock fails closed).
    fn enforce(&self) -> bool {
        self.policy.read().map(|p| p.enforce).unwrap_or(false)
    }

    pub fn execute(&self, cmd: &Cmd) -> CommandResult {
        let res = match cmd.kind.as_str() {
            "kill_process" => self.kill_process(cmd),
            "isolate" => self.isolate(),
            "unisolate" => self.unisolate(),
            "disable_account" => self.disable_account(cmd),
            "block_upload" => self.block_upload(),
            "unblock_upload" => self.unblock_upload(),
            "block_usb" => self.block_usb(),
            "unblock_usb" => self.unblock_usb(),
            "kill_tree" => self.kill_tree(cmd),
            "freeze" => self.freeze(cmd, true),
            "unfreeze" => self.freeze(cmd, false),
            "quarantine_file" => self.quarantine_file(cmd),
            "live_triage" => self.live_triage(),
            "update_policy" => self.update_policy(cmd),
            "self_update" => self.self_update(cmd),
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
        let pid = cmd
            .target
            .get("pid")
            .and_then(|v| v.as_i64())
            .ok_or("missing pid")? as i32;
        if pid <= 1 {
            return Err("refusing to kill pid <= 1".into());
        }
        #[cfg(target_os = "linux")]
        {
            // Prefer cgroup.kill: atomic, race-free against forks (kernel 5.14+).
            if let Some(dir) = cgroup_dir(pid) {
                let kf = std::path::Path::new(&dir).join("cgroup.kill");
                if kf.exists() && std::fs::write(&kf, "1").is_ok() {
                    return Ok(format!(
                        "process tree of {pid} killed via cgroup.kill ({dir})"
                    ));
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
            Ok(format!(
                "process tree of {pid} killed ({killed}/{} pids, recursive SIGKILL)",
                victims.len()
            ))
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err("process-tree kill requires Linux".into())
        }
    }

    // -------- cgroup freeze / thaw (forensic hold without killing) --------
    fn freeze(&self, cmd: &Cmd, freeze: bool) -> Result<String, String> {
        let pid = cmd
            .target
            .get("pid")
            .and_then(|v| v.as_i64())
            .ok_or("missing pid")? as i32;
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
            std::fs::write(&f, if freeze { "1" } else { "0" })
                .map_err(|e| format!("write cgroup.freeze: {e}"))?;
            Ok(format!(
                "process tree of {pid} {} ({dir})",
                if freeze {
                    "frozen for forensics"
                } else {
                    "thawed"
                }
            ))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = freeze;
            Err("cgroup freeze requires Linux".into())
        }
    }

    // -------- quarantine a file (copy → 0000, hash, record for restore) --------
    fn quarantine_file(&self, cmd: &Cmd) -> Result<String, String> {
        let path = cmd
            .target
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or("missing path")?;
        if !valid_quarantine_path(path) {
            return Err(format!("refusing to quarantine protected path: {path}"));
        }
        let src = std::path::Path::new(path);
        // Use symlink_metadata (lstat) — a symlink at an allowed path could point at a
        // protected target (e.g. /home/x -> /etc/shadow); following it would copy that
        // target's bytes into the quarantine store. Refuse symlinks; require a real file.
        let md = std::fs::symlink_metadata(src).map_err(|e| format!("stat: {e}"))?;
        if md.file_type().is_symlink() {
            return Err(format!("refusing to quarantine a symlink: {path}"));
        }
        if !md.is_file() {
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
        let _ = write_private(
            &qdir.join(format!("{hash}.json")),
            meta.to_string().as_bytes(),
        );
        // neutralize the original: chmod 000 then remove (copy is safe in quarantine)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(src, std::fs::Permissions::from_mode(0o000));
        }
        std::fs::remove_file(src).map_err(|e| format!("remove original: {e}"))?;
        Ok(format!(
            "quarantined {path} (sha256 {}…) → /var/lib/sentinel/quarantine",
            &hash[..16]
        ))
    }

    // -------- on-demand live triage snapshot --------
    fn live_triage(&self) -> Result<String, String> {
        let procs = Command::new("ps")
            .args(["-eo", "pid,ppid,user,comm,args", "--sort=-%cpu"])
            .output()
            .ok()
            .map(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .take(40)
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default();
        #[cfg(target_os = "linux")]
        let socks = Command::new("ss")
            .args(["-tunp"])
            .output()
            .ok()
            .map(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .take(60)
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default();
        #[cfg(not(target_os = "linux"))]
        let socks = String::new();
        let modules = std::fs::read_to_string("/proc/modules")
            .unwrap_or_default()
            .lines()
            .filter_map(|l| l.split_whitespace().next())
            .take(80)
            .collect::<Vec<_>>()
            .join(",");
        let summary = format!(
            "triage: {} procs sampled, {} socket rows, {} modules",
            procs.lines().count(),
            socks.lines().count(),
            modules.split(',').filter(|s| !s.is_empty()).count()
        );
        // write the full snapshot to the audit dir for retrieval; return a summary inline.
        let dir = std::path::Path::new("/var/lib/sentinel/triage");
        if std::fs::create_dir_all(dir).is_ok() {
            let f = dir.join(format!("triage-{}.txt", Utc::now().timestamp()));
            let _ = write_private(&f, format!("== PROCESSES ==\n{procs}\n\n== SOCKETS ==\n{socks}\n\n== MODULES ==\n{modules}\n").as_bytes());
        }
        Ok(summary)
    }

    // -------- policy push (console → agent, hot-reloaded, persisted) --------
    // Applies operator-tunable knobs without a restart and writes them to policy.json so
    // they survive one. Unknown fields are ignored; out-of-range values are rejected per
    // field rather than failing the whole push.
    fn update_policy(&self, cmd: &Cmd) -> Result<String, String> {
        let t = &cmd.target;
        let mut changed: Vec<String> = Vec::new();
        {
            let mut p = self
                .policy
                .write()
                .map_err(|_| "policy lock poisoned".to_string())?;
            if let Some(v) = t.get("enforce").and_then(|v| v.as_bool()) {
                p.enforce = v;
                changed.push(format!("enforce={v}"));
            }
            if let Some(v) = t.get("dlp_enabled").and_then(|v| v.as_bool()) {
                p.dlp_enabled = v;
                changed.push(format!("dlp_enabled={v}"));
            }
            if let Some(v) = t.get("paused").and_then(|v| v.as_bool()) {
                p.paused = v;
                changed.push(format!("paused={v}"));
            }
            if let Some(v) = t.get("interval").and_then(|v| v.as_u64()) {
                if (1..=3600).contains(&v) {
                    p.interval_secs = v;
                    changed.push(format!("interval={v}s"));
                } else {
                    return Err("interval must be 1..=3600".into());
                }
            }
            if let Some(arr) = t.get("watch").and_then(|v| v.as_array()) {
                // absolute paths only; reject a push that would leave FIM watching nothing.
                let dirs: Vec<String> = arr
                    .iter()
                    .filter_map(|x| x.as_str())
                    .filter(|s| s.starts_with('/') && !s.contains(".."))
                    .map(|s| s.to_string())
                    .collect();
                if dirs.is_empty() {
                    return Err("watch list must contain at least one absolute path".into());
                }
                p.watch = dirs.clone();
                changed.push(format!("watch={} dirs", dirs.len()));
            }
            if changed.is_empty() {
                return Err("no recognized policy fields in push".into());
            }
            // persist the snapshot while holding the lock so disk + memory stay consistent.
            p.save(&self.policy_path).map_err(|e| e.to_string())?;
        }
        Ok(format!("policy updated: {}", changed.join(", ")))
    }

    // -------- agent self-update (verified binary swap + supervised restart) --------
    // Downloads a new agent binary over HTTPS from the configured Sentinel server, verifies
    // its sha256 against the command's expected digest, atomically replaces the running
    // binary, and asks systemd to restart us into it. Gated behind `enforce` so a
    // compromised channel can't silently swap the binary on a monitor-only fleet.
    fn self_update(&self, cmd: &Cmd) -> Result<String, String> {
        if !self.enforce() {
            return Err("self-update disabled by policy (--enforce=false)".into());
        }
        let url = cmd
            .target
            .get("url")
            .and_then(|v| v.as_str())
            .ok_or("missing url")?;
        let sha = cmd
            .target
            .get("sha256")
            .and_then(|v| v.as_str())
            .ok_or("missing sha256")?
            .to_lowercase();
        let version = cmd
            .target
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let update_url = validate_update_url(url, &self.server_host)?;
        if sha.len() != 64 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("sha256 must be 64 hex chars".into());
        }
        #[cfg(target_os = "linux")]
        {
            self.apply_self_update(update_url.as_str(), &sha, version)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (version, update_url);
            Err("self-update only supported on Linux".into())
        }
    }

    #[cfg(target_os = "linux")]
    fn apply_self_update(&self, url: &str, sha: &str, version: &str) -> Result<String, String> {
        let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
        // stage in the same directory so the final rename is atomic (same filesystem).
        let tmp = exe.with_extension("update");
        // curl with structured argv — no shell, no interpolation into a command string.
        let out = Command::new("curl")
            .args(["-fsSL", "--proto", "=https", "--tlsv1.2", "-o"])
            .arg(&tmp)
            .arg(url)
            .output()
            .map_err(|e| format!("curl spawn: {e}"))?;
        if !out.status.success() {
            let _ = std::fs::remove_file(&tmp);
            return Err(format!("download failed: {}", stderr(&out.stderr)));
        }
        let bytes = std::fs::read(&tmp).map_err(|e| format!("read staged binary: {e}"))?;
        let mut h = Sha256::new();
        h.update(&bytes);
        let got = h.finalize();
        let got_hex: String = got.iter().map(|b| format!("{b:02x}")).collect();
        if got_hex != sha {
            let _ = std::fs::remove_file(&tmp);
            return Err(format!(
                "sha256 mismatch: expected {sha}, got {got_hex} — aborting"
            ));
        }
        // make it executable, then atomically swap over the running binary.
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("chmod staged binary: {e}"))?;
        std::fs::rename(&tmp, &exe).map_err(|e| format!("atomic replace: {e}"))?;
        let size = bytes.len();
        // restart on a short delay so this command's result flushes back over the WS first.
        // systemd (Restart=always) brings us back up on the new binary.
        std::thread::spawn(|| {
            std::thread::sleep(std::time::Duration::from_secs(2));
            let _ = Command::new("systemctl")
                .args(["restart", "sentinel-agent"])
                .status();
        });
        Ok(format!(
            "update verified ({size} bytes{}), restarting in 2s",
            if version.is_empty() {
                String::new()
            } else {
                format!(", v{version}")
            }
        ))
    }

    // -------- isolation (dedicated nft table) --------
    fn isolate(&self) -> Result<String, String> {
        if !self.enforce() {
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
        if !self.enforce() {
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
        if !self.enforce() {
            return Err("upload block disabled by policy (--enforce=false)".into());
        }
        #[cfg(target_os = "linux")]
        {
            let server_allow = validated_ip(&self.server_host)
                .map(|ip| format!("    ip daddr {ip} accept\n"))
                .unwrap_or_default();
            // Drop NEW outbound exfil channels while keeping the box usable (DNS + the Sentinel
            // server + already-established flows stay up). Critically this also drops UDP/443:
            // without it, HTTP/3 (QUIC) lets every modern browser upload straight past a
            // TCP-only DLP rule. TCP set covers web, FTP, SCP/SFTP (22), SMB (445), mail
            // submission (465/587/993/995), NFS (2049), and common alt-HTTP ports.
            let ruleset = format!(
                "table inet sentinel_dlp {{\n  \
                 chain output {{ type filter hook output priority -2; policy accept;\n    \
                 oif \"lo\" accept\n\
                 {server_allow}    \
                 ct state established,related accept\n    \
                 udp dport 53 accept\n    \
                 udp dport {{ 80, 443 }} drop\n    \
                 tcp dport {{ 20, 21, 22, 80, 443, 445, 465, 587, 993, 995, 2049, 8080, 8443 }} ct state new drop\n  \
                 }}\n}}\n"
            );
            apply_nft(&ruleset, "sentinel-dlp.nft")?;
            verify_nft_table("sentinel_dlp")?;
            self.flags.upload_blocked.store(true, Ordering::SeqCst);
            Ok("outbound upload channels blocked (new web/QUIC/ftp/scp/smb/mail/nfs egress dropped)".into())
        }
        #[cfg(not(target_os = "linux"))]
        {
            // Do NOT set the flag — nothing is actually blocked on this platform, so
            // telemetry must not be annotated as "blocked".
            Err("upload enforcement requires Linux nftables".into())
        }
    }

    // -------- lift the upload block --------
    fn unblock_upload(&self) -> Result<String, String> {
        #[cfg(target_os = "linux")]
        {
            // delete only OUR DLP table; never touch the host's global ruleset
            let _ = nft(&["delete", "table", "inet", "sentinel_dlp"]); // ok if already absent
                                                                       // Only clear the flag once the table is verifiably gone, so telemetry can't
                                                                       // claim egress is restored while traffic is still dropped.
            if verify_nft_table("sentinel_dlp").is_ok() {
                return Err("failed to remove upload-block table (still present)".into());
            }
            self.flags.upload_blocked.store(false, Ordering::SeqCst);
            Ok("outbound upload block lifted".into())
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.flags.upload_blocked.store(false, Ordering::SeqCst);
            Ok("upload-block flag cleared".into())
        }
    }

    // -------- block USB mass storage (storage class only) --------
    // Targets ONLY the USB mass-storage interface class (0x08). USB HID (mouse/keyboard,
    // class 0x03) and wireless/Bluetooth controllers (class 0xe0) are deliberately left
    // authorized, so blocking exfil never bricks input devices or locks an admin out.
    // We do NOT use USBGuard's `ImplicitPolicyTarget block` — that denies *every* class
    // not whitelisted and would kill keyboards/Bluetooth on the next plug.
    //
    // Three storage-scoped layers, applied together and then verified:
    //   1. Persistent modprobe override (`install … /bin/true`) so the driver stays out
    //      across reboots and indirect/udev auto-loads (stronger than `blacklist`).
    //   2. Live `modprobe -r` of uas + usb_storage (uas depends on usb_storage → remove first).
    //   3. sysfs deauthorization of already-connected storage devices — unbinds the driver
    //      INSTANTLY even when the module is busy (a mounted drive), which `modprobe -r`
    //      cannot. Per-device + class-filtered, so non-storage interfaces are untouched.
    fn block_usb(&self) -> Result<String, String> {
        if !self.enforce() {
            return Err("usb block disabled by policy (--enforce=false)".into());
        }
        #[cfg(target_os = "linux")]
        {
            // 1. persistent, storage-class-only override
            let conf = "# Managed by Sentinel EDR — block USB mass storage (storage class only).\n\
                        # HID (keyboard/mouse) and Bluetooth are intentionally NOT blocked.\n\
                        install usb_storage /bin/true\n\
                        install uas /bin/true\n";
            std::fs::write(USB_BLOCK_CONF, conf)
                .map_err(|e| format!("write {USB_BLOCK_CONF}: {e}"))?;

            // 2. best-effort live unload (uas first — it depends on usb_storage)
            let _ = Command::new("modprobe").arg("-r").arg("uas").output();
            let _ = Command::new("modprobe")
                .arg("-r")
                .arg("usb_storage")
                .output();

            // 3. deauthorize already-attached storage devices via sysfs (works while busy)
            let mut deauthorized = 0usize;
            for dev in usb_mass_storage_devices() {
                if std::fs::write(dev.join("authorized"), "0").is_ok() {
                    deauthorized += 1;
                }
            }

            // verify: enforced if the driver is gone OR no storage device remains bound.
            let module_gone = !module_loaded("usb_storage");
            let still_bound = usb_mass_storage_devices().len();
            if !module_gone && still_bound > 0 {
                return Err(format!(
                    "usb_storage still active: module loaded and {still_bound} storage device(s) still bound (deauthorization failed — need CAP_SYS_ADMIN and writable /sys)"
                ));
            }
            self.flags.usb_blocked.store(true, Ordering::SeqCst);
            Ok(format!(
                "USB mass storage blocked (persistent modprobe override{}; {deauthorized} attached device(s) deauthorized) — HID/Bluetooth unaffected",
                if module_gone { ", driver unloaded" } else { "" }
            ))
        }
        #[cfg(not(target_os = "linux"))]
        {
            // Do NOT set the flag — nothing is actually blocked on this platform.
            Err("USB enforcement requires Linux (modprobe/sysfs)".into())
        }
    }

    // -------- lift the USB block --------
    fn unblock_usb(&self) -> Result<String, String> {
        #[cfg(target_os = "linux")]
        {
            // 1. remove the persistent override so the driver can load again
            std::fs::remove_file(USB_BLOCK_CONF).or_else(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    Ok(())
                } else {
                    Err(format!("remove {USB_BLOCK_CONF}: {e}"))
                }
            })?;
            // 2. re-authorize any device we deauthorized (kernel re-probes & rebinds)
            let reauthorized = reauthorize_usb_devices();
            // 3. reload the mass-storage drivers (no-op/harmless if built into the kernel)
            let _ = Command::new("modprobe").arg("usb_storage").output();
            let _ = Command::new("modprobe").arg("uas").output();
            self.flags.usb_blocked.store(false, Ordering::SeqCst);
            Ok(format!(
                "USB mass-storage block lifted (override removed, {reauthorized} device(s) re-authorized, drivers reloaded)"
            ))
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.flags.usb_blocked.store(false, Ordering::SeqCst);
            Ok("usb-block flag cleared".into())
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

fn validate_update_url(url: &str, trusted_host: &str) -> Result<reqwest::Url, String> {
    let parsed = reqwest::Url::parse(url).map_err(|e| format!("invalid update url: {e}"))?;
    if parsed.scheme() != "https" {
        return Err("update url must be https".into());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("update url must not contain credentials".into());
    }
    if parsed.fragment().is_some() {
        return Err("update url must not contain a fragment".into());
    }
    let update_host = parsed
        .host_str()
        .ok_or_else(|| "update url must include a host".to_string())?;
    if !hosts_match(update_host, trusted_host) {
        return Err(format!(
            "update host {update_host} is not the trusted Sentinel server {trusted_host}"
        ));
    }
    Ok(parsed)
}

fn hosts_match(update_host: &str, trusted_host: &str) -> bool {
    let update = normalize_host(update_host);
    let trusted = normalize_host(trusted_host);
    !trusted.is_empty() && update == trusted
}

fn normalize_host(host: &str) -> String {
    host.trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase()
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

/// Persistent modprobe override that keeps the USB mass-storage drivers from loading.
#[cfg(target_os = "linux")]
const USB_BLOCK_CONF: &str = "/etc/modprobe.d/sentinel-usb-block.conf";

/// Device dirs under /sys/bus/usb/devices that currently expose a USB mass-storage
/// interface (bInterfaceClass == 08). Interface dirs are named "<dev>:<cfg>.<intf>"
/// (they contain a ':'); the parent device dir has no ':'. We map a matching interface
/// back to its device so deauthorizing it unbinds storage without touching HID/BT.
#[cfg(target_os = "linux")]
fn usb_mass_storage_devices() -> Vec<std::path::PathBuf> {
    let base = std::path::Path::new("/sys/bus/usb/devices");
    let mut devs: Vec<std::path::PathBuf> = Vec::new();
    let Ok(rd) = std::fs::read_dir(base) else {
        return devs;
    };
    for entry in rd.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        // only interface dirs carry bInterfaceClass; they look like "1-1:1.0"
        let Some((dev, _)) = name.split_once(':') else {
            continue;
        };
        let class =
            std::fs::read_to_string(entry.path().join("bInterfaceClass")).unwrap_or_default();
        if class.trim().eq_ignore_ascii_case("08") {
            let p = base.join(dev);
            if !devs.contains(&p) {
                devs.push(p);
            }
        }
    }
    devs
}

/// Re-authorize every USB device left deauthorized (authorized == 0). Called on unblock;
/// after a deauthorization the device's interface children are gone, so we can no longer
/// read the class — we re-authorize any deauthorized device and let the kernel re-probe.
#[cfg(target_os = "linux")]
fn reauthorize_usb_devices() -> usize {
    let base = std::path::Path::new("/sys/bus/usb/devices");
    let mut n = 0usize;
    let Ok(rd) = std::fs::read_dir(base) else {
        return 0;
    };
    for entry in rd.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.contains(':') {
            continue; // skip interface dirs; act on device dirs only
        }
        let af = entry.path().join("authorized");
        let deauthorized = std::fs::read_to_string(&af)
            .map(|s| s.trim() == "0")
            .unwrap_or(false);
        if deauthorized && std::fs::write(&af, "1").is_ok() {
            n += 1;
        }
    }
    n
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
    const PROTECTED: [&str; 8] = [
        "/bin/", "/sbin/", "/usr/", "/lib/", "/lib64/", "/etc/", "/boot/", "/proc/",
    ];
    !PROTECTED.iter().any(|p| path.starts_with(p))
}

/// Write a 0600 file (overwrite), for quarantine/triage artifacts.
#[cfg(unix)]
fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
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

    fn test_policy() -> crate::config::SharedPolicy {
        std::sync::Arc::new(std::sync::RwLock::new(crate::config::AgentPolicy {
            enforce: true,
            dlp_enabled: true,
            paused: false,
            interval_secs: 5,
            watch: vec!["/etc".into()],
        }))
    }
    fn responder() -> Responder {
        Responder::new(
            test_policy(),
            std::env::temp_dir().join("sentinel-test-policy.json"),
            "10.0.0.1".into(),
            Enforcement::new(),
            std::env::temp_dir().join("sentinel-test-audit.log"),
        )
    }
    fn cmd(kind: &str, target: serde_json::Value) -> Cmd {
        let m: BTreeMap<String, serde_json::Value> = target
            .as_object()
            .map(|o| o.clone().into_iter().collect())
            .unwrap_or_default();
        Cmd {
            id: "t".into(),
            kind: kind.into(),
            target: m,
        }
    }

    #[test]
    fn username_validation() {
        assert!(valid_username("alice"));
        assert!(valid_username("app_1"));
        assert!(valid_username("_svc"));
        assert!(!valid_username(""));
        assert!(!valid_username("1abc")); // leading digit
        assert!(!valid_username("Alice")); // uppercase
        assert!(!valid_username("a;rm -rf")); // injection chars
        assert!(!valid_username("a b")); // space
        assert!(!valid_username(&"x".repeat(33))); // too long
    }

    #[test]
    fn server_host_must_be_ip() {
        assert_eq!(validated_ip("10.0.0.5"), Some("10.0.0.5".into()));
        assert!(validated_ip("evil.example.com").is_none());
        assert!(validated_ip("").is_none());
    }

    #[test]
    fn self_update_url_validation_pins_trusted_server() {
        let good = validate_update_url(
            "https://APP2.MAKEBELL.COM./agent/sentinel-agent",
            "app2.makebell.com",
        )
        .unwrap();
        assert_eq!(good.scheme(), "https");
        assert_eq!(good.host_str(), Some("app2.makebell.com."));

        assert!(
            validate_update_url("http://app2.makebell.com/agent", "app2.makebell.com")
                .unwrap_err()
                .contains("https")
        );
        assert!(
            validate_update_url("https://evil.example/agent", "app2.makebell.com")
                .unwrap_err()
                .contains("trusted Sentinel server")
        );
        assert!(
            validate_update_url("https://app2.makebell.com.evil/agent", "app2.makebell.com")
                .unwrap_err()
                .contains("trusted Sentinel server")
        );
        assert!(validate_update_url(
            "https://user:pass@app2.makebell.com/agent",
            "app2.makebell.com"
        )
        .unwrap_err()
        .contains("credentials"));
        assert!(validate_update_url(
            "https://app2.makebell.com/agent#fragment",
            "app2.makebell.com"
        )
        .unwrap_err()
        .contains("fragment"));
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
        assert!(
            !r.execute(&cmd("disable_account", json!({"user": "root"})))
                .ok
        );
        assert!(
            !r.execute(&cmd("disable_account", json!({"user": "a;rm"})))
                .ok
        );
        assert!(!r.execute(&cmd("disable_account", json!({}))).ok); // missing user
    }

    #[test]
    fn unknown_command_is_rejected() {
        assert!(!responder().execute(&cmd("nuke_everything", json!({}))).ok);
    }

    #[test]
    fn self_update_rejects_untrusted_host_before_download() {
        let r = responder();
        let res = r.execute(&cmd(
            "self_update",
            json!({
                "url": "https://evil.example/sentinel-agent",
                "sha256": "a".repeat(64),
            }),
        ));
        assert!(!res.ok);
        assert!(res.message.contains("trusted Sentinel server"));
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

    #[cfg(unix)]
    #[test]
    fn quarantine_refuses_symlink() {
        let dir = std::env::temp_dir().join(format!("sentinel-qtest-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let link = dir.join("link");
        std::os::unix::fs::symlink("/etc/hostname", &link).unwrap();
        let r = responder();
        let res = r.execute(&cmd(
            "quarantine_file",
            json!({ "path": link.to_str().unwrap() }),
        ));
        assert!(!res.ok, "must refuse a symlink target");
        assert!(res.message.contains("symlink"), "msg: {}", res.message);
        // the symlink itself must still exist (we refused before touching it)
        assert!(link.symlink_metadata().is_ok());
        let _ = std::fs::remove_dir_all(&dir);
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
        let r = Responder::new(
            test_policy(),
            std::env::temp_dir().join("sentinel-test-policy2.json"),
            "10.0.0.1".into(),
            enf.clone(),
            std::env::temp_dir().join("a.log"),
        );
        // On non-Linux these must report failure AND leave the flag false (no faked block).
        assert!(!r.execute(&cmd("block_usb", json!({}))).ok);
        assert!(!enf.usb_blocked.load(std::sync::atomic::Ordering::SeqCst));
        assert!(!r.execute(&cmd("block_upload", json!({}))).ok);
        assert!(!enf.upload_blocked.load(std::sync::atomic::Ordering::SeqCst));
        assert!(!r.execute(&cmd("isolate", json!({}))).ok);
        assert!(!enf.isolated.load(std::sync::atomic::Ordering::SeqCst));
    }
}
