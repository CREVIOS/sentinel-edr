//! User-facing warnings when an enforcement block intercepts an action on the endpoint.
//!
//! When a USB drive is used while USB is blocked, or an upload is dropped by DLP, the
//! person at the keyboard otherwise sees only a silent failure ("permission denied",
//! "device not ready"). This surfaces *why* it failed, on the host itself, over two
//! best-effort channels:
//!   * `notify-send` — a desktop popup to each active graphical session (needs the
//!     user's D-Bus session bus; we run it as that user via `runuser`).
//!   * `wall`        — a broadcast to all terminals, covering headless / SSH sessions.
//!
//! Both are best-effort and Linux-only: failures are swallowed (a missing notify-send or
//! no graphical session must never break the agent or the block itself).

/// Show a warning on the endpoint. No-op (logs nothing) on non-Linux.
pub fn warn(title: &str, body: &str) {
    #[cfg(target_os = "linux")]
    {
        desktop_notify(title, body);
        wall_broadcast(&format!("{title} — {body}"));
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (title, body);
    }
}

/// Pop a `notify-send` toast in every active graphical session.
#[cfg(target_os = "linux")]
fn desktop_notify(title: &str, body: &str) {
    use std::process::{Command, Stdio};

    // Enumerate sessions; columns are: SESSION  UID  USER  SEAT  TTY
    let out = match Command::new("loginctl")
        .args(["list-sessions", "--no-legend"])
        .output()
    {
        Ok(o) if o.status.success() => o.stdout,
        _ => return, // no systemd-logind / no sessions — wall still covers terminals
    };
    let listing = String::from_utf8_lossy(&out);
    let mut notified: Vec<String> = Vec::new();
    for line in listing.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 3 {
            continue;
        }
        let (uid, user) = (cols[1], cols[2]);
        if notified.iter().any(|u| u == uid) {
            continue; // one popup per user even with multiple sessions
        }
        // A graphical session has a per-user D-Bus session bus socket here.
        let bus = format!("/run/user/{uid}/bus");
        if !std::path::Path::new(&bus).exists() {
            continue;
        }
        // Run as the logged-in user (root → user needs no password via runuser).
        let _ = Command::new("runuser")
            .args([
                "-u",
                user,
                "--",
                "notify-send",
                "--app-name=Sentinel EDR",
                "--urgency=critical",
                "--icon=security-high",
                title,
                body,
            ])
            .env("DBUS_SESSION_BUS_ADDRESS", format!("unix:path={bus}"))
            .env("DISPLAY", ":0")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        notified.push(uid.to_string());
    }
}

/// Broadcast a one-line warning to all logged-in terminals.
#[cfg(target_os = "linux")]
fn wall_broadcast(msg: &str) {
    use std::io::Write;
    use std::process::{Command, Stdio};

    // `-n` suppresses the banner (root only); message is read from stdin.
    let child = Command::new("wall")
        .arg("-n")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    if let Ok(mut child) = child {
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(format!("[Sentinel EDR] {msg}\n").as_bytes());
        }
        let _ = child.wait();
    }
}
