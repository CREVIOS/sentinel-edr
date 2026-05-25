//! libbpf-rs loader for the C/CO-RE object (`agent/bpf/sentinel.bpf.c` → sentinel.bpf.o).
//!
//! Loads at runtime (object shipped to /usr/lib/sentinel/sentinel.bpf.o), attaches the exec
//! telemetry tracepoint + the LSM tamper-protection hooks, arms enforcement, protects the
//! agent's own pid + files, and drains exec events from the ring buffer into the agent batch.
//!
//! LSM attach is best-effort: without `lsm=bpf` at boot the hooks won't attach (warn + keep
//! telemetry). Enforcement is gated by the ENFORCE map so it can be armed live.
#![cfg(all(feature = "ebpf", target_os = "linux"))]

use crate::event::{Event, Process};
use libbpf_rs::{MapCore, MapFlags, ObjectBuilder, RingBufferBuilder};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const OBJECT_PATH: &str = "/usr/lib/sentinel/sentinel.bpf.o";

/// Mirror of `struct exec_event` in sentinel.bpf.c (same #[repr(C)] layout).
#[repr(C)]
#[derive(Clone, Copy)]
struct ExecEvent {
    pid: u32,
    ppid: u32,
    uid: u32,
    comm: [u8; 16],
    filename: [u8; 256],
}

/// Mirror of `struct tamper_event` — emitted by the LSM hooks when a kill/ptrace/file-write
/// against the agent is denied.
#[repr(C)]
#[derive(Clone, Copy)]
struct TamperEvent {
    caller_pid: u32,
    target_pid: u32,
    hook: u32, // 1=kill, 2=ptrace, 3=file
    sig: u32,
    caller_comm: [u8; 16],
}

pub type Sink = Arc<Mutex<Vec<Event>>>;

/// LSM enforcement level (matches the ENFORCE map in the kernel program).
#[derive(Clone, Copy)]
pub enum Enforce {
    /// observe only; never deny
    Audit = 0,
    /// deny kill/ptrace/etc. of the agent, but allow init(pid 1) to manage it
    AllowInit = 1,
    /// deny everyone but the agent itself (fully un-killable)
    All = 2,
}

/// Load the object, arm enforcement, protect self, attach programs, and start draining exec
/// events. Returns the sink the agent loop folds into each batch. The Object is leaked so the
/// programs + ring buffer stay live for the process lifetime.
pub fn load_and_run(enforce: Enforce) -> anyhow::Result<Sink> {
    let mut open = ObjectBuilder::default().open_file(OBJECT_PATH)?;
    // libbpf loads ALL programs at once; the LSM programs fail with -EINVAL unless `lsm=bpf` is
    // in the kernel's active LSM list. So when it isn't, disable autoload for everything except
    // the telemetry tracepoint — telemetry always works; the LSM hooks light up after a reboot
    // with lsm=bpf (same object, just restart). The agent detects this at startup.
    let lsm_active = std::fs::read_to_string("/sys/kernel/security/lsm")
        .map(|s| s.contains("bpf"))
        .unwrap_or(false);
    if !lsm_active {
        for mut p in open.progs_mut() {
            if p.name() != "handle_exec" {
                let _ = p.set_autoload(false);
            }
        }
        tracing::warn!(
            "lsm=bpf not in the active LSM list — loading telemetry only; kernel tamper-protection \
             (kill/ptrace/exec/file hooks) stays OFF until a reboot with lsm=bpf"
        );
    }
    let obj = open.load()?;
    // 'static so the ring buffer + links can outlive this function on the poll thread.
    let obj: &'static mut libbpf_rs::Object = Box::leak(Box::new(obj));

    // arm enforcement level
    if let Some(m) = obj.maps().find(|m| m.name() == "ENFORCE") {
        let _ = m.update(
            &0u32.to_ne_bytes(),
            &(enforce as u32).to_ne_bytes(),
            MapFlags::ANY,
        );
    }
    // protect the agent's own pid (and its guardian parent) → kill/ptrace denied
    if let Some(m) = obj.maps().find(|m| m.name() == "PROTECTED_PIDS") {
        let pid = std::process::id();
        let _ = m.update(&pid.to_ne_bytes(), &[1u8], MapFlags::ANY);
        let ppid = parent_pid();
        if ppid > 1 {
            let _ = m.update(&ppid.to_ne_bytes(), &[1u8], MapFlags::ANY);
        }
    }
    // protect the agent's files (binary, pinned key, config) from delete/rename
    if let Some(m) = obj.maps().find(|m| m.name() == "PROTECTED_INODES") {
        use std::os::unix::fs::MetadataExt;
        for p in [
            "/usr/local/bin/sentinel-agent",
            "/etc/sentinel/server_cmd.pub",
            "/var/lib/sentinel/policy.json",
        ] {
            if let Ok(meta) = std::fs::metadata(p) {
                let _ = m.update(&meta.ino().to_ne_bytes(), &[1u8], MapFlags::ANY);
            }
        }
    }

    // attach every program (tracepoint always; LSM only when lsm=bpf is armed)
    let mut links = Vec::new();
    let mut attached = 0;
    for prog in obj.progs_mut() {
        let name = prog.name().to_string_lossy().into_owned();
        if !lsm_active && name != "handle_exec" {
            continue; // LSM progs aren't loaded when lsm=bpf is off
        }
        match prog.attach() {
            Ok(link) => {
                links.push(link);
                attached += 1;
            }
            Err(e) => {
                tracing::warn!(prog = %name, error = %e, "bpf attach failed (LSM needs lsm=bpf?)")
            }
        }
    }
    std::mem::forget(links); // keep attached for the process lifetime

    // drain exec events → sink
    let sink: Sink = Arc::new(Mutex::new(Vec::new()));
    let sink2 = sink.clone();
    let events_map = obj
        .maps()
        .find(|m| m.name() == "EXEC_EVENTS")
        .ok_or_else(|| anyhow::anyhow!("EXEC_EVENTS map missing"))?;
    let mut rbb = RingBufferBuilder::new();
    rbb.add(&events_map, move |data: &[u8]| {
        if data.len() >= core::mem::size_of::<ExecEvent>() {
            let e = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const ExecEvent) };
            if let Ok(mut q) = sink2.lock() {
                q.push(to_event(&e));
            }
        }
        0
    })?;
    // drain tamper-attempt events (LSM denials) → critical detections on the same sink.
    // bound at this scope (not inside the `if let`) so the map outlives the builder borrow.
    let tamper_map = obj.maps().find(|m| m.name() == "TAMPER_EVENTS");
    if let Some(tm) = &tamper_map {
        let sink3 = sink.clone();
        rbb.add(tm, move |data: &[u8]| {
            if data.len() >= core::mem::size_of::<TamperEvent>() {
                let t = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const TamperEvent) };
                if let Ok(mut q) = sink3.lock() {
                    q.push(to_tamper_event(&t));
                }
            }
            0
        })?;
    }
    let rb = rbb.build()?;
    std::thread::Builder::new()
        .name("bpf-ringbuf".into())
        .spawn(move || loop {
            // poll blocks up to the timeout; the registered callback drains exec events into the
            // shared sink, which the agent loop folds into each batch.
            let _ = rb.poll(Duration::from_millis(250));
        })
        .ok();

    tracing::info!(
        progs = attached,
        "eBPF (libbpf) telemetry + LSM tamper-protection loaded"
    );
    Ok(sink)
}

fn parent_pid() -> u32 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("PPid:").map(|v| v.trim().to_string()))
        })
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

fn to_event(e: &ExecEvent) -> Event {
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

fn to_tamper_event(t: &TamperEvent) -> Event {
    let comm = cstr(&t.caller_comm);
    let hook = match t.hook {
        1 => "kill",
        2 => "ptrace",
        3 => "file-write/delete",
        _ => "unknown",
    };
    let mut ev = Event::new("system", "tamper_attempt", "critical").msg(format!(
        "tamper attempt BLOCKED: {hook} of the Sentinel agent by {comm} (pid {}, target pid {}, sig {})",
        t.caller_pid, t.target_pid, t.sig
    ));
    ev.process = Some(Process {
        pid: t.caller_pid as i64,
        name: comm,
        ..Default::default()
    });
    ev
}

fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

fn uid_name(uid: u32) -> String {
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
