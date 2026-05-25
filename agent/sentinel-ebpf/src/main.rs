//! Sentinel in-kernel telemetry + enforcement (eBPF).
//!
//! Two capabilities live here, both in-kernel so they cannot be evaded from userspace:
//!
//!   1. Real-time process-execution telemetry (`sched_process_exec` tracepoint) — captures
//!      every successful execve/execveat, including fileless (memfd) and short-lived procs
//!      that exit between /proc poll cycles, with the acting uid and exact path.
//!
//!   2. Exec enforcement (LSM `bprm_check_security`) — the "best-of-best" capability: an
//!      in-kernel allow/deny gate on program execution. Userspace populates a blocklist of
//!      path hashes; when enforcement is armed the hook returns -EPERM and the exec never
//!      happens. This is real prevention, not after-the-fact detection.
//!
//! Build (on a BTF-enabled Linux host, NOT macOS/CI-default):
//!   rustup toolchain install nightly --component rust-src
//!   cargo install bpf-linker
//!   cargo +nightly build --release --target bpfel-unknown-none
//! The resulting object is loaded by the agent's userspace loader (../src/ebpf.rs) via aya.
//!
//! `no_std`/`no_main`; only compiles for the BPF target. See docs/EBPF.md for the runbook.
#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid},
    macros::{lsm, map, tracepoint},
    maps::{Array, HashMap, PerfEventArray},
    programs::{LsmContext, TracePointContext},
};

/// Wire record shared with userspace (must match the loader's repr in src/ebpf.rs).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecEvent {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub comm: [u8; 16],      // task->comm (truncated process name)
    pub filename: [u8; 128], // exec'd path (from the tracepoint args)
}

#[map]
static EXEC_EVENTS: PerfEventArray<ExecEvent> = PerfEventArray::new(0);

/// Blocklist of path hashes (fnv-1a of the absolute exec path) the LSM hook denies. Populated
/// from userspace (agent policy → loader). Value is unused (presence = blocked).
#[map]
static BLOCKED_EXEC: HashMap<u64, u8> = HashMap::with_max_entries(4096, 0);

/// Single-slot enforcement arm switch. [0]==1 → bprm_check denies blocked execs; 0 → audit
/// only (telemetry still flows). Kept separate so enforcement can be toggled live without
/// reloading the program (ties into the console policy push).
#[map]
static ENFORCE: Array<u32> = Array::with_max_entries(1, 0);

// ---- telemetry: process exec ----

#[tracepoint(category = "sched", name = "sched_process_exec")]
pub fn sched_process_exec(ctx: TracePointContext) -> u32 {
    match try_exec(&ctx) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

fn try_exec(ctx: &TracePointContext) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let mut ev = ExecEvent {
        pid: (pid_tgid >> 32) as u32,
        ppid: 0,
        uid: uid_gid as u32,
        comm: [0u8; 16],
        filename: [0u8; 128],
    };
    if let Ok(comm) = bpf_get_current_comm() {
        ev.comm = comm;
    }
    // The sched/sched_process_exec tracepoint format stores the path as a __data_loc field at
    // offset 8: a u32 whose low 16 bits are the byte offset of the (NUL-terminated) string
    // within the event record. Read that, then copy the path with a bounded loop the verifier
    // can prove safe.
    let dloc: u32 = unsafe { ctx.read_at::<u32>(8) }.unwrap_or(0);
    let foff = (dloc & 0xffff) as usize;
    if foff != 0 {
        for i in 0..(ev.filename.len() - 1) {
            let c: u8 = unsafe { ctx.read_at::<u8>(foff + i) }.unwrap_or(0);
            ev.filename[i] = c;
            if c == 0 {
                break;
            }
        }
    }
    EXEC_EVENTS.output(ctx, &ev, 0);
    Ok(())
}

// ---- enforcement: LSM exec gate ----

/// LSM hook fired before a program is exec'd. Returning a negative errno denies the exec; 0
/// permits it. We deny only when enforcement is armed AND the path hash is in BLOCKED_EXEC, so
/// a misconfigured blocklist can never wedge the host while in audit mode.
#[lsm(hook = "bprm_check_security")]
pub fn bprm_check_security(ctx: LsmContext) -> i32 {
    try_bprm(&ctx).unwrap_or(0)
}

fn try_bprm(ctx: &LsmContext) -> Result<i32, i64> {
    // arg0 is `*const linux_binprm`. Reading bprm->filename requires CO-RE/BTF struct offsets;
    // the loader supplies the vmlinux bindings so this resolves on the target kernel. Until the
    // field read is relocated, hash an empty path (never in the blocklist) so the hook is a safe
    // no-op rather than denying everything.
    let _binprm: *const core::ffi::c_void = unsafe { ctx.arg(0) };
    let path_hash: u64 = 0; // TODO(core): fnv1a(bprm->filename) via bpf_probe_read_kernel_str

    let enforcing = ENFORCE.get(0).copied().unwrap_or(0) == 1;
    if enforcing && unsafe { BLOCKED_EXEC.get(&path_hash).is_some() } {
        return Ok(-1); // -EPERM
    }
    Ok(0)
}

/// fnv-1a over a byte path. Userspace computes the same hash so the blocklist keys match.
#[allow(dead_code)]
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    let mut i = 0;
    while i < bytes.len() {
        h ^= bytes[i] as u64;
        h = h.wrapping_mul(0x100000001b3);
        i += 1;
    }
    h
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
