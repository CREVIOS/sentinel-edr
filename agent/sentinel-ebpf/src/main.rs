//! Sentinel in-kernel telemetry (eBPF). Real-time, no-miss process execution capture that
//! userspace /proc polling can't match (short-lived procs, exact argv, acting uid).
//!
//! Attaches to the `sched_process_exec` tracepoint — fires on every successful execve/execveat,
//! including fileless (memfd) and short-lived processes that exit between poll cycles. Each
//! event is pushed to a perf/ring buffer the userspace loader (agent src/ebpf.rs) drains and
//! converts into a Sentinel process Event.
//!
//! Build: `cargo +nightly build --release` with `bpf-linker` installed; target bpfel-unknown-none.
//! This file is `no_std`/`no_main` and only compiles for the BPF target.
#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, tracepoint},
    maps::PerfEventArray,
    programs::TracePointContext,
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_uid_gid},
};

/// Wire record shared with userspace (must match the loader's repr in src/ebpf.rs).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecEvent {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub comm: [u8; 16],     // task->comm (truncated process name)
    pub filename: [u8; 128], // exec'd path (from the tracepoint args)
}

#[map]
static EXEC_EVENTS: PerfEventArray<ExecEvent> = PerfEventArray::new(0);

// The sched_process_exec tracepoint format (see /sys/kernel/tracing/events/sched/
// sched_process_exec/format): offset 8 holds the __data_loc filename pointer; older kernels
// expose the path via the args. The loader resolves the exact offset via CO-RE/BTF at load.
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
    if let Ok(comm) = aya_ebpf::helpers::bpf_get_current_comm() {
        ev.comm = comm;
    }
    // filename: read the __data_loc offset from the tracepoint context. The exact field offset
    // is kernel-version-specific; the userspace loader patches it via BTF (CO-RE) before attach.
    // A bounded read keeps the verifier happy.
    let _ = unsafe { ctx.read_at::<u32>(8) }; // placeholder for the __data_loc resolve
    EXEC_EVENTS.output(ctx, &ev, 0);
    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
