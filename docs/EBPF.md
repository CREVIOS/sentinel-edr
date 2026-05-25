# Sentinel eBPF — in-kernel telemetry + exec enforcement

> **Status (2026-05-25):** eBPF **telemetry is LIVE on app2/mbovh1** (kernel 6.8, BTF). The
> `sched_process_exec` tracepoint is loaded + attached across all CPUs and streams real-time
> exec events *with full paths* into the pipeline (verified: `bpftool prog show` lists the
> program; 177 events/90s). The `bprm_check_security` **LSM program loads** but is **not
> attached** — that needs `lsm=…,bpf` in GRUB + a reboot (deferred; the loader warns and
> continues). The default agent build (and CI) still **excludes** `--features ebpf`, so the
> shipping binary is unaffected; the eBPF build is opt-in.
>
> Build that worked: bpf-linker via rustc's bundled LLVM (NOT system LLVM — macOS picks up an
> old brew llvm@14 and fails on opaque pointers). On Linux, a builder image
> (`FROM rustlang/rust:nightly-bookworm; RUN rustup component add rust-src && cargo install
> bpf-linker`) caches bpf-linker; then `cargo build --release` in `sentinel-ebpf/` emits the
> portable BPF object. Do NOT mount a volume over `/usr/local/cargo` (hides rustc), and do NOT
> ship a `rust-toolchain.toml` that re-pins the channel (triggers a cross-device rustup sync).

## Why

The polling collectors read `/proc` on an interval. That misses short-lived and fileless
(`memfd`) processes that start and exit between ticks, and it can't *prevent* anything. The
eBPF tier closes both gaps:

| Capability | Mechanism | Kind |
|---|---|---|
| No-miss exec telemetry | `sched_process_exec` tracepoint → perf array | detect |
| Exec allow/deny gate | LSM `bprm_check_security` → `-EPERM` | **prevent** |

## Capability fallback

`ebpf::detect_tier()` picks the best available tier at boot and logs it; the agent never hard-
requires the kernel:

```
eBPF (this module)  →  auditd  →  netlink cn_proc  →  userspace polling (always present)
```

eBPF is selected only when `/sys/kernel/btf/vmlinux` exists **and** the agent has
`CAP_BPF`/`CAP_SYS_ADMIN` (root systemd unit qualifies).

## Kernel requirements

- **BTF**: `CONFIG_DEBUG_INFO_BTF=y` → `/sys/kernel/btf/vmlinux` present (CO-RE relocations).
- **Telemetry**: any modern kernel with tracepoints (≥ 4.18 practically).
- **LSM enforcement**: kernel built with the BPF LSM and it enabled at boot:
  ```
  CONFIG_BPF_LSM=y
  # /etc/default/grub:  GRUB_CMDLINE_LINUX="... lsm=...,bpf"
  cat /sys/kernel/security/lsm   # must list "bpf"
  ```

## Build the kernel object (on a Linux BTF host — not macOS/CI)

```bash
rustup toolchain install nightly --component rust-src
cargo install bpf-linker
cd agent/sentinel-ebpf
cargo +nightly build --release --target bpfel-unknown-none
install -D -m0644 target/bpfel-unknown-none/release/sentinel-ebpf \
  /usr/lib/sentinel/sentinel-ebpf.o
```

The agent loader reads `/usr/lib/sentinel/sentinel-ebpf.o` at runtime (not `include_bytes!`),
so the agent binary builds and ships independently of the object.

## Build + run the agent with eBPF

```bash
cd agent
cargo build --release --features ebpf
# runs as root via systemd; tier auto-detects to "ebpf" when BTF+priv are present
SENTINEL_SERVER=https://sentinel.corp:8443 ./target/release/sentinel-agent
```

## Control plane (ties into the console policy push)

The loader (`agent/src/ebpf.rs::loader`) exposes:

- `load()` → attaches the exec tracepoint (always) and the LSM gate (best-effort; warns and
  continues if the kernel lacks BPF LSM, so telemetry still flows).
- `Loaded::set_enforce(bool)` → arms/disarms the in-kernel gate live (the `ENFORCE` array).
- `Loaded::block_path(path)` / `unblock_path(path)` → maintain the `BLOCKED_EXEC` hash set.

Userspace and the kernel hash paths with the **same fnv-1a** so blocklist keys match. The
intended wiring is: a console `update_policy`/response action (a `block_exec` target) →
loader `block_path` + `set_enforce(true)`. Enforcement defaults **off** (audit-only) so a bad
blocklist can never wedge a host.

## Verification (on the test-bed)

```bash
# telemetry: short-lived proc the poller would miss should still appear (engine/source=ebpf)
bash -c 'true'                       # exec'd + exits instantly
# enforcement (audit → arm → deny):
#  1) block a canary path, keep ENFORCE=0  → exec still allowed (audited)
#  2) set ENFORCE=1                          → exec of the canary returns EACCES/EPERM
/usr/local/bin/canary && echo allowed || echo "blocked by LSM"
sudo bpftool prog show | grep -E 'tracepoint|lsm'   # programs attached
sudo bpftool map dump name BLOCKED_EXEC             # blocklist contents
```

## Remaining integration (the honest TODO list)

1. **CO-RE field reads** — resolve `bprm->filename` (LSM) and the `sched_process_exec`
   `__data_loc` path via the loader's BTF/vmlinux bindings; today both are safe no-ops
   (LSM hashes an empty path → never blocks; tracepoint emits comm+uid without the full path).
2. **Perf drain loop** — `Loaded::exec_events()` returns the map; wire the per-CPU
   `PerfEventArray` reader → `to_event()` → the agent's event channel, and spawn it from
   `main.rs` when `detect_tier() == Tier::Ebpf`.
3. **Policy tie-in** — map a `block_exec` response/policy field to `block_path` + `set_enforce`.
4. **End-to-end test** on a `CONFIG_BPF_LSM` kernel; capture `bpftool` output as evidence.

## Sources

aya book (aya-rs.dev), aya LSM example (dawidmacek.com, eunomia.dev BPF LSM), CO-RE/BTF
(nakryiko.com), `sched_process_exec` format (`/sys/kernel/tracing/events/sched/...`),
BPF LSM boot config (kernel docs `bpf/prog_lsm.rst`).
