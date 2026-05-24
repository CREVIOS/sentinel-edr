# Sentinel — Capability Build Plan (Tier 1–4)

Research-backed implementation plan. Increments are build-verified + committed independently;
kernel-only pieces (eBPF-LSM) are isolated so the rest ships without a kernel test-bed.

## Guiding split
- **Userspace, testable, deployable now** → do first (most value lands without kernel risk).
- **Kernel/eBPF** → isolated module + auditd fallback; documented interface.

## Workstreams

### W1 — Deploy new agent to fleet (Goal #1)  [PRIORITY]
- Build agent for linux in a container (Rust builds fine in docker; gremlin is dashboard-only).
- Publish `sentinel-agent-linux-x86_64` + `.sha256` to nginx webroot `/dl/`.
- Reinstall on `mbovh1` via `install-agent.sh` (SHA-256 verified). Confirm new telemetry
  (uid/user, net pid+bytes, container, lineage, kmod, mount) lands in console.

### W2 — IOC / threat-intel engine (Goal #5, server)
- `internal/intel`: in-memory IOC store (sha256 / ip / domain), loaded from local feed files +
  optional URL feeds (OTX/abuse.ch/Bert-JanP lists; newline or CSV). TTL refresh.
- Pipeline: match `file.hash`, `network.remote`/`domain`, process exe hash → `detection`
  (engine="ioc"), severity from feed. Bounded, unit-tested.
- Console: IOC count on overview; feed status in settings.

### W3 — Rootkit + hardening posture (Goal #6, agent)
- `RootkitCollector`: hidden-PID (walk pid range, `kill(pid,0)` vs `/proc` listing diff),
  hidden listening ports (`/proc/net` vs `ss`), `/etc/ld.so.preload` present/changed,
  kernel taint (`/proc/sys/kernel/tainted`).
- `PostureCollector` (periodic): sysctl posture (`kptr_restrict`, `dmesg_restrict`,
  `kexec_load_disabled`, `unprivileged_bpf_disabled`), Secure-Boot/lockdown
  (`/sys/kernel/security/lockdown`), IMA present (`/sys/kernel/security/ima`), CIS-style checks.
  Emits `system`/`posture` events → server rules grade them.

### W4 — Enforcement (Goal #7) — userspace first
- respond.rs: **cgroup-aware whole-tree kill** (`cgroup.kill` write; fallback pidfd + SIGKILL
  of pid+children), **cgroup.freeze** action (forensic hold), **agent self-protection**
  (`oom_score_adj=-1000`, `PR_SET_DUMPABLE=0`, watchdog re-exec via systemd `Restart=always`).
- **fanotify exec-allowlist** (FAN_OPEN_EXEC_PERM, userspace — no eBPF) as opt-in `block_exec`.
- eBPF-LSM `bprm_check_security` → separate `agent/ebpf/` (aya), documented, kernel-gated, NOT
  blocking this milestone.

### W5 — Forensics / response (Goal #8)
- respond.rs commands: **quarantine_file** (copy→`/var/lib/sentinel/quarantine`, `chmod 000`,
  sha256, original perms recorded for restore), **live_triage** (snapshot procs/sockets/
  modules/recent-files/loaded-libs → result), **memdump** (`/proc/<pid>/maps`+`mem` regions → file).
- **console→agent policy push**: new command `update_policy` (watch dirs, rule toggles, DLP on/off);
  server endpoint `POST /api/v1/agents/{id}/policy`.
- **Console incident view**: process-tree from `lineage`, unified timeline (events+detections+
  responses for an agent/detection) — "show the right thing first, rest one click away".

### W6 — Scale / ops (Goal #13)
- TimescaleDB **hierarchical continuous aggregate**: `events_daily` on `events_hourly`
  (2.9+), staggered non-overlapping refresh (no concurrent refresh on hierarchical).
- **Retention tiers**: raw 30d, hourly 180d, daily 2y (drop raw, keep rollups).
- **Agent auto-update**: enroll/heartbeat reports version; server compares to published; pushes
  `self_update` command (download verified binary + systemd restart).
- Mesh soak: load-gen script for N agents (documented; not run against prod).

## Sequence
W1 (deploy) → W2 (IOC) → W3 (posture/rootkit) → W6 (caggs/retention) → W4 (enforcement) →
W5 (forensics + console timeline) → eBPF-LSM (documented module).

## Sources
YARA-X (docs.rs/yara-x), aya eBPF-LSM (dawidmacek.com, eunomia.dev), cgroup.kill (LWN 855924),
TimescaleDB hierarchical caggs (tigerdata docs), OTX/MISP/abuse.ch + Bert-JanP/Open-Source-Threat-Intel-Feeds,
fapolicyd/FAN_OPEN_EXEC_PERM (man7, Red Hat), rootkit detection (lsrootkit, getdents/kill diff),
SOC process-tree/timeline UX (Vectra, Netwitness, Simbian 2025).
