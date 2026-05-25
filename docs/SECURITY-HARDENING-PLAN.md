# Sentinel — Enterprise Security Hardening Plan

**Goal:** make it cryptographically infeasible to forge commands or telemetry, tamper-evident
when anyone touches the agent, and lock ingest/console to known source IPs. Single-tenant
deployment (no multi-tenancy). The headline guarantee: **no network attacker, MITM, compromised
server path, or rogue operator can change what the agent does or fake what it reports — and any
local tampering is loud, not silent.**

## 0. Honest threat model (what "unbreakable" really means)

We defend against:

| # | Adversary | Defense |
|---|---|---|
| T1 | Network MITM / CA compromise | cert pinning + Ed25519 command signing |
| T2 | Compromised server path / rogue operator forging commands | Ed25519 command signing with an **offline** key the server process doesn't hold |
| T3 | Replay of captured valid commands | nonce + monotonic ts/seq, persisted replay cache |
| T4 | Spoofed/forged telemetry (attacker posts fake "all clear") | per-device Ed25519 telemetry signatures |
| T5 | Local root: kill / disable / uninstall agent | passphrase-gated uninstall, self-FIM, "agent-dark" server alert, (Phase 3) eBPF-LSM kill-protection |
| T6 | Local root: modify agent binary / config / pinned keys | self-FIM + signature-checked config + immutability flags + (P3) LSM write-block |
| T7 | Ingest/console reached from unknown IP | source-IP allowlists (ingest + console), admin-editable |
| T8 | Data-at-rest theft (DB/backup) | field-level envelope encryption of sensitive columns |
| T9 | Supply-chain (tampered binary/object/image) | signed releases (cosign/minisign), SBOM, verified install |
| T10 | Tampering with the audit trail | hash-chained immutable audit log |

**What is NOT achievable (state plainly):** a local root user can always *kill* a userspace
process (DoS the agent) — no userspace EDR is immune, and even CrowdStrike/SentinelOne are
bypassed (2025 BYOI/BYOVD). Our guarantee is **integrity + tamper-evidence**, not
indestructibility: root can stop the agent, but cannot (a) forge its telemetry, (b) make it run
attacker commands, or (c) do any of it *silently* — every tamper raises a high-severity,
server-side, cryptographically-trustworthy alert. Phase 3 (eBPF-LSM, needs a reboot) adds
kernel-grade kill/write protection that makes even the DoS require defeating the kernel.

---

## Phase 1 — Cryptographic integrity + IP lockdown (no reboot, highest value)

### 1.1 Key hierarchy

- **Command signing keypair (Ed25519)** — the root of "nobody changes the agent".
  - Private key generated **offline**, stored age/KMS-encrypted, loaded by the *signing* service
    only (ideally a separate tiny signer process / HSM, not the public-facing API). Never in the
    DB, never in the agent.
  - Public key is **baked into the agent at install** → `/etc/sentinel/server_cmd.pub` (root:root,
    0444) and also compiled-in as a fallback default. Agent pins it.
- **Per-device identity keypair (Ed25519)** — proves "this telemetry is really from this host".
  - Generated **on-device** at enroll; private key `0600`, TPM-sealed when a TPM is present.
  - Public key registered with the server during enroll (bound to `agent_id`).
- **Enroll token** (existing) — one-time, scopes first contact only; replaced by device key after.

### 1.2 Command signing (server → agent) — defeats T1/T2/T3

Extend the wire `Command`/`ResponseAction` with an envelope:

```jsonc
{
  "id": "...", "kind": "kill_process", "target": {...}, "agent_id": "...",
  "nonce": "<uuid>", "ts": 1716640000, "exp": 1716640120,
  "sig": "<base64 Ed25519 over canonical-json(id,kind,target,agent_id,nonce,ts,exp)>"
}
```

Agent verifies, in order, before executing **any** command:
1. `sig` valid against the pinned command pubkey.
2. `agent_id == self`.
3. `now` within `[ts-skew, exp]` (skew ≤ 30s, TTL ≤ 120s).
4. `nonce` not in the persisted replay cache (`/var/lib/sentinel/seen_nonces`, bounded LRU).

Any failure → **drop + emit a `system`/critical "rejected unsigned/forged command" event** (itself
device-signed) + local audit. Result: full compromise of the WS/mTLS path still cannot inject a
runnable command without the offline private key.

### 1.3 Policy signing + anti-rollback — defeats T2 for `update_policy`

`update_policy` carries a signed policy doc with a monotonic `version`. Agent applies only if the
signature verifies **and** `version > last_applied` (stored in `policy.json`). Blocks rogue policy
push and downgrade-to-weak-policy.

### 1.4 Self-update signing + anti-rollback — hardens existing `self_update`

Manifest `{version,url,sha256,exp}` is Ed25519-signed. Agent verifies signature → downloads →
verifies sha256 (existing) → checks `version > current` → atomic swap. No unsigned or rollback
updates.

### 1.5 Telemetry authenticity (agent → server) — defeats T4

Each event batch is signed with the device key (header `X-Sentinel-Sig` + `X-Sentinel-Seq`
monotonic + `ts`). Server verifies against the enrolled device pubkey; rejects bad sig / replayed
seq / stale ts. Upgrades today's shared-key auth to non-repudiable per-device signatures.

### 1.6 Certificate pinning — defeats T1 even on CA compromise

Agent pins the server leaf **SPKI** (public-key pin), with a backup pin for rotation:
`SENTINEL_SERVER_PIN="sha256//<b64>,sha256//<backup>"`. Connection refused on mismatch even if the
presented cert chains to a trusted CA. Layer on top of existing mTLS.

### 1.7 IP allowlisting (admin-editable) — T7, explicitly requested

Two independent allowlists, evaluated on the **real client IP** (existing trusted-proxy/XFF
handling), *before* auth:

- `INGEST_ALLOW_CIDRS` — only these source IPs/CIDRs may hit `enroll`, `events`, `agent/ws`
  ("where the data comes from"). Everything else → 403 + logged.
- `CONSOLE_ALLOW_CIDRS` — only these may reach the console + `/api/v1/*` admin surface (office/VPN).

Stored in the DB (`settings` table), **hot-reloaded**, edited from an admin **Settings → Access**
page (CIDR list, add/remove, with a "you're about to lock yourself out" guard that always keeps the
caller's current IP). Defense-in-depth layers: host nftables + nginx `allow/deny` documented as
belt-and-suspenders. (This is the practical form of "white-label IP" for a single tenant — bind +
restrict the console to a chosen IP/domain.)

### 1.8 Agent anti-tamper (userspace, no reboot) — T5/T6 (evidence)

- **Uninstall/stop guard:** local stop/uninstall requires a server-issued passphrase token; the
  installer + a `sentinel-agent guard` wrapper enforce it. systemd unit hardened:
  `NoNewPrivileges`, `ProtectSystem=strict` + explicit `ReadWritePaths`, `ProtectKernelModules`
  off only where needed, minimal `CapabilityBoundingSet` (keep `CAP_NET_ADMIN`, `CAP_BPF`,
  `CAP_DAC_OVERRIDE`, `CAP_NET_RAW`).
- **Self-FIM:** agent watches its own binary, `policy.json`, `server_cmd.pub`; on change → critical
  alert and refuse to run with a tampered pinned key.
- **Config immutability:** `chattr +i` on pinned key + unit where supported (signature-checked
  regardless).
- **Watchdog:** systemd `WatchdogSec` + `sd_notify` heartbeat (auto-restart a hung agent) on top of
  `Restart=always` + `oom_score_adj=-1000` (existing).
- **"Agent-dark" detection:** server raises a high-sev detection + notify when an enrolled agent
  stops heartbeating beyond a threshold → killing the agent is **loud**.

### 1.9 Self-healing / resurrection (killed ⇒ auto-restart, always) — T5

Layered so the agent comes back no matter how it's taken down, and staying down requires
defeating multiple independent mechanisms (each one logged):

1. **`Restart=always` + `RestartSec=1` + `StartLimitIntervalSec=0`** — any crash or SIGKILL ⇒
   restart within ~1s, with **no** start-limit (an attacker can't SIGKILL-loop it until systemd
   gives up — the default `StartLimitBurst=5/10s` would otherwise stop it; we disable that).
2. **Guardian timer (`sentinel-guard.timer` every 15s → `sentinel-guard.service`)** — covers what
   `Restart=` does NOT: `systemctl stop` / `disable` / `mask`. The guardian `unmask`s, `enable`s,
   and `start`s the agent if it isn't active. So a clean stop is undone within 15s.
3. **Mutual resurrection** — the agent's `ExecStartPre` re-arms the guardian timer on every start,
   and the guardian re-enables the agent. To keep both dead an attacker must `stop`+`mask` **both**
   units in the same window AND prevent either from re-running — and every such action is a logged,
   alertable event.
4. **Reboot survival** — `WantedBy=multi-user.target` + `OnBootSec` on the timer; agent + guardian
   both come up at boot.
5. **Watchdog (with the agent code change)** — `WatchdogSec` + `sd_notify` heartbeat so a *hung*
   (not killed) agent is force-restarted by systemd. Added when the agent emits `sd_notify`.
6. **Phase 3 (eBPF-LSM)** — the ultimate: `task_kill` hook **denies the SIGKILL itself** (EPERM),
   so the agent can't even be stopped without defeating the kernel. Resurrection layers above are
   the userspace approximation until the reboot window.

Honest bound: a determined root can, in one atomic burst, `mask`+`stop` both units and kill both
processes. Userspace can't make that impossible — but it makes it (a) multi-step, (b) racy against
1s/15s revival, and (c) **loud** (each stop/kill ⇒ device-signed critical event + server
"agent-dark" alarm). Phase 3 closes the last gap.

### Phase 1 acceptance tests
- Forge a command without the key → agent rejects + critical event. ✅
- Replay a captured valid command → rejected (nonce seen). ✅
- Present a valid-CA but wrong-key cert → connection refused (pin). ✅
- POST events from a non-allowlisted IP → 403. ✅
- POST forged telemetry for an agent → rejected (bad device sig). ✅
- `chmod`/overwrite the agent binary → self-FIM critical alert. ✅
- `systemctl kill` the agent → "agent-dark" alert within the heartbeat window. ✅

---

## Phase 2 — Data-at-rest + tamper-evident audit + signed supply chain

### 2.1 Field-level encryption (T8)
Envelope-encrypt sensitive columns (`process.cmdline`, `dlp.sample`, `file.path`, captured
`extra.content`): per-row AES-256-GCM data key wrapped by a master key from age/KMS/
`SENTINEL_MASTER_KEY` (not in DB). Decrypt only in the API for authorized roles; SIEM export
redacts unless explicitly authorized.

### 2.2 Hash-chained immutable audit log (T10)
Every privileged action (login, role change, response issued, policy push, allowlist edit, rule
toggle, suppression) appended with `prev_hash = H(prev_row)`; broken chain ⇒ tampering. Queryable
in console; optional daily anchor (publish the head hash out-of-band).

### 2.3 Signed releases (T9)
CI signs the agent binary + eBPF object + server/dashboard images with cosign/minisign + SBOM
(syft / `cargo auditable`). `install-agent.sh` verifies the **signature**, not just sha256.
Existing `cargo-audit`/`govulncheck`/`pnpm audit` stay.

---

## Phase 3 — Kernel-grade enforcement (needs `lsm=…,bpf` in GRUB + one reboot)

eBPF-LSM hooks make tampering require defeating the kernel:
- `task_kill` / `task_prctl` → deny SIGKILL/ptrace of the agent PID from non-init.
- `bprm_check_security` → the exec-allow/deny gate (already loaded) goes **enforcing**.
- `file_open` / `inode_setattr` → deny writes to the agent binary, pinned key, and config.

Gated on a maintenance window because the reboot restarts every service on the host.

---

## Sequencing & files touched (Phase 1)

1. `agent/src/crypto.rs` (new) — Ed25519 verify (pinned cmd key) + device keygen/sign; canonical
   JSON; nonce replay cache.
2. `agent/src/respond.rs` — verify command envelope before dispatch; reject + audit.
3. `agent/src/config.rs` — pinned pubkey load, device key persist, replay-cache path, server pin.
4. `agent/src/transport.rs` — cert pinning (rustls custom verifier), sign telemetry batches + seq.
5. `agent/src/main.rs` — self-FIM task; watchdog `sd_notify`.
6. `server/internal/sign/` (new) — Ed25519 sign service (key from age/KMS), used by `respond`.
7. `server/internal/respond/respond.go` — attach nonce/ts/exp/sig to every command.
8. `server/internal/api/api.go` — verify device-signed telemetry; IP allowlist middleware
   (ingest + console); settings CRUD for allowlists; "agent-dark" detection.
9. `server/internal/store` — `settings` table (allowlists), device pubkeys, audit chain (P2).
10. `dashboard/app/(app)/settings` — Access page (CIDR allowlists, with lock-out guard).
11. `deploy/app2/sentinel-agent.service` + `install-agent.sh` — hardening + key pinning + uninstall
    passphrase.
12. `docs/` — key-rotation runbook, threat model (this doc).

**Order:** signing+pinning → IP allowlists → self-FIM/agent-dark → uninstall guard. Each lands +
deploys + is verified by its acceptance test before the next.
