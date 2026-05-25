#!/usr/bin/env bash
#
# Sentinel agent installer — one command to deploy on a Linux endpoint.
#
#   curl -fsSL https://<server>/install-agent.sh | sudo \
#     SENTINEL_SERVER=https://sentinel.corp:8443 \
#     SENTINEL_ENROLL_TOKEN=xxxxx bash
#
# Resolves a binary in this order:
#   1) $SENTINEL_AGENT_BINARY  (path to a prebuilt binary)
#   2) $SENTINEL_RELEASE_URL/sentinel-agent-<os>-<arch>  (download)
#   3) build from ./agent with cargo (if this repo is present)
#
set -euo pipefail

SERVER="${SENTINEL_SERVER:-}"
TOKEN="${SENTINEL_ENROLL_TOKEN:-}"
WATCH="${SENTINEL_WATCH:-/etc,/usr/local/bin,/home,/var/www}"
PREFIX="${PREFIX:-/usr/local/bin}"
ETC="/etc/sentinel"
BIN="$PREFIX/sentinel-agent"

need_root() { if [ "$(id -u)" != "0" ]; then echo "ERROR: run as root (use sudo)"; exit 1; fi; }
log() { printf '\033[36m▸\033[0m %s\n' "$*"; }

need_root
[ -z "$SERVER" ] && { echo "ERROR: set SENTINEL_SERVER"; exit 1; }
[ -z "$TOKEN" ]  && { echo "ERROR: set SENTINEL_ENROLL_TOKEN"; exit 1; }
# Enroll token + agent key travel in headers — refuse cleartext transport in production.
case "$SERVER" in
  https://*) ;;
  *) if [ "${SENTINEL_ALLOW_INSECURE:-0}" = "1" ]; then
       log "WARNING: SENTINEL_SERVER is not https:// — credentials sent in cleartext (SENTINEL_ALLOW_INSECURE=1)"
     else
       echo "ERROR: SENTINEL_SERVER must be https:// (set SENTINEL_ALLOW_INSECURE=1 to override for local testing)"; exit 1
     fi ;;
esac

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"; case "$ARCH" in x86_64|amd64) ARCH=x86_64;; aarch64|arm64) ARCH=aarch64;; esac

# If no explicit binary source, default to the server's /dl directory so a single
# `SENTINEL_SERVER + SENTINEL_ENROLL_TOKEN` is enough to install anywhere.
if [ -z "${SENTINEL_AGENT_BINARY:-}" ] && [ -z "${SENTINEL_RELEASE_URL:-}" ]; then
  SENTINEL_RELEASE_URL="${SERVER%/}/dl"
fi

# --- 1) resolve binary ---
if [ -n "${SENTINEL_AGENT_BINARY:-}" ] && [ -x "$SENTINEL_AGENT_BINARY" ]; then
  log "using provided binary: $SENTINEL_AGENT_BINARY"
  install -m 0755 "$SENTINEL_AGENT_BINARY" "$BIN"
elif [ -n "${SENTINEL_RELEASE_URL:-}" ]; then
  url="$SENTINEL_RELEASE_URL/sentinel-agent-${OS}-${ARCH}"
  log "downloading $url"
  tmp="$(mktemp)"; curl -fsSL "$url" -o "$tmp"
  # Supply-chain integrity: verify the binary against a published SHA-256 before installing.
  if curl -fsSL "$url.sha256" -o "$tmp.sha" 2>/dev/null; then
    want="$(awk '{print $1}' "$tmp.sha")"
    got="$( (sha256sum "$tmp" 2>/dev/null || shasum -a 256 "$tmp") | awk '{print $1}')"
    if [ -z "$want" ] || [ "$want" != "$got" ]; then
      rm -f "$tmp" "$tmp.sha"; echo "ERROR: agent checksum mismatch (want=$want got=$got) — aborting"; exit 1
    fi
    log "checksum verified ($got)"
  elif [ "${SENTINEL_REQUIRE_CHECKSUM:-0}" = "1" ]; then
    rm -f "$tmp"; echo "ERROR: no checksum at $url.sha256 and SENTINEL_REQUIRE_CHECKSUM=1 — aborting"; exit 1
  else
    log "WARNING: no checksum published at $url.sha256 — installing UNVERIFIED binary (set SENTINEL_REQUIRE_CHECKSUM=1 to fail closed)"
  fi
  install -m 0755 "$tmp" "$BIN"; rm -f "$tmp" "$tmp.sha"
elif [ -d "agent" ] && command -v cargo >/dev/null 2>&1; then
  log "building from source (cargo, release)…"
  ( cd agent && cargo build --release )
  install -m 0755 agent/target/release/sentinel-agent "$BIN"
else
  echo "ERROR: no binary source. Set SENTINEL_AGENT_BINARY or SENTINEL_RELEASE_URL, or run from the repo with cargo installed."
  exit 1
fi
log "installed binary → $BIN"

# --- 2) install enforcement deps (best-effort) ---
if command -v apt-get >/dev/null 2>&1; then
  apt-get update -qq && apt-get install -y -qq nftables iproute2 procps usbutils >/dev/null 2>&1 || true
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y -q nftables iproute procps-ng usbutils >/dev/null 2>&1 || true
fi

# --- 3) write config ---
mkdir -p "$ETC"
umask 077
cat > "$ETC/agent.env" <<EOF
SENTINEL_SERVER=$SERVER
SENTINEL_ENROLL_TOKEN=$TOKEN
SENTINEL_WATCH=$WATCH
# mTLS (optional): SENTINEL_AGENT_TLS_CA / SENTINEL_AGENT_TLS_CERT / SENTINEL_AGENT_TLS_KEY
EOF
chmod 600 "$ETC/agent.env"
log "wrote $ETC/agent.env"

# --- 4) systemd service + self-healing guardian (always-on; survives kill/stop/disable/mask) ---
if command -v systemctl >/dev/null 2>&1; then
  cat > /etc/systemd/system/sentinel-agent.service <<'UNIT'
[Unit]
Description=Sentinel Endpoint Agent (EDR/DLP)
After=network-online.target
Wants=network-online.target
# Never stop trying to restart, no matter how fast it dies (an attacker SIGKILL-looping the
# agent can't exhaust a start-limit and make systemd give up).
StartLimitIntervalSec=0

[Service]
Type=simple
EnvironmentFile=-/etc/sentinel/agent.env
ExecStart=/usr/local/bin/sentinel-agent
# Resurrect on ANY exit (crash or SIGKILL) within ~1s.
Restart=always
RestartSec=1
# Mutual resurrection: each time the agent starts, make sure the guardian timer is armed —
# so if someone stops/disables the guardian, the next agent start re-arms it (and the guardian
# does the same for the agent). To keep both dead an attacker must stop+mask BOTH at once.
ExecStartPre=-/usr/bin/systemctl enable --now sentinel-guard.timer
# Self-protection: exempt from OOM killer so the agent survives memory pressure.
OOMScoreAdjust=-1000
StateDirectory=sentinel
Environment=SENTINEL_STATE=/var/lib/sentinel/agent.json
AmbientCapabilities=CAP_NET_ADMIN CAP_SYS_MODULE CAP_KILL CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_BPF CAP_PERFMON CAP_NET_RAW
# An EDR must read AND act (quarantine) on files fleet-wide, so /home must be writable; the
# responder itself refuses to touch system-critical paths (/usr,/etc,/boot,...). ProtectSystem
# stays at full so /usr,/boot,/etc remain read-only at the unit level (defence in depth).
ProtectHome=false
ProtectSystem=full

[Install]
WantedBy=multi-user.target
UNIT

  # Guardian: a oneshot that revives the agent if it was stopped/disabled/masked (Restart=always
  # only covers crash/kill, NOT `systemctl stop|disable|mask`). Driven by a timer every 15s.
  cat > /etc/systemd/system/sentinel-guard.service <<'GUNIT'
[Unit]
Description=Sentinel Agent Guardian (revives the agent if disabled/stopped/masked)

[Service]
Type=oneshot
# unmask (in case someone masked it) → ensure enabled → ensure running.
ExecStart=/bin/sh -c '/usr/bin/systemctl is-active --quiet sentinel-agent || { /usr/bin/systemctl unmask sentinel-agent 2>/dev/null; /usr/bin/systemctl enable --now sentinel-agent; }'
GUNIT

  cat > /etc/systemd/system/sentinel-guard.timer <<'TUNIT'
[Unit]
Description=Sentinel Agent Guardian timer

[Timer]
OnBootSec=15
OnUnitInactiveSec=15
AccuracySec=1s
Persistent=true

[Install]
WantedBy=timers.target
TUNIT

  systemctl daemon-reload
  systemctl enable --now sentinel-agent
  systemctl enable --now sentinel-guard.timer
  log "service + self-healing guardian enabled — status:"
  systemctl --no-pager --lines=0 status sentinel-agent || true
else
  log "no systemd; start manually: SENTINEL_STATE=/var/lib/sentinel/agent.json $BIN"
fi

echo
log "Sentinel agent installed & enrolled against $SERVER"
log "logs: journalctl -u sentinel-agent -f"
