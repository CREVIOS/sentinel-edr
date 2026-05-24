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
  tmp="$(mktemp)"; curl -fsSL "$url" -o "$tmp"; install -m 0755 "$tmp" "$BIN"; rm -f "$tmp"
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

# --- 4) systemd service (always-on, restart on crash + reboot) ---
if command -v systemctl >/dev/null 2>&1; then
  cat > /etc/systemd/system/sentinel-agent.service <<'UNIT'
[Unit]
Description=Sentinel Endpoint Agent (EDR/DLP)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=-/etc/sentinel/agent.env
ExecStart=/usr/local/bin/sentinel-agent
Restart=always
RestartSec=5
StateDirectory=sentinel
Environment=SENTINEL_STATE=/var/lib/sentinel/agent.json
AmbientCapabilities=CAP_NET_ADMIN CAP_SYS_MODULE CAP_KILL
ProtectHome=read-only
ProtectSystem=full

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable --now sentinel-agent
  log "service enabled — status:"
  systemctl --no-pager --lines=0 status sentinel-agent || true
else
  log "no systemd; start manually: SENTINEL_STATE=/var/lib/sentinel/agent.json $BIN"
fi

echo
log "Sentinel agent installed & enrolled against $SERVER"
log "logs: journalctl -u sentinel-agent -f"
