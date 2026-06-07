#!/usr/bin/env bash
#
# Sentinel agent installer — one command to deploy on a Linux endpoint.
#
#   curl -fsSL https://<console>/install-agent.sh | sudo \
#     SENTINEL_SERVER=https://<console> \
#     SENTINEL_ENROLL_TOKEN=xxxxx \
#     SENTINEL_SIGNING_PUBKEY_FILE=/etc/sentinel/release-signing.pub \
#     bash
#
# The whole script is wrapped in main() and executed only on the last line, so a truncated
# or interrupted download can never run a partial install. Downloads are HTTPS-pinned, the
# agent binary is verified against a published SHA-256 and, by default, an Ed25519 signature
# before it is installed, and the service is installed as a hardened systemd unit.
#
# Resolves a binary in this order:
#   1) $SENTINEL_AGENT_BINARY              (path to a prebuilt binary)
#   2) $SENTINEL_RELEASE_URL/sentinel-agent-<os>-<arch>   (download, default: <server>/dl)
#   3) build from ./agent with cargo      (if this repo is present)
#
set -euo pipefail

# Release signing public key (Ed25519, verified with openssl pkeyutl).
#
# Do not bake the old committed key back into this script: its private key was exposed in Git
# history and must be rotated. For production installs, provide the rotated trust anchor via
# SENTINEL_SIGNING_PUBKEY_FILE or SENTINEL_SIGNING_PUBKEY_PEM. Signature verification is required
# by default; set SENTINEL_REQUIRE_SIGNATURE=0 only for local development.
DEFAULT_SENTINEL_SIGNING_PUBKEY=''
SENTINEL_REQUIRE_SIGNATURE="${SENTINEL_REQUIRE_SIGNATURE:-1}"

log()  { printf '\033[36m▸\033[0m %s\n' "$*"; }
warn() { printf '\033[33m!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31m✗ ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# HTTPS-pinned curl. --proto '=https' refuses any non-HTTPS URL even across redirects, so a
# downgrade cannot leak the enroll token or fetch an unverified binary. Override only for
# local testing with SENTINEL_ALLOW_INSECURE=1.
sc_curl() {
  if [ "${SENTINEL_ALLOW_INSECURE:-0}" = "1" ]; then
    curl --fail --silent --show-error --location "$@"
  else
    curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 "$@"
  fi
}

need_root() { [ "$(id -u)" = "0" ] || die "run as root (use sudo)"; }

require_https() {
  case "$1" in
    https://*) ;;
    *) if [ "${SENTINEL_ALLOW_INSECURE:-0}" = "1" ]; then
         warn "SENTINEL_SERVER is not https:// — credentials will be sent in cleartext (SENTINEL_ALLOW_INSECURE=1)"
       else
         die "SENTINEL_SERVER must be https:// (set SENTINEL_ALLOW_INSECURE=1 to override for local testing)"
       fi ;;
  esac
}

verify_checksum() {
  # $1 = local file, $2 = checksum URL. Fails closed when SENTINEL_REQUIRE_CHECKSUM=1.
  local file="$1" url="$2" want got
  if sc_curl "$url" -o "$file.sha" 2>/dev/null; then
    want="$(awk '{print $1}' "$file.sha")"
    got="$( (sha256sum "$file" 2>/dev/null || shasum -a 256 "$file") | awk '{print $1}')"
    rm -f "$file.sha"
    [ -n "$want" ] && [ "$want" = "$got" ] || die "agent checksum mismatch (want=$want got=$got) — aborting"
    log "checksum verified (sha256:${got:0:16}…)"
  elif [ "${SENTINEL_REQUIRE_CHECKSUM:-0}" = "1" ]; then
    die "no checksum at $url and SENTINEL_REQUIRE_CHECKSUM=1 — aborting"
  else
    warn "no checksum published at $url — set SENTINEL_REQUIRE_CHECKSUM=1 to fail closed"
  fi
}

verify_signature() {
  # $1 = local file, $2 = signature URL. Ed25519 over the raw binary. Fails closed by default.
  local file="$1" url="$2" pub="" tmp_pub=""

  if ! command -v openssl >/dev/null 2>&1; then
    [ "$SENTINEL_REQUIRE_SIGNATURE" = "1" ] && die "openssl not found and signature verification is required — aborting"
    warn "openssl not found — skipping signature verification"
    return 0
  fi

  if ! sc_curl "$url" -o "$file.sig" 2>/dev/null; then
    [ "$SENTINEL_REQUIRE_SIGNATURE" = "1" ] && die "no signature at $url and signature verification is required — aborting"
    warn "no signature published at $url — set SENTINEL_REQUIRE_SIGNATURE=1 to fail closed"
    return 0
  fi

  if [ -n "${SENTINEL_SIGNING_PUBKEY_FILE:-}" ]; then
    [ -r "$SENTINEL_SIGNING_PUBKEY_FILE" ] || { rm -f "$file.sig"; die "cannot read SENTINEL_SIGNING_PUBKEY_FILE=$SENTINEL_SIGNING_PUBKEY_FILE"; }
    pub="$SENTINEL_SIGNING_PUBKEY_FILE"
  elif [ -n "${SENTINEL_SIGNING_PUBKEY_PEM:-}" ]; then
    tmp_pub="$(mktemp)"
    printf '%s\n' "$SENTINEL_SIGNING_PUBKEY_PEM" > "$tmp_pub"
    pub="$tmp_pub"
  elif [ -n "$DEFAULT_SENTINEL_SIGNING_PUBKEY" ]; then
    tmp_pub="$(mktemp)"
    printf '%s\n' "$DEFAULT_SENTINEL_SIGNING_PUBKEY" > "$tmp_pub"
    pub="$tmp_pub"
  else
    rm -f "$file.sig"
    die "signature is present but no trusted signing public key is configured; rotate the exposed key and set SENTINEL_SIGNING_PUBKEY_FILE"
  fi

  if openssl pkeyutl -verify -pubin -inkey "$pub" -rawin -in "$file" -sigfile "$file.sig" >/dev/null 2>&1; then
    log "signature verified (ed25519)"
  else
    rm -f "$tmp_pub" "$file.sig"
    die "agent signature verification FAILED — aborting (possible tampering)"
  fi
  rm -f "$tmp_pub" "$file.sig"
}

main() {
  need_root

  local SERVER TOKEN WATCH PREFIX ETC BIN OS ARCH
  SERVER="${SENTINEL_SERVER:-}"
  TOKEN="${SENTINEL_ENROLL_TOKEN:-}"
  WATCH="${SENTINEL_WATCH:-/etc,/usr/local/bin,/home,/var/www}"
  PREFIX="${PREFIX:-/usr/local/bin}"
  ETC="/etc/sentinel"
  BIN="$PREFIX/sentinel-agent"

  [ -n "$SERVER" ] || die "set SENTINEL_SERVER"
  [ -n "$TOKEN" ]  || die "set SENTINEL_ENROLL_TOKEN"
  require_https "$SERVER"

  OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
  ARCH="$(uname -m)"; case "$ARCH" in x86_64|amd64) ARCH=x86_64;; aarch64|arm64) ARCH=aarch64;; esac

  # Default the binary source to the server's /dl directory so SENTINEL_SERVER +
  # SENTINEL_ENROLL_TOKEN is enough to install anywhere.
  if [ -z "${SENTINEL_AGENT_BINARY:-}" ] && [ -z "${SENTINEL_RELEASE_URL:-}" ]; then
    SENTINEL_RELEASE_URL="${SERVER%/}/dl"
  fi

  # --- 1) resolve + verify binary into a staging file -----------------------------------
  local staged; staged="$(mktemp)"
  if [ -n "${SENTINEL_AGENT_BINARY:-}" ] && [ -x "${SENTINEL_AGENT_BINARY}" ]; then
    log "using provided binary: $SENTINEL_AGENT_BINARY"
    cp "$SENTINEL_AGENT_BINARY" "$staged"
  elif [ -n "${SENTINEL_RELEASE_URL:-}" ]; then
    local url="${SENTINEL_RELEASE_URL%/}/sentinel-agent-${OS}-${ARCH}"
    log "downloading $url"
    sc_curl "$url" -o "$staged" || die "download failed: $url"
    verify_checksum "$staged" "$url.sha256"
    verify_signature "$staged" "$url.sig"
  elif [ -d "agent" ] && command -v cargo >/dev/null 2>&1; then
    log "building from source (cargo, release)…"
    ( cd agent && cargo build --release )
    cp agent/target/release/sentinel-agent "$staged"
  else
    die "no binary source. Set SENTINEL_AGENT_BINARY or SENTINEL_RELEASE_URL, or run from the repo with cargo."
  fi

  # --- 2) install enforcement deps (best-effort) ----------------------------------------
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq && apt-get install -y -qq nftables iproute2 procps usbutils >/dev/null 2>&1 || true
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q nftables iproute procps-ng usbutils >/dev/null 2>&1 || true
  fi

  # --- 3) install binary atomically (stop first to avoid ETXTBSY on upgrade) -------------
  if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet sentinel-agent 2>/dev/null; then
    log "stopping running agent for upgrade"; systemctl stop sentinel-agent || true
  fi
  install -m 0755 "$staged" "$BIN"; rm -f "$staged"
  log "installed binary → $BIN"

  # --- 4) write config (root-only) ------------------------------------------------------
  mkdir -p "$ETC"; umask 077
  cat > "$ETC/agent.env" <<EOF
SENTINEL_SERVER=$SERVER
SENTINEL_ENROLL_TOKEN=$TOKEN
SENTINEL_WATCH=$WATCH
# mTLS (optional): SENTINEL_AGENT_TLS_CA / SENTINEL_AGENT_TLS_CERT / SENTINEL_AGENT_TLS_KEY
EOF
  chmod 600 "$ETC/agent.env"
  log "wrote $ETC/agent.env (mode 600)"

  # --- 5) hardened systemd unit (always-on; restart on crash + reboot) ------------------
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

# Capabilities the agent genuinely needs: nftables isolation (NET_ADMIN), eBPF/kernel-module
# load (SYS_MODULE/BPF), process containment (KILL).
AmbientCapabilities=CAP_NET_ADMIN CAP_SYS_MODULE CAP_BPF CAP_KILL
CapabilityBoundingSet=CAP_NET_ADMIN CAP_SYS_MODULE CAP_BPF CAP_KILL CAP_SYS_PTRACE CAP_DAC_READ_SEARCH

# Self-protection + sandboxing. These are SAFE for an EDR agent.
NoNewPrivileges=true
OOMScoreAdjust=-1000
ProtectSystem=full
ProtectHome=read-only
ProtectClock=true
ProtectHostname=true
ProtectKernelLogs=true
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true
SystemCallArchitectures=native

# Intentionally NOT set — each would break a core EDR capability:
#   ProtectKernelModules   → agent loads eBPF/kernel modules (CAP_SYS_MODULE)
#   MemoryDenyWriteExecute → eBPF JIT needs W^X exemption
#   PrivateDevices         → USB / removable-media monitoring needs /dev
#   RestrictAddressFamilies→ AF_NETLINK is required for process/net telemetry
#   ProtectControlGroups / ProtectKernelTunables → cgroup-freeze response + sysctl posture
#   SystemCallFilter       → too broad to constrain safely for a full-system monitor

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
}

# Execute only after the whole script has downloaded — guards against partial-pipe execution.
main "$@"
