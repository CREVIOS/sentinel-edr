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

# Enable the bpf LSM so the agent's in-kernel kill/ptrace/file tamper-protection hooks can
# attach (loophole L2). They are inert until 'bpf' is in the kernel's lsm= cmdline. This is
# OFF by default on most distros and requires a reboot to take effect.
#
# DANGEROUS: editing the kernel cmdline can make a host unbootable, so it is OPT-IN
# (SENTINEL_ENABLE_BPF_LSM=1). We back up /etc/default/grub, APPEND 'bpf' to the EXISTING LSM
# list (never replace it — dropping apparmor/selinux/lockdown would weaken the host), and
# regenerate the bootloader config. Without opt-in we only print the exact manual steps.
NEEDS_REBOOT=0
enable_bpf_lsm() {
  if grep -qw bpf /sys/kernel/security/lsm 2>/dev/null; then
    log "bpf LSM already active — kernel tamper-protection available"
    return 0
  fi
  local cur want
  cur="$(cat /sys/kernel/security/lsm 2>/dev/null || true)"
  if [ -z "$cur" ]; then want="bpf"; else want="${cur},bpf"; fi

  if [ "${SENTINEL_ENABLE_BPF_LSM:-0}" != "1" ]; then
    warn "kernel tamper-protection (kill/ptrace/file LSM) is OFF: 'bpf' is not in lsm= cmdline."
    warn "  enable automatically (will edit GRUB + require reboot): re-run with SENTINEL_ENABLE_BPF_LSM=1"
    warn "  or manually: add 'lsm=${want}' to GRUB_CMDLINE_LINUX in /etc/default/grub, run update-grub, reboot"
    return 0
  fi

  if [ ! -f /etc/default/grub ]; then
    warn "SENTINEL_ENABLE_BPF_LSM=1 but /etc/default/grub not found (non-GRUB bootloader?)."
    warn "Manually add 'lsm=${want}' to the kernel cmdline and reboot."
    return 0
  fi

  cp -a /etc/default/grub "/etc/default/grub.sentinel.bak.$(date +%s)"
  if grep -qE 'GRUB_CMDLINE_LINUX="[^"]*lsm=' /etc/default/grub; then
    # an lsm= is already present in GRUB_CMDLINE_LINUX → rewrite just that token
    sed -i -E "s/lsm=[^[:space:]\"']*/lsm=${want}/" /etc/default/grub
  elif grep -qE '^GRUB_CMDLINE_LINUX="' /etc/default/grub; then
    sed -i -E "s/^(GRUB_CMDLINE_LINUX=\")/\1lsm=${want} /" /etc/default/grub
  else
    warn "could not locate GRUB_CMDLINE_LINUX in /etc/default/grub — add 'lsm=${want}' manually + reboot."
    return 0
  fi

  if ! grep -qE "GRUB_CMDLINE_LINUX=\"[^\"]*lsm=${want}" /etc/default/grub; then
    warn "GRUB edit did not apply cleanly — restore from /etc/default/grub.sentinel.bak.* and add lsm=${want} manually."
    return 0
  fi

  if command -v update-grub >/dev/null 2>&1; then
    update-grub
  elif command -v grub2-mkconfig >/dev/null 2>&1; then
    if [ -d /boot/grub2 ]; then grub2-mkconfig -o /boot/grub2/grub.cfg; else grub2-mkconfig -o /boot/grub/grub.cfg; fi
  else
    warn "no update-grub/grub2-mkconfig found — regenerate the bootloader config manually."
  fi
  NEEDS_REBOOT=1
  log "added 'lsm=${want}' to the GRUB cmdline (backup saved). REBOOT required to activate kernel tamper-protection."
}

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
  # libnotify-bin (notify-send) + util-linux (wall) power the end-user "blocked" warnings.
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq && apt-get install -y -qq nftables iproute2 procps usbutils libnotify-bin util-linux >/dev/null 2>&1 || true
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q nftables iproute procps-ng usbutils libnotify util-linux >/dev/null 2>&1 || true
  fi

  # --- 3) install binary atomically (stop first to avoid ETXTBSY on upgrade) -------------
  if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet sentinel-agent 2>/dev/null; then
    log "stopping running agent for upgrade"; systemctl stop sentinel-agent || true
  fi
  install -m 0755 "$staged" "$BIN"; rm -f "$staged"
  log "installed binary → $BIN"

  # --- 3b) install the CO-RE BPF object (kernel telemetry + tamper-protection) -----------
  # Loaded at runtime from /usr/lib/sentinel/sentinel.bpf.o. It carries the LSM kill/ptrace/
  # file-protection hooks; without it the agent falls back to the userspace polling tier with
  # NO kernel tamper-protection. Verified with the same checksum+signature trust as the binary
  # (a tampered BPF object runs in-kernel as root — it must be authenticated).
  mkdir -p /usr/lib/sentinel
  if [ -n "${SENTINEL_BPF_OBJECT:-}" ] && [ -r "${SENTINEL_BPF_OBJECT}" ]; then
    install -m 0644 "$SENTINEL_BPF_OBJECT" /usr/lib/sentinel/sentinel.bpf.o
    log "installed BPF object → /usr/lib/sentinel/sentinel.bpf.o (provided)"
  elif [ -n "${SENTINEL_RELEASE_URL:-}" ]; then
    local bpf_url bpf_staged
    bpf_url="${SENTINEL_RELEASE_URL%/}/sentinel.bpf.o"
    bpf_staged="$(mktemp)"
    if sc_curl "$bpf_url" -o "$bpf_staged" 2>/dev/null; then
      verify_checksum "$bpf_staged" "$bpf_url.sha256"
      verify_signature "$bpf_staged" "$bpf_url.sig"
      install -m 0644 "$bpf_staged" /usr/lib/sentinel/sentinel.bpf.o
      log "installed BPF object → /usr/lib/sentinel/sentinel.bpf.o"
    else
      warn "BPF object not found at $bpf_url — agent will run telemetry-only (no kernel tamper-protection)"
    fi
    rm -f "$bpf_staged"
  fi

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
StartLimitIntervalSec=0

[Service]
Type=simple
EnvironmentFile=-/etc/sentinel/agent.env
ExecStart=/usr/local/bin/sentinel-agent
Restart=always
RestartSec=5
# Respawn on SIGKILL/SIGTERM/clean-exit/crash (defeats `systemctl kill`, `kill -9`, self-exit).
# A manual `systemctl stop` is still honored — covered by kernel kill-deny + tamper alert.
RestartForceExitStatus=0 1 2 SIGTERM SIGKILL
StateDirectory=sentinel
Environment=SENTINEL_STATE=/var/lib/sentinel/agent.json

# Capabilities the agent genuinely needs: nftables isolation/upload-block (NET_ADMIN),
# eBPF/perf capture (BPF/PERFMON), DNS sniffing (NET_RAW), USB module control (SYS_MODULE),
# process containment/inspection (KILL/SYS_PTRACE), and root-owned file reads/quarantine.
AmbientCapabilities=CAP_NET_ADMIN CAP_SYS_MODULE CAP_BPF CAP_PERFMON CAP_NET_RAW CAP_KILL CAP_SYS_PTRACE CAP_DAC_READ_SEARCH CAP_DAC_OVERRIDE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_SYS_MODULE CAP_BPF CAP_PERFMON CAP_NET_RAW CAP_KILL CAP_SYS_PTRACE CAP_DAC_READ_SEARCH CAP_DAC_OVERRIDE

# Self-protection + sandboxing. Keep /usr/local/bin writable so verified self-update can
# atomically stage and replace /usr/local/bin/sentinel-agent; the rest of /usr remains read-only.
NoNewPrivileges=true
OOMScoreAdjust=-1000
ProtectSystem=full
ReadWritePaths=/var/lib/sentinel /usr/local/bin
ProtectHome=read-only
ProtectClock=true
ProtectHostname=true
ProtectKernelLogs=true
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true
PrivateTmp=true
SystemCallArchitectures=native

# Intentionally NOT set — each would break a core EDR capability:
#   ProtectKernelModules    → agent unloads USB storage modules and may load eBPF/kernel helpers
#   MemoryDenyWriteExecute  → eBPF JIT can need W^X exemptions on some hosts
#   PrivateDevices          → USB / removable-media monitoring needs /dev
#   RestrictAddressFamilies → AF_NETLINK/packet sockets are required for process/net telemetry
#   ProtectControlGroups    → cgroup-freeze response needs cgroup access
#   ProtectKernelTunables   → posture collection reads kernel/sysctl state
#   SystemCallFilter        → too broad to constrain safely for a full-system monitor

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

  # --- 6) enable kernel tamper-protection (bpf LSM) -------------------------------------
  enable_bpf_lsm

  echo
  log "Sentinel agent installed & enrolled against $SERVER"
  log "logs: journalctl -u sentinel-agent -f"
  if [ "$NEEDS_REBOOT" = "1" ]; then
    echo
    warn "REBOOT REQUIRED: kernel tamper-protection (lsm=bpf) activates on next boot."
  fi
}

# Execute only after the whole script has downloaded — guards against partial-pipe execution.
main "$@"
