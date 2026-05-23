# Installing the Sentinel agent on endpoints

The agent is a single static Rust binary. Install it on each Linux endpoint and it enrolls,
starts collecting, and stays running as a service.

## One-command install (recommended)

```bash
curl -fsSL https://<server>/install-agent.sh | sudo \
  SENTINEL_SERVER=https://sentinel.corp:8443 \
  SENTINEL_ENROLL_TOKEN=<ENROLL_TOKEN> bash
```

The installer (`scripts/install-agent.sh`):
1. resolves a binary — provided path, a release URL, or builds from source with cargo;
2. installs enforcement deps (`nftables`, `iproute2`, `procps`, `usbutils`) best-effort;
3. writes `/etc/sentinel/agent.env` (mode 600) with server + enrollment token;
4. installs a **systemd** unit and `systemctl enable --now sentinel-agent` — auto-starts on boot,
   restarts on crash, runs with `CAP_NET_ADMIN`/`CAP_SYS_MODULE`/`CAP_KILL` for real response.

Binary source options (env):
- `SENTINEL_AGENT_BINARY=/path/to/sentinel-agent` — use a prebuilt binary
- `SENTINEL_RELEASE_URL=https://…` — download `sentinel-agent-<os>-<arch>`
- otherwise, run from the repo with `cargo` installed (builds `--release`)

## Build a release binary

```bash
cd agent && cargo build --release
# → agent/target/release/sentinel-agent  (strip+LTO, single static binary)
```

Cross-compile for the fleet's arch (e.g. x86_64 + aarch64) and host the artifacts at
`SENTINEL_RELEASE_URL`, or bake into a golden image / config-management (Ansible, etc.).

## Docker

```bash
docker run -d --name sentinel-agent --restart unless-stopped --cap-add NET_ADMIN \
  -e SENTINEL_SERVER=https://sentinel.corp:8443 \
  -e SENTINEL_ENROLL_TOKEN=<ENROLL_TOKEN> \
  -v sentinel-agent:/var/lib/sentinel \
  sentinel/agent:1.0
```

## mTLS (optional, hardened fleets)
Add to `/etc/sentinel/agent.env`:
```
SENTINEL_AGENT_TLS_CA=/etc/sentinel/ca.crt
SENTINEL_AGENT_TLS_CERT=/etc/sentinel/agent.crt
SENTINEL_AGENT_TLS_KEY=/etc/sentinel/agent.key
```
Generate a dev PKI with `make tls`; in production issue per-host client certs from your CA and
set `SENTINEL_TLS_CLIENT_CA` on the server.

## Verify
```bash
systemctl status sentinel-agent
journalctl -u sentinel-agent -f
```
The endpoint appears under **Endpoints** in the console within a few seconds (MAC, IP, arch,
kernel, live event count).

## Uninstall
```bash
sudo systemctl disable --now sentinel-agent
sudo rm -f /usr/local/bin/sentinel-agent /etc/systemd/system/sentinel-agent.service
sudo rm -rf /etc/sentinel /var/lib/sentinel
```
