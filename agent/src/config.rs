//! CLI flags, persisted enrollment state, and host identity collection.

use anyhow::{Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::net::UdpSocket;
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
#[command(name = "sentinel-agent", version, about = "Sentinel endpoint agent")]
pub struct Cli {
    /// Server base URL (e.g. https://sentinel.corp:8443)
    #[arg(long, env = "SENTINEL_SERVER", default_value = "http://localhost:8080")]
    pub server: String,

    /// Enrollment token (required on first run only)
    #[arg(long, env = "SENTINEL_ENROLL_TOKEN", default_value = "")]
    pub enroll_token: String,

    /// Path to the persisted agent state file
    #[arg(long, env = "SENTINEL_STATE")]
    pub state: Option<PathBuf>,

    /// Collection interval in seconds
    #[arg(long, default_value_t = 5)]
    pub interval: u64,

    /// Comma-separated directories to watch for file integrity monitoring
    #[arg(
        long,
        env = "SENTINEL_WATCH",
        default_value = "/etc,/root,/home,/var/www,/usr/local/bin"
    )]
    pub watch: String,

    /// Comma-separated labels to attach to this endpoint
    #[arg(long, default_value = "")]
    pub labels: String,

    /// Run the built-in attack-scenario generator (for testing detections end-to-end)
    #[arg(long, default_value_t = false)]
    pub scenario: bool,

    /// Permit real enforcement actions (isolate/disable). Requires privilege.
    #[arg(long, default_value_t = true)]
    pub enforce: bool,

    /// PEM CA bundle used to verify the Sentinel server.
    #[arg(long, env = "SENTINEL_AGENT_TLS_CA")]
    pub tls_ca: Option<PathBuf>,

    /// PEM client certificate used for mutual TLS.
    #[arg(long, env = "SENTINEL_AGENT_TLS_CERT")]
    pub tls_cert: Option<PathBuf>,

    /// PEM private key matching --tls-cert.
    #[arg(long, env = "SENTINEL_AGENT_TLS_KEY")]
    pub tls_key: Option<PathBuf>,
}

/// TLS material used by HTTPS ingest and the command WebSocket.
#[derive(Debug, Clone, Default)]
pub struct TLSConfig {
    pub ca: Option<PathBuf>,
    pub cert: Option<PathBuf>,
    pub key: Option<PathBuf>,
}

impl TLSConfig {
    pub fn from_cli(cli: &Cli) -> Self {
        Self {
            ca: cli.tls_ca.clone(),
            cert: cli.tls_cert.clone(),
            key: cli.tls_key.clone(),
        }
    }

    pub fn has_client_cert(&self) -> bool {
        self.cert.is_some() || self.key.is_some()
    }

    pub fn has_custom_tls(&self) -> bool {
        self.ca.is_some() || self.has_client_cert()
    }
}

/// Persisted enrollment + crypto state.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AgentState {
    pub agent_id: String,
    pub key: String,
    /// hex-encoded 32-byte AES key for the offline spool
    pub spool_key: String,
}

impl AgentState {
    pub fn path(cli: &Cli) -> PathBuf {
        if let Some(p) = &cli.state {
            return p.clone();
        }
        let base = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
        base.join("sentinel").join("agent.json")
    }

    pub fn load(path: &PathBuf) -> Option<AgentState> {
        let data = std::fs::read(path).ok()?;
        serde_json::from_slice(&data).ok()
    }

    pub fn save(&self, path: &PathBuf) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
            set_private_dir(parent).ok();
        }
        let data = serde_json::to_vec_pretty(self)?;
        write_private(path, &data).context("write state")?;
        Ok(())
    }
}

/// Static host identity reported at enrollment.
#[derive(Debug, Clone, Serialize)]
pub struct Identity {
    pub hostname: String,
    pub os: String,
    pub kernel: String,
    pub arch: String,
    pub ip: String,
    pub mac: String,
    pub version: String,
    pub labels: Vec<String>,
}

impl Identity {
    pub fn collect(labels: Vec<String>) -> Identity {
        let hostname = hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "unknown".into());
        let os = format!(
            "{} {}",
            sysinfo::System::name().unwrap_or_default(),
            sysinfo::System::os_version().unwrap_or_default()
        )
        .trim()
        .to_string();
        let kernel = sysinfo::System::kernel_version().unwrap_or_default();
        let arch = std::env::consts::ARCH.to_string();
        let mac = mac_address::get_mac_address()
            .ok()
            .flatten()
            .map(|m| m.to_string())
            .unwrap_or_default();
        Identity {
            hostname,
            os,
            kernel,
            arch,
            ip: primary_ip(),
            mac,
            version: env!("CARGO_PKG_VERSION").to_string(),
            labels,
        }
    }
}

/// Determine the primary outbound IP without sending traffic (connect a UDP socket).
pub fn primary_ip() -> String {
    let sock = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return String::new(),
    };
    // 203.0.113.1 is TEST-NET-3; no packets are actually sent by connect().
    if sock.connect("203.0.113.1:80").is_ok() {
        if let Ok(addr) = sock.local_addr() {
            return addr.ip().to_string();
        }
    }
    String::new()
}

pub fn parse_csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(|x| x.trim().to_string())
        .filter(|x| !x.is_empty())
        .collect()
}

#[cfg(unix)]
fn write_private(path: &PathBuf, data: &[u8]) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;

    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(data)?;
    f.sync_all().ok();
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &PathBuf, data: &[u8]) -> Result<()> {
    std::fs::write(path, data)?;
    Ok(())
}

#[cfg(unix)]
fn set_private_dir(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_dir(_path: &std::path::Path) -> Result<()> {
    Ok(())
}
