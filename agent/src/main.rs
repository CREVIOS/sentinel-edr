//! Sentinel endpoint agent.
//!
//! Responsibilities:
//!   * enroll once, persist identity + keys
//!   * collect endpoint telemetry (process, login, file, usb, package, network)
//!   * inspect content locally for DLP
//!   * upload batched events; spool encrypted to disk and replay when offline
//!   * maintain a command channel and execute containment actions

mod collectors;
mod config;
mod dlp;
mod dnscache;
mod ebpf;
mod event;
mod respond;
mod scenario;
mod spool;
mod transport;

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use std::time::Duration;
use tracing::{error, info, warn};

use config::{AgentState, Cli, Identity, TLSConfig};
use respond::{Enforcement, Responder};
use spool::Spool;
use transport::Sender;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    // rustls 0.23 refuses to pick a CryptoProvider when more than one is linked into the
    // process (reqwest pulls aws-lc-rs, our direct rustls pulls ring), which otherwise panics
    // the command-channel TLS task. Install ring as the deterministic process default before
    // any TLS client is built. Idempotent; ignore the error if one is already installed.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cli = Cli::parse();
    harden_self();
    let labels = config::parse_csv(&cli.labels);
    let state_path = AgentState::path(&cli);
    let tls = TLSConfig::from_cli(&cli);

    // --- enrollment ---
    let mut state = AgentState::load(&state_path).unwrap_or_default();
    if state.agent_id.is_empty() || state.key.is_empty() {
        let id = Identity::collect(labels.clone());
        info!(host = %id.hostname, mac = %id.mac, ip = %id.ip, "enrolling");
        let (agent_id, key) = enroll_with_retry(&cli, &tls, &id).await?;
        state.agent_id = agent_id;
        state.key = key;
        if state.spool_key.is_empty() {
            state.spool_key = spool::random_key_hex();
        }
        state.save(&state_path)?;
        info!(agent_id = %state.agent_id, "enrolled");
    } else {
        info!(agent_id = %state.agent_id, "loaded existing enrollment");
    }
    if state.spool_key.is_empty() {
        state.spool_key = spool::random_key_hex();
        state.save(&state_path)?;
    }

    let sender = Sender::new(
        cli.server.clone(),
        state.agent_id.clone(),
        state.key.clone(),
        tls.clone(),
    )?;
    let spool = Spool::open(spool_dir(&state_path), &state.spool_key)?;

    // --- live policy (CLI defaults + persisted console push), shared with collectors ---
    let policy = config::shared_policy(&cli, &state_path);
    let policy_path = config::AgentPolicy::path(&state_path);

    // --- response channel ---
    let enforcement = Enforcement::new();
    let server_host = host_only(&cli.server);
    let audit_path = state_path
        .parent()
        .map(|p| p.join("audit.log"))
        .unwrap_or_else(|| PathBuf::from("audit.log"));
    let responder = Responder::new(
        policy.clone(),
        policy_path,
        server_host,
        enforcement.clone(),
        audit_path,
    );
    tokio::spawn(transport::command_channel(
        cli.server.clone(),
        state.agent_id.clone(),
        state.key.clone(),
        tls.clone(),
        responder,
    ));

    // Telemetry tier: prefer in-kernel eBPF, else auditd/netlink, else userspace polling.
    // Polling collectors below always run; eBPF (when enabled+supported) augments them with
    // real-time, no-miss process capture.
    let tier = ebpf::detect_tier();
    info!(telemetry_tier = tier.as_str(), "capture tier selected");

    // Shared IP→domain cache for network attribution. With the authoritative eBPF DNS feed it
    // is filled from observed DNS responses; otherwise best-effort forward-confirmed reverse DNS
    // enriches it. (eBPF DNS-fill flips rDNS off once wired.)
    let dns = dnscache::DnsCache::new(tier != ebpf::Tier::Ebpf);

    // --- collectors ---
    let mut proc_c = collectors::ProcessCollector::new();
    let mut login_c = collectors::LoginCollector::new();
    let mut usb_c = collectors::UsbCollector::new();
    let mut fim_c = collectors::FimCollector::new(policy.clone());
    let mut pkg_c = collectors::PackageCollector::new();
    let mut net_c = collectors::NetworkCollector::new(dns.clone());
    let mut authlog_c = collectors::AuthLogCollector::new();
    let mut mount_c = collectors::MountCollector::new();
    let mut module_c = collectors::ModuleCollector::new();
    let mut rootkit_c = collectors::RootkitCollector::new();
    let mut posture_c = collectors::PostureCollector::new();

    info!(
        interval = cli.interval,
        scenario = cli.scenario,
        "agent running"
    );

    let mut ticks: u64 = 0;
    let mut cur_interval = policy.read().map(|p| p.interval_secs).unwrap_or(5).max(1);
    let mut interval = tokio::time::interval(Duration::from_secs(cur_interval));
    let mut pkg_interval = 0u64;

    // graceful shutdown
    let mut sig = signal_stream();

    loop {
        tokio::select! {
            _ = interval.tick() => {}
            _ = &mut sig => { info!("shutdown signal received"); break; }
        }
        ticks += 1;

        // hot-reload the cadence if a console push changed it.
        let (paused, want_interval) = match policy.read() {
            Ok(p) => (p.paused, p.interval_secs.max(1)),
            Err(_) => (false, cur_interval),
        };
        if want_interval != cur_interval {
            cur_interval = want_interval;
            interval = tokio::time::interval(Duration::from_secs(cur_interval));
            info!(
                interval = cur_interval,
                "collection interval updated by policy"
            );
        }

        // paused by policy: skip telemetry but keep the heartbeat so the console still shows
        // the endpoint online (and still receives commands like un-pause).
        if paused {
            flush_and_send(&sender, &spool, vec![heartbeat(ticks)]).await;
            continue;
        }

        let mut batch: Vec<event::Event> = Vec::new();
        batch.extend(proc_c.poll());
        batch.extend(login_c.poll());
        batch.extend(usb_c.poll());
        batch.extend(fim_c.poll());
        batch.extend(net_c.poll());
        batch.extend(authlog_c.poll());
        batch.extend(mount_c.poll());
        batch.extend(module_c.poll());
        batch.extend(rootkit_c.poll());
        batch.extend(posture_c.poll());
        // package scan is heavier; run every ~12 ticks
        pkg_interval += 1;
        if pkg_interval >= 12 {
            pkg_interval = 0;
            batch.extend(pkg_c.poll());
        }

        // scenario injection for end-to-end testing
        if cli.scenario {
            batch.extend(scenario::generate_wave());
        }

        // reflect active enforcement in outgoing telemetry
        annotate_enforcement(&mut batch, &enforcement);

        // always send a heartbeat so the server keeps us "online"
        batch.push(heartbeat(ticks));

        flush_and_send(&sender, &spool, batch).await;
    }

    Ok(())
}

/// Send the new batch, then try to drain any spooled (offline) batches in order.
async fn flush_and_send(sender: &Sender, spool: &Spool, batch: Vec<event::Event>) {
    match sender.send(&batch).await {
        Ok(n) => {
            if n > 0 {
                info!(count = n, "events sent");
            }
            // back online: replay spooled batches oldest-first
            drain_spool(sender, spool).await;
        }
        Err(e) => {
            warn!(error = %e, "send failed; spooling encrypted to disk");
            if let Err(se) = spool.store(&batch) {
                error!(error = %se, "spool store failed (events dropped)");
            }
        }
    }
}

async fn drain_spool(sender: &Sender, spool: &Spool) {
    loop {
        match spool.take_oldest() {
            Ok(Some((path, events))) => match sender.send(&events).await {
                Ok(n) => {
                    info!(count = n, "replayed spooled batch");
                    spool.ack(&path);
                }
                Err(_) => break, // still offline; stop draining
            },
            Ok(None) => break,
            Err(e) => {
                warn!(error = %e, "spool read error");
                break;
            }
        }
    }
}

/// Reflect active enforcement flags in outgoing events so the console shows blocked
/// transfers. Real kernel-level blocking (nftables/USBGuard) is applied by the responder;
/// this annotation surfaces that state in telemetry.
fn annotate_enforcement(batch: &mut [event::Event], enf: &Enforcement) {
    use std::sync::atomic::Ordering;
    let usb_blocked = enf.usb_blocked.load(Ordering::SeqCst);
    let upload_blocked = enf.upload_blocked.load(Ordering::SeqCst);
    if !usb_blocked && !upload_blocked {
        return;
    }
    for ev in batch.iter_mut() {
        if usb_blocked && ev.usb.is_some() {
            if let Some(u) = ev.usb.as_mut() {
                if u.action.is_empty() {
                    u.action = "blocked".into();
                }
            }
            ev.labels.push("usb-blocked".into());
        }
        if upload_blocked {
            if let Some(n) = ev.network.as_mut() {
                if n.direction == "outbound" {
                    n.blocked = true;
                    ev.labels.push("upload-blocked".into());
                }
            }
        }
    }
}

fn heartbeat(tick: u64) -> event::Event {
    let mut ev = event::Event::new("system", "heartbeat", "info").msg("agent heartbeat");
    ev.extra
        .insert("tick".into(), serde_json::Value::from(tick));
    ev
}

async fn enroll_with_retry(cli: &Cli, tls: &TLSConfig, id: &Identity) -> Result<(String, String)> {
    if cli.enroll_token.is_empty() {
        warn!("no enrollment token provided; set --enroll-token / SENTINEL_ENROLL_TOKEN");
    }
    let mut last = String::new();
    for attempt in 1..=30 {
        match transport::enroll(&cli.server, &cli.enroll_token, tls, id).await {
            Ok(v) => return Ok(v),
            Err(e) => {
                last = e.to_string();
                warn!(attempt, error = %last, "enroll retry");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
    Err(anyhow::anyhow!("enrollment failed after retries: {last}"))
}

fn spool_dir(state_path: &PathBuf) -> PathBuf {
    state_path
        .parent()
        .map(|p| p.join("spool"))
        .unwrap_or_else(|| PathBuf::from("spool"))
}

fn host_only(url: &str) -> String {
    let s = url
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let s = s.split('/').next().unwrap_or(s);
    s.split(':').next().unwrap_or(s).to_string()
}

/// A future that resolves on SIGINT/SIGTERM.
/// Agent self-protection: make the agent hard to OOM-kill and not core-dumpable, so it
/// survives memory pressure and won't leak its memory (keys/spool) to a dump. The systemd
/// unit already sets Restart=always for watchdog recovery; eBPF-LSM kill/ptrace blocking is
/// the documented next tier (needs a kernel test-bed). Best-effort — failures are non-fatal.
fn harden_self() {
    #[cfg(target_os = "linux")]
    {
        // oom_score_adj = -1000 → exempt from the OOM killer.
        let _ = std::fs::write("/proc/self/oom_score_adj", b"-1000");
        // PR_SET_DUMPABLE = 0 → no core dumps / ptrace-attach of our memory.
        unsafe {
            libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        }
    }
}

fn signal_stream() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
    Box::pin(async {
        // Handle SIGTERM too — that's what `systemctl stop` sends; without it the agent is
        // hard-killed and never runs its graceful-shutdown path.
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut term = match signal(SignalKind::terminate()) {
                Ok(s) => s,
                Err(_) => {
                    let _ = tokio::signal::ctrl_c().await;
                    return;
                }
            };
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
    })
}
