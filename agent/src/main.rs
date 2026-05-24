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

    let cli = Cli::parse();
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

    // --- response channel ---
    let enforcement = Enforcement::new();
    let server_host = host_only(&cli.server);
    let audit_path = state_path
        .parent()
        .map(|p| p.join("audit.log"))
        .unwrap_or_else(|| PathBuf::from("audit.log"));
    let responder = Responder::new(cli.enforce, server_host, enforcement.clone(), audit_path);
    tokio::spawn(transport::command_channel(
        cli.server.clone(),
        state.agent_id.clone(),
        state.key.clone(),
        tls.clone(),
        responder,
    ));

    // --- collectors ---
    let watch = config::parse_csv(&cli.watch);
    let mut proc_c = collectors::ProcessCollector::new();
    let mut login_c = collectors::LoginCollector::new();
    let mut usb_c = collectors::UsbCollector::new();
    let mut fim_c = collectors::FimCollector::new(watch);
    let mut pkg_c = collectors::PackageCollector::new();
    let mut net_c = collectors::NetworkCollector::new();
    let mut authlog_c = collectors::AuthLogCollector::new();
    let mut mount_c = collectors::MountCollector::new();
    let mut module_c = collectors::ModuleCollector::new();

    info!(
        interval = cli.interval,
        scenario = cli.scenario,
        "agent running"
    );

    let mut ticks: u64 = 0;
    let mut interval = tokio::time::interval(Duration::from_secs(cli.interval.max(1)));
    let mut pkg_interval = 0u64;

    // graceful shutdown
    let mut sig = signal_stream();

    loop {
        tokio::select! {
            _ = interval.tick() => {}
            _ = &mut sig => { info!("shutdown signal received"); break; }
        }
        ticks += 1;

        let mut batch: Vec<event::Event> = Vec::new();
        batch.extend(proc_c.poll());
        batch.extend(login_c.poll());
        batch.extend(usb_c.poll());
        batch.extend(fim_c.poll());
        batch.extend(net_c.poll());
        batch.extend(authlog_c.poll());
        batch.extend(mount_c.poll());
        batch.extend(module_c.poll());
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
fn signal_stream() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
    Box::pin(async {
        let _ = tokio::signal::ctrl_c().await;
    })
}
