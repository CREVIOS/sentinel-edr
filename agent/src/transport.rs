//! Server transport: enrollment, batched event upload over HTTPS, and the WebSocket
//! command channel that receives containment actions and returns their results.

use anyhow::{anyhow, Context, Result};
use futures_util::{SinkExt, StreamExt};
use rustls::{ClientConfig, RootCertStore};
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, connect_async_tls_with_config, Connector};
use tracing::{info, warn};

use crate::config::{Identity, TLSConfig};
use crate::event::{Command, CommandResult, Event, EventBatch};
use crate::respond::Responder;

#[derive(serde::Deserialize)]
struct EnrollResp {
    agent_id: String,
    key: String,
}

/// Enroll with the server, returning (agent_id, key).
pub async fn enroll(
    base: &str,
    token: &str,
    tls: &TLSConfig,
    id: &Identity,
) -> Result<(String, String)> {
    let client = http_client(tls, Duration::from_secs(15))?;
    let resp = client
        .post(format!("{base}/api/v1/enroll"))
        .header("X-Enroll-Token", token)
        .json(id)
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(anyhow!("enroll rejected: HTTP {}", resp.status()));
    }
    let e: EnrollResp = resp.json().await?;
    Ok((e.agent_id, e.key))
}

/// Sender uploads event batches.
pub struct Sender {
    client: reqwest::Client,
    base: String,
    agent_id: String,
    key: String,
}

impl Sender {
    pub fn new(base: String, agent_id: String, key: String, tls: TLSConfig) -> Result<Sender> {
        let client = http_client(&tls, Duration::from_secs(20))?;
        Ok(Sender {
            client,
            base,
            agent_id,
            key,
        })
    }

    /// Upload a batch; Err means the caller should spool for later retry.
    pub async fn send(&self, events: &[Event]) -> Result<usize> {
        if events.is_empty() {
            return Ok(0);
        }
        let batch = EventBatch {
            agent_id: &self.agent_id,
            events,
        };
        let resp = self
            .client
            .post(format!("{}/api/v1/events", self.base))
            .header("X-Agent-Id", &self.agent_id)
            .header("X-Agent-Key", &self.key)
            .json(&batch)
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(anyhow!("ingest HTTP {}", resp.status()));
        }
        Ok(events.len())
    }
}

/// Maintain the WebSocket command channel, reconnecting forever.
pub async fn command_channel(
    base: String,
    agent_id: String,
    key: String,
    tls: TLSConfig,
    responder: Responder,
) {
    let url = ws_url(&base);
    loop {
        match serve_commands(&url, &agent_id, &key, &tls, &responder).await {
            Ok(_) => warn!("command channel closed; reconnecting"),
            Err(e) => warn!(error = %e, "command channel error; reconnecting"),
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

async fn serve_commands(
    url: &str,
    agent_id: &str,
    key: &str,
    tls: &TLSConfig,
    responder: &Responder,
) -> Result<()> {
    // Credentials in headers, not the URL.
    let mut req = url.into_client_request()?;
    req.headers_mut().insert(
        "X-Agent-Id",
        agent_id.parse().map_err(|_| anyhow!("bad agent id"))?,
    );
    req.headers_mut().insert(
        "Authorization",
        format!("Bearer {key}")
            .parse()
            .map_err(|_| anyhow!("bad key"))?,
    );
    let (ws, _) = if tls.has_custom_tls() && url.starts_with("wss://") {
        let connector = websocket_connector(tls)?;
        connect_async_tls_with_config(req, None, false, Some(connector)).await?
    } else {
        connect_async(req).await?
    };
    info!("command channel connected");
    let (mut write, mut read) = ws.split();
    while let Some(msg) = read.next().await {
        let msg = msg?;
        match msg {
            Message::Text(txt) => {
                // tungstenite 0.26: Text payload is Utf8Bytes; borrow as &str for serde.
                let cmd: Command = match serde_json::from_str(txt.as_str()) {
                    Ok(c) => c,
                    Err(_) => continue,
                };
                info!(kind = %cmd.kind, "command received");
                let res: CommandResult = responder.execute(&cmd);
                let body = serde_json::to_string(&res).unwrap_or_default();
                // The action has ALREADY been applied (and locally audited). If delivering the
                // result fails, log it distinctly — don't let it look like a generic channel
                // error — then reconnect. The server may time out and re-issue; containment
                // actions are idempotent (re-isolate, re-kill of a dead pid, re-lock) so a
                // replay is safe.
                if let Err(e) = write.send(Message::Text(body.into())).await {
                    warn!(error = %e, kind = %cmd.kind,
                        "command applied but result delivery failed; reconnecting");
                    break;
                }
            }
            Message::Ping(p) => write.send(Message::Pong(p)).await?,
            Message::Close(_) => break,
            _ => {}
        }
    }
    Ok(())
}

fn ws_url(base: &str) -> String {
    let ws_base = if let Some(rest) = base.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = base.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        base.to_string()
    };
    format!("{}/agent/ws", ws_base.trim_end_matches('/'))
}

fn http_client(tls: &TLSConfig, timeout: Duration) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder().timeout(timeout);
    if let Some(ca) = &tls.ca {
        let pem = std::fs::read(ca).with_context(|| format!("read TLS CA {}", ca.display()))?;
        for cert in reqwest::Certificate::from_pem_bundle(&pem).context("parse TLS CA bundle")? {
            builder = builder.add_root_certificate(cert);
        }
    }
    match (&tls.cert, &tls.key) {
        (Some(cert), Some(key)) => {
            let mut pem =
                std::fs::read(cert).with_context(|| format!("read TLS cert {}", cert.display()))?;
            pem.push(b'\n');
            pem.extend(
                std::fs::read(key).with_context(|| format!("read TLS key {}", key.display()))?,
            );
            let id = reqwest::Identity::from_pem(&pem).context("parse TLS client identity")?;
            builder = builder.identity(id);
        }
        (None, None) => {}
        _ => {
            return Err(anyhow!(
                "both SENTINEL_AGENT_TLS_CERT and SENTINEL_AGENT_TLS_KEY are required for mTLS"
            ))
        }
    }
    Ok(builder.build()?)
}

fn websocket_connector(tls: &TLSConfig) -> Result<Connector> {
    let Some(ca) = &tls.ca else {
        return Err(anyhow!(
            "SENTINEL_AGENT_TLS_CA is required when custom WebSocket TLS is configured"
        ));
    };
    let mut roots = RootCertStore::empty();
    for cert in load_certs(ca)? {
        roots.add(cert).context("add TLS root certificate")?;
    }
    let builder = ClientConfig::builder().with_root_certificates(roots);
    let cfg = match (&tls.cert, &tls.key) {
        (Some(cert), Some(key)) => {
            let certs = load_certs(cert)?;
            let key = load_private_key(key)?;
            builder
                .with_client_auth_cert(certs, key)
                .context("build mTLS websocket config")?
        }
        (None, None) => builder.with_no_client_auth(),
        _ => {
            return Err(anyhow!(
                "both SENTINEL_AGENT_TLS_CERT and SENTINEL_AGENT_TLS_KEY are required for mTLS"
            ))
        }
    };
    Ok(Connector::Rustls(Arc::new(cfg)))
}

fn load_certs(path: &Path) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("open certificate {}", path.display()))?;
    let mut rd = BufReader::new(file);
    let certs: Vec<_> = rustls_pemfile::certs(&mut rd)
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("parse certificate {}", path.display()))?;
    if certs.is_empty() {
        return Err(anyhow!("no certificates found in {}", path.display()));
    }
    Ok(certs)
}

fn load_private_key(path: &Path) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("open private key {}", path.display()))?;
    let mut rd = BufReader::new(file);
    rustls_pemfile::private_key(&mut rd)
        .with_context(|| format!("parse private key {}", path.display()))?
        .ok_or_else(|| anyhow!("no private key found in {}", path.display()))
}
