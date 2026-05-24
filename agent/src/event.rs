//! Wire types shared with the server. Field names and shapes mirror
//! `server/internal/model` exactly so the Go server can decode agent JSON 1:1.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Process {
    #[serde(default, skip_serializing_if = "is_zero")]
    pub pid: i64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub ppid: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub exe: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cmdline: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub uid: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub user: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub parent: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub lineage: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub container: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FileInfo {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub op: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub size: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub mode: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hash: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_dir: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetInfo {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub direction: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub proto: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub local_addr: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub remote: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub domain: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub url: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub category: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub bytes_out: i64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub bytes_in: i64,
    #[serde(default, skip_serializing_if = "is_false")]
    pub blocked: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UsbInfo {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub action: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub vendor: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub product: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub serial: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub mount: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub size_gb: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthInfo {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub method: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source_ip: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tty: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub result: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DlpInfo {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub classifier: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub channel: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub matches: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sample: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub policy: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub verdict: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: String,
    #[serde(default)]
    pub agent_id: String,
    #[serde(default)]
    pub hostname: String,
    pub ts: DateTime<Utc>,
    pub category: String,
    pub action: String,
    pub severity: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub user: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process: Option<Process>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<FileInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<NetInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usb: Option<UsbInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<AuthInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dlp: Option<DlpInfo>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, serde_json::Value>,
}

impl Event {
    pub fn new(category: &str, action: &str, severity: &str) -> Self {
        Event {
            id: uuid::Uuid::new_v4().to_string(),
            agent_id: String::new(),
            hostname: String::new(),
            ts: Utc::now(),
            category: category.into(),
            action: action.into(),
            severity: severity.into(),
            user: String::new(),
            message: String::new(),
            process: None,
            file: None,
            network: None,
            usb: None,
            auth: None,
            dlp: None,
            labels: Vec::new(),
            extra: BTreeMap::new(),
        }
    }
    pub fn msg(mut self, m: impl Into<String>) -> Self {
        self.message = m.into();
        self
    }
    pub fn with_user(mut self, u: impl Into<String>) -> Self {
        self.user = u.into();
        self
    }
}

#[derive(Debug, Serialize)]
pub struct EventBatch<'a> {
    pub agent_id: &'a str,
    pub events: &'a [Event],
}

/// Command pushed from server over the WebSocket control channel.
#[derive(Debug, Clone, Deserialize)]
pub struct Command {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub target: BTreeMap<String, serde_json::Value>,
}

/// Reply the agent sends back for a command.
#[derive(Debug, Clone, Serialize)]
pub struct CommandResult {
    pub id: String,
    pub ok: bool,
    pub message: String,
}

fn is_zero(v: &i64) -> bool {
    *v == 0
}
fn is_false(v: &bool) -> bool {
    !*v
}
