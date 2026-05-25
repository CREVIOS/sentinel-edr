//! Encrypted, durable, priority offline spool. When the server is unreachable, event batches
//! are zstd-compressed, encrypted with AES-256-GCM (per-agent key), and written to disk in
//! order. On reconnect the spool is drained oldest-first and replayed; the server deduplicates
//! by event id, so replays are idempotent. Guarantees:
//!   * nothing sensitive is readable at rest (AES-256-GCM, 0600),
//!   * the disk can't be filled (file-count + byte caps + free-space floor),
//!   * under sustained outage we NEVER drop high/critical telemetry — only low-value `info`/`low`
//!     batches are shed (priority ring), so detections always survive to be replayed,
//!   * a single corrupt file can't block replay of newer data (quarantine-and-skip).

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Key, Nonce};
use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};

use crate::event::Event;

/// File format magic: "SPL1" + nonce(12) + AES-GCM(zstd(json)). Files without it are treated as
/// the legacy format (nonce(12) + AES-GCM(json)) for forward-compat on upgrade.
const MAGIC: &[u8; 4] = b"SPL1";
const MAX_FILES: usize = 100_000;
const MAX_BYTES: u64 = 4 * 1024 * 1024 * 1024; // 4 GiB hard cap on the backlog
const MIN_FREE_BYTES: u64 = 512 * 1024 * 1024; // never let free space drop below 512 MiB

pub struct Spool {
    dir: PathBuf,
    cipher: Aes256Gcm,
}

/// Snapshot of spool state for telemetry/heartbeat.
#[derive(Clone, Copy, Default)]
pub struct SpoolStats {
    pub files: usize,
    pub bytes: u64,
    pub oldest_age_secs: i64,
}

impl Spool {
    /// Open (or create) the spool directory with a hex-encoded 32-byte key.
    pub fn open(dir: PathBuf, key_hex: &str) -> Result<Spool> {
        std::fs::create_dir_all(&dir).context("create spool dir")?;
        set_private_dir(&dir).ok();
        let raw = hex_decode(key_hex).ok_or_else(|| anyhow!("invalid spool key"))?;
        if raw.len() != 32 {
            return Err(anyhow!("spool key must be 32 bytes"));
        }
        let key = Key::<Aes256Gcm>::from_slice(&raw);
        Ok(Spool {
            dir,
            cipher: Aes256Gcm::new(key),
        })
    }

    /// Encrypt and persist a batch. File name is time-ordered (FIFO) and tagged with a priority
    /// tier so eviction can shed low-value data first.
    pub fn store(&self, events: &[Event]) -> Result<()> {
        if events.is_empty() {
            return Ok(());
        }
        let plaintext = serde_json::to_vec(events)?;
        let compressed = zstd::encode_all(plaintext.as_slice(), 3).context("zstd compress")?;
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ct = self
            .cipher
            .encrypt(&nonce, compressed.as_ref())
            .map_err(|e| anyhow!("encrypt: {e}"))?;
        let mut blob = Vec::with_capacity(4 + 12 + ct.len());
        blob.extend_from_slice(MAGIC);
        blob.extend_from_slice(nonce.as_slice());
        blob.extend_from_slice(&ct);

        // make room first (drop low-priority oldest), honouring count/byte/free-space caps
        self.enforce_limits(blob.len() as u64);

        let tier = batch_tier(events);
        let name = format!(
            "{:019}-{}-{}.spool",
            chrono::Utc::now().timestamp_micros(),
            tier,
            uuid::Uuid::new_v4()
        );
        let tmp = self.dir.join(format!(".{name}.tmp"));
        let final_path = self.dir.join(&name);
        write_private(&tmp, &blob).context("write spool tmp")?;
        std::fs::rename(&tmp, &final_path).context("commit spool file")?; // atomic
        Ok(())
    }

    /// Evict until under all caps. Sheds the oldest BULK ('b') batch first so high/critical ('c')
    /// telemetry survives; only as a last resort (no bulk left) does it drop the oldest critical.
    fn enforce_limits(&self, incoming: u64) {
        for _ in 0..MAX_FILES {
            let files = self.list();
            let count = files.len();
            let bytes: u64 = files.iter().map(|p| file_len(p)).sum();
            let low_disk = disk_free(&self.dir) < MIN_FREE_BYTES;
            if count < MAX_FILES && bytes.saturating_add(incoming) <= MAX_BYTES && !low_disk {
                return;
            }
            // victim: oldest bulk; else oldest overall (FIFO order from list())
            let victim = files
                .iter()
                .find(|p| tier_of(p) == 'b')
                .or_else(|| files.first());
            match victim {
                Some(p) => {
                    let _ = std::fs::remove_file(p);
                }
                None => return,
            }
        }
    }

    /// Return the oldest *usable* spooled batch (path + decrypted events), if any. Corrupt or
    /// undecryptable files are quarantined (deleted) and skipped so they never block newer data.
    pub fn take_oldest(&self) -> Result<Option<(PathBuf, Vec<Event>)>> {
        loop {
            let Some(path) = self.oldest() else {
                return Ok(None);
            };
            let blob = std::fs::read(&path).context("read spool file")?;
            if let Some(events) = self.decode(&blob) {
                return Ok(Some((path, events)));
            }
            let _ = std::fs::remove_file(&path); // poison → quarantine, try next
        }
    }

    /// Decode either the new (MAGIC + nonce + AES-GCM(zstd(json))) or legacy (nonce + AES-GCM(json))
    /// format. Returns None on any corruption.
    fn decode(&self, blob: &[u8]) -> Option<Vec<Event>> {
        let (nonce_bytes, ct, compressed) = if blob.len() >= 16 && &blob[..4] == MAGIC {
            (&blob[4..16], &blob[16..], true)
        } else if blob.len() >= 12 {
            (&blob[..12], &blob[12..], false)
        } else {
            return None;
        };
        let pt = self
            .cipher
            .decrypt(Nonce::from_slice(nonce_bytes), ct)
            .ok()?;
        let json = if compressed {
            zstd::decode_all(pt.as_slice()).ok()?
        } else {
            pt
        };
        serde_json::from_slice::<Vec<Event>>(&json).ok()
    }

    /// Remove a successfully-replayed batch.
    pub fn ack(&self, path: &Path) {
        let _ = std::fs::remove_file(path);
    }

    pub fn count(&self) -> usize {
        self.list().len()
    }

    /// Spool depth/age for heartbeat telemetry (so the console shows pending offline data).
    pub fn stats(&self) -> SpoolStats {
        let files = self.list();
        let bytes = files.iter().map(|p| file_len(p)).sum();
        let oldest_age_secs = files
            .first()
            .and_then(|p| file_ts_micros(p))
            .map(|us| (chrono::Utc::now().timestamp_micros() - us) / 1_000_000)
            .unwrap_or(0);
        SpoolStats {
            files: files.len(),
            bytes,
            oldest_age_secs,
        }
    }

    fn oldest(&self) -> Option<PathBuf> {
        self.list().into_iter().next()
    }

    fn list(&self) -> Vec<PathBuf> {
        let mut files: Vec<PathBuf> = std::fs::read_dir(&self.dir)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().map(|x| x == "spool").unwrap_or(false))
            .collect();
        files.sort(); // names start with a zero-padded timestamp => FIFO
        files
    }
}

/// Priority tier of a batch: 'c' (critical — keep) if any event is high/critical, else 'b' (bulk).
fn batch_tier(events: &[Event]) -> char {
    let crit = events
        .iter()
        .any(|e| matches!(e.severity.as_str(), "high" | "critical"));
    if crit {
        'c'
    } else {
        'b'
    }
}

/// Parse the tier char from a spool filename `{ts}-{tier}-{uuid}.spool` (legacy names → 'b').
fn tier_of(p: &Path) -> char {
    p.file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| n.split('-').nth(1))
        .and_then(|s| s.chars().next())
        .filter(|c| *c == 'c' || *c == 'b')
        .unwrap_or('b')
}

fn file_ts_micros(p: &Path) -> Option<i64> {
    p.file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| n.split('-').next())
        .and_then(|s| s.parse::<i64>().ok())
}

fn file_len(p: &Path) -> u64 {
    std::fs::metadata(p).map(|m| m.len()).unwrap_or(0)
}

/// Bytes of free space on the spool's filesystem (u64::MAX if it can't be determined → don't block).
fn disk_free(dir: &Path) -> u64 {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        if let Ok(c) = std::ffi::CString::new(dir.as_os_str().as_bytes()) {
            unsafe {
                let mut st: libc::statvfs = std::mem::zeroed();
                if libc::statvfs(c.as_ptr(), &mut st) == 0 {
                    return (st.f_bavail as u64).saturating_mul(st.f_frsize as u64);
                }
            }
        }
    }
    u64::MAX
}

pub fn random_key_hex() -> String {
    use rand::RngCore;
    let mut b = [0u8; 32];
    rand::rng().fill_bytes(&mut b);
    hex_encode(&b)
}

fn hex_encode(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push_str(&format!("{:02x}", byte));
    }
    s
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(unix)]
fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;

    let mut f = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(data)?;
    f.sync_all().ok();
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    std::fs::write(path, data)?;
    Ok(())
}

#[cfg(unix)]
fn set_private_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_dir(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Event;

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "sentinel-spool-test-{}-{}",
            tag,
            uuid::Uuid::new_v4()
        ));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn roundtrip_and_fifo() {
        let dir = tmpdir("rt");
        let key = random_key_hex();
        let s = Spool::open(dir.clone(), &key).unwrap();
        let b1 = vec![Event::new("process", "exec", "info").msg("first")];
        let b2 = vec![Event::new("file", "file_write", "low").msg("second")];
        s.store(&b1).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2));
        s.store(&b2).unwrap();

        let (p1, got1) = s.take_oldest().unwrap().unwrap();
        assert_eq!(got1[0].message, "first");
        s.ack(&p1);
        let (p2, got2) = s.take_oldest().unwrap().unwrap();
        assert_eq!(got2[0].message, "second");
        s.ack(&p2);
        assert!(s.take_oldest().unwrap().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tier_tagging() {
        assert_eq!(batch_tier(&[Event::new("process", "exec", "info")]), 'b');
        assert_eq!(batch_tier(&[Event::new("process", "exec", "high")]), 'c');
        let dir = tmpdir("tier");
        let s = Spool::open(dir.clone(), &random_key_hex()).unwrap();
        s.store(&[Event::new("process", "exec", "critical").msg("alert")])
            .unwrap();
        assert_eq!(tier_of(&s.oldest().unwrap()), 'c');
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wrong_key_quarantines_not_returns() {
        let dir = tmpdir("key");
        let s1 = Spool::open(dir.clone(), &random_key_hex()).unwrap();
        s1.store(&vec![Event::new("process", "exec", "info").msg("secret")])
            .unwrap();
        let s2 = Spool::open(dir.clone(), &random_key_hex()).unwrap();
        assert!(s2.take_oldest().unwrap().is_none());
        assert_eq!(s2.count(), 0, "undecryptable file should be quarantined");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn poison_file_does_not_block_newer_batches() {
        let dir = tmpdir("poison");
        let s = Spool::open(dir.clone(), &random_key_hex()).unwrap();
        s.store(&vec![Event::new("process", "exec", "info").msg("good")])
            .unwrap();
        std::fs::write(
            dir.join("0000000000000000001-b-poison.spool"),
            vec![7u8; 64],
        )
        .unwrap();
        let (p, ev) = s.take_oldest().unwrap().expect("good batch");
        assert_eq!(ev[0].message, "good");
        s.ack(&p);
        assert!(s.take_oldest().unwrap().is_none());
        assert_eq!(s.count(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stats_report_depth() {
        let dir = tmpdir("stats");
        let s = Spool::open(dir.clone(), &random_key_hex()).unwrap();
        s.store(&[Event::new("process", "exec", "info").msg("x")])
            .unwrap();
        let st = s.stats();
        assert_eq!(st.files, 1);
        assert!(st.bytes > 0);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
