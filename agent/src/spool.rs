//! Encrypted, durable offline spool. When the server is unreachable, event batches are
//! serialized, encrypted with AES-256-GCM (key persisted per-agent), and written to disk
//! in order. On reconnect the spool is drained oldest-first and replayed; the server
//! deduplicates by event id, so replays are idempotent. This guarantees no telemetry is
//! lost if the network drops, and nothing sensitive is readable at rest.

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Key, Nonce};
use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};

use crate::event::Event;

pub struct Spool {
    dir: PathBuf,
    cipher: Aes256Gcm,
    max_files: usize,
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
            max_files: 50_000, // bounded backlog to protect the disk
        })
    }

    /// Encrypt and persist a batch. File name is time-ordered for FIFO replay.
    pub fn store(&self, events: &[Event]) -> Result<()> {
        if events.is_empty() {
            return Ok(());
        }
        if self.count() >= self.max_files {
            // drop the oldest to make room (ring buffer semantics under sustained outage)
            if let Some(oldest) = self.oldest() {
                let _ = std::fs::remove_file(oldest);
            }
        }
        let plaintext = serde_json::to_vec(events)?;
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ct = self
            .cipher
            .encrypt(&nonce, plaintext.as_ref())
            .map_err(|e| anyhow!("encrypt: {e}"))?;
        let mut blob = Vec::with_capacity(12 + ct.len());
        blob.extend_from_slice(nonce.as_slice());
        blob.extend_from_slice(&ct);

        let name = format!(
            "{:019}-{}.spool",
            chrono::Utc::now().timestamp_micros(),
            uuid::Uuid::new_v4()
        );
        let tmp = self.dir.join(format!(".{name}.tmp"));
        let final_path = self.dir.join(&name);
        write_private(&tmp, &blob).context("write spool tmp")?;
        std::fs::rename(&tmp, &final_path).context("commit spool file")?; // atomic
        Ok(())
    }

    /// Return the oldest *usable* spooled batch (path + decrypted events), if any.
    ///
    /// Unrecoverable files (truncated, undecryptable after a key rotation/tamper, or
    /// undecodable) are quarantined (deleted) and skipped — never returned and never left at
    /// the head of the queue. This is critical: a single poisoned file must not permanently
    /// block replay of all newer telemetry on an endpoint. Only a genuine (likely transient)
    /// IO read error returns Err, so the caller retries later instead of discarding.
    pub fn take_oldest(&self) -> Result<Option<(PathBuf, Vec<Event>)>> {
        loop {
            let Some(path) = self.oldest() else {
                return Ok(None);
            };
            let blob = std::fs::read(&path).context("read spool file")?;
            if blob.len() >= 12 {
                let (nonce_bytes, ct) = blob.split_at(12);
                if let Some(events) = self
                    .cipher
                    .decrypt(Nonce::from_slice(nonce_bytes), ct)
                    .ok()
                    .and_then(|pt| serde_json::from_slice::<Vec<Event>>(&pt).ok())
                {
                    return Ok(Some((path, events)));
                }
            }
            // Truncated / undecryptable / undecodable → quarantine and try the next file.
            let _ = std::fs::remove_file(&path);
        }
    }

    /// Remove a successfully-replayed batch.
    pub fn ack(&self, path: &Path) {
        let _ = std::fs::remove_file(path);
    }

    pub fn count(&self) -> usize {
        self.list().len()
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
        files.sort(); // names are time-ordered => FIFO
        files
    }
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

        // FIFO: oldest (b1) comes back first, decrypted intact
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
    fn wrong_key_quarantines_not_returns() {
        let dir = tmpdir("key");
        let s1 = Spool::open(dir.clone(), &random_key_hex()).unwrap();
        s1.store(&vec![Event::new("process", "exec", "info").msg("secret")])
            .unwrap();
        // Opened with a different key (e.g. state-file lost / key rotated): the undecryptable
        // file must NOT be returned, must NOT error forever — it is quarantined and drained.
        let s2 = Spool::open(dir.clone(), &random_key_hex()).unwrap();
        assert!(s2.take_oldest().unwrap().is_none());
        assert_eq!(s2.count(), 0, "undecryptable file should be quarantined");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn poison_file_does_not_block_newer_batches() {
        let dir = tmpdir("poison");
        let s = Spool::open(dir.clone(), &random_key_hex()).unwrap();
        // a valid batch (gets a current-time-ordered name)
        s.store(&vec![Event::new("process", "exec", "info").msg("good")])
            .unwrap();
        // a poison file that sorts FIRST (older timestamp) and is >=12 bytes but undecryptable
        std::fs::write(dir.join("0000000000000000001-poison.spool"), vec![7u8; 64]).unwrap();
        // take_oldest must skip the poison (head of FIFO) and still return the good batch
        let (p, ev) = s.take_oldest().unwrap().expect("good batch");
        assert_eq!(ev[0].message, "good");
        s.ack(&p);
        assert!(s.take_oldest().unwrap().is_none());
        assert_eq!(s.count(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_file_is_discarded_not_returned() {
        let dir = tmpdir("corrupt");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("0000000000000000001-x.spool"), b"tiny").unwrap();
        let s = Spool::open(dir.clone(), &random_key_hex()).unwrap();
        // < 12 bytes => not a valid nonce+ct => discarded, returns None (no panic).
        assert!(s.take_oldest().unwrap().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
