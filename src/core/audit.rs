use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use sha2::{Digest, Sha256};

use serde::{Deserialize, Serialize};

use crate::core::safety::DecisionRecord;

const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn digest(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub seq: u64,
    pub prev_hash: String,
    pub hash: String,
    #[serde(flatten)]
    pub record: DecisionRecord,
}

impl AuditEntry {
    pub fn new(seq: u64, prev_hash: &str, record: DecisionRecord) -> Self {
        let payload = format!(
            "{prev_hash}|{}",
            serde_json::to_string(&record).unwrap_or_default()
        );
        let hash = digest(payload.as_bytes());
        AuditEntry {
            seq,
            prev_hash: prev_hash.to_string(),
            hash,
            record,
        }
    }

    fn chain_bytes(&self) -> Vec<u8> {
        format!(
            "{}|{}",
            self.prev_hash,
            serde_json::to_string(&self.record).unwrap_or_default()
        )
        .into_bytes()
    }
}

/// Append-only, hash-chained audit ledger; tampering is detected at verify().
///
/// When constructed with [`HashChain::with_path`], every `append` is durably
/// written as one JSON line to disk (fsync'd) so the ledger survives restarts.
/// On load the file is replayed line-by-line; a truncated final line (left by a
/// crash mid-write) is tolerated and discarded, then the chain is verified.
#[derive(Debug, Default)]
pub struct HashChain {
    entries: Vec<AuditEntry>,
    head: String,
    /// Durable sink. `None` => in-memory only (tests / no workspace).
    file: Option<File>,
}

impl HashChain {
    /// In-memory only ledger (no durability).
    pub fn new() -> Self {
        HashChain {
            entries: Vec::new(),
            head: GENESIS.to_string(),
            file: None,
        }
    }

    /// Open (or create) a durable ledger at `path`. Parent dirs are created.
    /// Replays any existing entries and verifies integrity on load.
    pub fn with_path(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("audit dir create failed: {e}"))?;
        }
        let mut chain = HashChain {
            entries: Vec::new(),
            head: GENESIS.to_string(),
            file: None,
        };
        if path.exists() {
            let file = std::fs::File::open(&path).map_err(|e| format!("audit open failed: {e}"))?;
            let reader = BufReader::new(file);
            for line in reader.lines() {
                let line = match line {
                    Ok(l) => l,
                    Err(_) => break, // truncated tail from a crash: stop replay
                };
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                match serde_json::from_str::<AuditEntry>(line) {
                    Ok(entry) => chain.entries.push(entry),
                    Err(_) => break, // corrupted tail line: stop, keep verified prefix
                }
            }
            if !chain.verify() {
                return Err(format!(
                    "audit ledger at {} failed integrity verification",
                    path.display()
                ));
            }
            chain.head = chain
                .entries
                .last()
                .map(|e| e.hash.clone())
                .unwrap_or_else(|| GENESIS.to_string());
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| format!("audit open (append) failed: {e}"))?;
        chain.file = Some(file);
        Ok(chain)
    }

    /// Attach a durable sink to an already-populated in-memory chain,
    /// continuing the hash chain from the current head. Used after restoring a
    /// snapshot so subsequent appends remain both durable and chained.
    pub fn attach_path(&mut self, path: impl AsRef<Path>) -> Result<(), String> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("audit dir create failed: {e}"))?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| format!("audit open (append) failed: {e}"))?;
        self.file = Some(file);
        Ok(())
    }

    pub fn append(&mut self, record: DecisionRecord) -> u64 {
        let seq = (self.entries.len() as u64) + 1;
        let entry = AuditEntry::new(seq, &self.head, record);
        self.head = entry.hash.clone();
        if let Some(file) = self.file.as_mut() {
            let line = serde_json::to_string(&entry).expect("audit entry serializes");
            // One JSON line per entry; fsync so the ledger survives a crash.
            let mut wrote = file.write_all(line.as_bytes());
            if wrote.is_ok() {
                wrote = file.write_all(b"\n");
            }
            if wrote.is_ok() {
                let _ = file.flush();
                let _ = file.sync_all();
            }
            if wrote.is_err() {
                // Durability is a hard guarantee; surface failure loudly.
                eprintln!("ERROR: audit ledger write failed: {wrote:?}");
            }
        }
        self.entries.push(entry);
        seq
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn records(&self) -> Vec<DecisionRecord> {
        self.entries.iter().map(|e| e.record.clone()).collect()
    }

    pub fn last_record(&self) -> Option<&DecisionRecord> {
        self.entries.last().map(|e| &e.record)
    }

    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }

    pub fn recent(&self, n: usize) -> Vec<DecisionRecord> {
        let end = self.entries.len();
        let start = end.saturating_sub(n);
        self.entries[start..]
            .iter()
            .map(|e| e.record.clone())
            .collect()
    }

    /// Hex-encoded SHA-256 hash of the latest entry in the chain.
    pub fn tip_hex(&self) -> String {
        self.head.clone()
    }

    pub fn verify(&self) -> bool {
        let mut prev = GENESIS.to_string();
        for e in &self.entries {
            if e.seq == 0 || e.prev_hash != prev {
                return false;
            }
            let expected = digest(&e.chain_bytes());
            if e.hash != expected {
                return false;
            }
            prev = e.hash.clone();
        }
        true
    }

    /// Serialize the full chain (used by workspace snapshot save/load).
    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), String> {
        let snap = SerializableChain {
            entries: self.entries.clone(),
        };
        let json = serde_json::to_string_pretty(&snap)
            .map_err(|e| format!("audit serialization failed: {e}"))?;
        // Atomic write: temp file + rename.
        let path = path.as_ref();
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, &json).map_err(|e| format!("audit write failed: {e}"))?;
        std::fs::rename(&tmp, path).map_err(|e| format!("audit rename failed: {e}"))
    }

    /// Restore a full chain (used by workspace snapshot load). In-memory only;
    /// does not attach a durable file (use [`HashChain::with_path`] for that).
    pub fn load(path: impl AsRef<Path>) -> Result<Self, String> {
        if !path.as_ref().exists() {
            return Ok(HashChain::new());
        }
        let json = std::fs::read_to_string(path.as_ref())
            .map_err(|e| format!("audit read failed: {e}"))?;
        let snap: SerializableChain =
            serde_json::from_str(&json).map_err(|e| format!("audit parse failed: {e}"))?;
        let mut chain = HashChain {
            entries: snap.entries,
            head: GENESIS.to_string(),
            file: None,
        };
        chain.head = chain
            .entries
            .last()
            .map(|e| e.hash.clone())
            .unwrap_or_else(|| GENESIS.to_string());
        if !chain.verify() {
            return Err("restored audit chain failed verification".into());
        }
        Ok(chain)
    }

    /// Build an in-memory chain from existing entries (workspace snapshot).
    pub fn from_entries(entries: Vec<AuditEntry>) -> Self {
        let mut chain = HashChain {
            entries,
            head: GENESIS.to_string(),
            file: None,
        };
        chain.head = chain
            .entries
            .last()
            .map(|e| e.hash.clone())
            .unwrap_or_else(|| GENESIS.to_string());
        chain
    }

    pub fn entries_owned(&self) -> Vec<AuditEntry> {
        self.entries.clone()
    }
}

/// Serialization shape for the chain (excludes the open file handle).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SerializableChain {
    entries: Vec<AuditEntry>,
}

impl From<&HashChain> for Vec<DecisionRecord> {
    fn from(c: &HashChain) -> Self {
        c.records()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::module::{Capability, Intent};
    use crate::core::safety::{PolicyContext, PolicyDecision, RiskLevel};

    fn fake_record(seq: u64) -> DecisionRecord {
        DecisionRecord {
            at: seq,
            target: format!("10.0.0.{}", seq),
            module: "test".into(),
            capabilities: vec![Capability::NetworkScan],
            intents: vec![Intent::Read],
            impact: RiskLevel::Low,
            context: PolicyContext::Cli,
            decision: PolicyDecision::Allow,
        }
    }

    #[test]
    fn empty_chain_verifies() {
        let c = HashChain::new();
        assert!(c.verify());
        assert!(c.is_empty());
        assert_eq!(c.len(), 0);
    }

    #[test]
    fn single_entry_verifies() {
        let mut c = HashChain::new();
        c.append(fake_record(1));
        assert!(c.verify());
        assert_eq!(c.len(), 1);
        assert_eq!(c.records().len(), 1);
    }

    #[test]
    fn chain_of_three_verifies() {
        let mut c = HashChain::new();
        for i in 1..=3 {
            c.append(fake_record(i));
        }
        assert!(c.verify());
        assert_eq!(c.len(), 3);
        assert_eq!(c.recent(2).len(), 2);
        assert_eq!(c.recent(10).len(), 3);
    }

    #[test]
    fn tampered_entry_fails_verify() {
        let mut c = HashChain::new();
        c.append(fake_record(1));
        c.append(fake_record(2));
        assert!(c.verify());
        if let Some(entry) = c.entries.last_mut() {
            entry.record.target = "tampered".into();
        }
        assert!(!c.verify(), "tampered chain must fail verification");
    }

    #[test]
    fn broken_prev_hash_fails_verify() {
        let mut c = HashChain::new();
        c.append(fake_record(1));
        assert!(c.verify());
        if let Some(entry) = c.entries.last_mut() {
            entry.prev_hash = "badbadbad".into();
        }
        assert!(!c.verify());
    }

    #[test]
    fn sha256_genesis_is_64_hex_chars() {
        // Regression: hash chain must use SHA-256 (64 hex chars), not SHA-1 (40).
        let mut c = HashChain::new();
        c.append(fake_record(1));
        assert_eq!(c.tip_hex().len(), 64, "SHA-256 tip must be 64 hex chars");
        assert!(c.tip_hex().chars().all(|ch| ch.is_ascii_hexdigit()));
    }

    #[test]
    fn save_and_load_roundtrip_preserves_chain() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("icebox_audit_test_{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);

        let mut c = HashChain::new();
        for i in 1..=5 {
            c.append(fake_record(i));
        }
        assert!(c.verify());

        c.save(&path).expect("save must succeed");
        let loaded = HashChain::load(&path).expect("load must succeed");
        assert_eq!(loaded.len(), 5);
        assert!(loaded.verify(), "restored chain must still verify");
        assert_eq!(
            loaded.tip_hex(),
            c.tip_hex(),
            "tip must match after roundtrip"
        );
        assert_eq!(loaded.records().len(), c.records().len());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_missing_file_returns_empty_chain() {
        let path = std::env::temp_dir().join(format!(
            "icebox_audit_missing_{}_{}.json",
            std::process::id(),
            "nonexistent"
        ));
        let _ = std::fs::remove_file(&path);
        let c = HashChain::load(&path).expect("load of missing file must yield empty chain");
        assert!(c.is_empty());
        assert!(c.verify());
    }
}
