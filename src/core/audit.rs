use sha1::{Digest, Sha1};

use serde::Serialize;

use crate::core::safety::DecisionRecord;

fn digest(bytes: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// A tamper-evident audit entry: a decision record chained to its predecessor
/// by a SHA-1 hash over (prev_hash || canonical record).
#[derive(Debug, Clone, Serialize)]
pub struct AuditEntry {
    pub seq: u64,
    pub prev_hash: String,
    pub hash: String,
    #[serde(flatten)]
    pub record: DecisionRecord,
}

impl AuditEntry {
    pub fn new(seq: u64, prev_hash: &str, record: DecisionRecord) -> Self {
        let payload = format!("{prev_hash}|{}", serde_json::to_string(&record).unwrap_or_default());
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

/// The append-only, hash-chained audit ledger of a Governed Execution Environment.
/// Every decision (allow, deny, require-approval) is linked to the one before it,
/// so any retrospective modification of a record breaks the chain at verify().
#[derive(Debug, Clone, Default, Serialize)]
pub struct HashChain {
    entries: Vec<AuditEntry>,
    head: String,
}

impl HashChain {
    pub fn new() -> Self {
        HashChain {
            entries: Vec::new(),
            head: "0".repeat(40),
        }
    }

    pub fn append(&mut self, record: DecisionRecord) -> u64 {
        let seq = (self.entries.len() as u64) + 1;
        let entry = AuditEntry::new(seq, &self.head, record);
        self.head = entry.hash.clone();
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
        self.entries[start..].iter().map(|e| e.record.clone()).collect()
    }

    /// Hex-encoded SHA-1 hash of the latest entry in the chain.
    pub fn tip_hex(&self) -> String {
        self.head.clone()
    }

    /// Recompute every link from the genesis hash; returns false on the first
    /// entry whose hash does not match its claimed predecessor (tamper proof).
    pub fn verify(&self) -> bool {
        let mut prev = "0".repeat(40);
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
}
