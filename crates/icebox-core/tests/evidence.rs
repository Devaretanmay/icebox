//! Phase 4 eval: evidence normalization, confidence scoring, and provenance.
//! Run with `cargo test -p icebox-core --test evidence`.

use icebox_core::safety::{normalize_evidence, Evidence, EvidenceProvenance};

#[test]
fn structured_json_is_high_confidence_and_normalized() {
    let (kind, conf, norm) = normalize_evidence(r#"{"port":22,"service":"ssh"}"#, "tcp_port_scanner");
    assert_eq!(kind.as_deref(), Some("service"));
    assert_eq!(conf, 0.9);
    assert!(norm.is_some());
}

#[test]
fn keyword_hints_set_kind_and_confidence() {
    assert_eq!(normalize_evidence("found open port 443", "x").0.as_deref(), Some("port"));
    assert_eq!(normalize_evidence("found open port 443", "x").1, 0.65);

    assert_eq!(
        normalize_evidence("credential admin:admin leaked", "x").0.as_deref(),
        Some("credential")
    );
    assert_eq!(normalize_evidence("credential admin:admin leaked", "x").1, 0.7);

    assert_eq!(normalize_evidence("cve-2024-1234 present", "x").0.as_deref(), Some("vulnerability"));
    assert_eq!(normalize_evidence("connection error", "x").1, 0.3);
}

#[test]
fn evidence_carries_provenance_and_id() {
    let e = Evidence::new("ssh_bruteforce", "10.0.0.5", "credential root:toor", Some(42), 0);
    assert_eq!(e.provenance, EvidenceProvenance { job_id: Some(42) });
    assert!(!e.id.is_empty());
    assert_eq!(e.kind.as_deref(), Some("credential"));
    assert_eq!(e.confidence, 0.7);
}
