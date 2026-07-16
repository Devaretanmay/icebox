//! Phase 6 eval: enterprise governance primitives (RBAC, policy packs,
//! approval queue, audit export). Run with `cargo test --test governance`.

use icebox::core::governance::{audit_to_csv, role_allows, ApprovalQueue, PolicyPack, Role};
use icebox::core::safety::{
    target_matches, CvssScore, DecisionRecord, PolicyContext, PolicyDecision, PolicyRequest,
    PolicyRule, RiskLevel,
};
use icebox::core::Capability;

#[test]
fn role_ordering_and_parse() {
    assert!(Role::Viewer < Role::Operator);
    assert!(Role::Operator < Role::Admin);
    assert_eq!("viewer".parse::<Role>(), Ok(Role::Viewer));
    assert_eq!("operator".parse::<Role>(), Ok(Role::Operator));
    assert_eq!("admin".parse::<Role>(), Ok(Role::Admin));
    assert!("nope".parse::<Role>().is_err());
}

#[test]
fn role_allows_matrix() {
    // Least privilege: a viewer can only do viewer-scoped actions.
    assert!(role_allows(Role::Viewer, Role::Viewer));
    assert!(!role_allows(Role::Viewer, Role::Operator));
    assert!(!role_allows(Role::Viewer, Role::Admin));

    assert!(role_allows(Role::Operator, Role::Operator));
    assert!(!role_allows(Role::Operator, Role::Admin));

    // Admin outranks everything.
    assert!(role_allows(Role::Admin, Role::Admin));
    assert!(role_allows(Role::Admin, Role::Operator));
    assert!(role_allows(Role::Admin, Role::Viewer));
}

#[test]
fn approval_queue_lifecycle() {
    let mut q = ApprovalQueue::default();
    let a = q.request(
        "exploit".into(),
        "10.0.0.1".into(),
        "authorized test".into(),
        Default::default(),
    );
    let b = q.request(
        "scanner".into(),
        "10.0.0.2".into(),
        "routine".into(),
        Default::default(),
    );
    assert_eq!(a, 1);
    assert_eq!(b, 2);
    assert_eq!(q.list().len(), 2);

    assert!(q.approve(a));
    assert!(q.deny(b));
    assert_eq!(
        q.get(a).unwrap().status,
        icebox::core::governance::ApprovalStatus::Approved
    );
    assert_eq!(
        q.get(b).unwrap().status,
        icebox::core::governance::ApprovalStatus::Denied
    );

    // Already resolved entries cannot be re-decided.
    assert!(!q.approve(a));
    assert!(!q.deny(a));
    assert!(!q.approve(99));
}

#[test]
fn policy_pack_bumps_version_on_set_rules() {
    let mut pack = PolicyPack::new(
        "baseline",
        vec![PolicyRule::AllowCapability(Capability::NetworkScan)],
    );
    assert_eq!(pack.version, 1);
    pack.set_rules(vec![]);
    assert_eq!(pack.version, 2);
    pack.set_rules(vec![
        PolicyRule::AllowCapability(Capability::NetworkScan),
        PolicyRule::MaxRisk(RiskLevel::High),
    ]);
    assert_eq!(pack.version, 3);
}

#[test]
fn cvss_deny_above_threshold() {
    use icebox::core::safety::PolicyEngine;
    let cvss_high = CvssScore {
        cvss_v31: Some(9.1),
        cvss_v40: None,
        epss: None,
        kev: false,
    };
    let cvss_low = CvssScore {
        cvss_v31: Some(4.5),
        cvss_v40: None,
        epss: None,
        kev: false,
    };

    let policy = icebox::core::safety::ConfigPolicy {
        max_risk: RiskLevel::Critical,
        context: PolicyContext::Autonomous,
        rules: icebox::core::safety::PolicySet {
            rules: vec![PolicyRule::DenyIfCvssAbove(7.0)],
            version: 1,
        },
    };
    let req = PolicyRequest {
        target: "10.0.0.5".into(),
        capabilities: vec![Capability::NetworkScan],
        impact: RiskLevel::Low,
        destructive: false,
        charter_accepted: true,
        in_scope: true,
        approved: false,
        context: PolicyContext::Autonomous,
        cvss: Some(cvss_high.clone()),
    };
    assert!(matches!(policy.evaluate(&req), PolicyDecision::Deny(_)));

    let req_low = PolicyRequest {
        cvss: Some(cvss_low),
        ..req
    };
    assert!(matches!(policy.evaluate(&req_low), PolicyDecision::Allow));
}

#[test]
fn cvss_require_approval_above_threshold() {
    use icebox::core::safety::PolicyEngine;
    let cvss_high = CvssScore {
        cvss_v31: Some(8.5),
        cvss_v40: None,
        epss: None,
        kev: false,
    };
    let cvss_low = CvssScore {
        cvss_v31: Some(3.0),
        cvss_v40: None,
        epss: None,
        kev: false,
    };

    let policy = icebox::core::safety::ConfigPolicy {
        max_risk: RiskLevel::Critical,
        context: PolicyContext::Autonomous,
        rules: icebox::core::safety::PolicySet {
            rules: vec![PolicyRule::RequireApprovalIf {
                cvss_above: Some(7.0),
                epss_above: None,
                kev: false,
            }],
            version: 1,
        },
    };
    let req = PolicyRequest {
        target: "10.0.0.5".into(),
        capabilities: vec![Capability::NetworkScan],
        impact: RiskLevel::Low,
        destructive: false,
        charter_accepted: true,
        in_scope: true,
        approved: false,
        context: PolicyContext::Autonomous,
        cvss: Some(cvss_high),
    };
    assert!(matches!(
        policy.evaluate(&req),
        PolicyDecision::RequireApproval(_)
    ));

    let req_low = PolicyRequest {
        cvss: Some(cvss_low),
        ..req
    };
    assert!(matches!(policy.evaluate(&req_low), PolicyDecision::Allow));
}

#[test]
fn cvss_epss_triggers_approval() {
    use icebox::core::safety::PolicyEngine;
    let cvss = CvssScore {
        cvss_v31: Some(4.0),
        cvss_v40: None,
        epss: Some(0.8),
        kev: false,
    };

    let policy = icebox::core::safety::ConfigPolicy {
        max_risk: RiskLevel::Critical,
        context: PolicyContext::Autonomous,
        rules: icebox::core::safety::PolicySet {
            rules: vec![PolicyRule::RequireApprovalIf {
                cvss_above: None,
                epss_above: Some(0.5),
                kev: false,
            }],
            version: 1,
        },
    };
    let req = PolicyRequest {
        target: "10.0.0.5".into(),
        capabilities: vec![Capability::NetworkScan],
        impact: RiskLevel::Low,
        destructive: false,
        charter_accepted: true,
        in_scope: true,
        approved: false,
        context: PolicyContext::Autonomous,
        cvss: Some(cvss),
    };
    assert!(matches!(
        policy.evaluate(&req),
        PolicyDecision::RequireApproval(_)
    ));
}

#[test]
fn cvss_kev_triggers_approval() {
    use icebox::core::safety::PolicyEngine;
    let cvss = CvssScore::kev(6.5);

    let policy = icebox::core::safety::ConfigPolicy {
        max_risk: RiskLevel::Critical,
        context: PolicyContext::Autonomous,
        rules: icebox::core::safety::PolicySet {
            rules: vec![PolicyRule::RequireApprovalIf {
                cvss_above: None,
                epss_above: None,
                kev: true,
            }],
            version: 1,
        },
    };
    let req = PolicyRequest {
        target: "10.0.0.5".into(),
        capabilities: vec![Capability::NetworkScan],
        impact: RiskLevel::Low,
        destructive: false,
        charter_accepted: true,
        in_scope: true,
        approved: false,
        context: PolicyContext::Autonomous,
        cvss: Some(cvss),
    };
    assert!(matches!(
        policy.evaluate(&req),
        PolicyDecision::RequireApproval(_)
    ));
}

#[test]
fn target_matches_wildcard() {
    assert!(target_matches("192.168.1.5", "192.168.*"));
    assert!(target_matches("10.0.0.1", "10.*"));
    assert!(!target_matches("8.8.8.8", "192.168.*"));
    assert!(target_matches("10.0.0.1", "10.0.0.1"));
}

#[test]
fn audit_csv_has_header_and_escapes_commas() {
    let rec = DecisionRecord {
        at: 123,
        target: "host,a".into(),
        module: "probe".into(),
        capabilities: vec![Capability::NetworkScan],
        intents: vec![],
        impact: RiskLevel::Low,
        context: PolicyContext::Cli,
        decision: PolicyDecision::Allow,
    };
    let csv = audit_to_csv(&[rec]);
    let lines: Vec<&str> = csv.lines().collect();
    assert_eq!(
        lines[0],
        "at,target,module,capabilities,intents,impact,context,decision,reason"
    );
    // Comma in the target field must be quoted so the row stays well-formed.
    assert!(lines[1].starts_with("123,\"host,a\""), "got: {}", lines[1]);
    assert_eq!(lines.len(), 2);
}
