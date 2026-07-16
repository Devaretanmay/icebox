//! E2E dogfooding: seam enforcement, policy abuse, audit trails,
//! approval fatigue, operator visibility, continuous validation.

use std::collections::HashMap;

use icebox::core::executor::ModuleExecutor;
use icebox::core::framework::{new_shared_framework, SharedFramework};
use icebox::core::governance::{ApprovalQueue, PolicyPack, Role};
use icebox::core::job::Job;
use icebox::core::module::{Capability, LoadedModule, ModuleResult};
use icebox::core::safety::{
    now_secs, Charter, CvssScore, DecisionRecord, DefaultRiskEvaluator, MemoryKind, PolicyContext,
    PolicyDecision, PolicyEngine, PolicyRule, ReasoningTrace, RiskEvaluator, RiskLevel,
    ScopeManager,
};

use icebox::core::workspace::WorkspaceSnapshot;

fn base_executor() -> ModuleExecutor {
    ModuleExecutor::new(
        Charter::accept("dogfooding-e2e", vec!["authorized".into()]),
        ScopeManager::new(vec!["10.0.0.0/8".into(), "127.0.0.1".into()]),
        RiskLevel::Critical,
    )
}

fn base_framework() -> SharedFramework {
    new_shared_framework(base_executor())
}

async fn setup_module(fw: &SharedFramework) -> LoadedModule {
    let mut g = fw.lock().await;
    g.operator_role = Role::Operator;
    let mut loaded = icebox::modules::load("tcp_port_scanner").expect("module must be available");
    let _ = loaded.module.set_option("host", "127.0.0.1");
    let _ = loaded.module.set_option("ports", "22");
    loaded
}

async fn run_through_seam(
    fw: &SharedFramework,
    loaded: &LoadedModule,
    target: &str,
    approved: bool,
) -> (
    Result<ModuleResult, icebox::core::executor::ExecutorError>,
    usize,
) {
    let decisions_before = fw.lock().await.executor.decisions.len();
    let mut g = fw.lock().await;
    let job = Job::new(&loaded.info.name, target);
    let jid = job.id;
    g.jobs.register(job);
    let result = g
        .executor
        .execute(
            loaded,
            target,
            None,
            approved,
            PolicyContext::Autonomous,
            Some(jid.as_u64()),
            false,
        )
        .await;
    let decisions_after = g.executor.decisions.len();
    match &result {
        Ok(r) => {
            g.jobs.complete(jid, r.clone());
        }
        Err(_) => {
            g.jobs.cancel(jid);
        }
    }
    (result, decisions_after - decisions_before)
}

#[tokio::test]
async fn seam_bypass_direct_module_run_skips_policy() {
    let fw = base_framework();
    let loaded = setup_module(&fw).await;

    let result = loaded.module.run().await;
    assert!(result.is_ok(), "direct .run() works without any governance");

    let g = fw.lock().await;
    assert_eq!(
        g.executor.decisions.len(),
        0,
        "bypass leaves no audit trail"
    );
    assert_eq!(
        g.executor.evidence.len(),
        0,
        "bypass leaves no evidence trail"
    );
}

#[tokio::test]
async fn leaked_loaded_module_bypasses_all_gates() {
    let mut loaded = icebox::modules::load("reverse_shell_payload").expect("module available");
    let _ = loaded.module.set_option("lhost", "127.0.0.1");
    let _ = loaded.module.set_option("lport", "4444");

    let result = loaded.module.run().await;
    assert!(result.is_ok(), "leaked module runs without any governance");

    let fw = base_framework();
    {
        let mut g = fw.lock().await;
        g.operator_role = Role::Operator;
        g.executor.scope = ScopeManager::new(vec!["127.0.0.5".into()]);
        let pf = g
            .executor
            .preflight(&loaded, "127.0.0.5", None, false, PolicyContext::Autonomous);
        let policy = g.executor.policy(PolicyContext::Autonomous);
        assert!(
            pf.check(&policy).is_err(),
            "the same module through the seam IS blocked by scope/approval gates"
        );
    }
}

#[tokio::test]
async fn policy_deny_always_wins_over_approval() {
    let fw = base_framework();
    {
        let mut g = fw.lock().await;
        g.operator_role = Role::Operator;
        g.executor
            .policy_set
            .add_rule(PolicyRule::DenyCapability(Capability::CredentialAccess));
    }

    let loaded = icebox::modules::load("ssh_bruteforce").expect("module available");
    let pf = {
        let g = fw.lock().await;
        g.executor
            .preflight(&loaded, "10.0.0.5", None, true, PolicyContext::Autonomous)
    };
    let policy = {
        let g = fw.lock().await;
        g.executor.policy(PolicyContext::Autonomous)
    };
    let decision = policy.evaluate(&pf.to_request());
    assert!(
        matches!(decision, PolicyDecision::Deny(ref r) if r.contains("denied by policy")),
        "deny rule must win even with approved=true: got {decision:?}"
    );
}

#[tokio::test]
async fn max_risk_ceiling_cannot_be_bypassed() {
    let fw = new_shared_framework(ModuleExecutor::new(
        Charter::accept("test", vec![]),
        ScopeManager::new(vec!["10.0.0.0/8".into()]),
        RiskLevel::Low, // ceiling = Low
    ));
    {
        let mut g = fw.lock().await;
        g.operator_role = Role::Operator;
    }

    let loaded = icebox::modules::load("ssh_bruteforce").expect("module available");
    let pf = {
        let g = fw.lock().await;
        g.executor
            .preflight(&loaded, "10.0.0.5", None, true, PolicyContext::Autonomous)
    };
    let policy = {
        let g = fw.lock().await;
        g.executor.policy(PolicyContext::Autonomous)
    };
    let decision = policy.evaluate(&pf.to_request());
    assert!(
        matches!(decision, PolicyDecision::Deny(ref r) if r.contains("exceeds maximum")),
        "max-risk ceiling must deny even with approval: got {decision:?}"
    );
}

#[tokio::test]
async fn viewer_role_cannot_execute_via_rbac() {
    let fw = base_framework();
    {
        let mut g = fw.lock().await;
        g.operator_role = Role::Viewer;
    }

    let role = fw.lock().await.operator_role;
    assert_eq!(role, Role::Viewer);

    assert!(
        !icebox::core::governance::role_allows(role, Role::Operator),
        "viewer must not be allowed operator actions"
    );
}

#[test]
fn module_capability_declarations_are_honest() {
    let loaded = icebox::modules::load("ssh_bruteforce").expect("module available");
    assert!(
        loaded
            .info
            .capabilities
            .contains(&Capability::CredentialAccess),
        "ssh_bruteforce must declare CredentialAccess capability"
    );
    assert_eq!(
        loaded.info.effective_impact(),
        RiskLevel::Critical,
        "ssh_bruteforce must have Critical impact"
    );

    let scan = icebox::modules::load("tcp_port_scanner").expect("module available");
    assert!(
        !scan
            .info
            .capabilities
            .contains(&Capability::CredentialAccess),
        "tcp_port_scanner must NOT declare CredentialAccess"
    );
    assert_eq!(
        scan.info.effective_impact(),
        RiskLevel::Low,
        "tcp_port_scanner must have Low impact"
    );
}

#[tokio::test]
async fn options_cannot_override_policy() {
    let fw = base_framework();
    let mut loaded = icebox::modules::load("reverse_shell_payload").expect("module available");
    let _ = loaded.module.set_option("lhost", "10.0.0.99");
    let _ = loaded.module.set_option("lport", "4444");

    let pf = {
        let g = fw.lock().await;
        g.executor
            .preflight(&loaded, "10.0.0.99", None, false, PolicyContext::Autonomous)
    };

    assert!(
        pf.risk >= RiskLevel::High,
        "payload impact must remain High regardless of options"
    );

    let policy = {
        let g = fw.lock().await;
        g.executor.policy(PolicyContext::Autonomous)
    };
    let decision = policy.evaluate(&pf.to_request());
    assert!(
        matches!(decision, PolicyDecision::RequireApproval(_)),
        "changing options must not bypass approval gate: got {decision:?}"
    );
}

#[tokio::test]
async fn every_execution_is_audited() {
    let fw = base_framework();
    let loaded = setup_module(&fw).await;

    let (result, added) = run_through_seam(&fw, &loaded, "127.0.0.1", false).await;
    assert!(result.is_ok(), "seamed run should succeed");
    assert_eq!(
        added, 1,
        "each execute must add exactly one decision record"
    );

    let g = fw.lock().await;
    let last = g.executor.decisions.last().unwrap();
    assert_eq!(last.module, "tcp_port_scanner");
    assert_eq!(last.target, "127.0.0.1");
    assert!(last.capabilities.contains(&Capability::NetworkScan));
    assert!(last.at > 0, "timestamp must be set");
    assert!(
        matches!(last.decision, PolicyDecision::Allow),
        "in-scope approved should be allowed"
    );
}

#[tokio::test]
async fn audit_trail_links_decisions_to_evidence_to_preflight() {
    let fw = base_framework();
    let loaded = setup_module(&fw).await;
    let target = "127.0.0.1";

    let preflight = {
        let g = fw.lock().await;
        g.executor
            .preflight(&loaded, target, None, false, PolicyContext::Autonomous)
    };

    let (result, _) = run_through_seam(&fw, &loaded, target, false).await;
    assert!(result.is_ok());

    let g = fw.lock().await;
    let decisions = &g.executor.decisions;
    let evidence_records = &g.executor.evidence;

    let decision = decisions.last().unwrap();
    assert_eq!(decision.target, preflight.target);
    assert_eq!(decision.capabilities, preflight.capabilities);
    assert_eq!(decision.impact, preflight.risk);

    if !evidence_records.is_empty() {
        assert!(
            evidence_records[0].provenance.job_id.is_some(),
            "evidence must have provenance linking it to a job"
        );
        assert_eq!(evidence_records[0].module, "tcp_port_scanner");
        assert_eq!(evidence_records[0].target, target);
    }
}

#[tokio::test]
async fn denied_decisions_include_reason() {
    let fw = new_shared_framework(ModuleExecutor::new(
        Charter::default(), // NOT accepted
        ScopeManager::new(vec!["10.0.0.0/8".into()]),
        RiskLevel::Critical,
    ));
    {
        let mut g = fw.lock().await;
        g.operator_role = Role::Operator;
    }

    let loaded = setup_module(&fw).await;
    let pf = {
        let g = fw.lock().await;
        g.executor
            .preflight(&loaded, "10.0.0.5", None, false, PolicyContext::Autonomous)
    };
    let policy = {
        let g = fw.lock().await;
        g.executor.policy(PolicyContext::Autonomous)
    };
    let decision = policy.evaluate(&pf.to_request());

    {
        let mut g = fw.lock().await;
        g.executor.decisions.push(DecisionRecord {
            at: now_secs(),
            target: "10.0.0.5".into(),
            module: "tcp_port_scanner".into(),
            capabilities: pf.capabilities.clone(),
            intents: pf.intents.clone(),
            impact: pf.risk,
            context: pf.context,
            decision: decision.clone(),
        });

        let recorded = g.executor.decisions.last().unwrap();
        match &recorded.decision {
            PolicyDecision::Deny(reason) => {
                assert!(!reason.is_empty(), "denied decision must have a reason");
                assert!(
                    reason.contains("charter"),
                    "denied decision reason must explain why"
                );
            }
            _ => panic!("expected Deny, got {:?}", recorded.decision),
        }
    }
}

#[tokio::test]
async fn reasoning_traces_are_preserved() {
    let fw = base_framework();
    {
        let mut g = fw.lock().await;
        g.executor.record_trace(ReasoningTrace {
            at: now_secs(),
            phase: "scan".into(),
            context_len: 150,
            summary: "found open port 22".into(),
            actions: vec!["tcp_port_scanner".into()],
        });
        g.executor.record_trace(ReasoningTrace {
            at: now_secs(),
            phase: "analyze".into(),
            context_len: 300,
            summary: "SSH service detected".into(),
            actions: vec!["ssh_bruteforce".into()],
        });
    }

    let g = fw.lock().await;
    let traces = g.executor.recent_traces(10);
    assert_eq!(traces.len(), 2, "both reasoning traces must be preserved");
    assert_eq!(traces[0].phase, "scan");
    assert_eq!(traces[1].phase, "analyze");
    assert!(traces[1].context_len > traces[0].context_len);
}

#[test]
fn approval_queue_handles_bulk() {
    let mut q = ApprovalQueue::default();
    let count = 150;

    let mut ids = Vec::with_capacity(count);
    for i in 0..count {
        let req = q.request(
            format!("module_{i}"),
            format!("10.0.0.{}", i % 254 + 1),
            format!("reason {i}"),
            HashMap::new(),
        );
        ids.push(req);
    }

    let all = q.list();
    assert_eq!(
        all.len(),
        count,
        "all {count} approval requests must be stored"
    );
    assert_eq!(
        all.iter()
            .filter(|r| r.status == icebox::core::governance::ApprovalStatus::Pending)
            .count(),
        count,
        "all requests must be pending initially"
    );

    for (i, id) in ids.iter().enumerate() {
        if i % 2 == 0 {
            assert!(q.approve(*id), "must be able to approve request {id}");
        } else {
            assert!(q.deny(*id), "must be able to deny request {id}");
        }
    }

    let final_list = q.list();
    let approved_count = final_list
        .iter()
        .filter(|r| r.status == icebox::core::governance::ApprovalStatus::Approved)
        .count();
    let denied_count = final_list
        .iter()
        .filter(|r| r.status == icebox::core::governance::ApprovalStatus::Denied)
        .count();
    assert_eq!(
        approved_count,
        count / 2 + count % 2,
        "expected ~half approved"
    );
    assert_eq!(denied_count, count / 2, "expected ~half denied");

    assert!(
        !q.approve(0),
        "already approved request cannot be re-approved"
    );
    assert!(!q.deny(1), "already denied request cannot be re-denied");
}

#[tokio::test]
async fn full_traceability_chain() {
    let fw = base_framework();
    let loaded = setup_module(&fw).await;
    let target = "127.0.0.1";

    let (result, _) = run_through_seam(&fw, &loaded, target, false).await;
    assert!(result.is_ok());
    let module_result = result.unwrap();

    assert!(module_result.finding.is_some(), "finding must be present");
    let finding = module_result.finding.as_deref().unwrap_or("");
    assert!(
        finding.contains("Open ports") || finding.contains("No open ports"),
        "finding must describe scan results: got '{finding}'"
    );

    let g = fw.lock().await;
    if !g.executor.evidence.is_empty() {
        let ev = &g.executor.evidence[0];
        assert!(
            ev.provenance.job_id.is_some(),
            "evidence must link to a job"
        );
        assert!(ev.confidence > 0.0, "evidence must have confidence score");
        assert_eq!(ev.module, "tcp_port_scanner");
    }

    assert!(
        !g.executor.decisions.is_empty(),
        "at least one decision must be recorded"
    );
    let last_decision = &g.executor.decisions.last().unwrap();
    assert!(matches!(&last_decision.decision, PolicyDecision::Allow));
    assert_eq!(last_decision.target, target);
    assert_eq!(last_decision.module, "tcp_port_scanner");
}

#[tokio::test]
async fn operator_can_inspect_state() {
    let fw = base_framework();
    let loaded = setup_module(&fw).await;

    let (result, _) = run_through_seam(&fw, &loaded, "127.0.0.1", false).await;
    assert!(result.is_ok());

    let g = fw.lock().await;

    let recent_jobs = g.jobs.list_recent(10);
    assert!(!recent_jobs.is_empty(), "operator must see recent jobs");
    assert_eq!(recent_jobs[0].module_name, "tcp_port_scanner");
    assert!(
        matches!(
            recent_jobs[0].status,
            icebox::core::job::JobStatus::Completed | icebox::core::job::JobStatus::Failed
        ),
        "job must have completed or failed"
    );

    assert!(
        g.executor.policy_set.version >= 1,
        "policy version must be >= 1"
    );
}

#[test]
fn continuous_validation_diff_detects_policy_drift() {
    use icebox::ai::diff;
    use icebox::ai::CampaignReport;
    use icebox::ai::ValidationReport;

    let v1 = ValidationReport {
        ran_at: 1000,
        policy_version: 1,
        campaign: CampaignReport {
            targets: vec!["10.0.0.1".into()],
            summaries: vec!["baseline".into()],
            ok: 1,
            failed: 0,
            total_jobs: 5,
            total_sessions: 2,
            total_decisions: 4,
            total_evidence: 3,
            total_traces: 6,
        },
    };

    let v2 = ValidationReport {
        ran_at: 2000,
        policy_version: 3, // policy changed!
        campaign: CampaignReport {
            targets: vec!["10.0.0.1".into(), "10.0.0.2".into()],
            summaries: vec!["expanded".into()],
            ok: 2,
            failed: 0,
            total_jobs: 12, // more activity
            total_sessions: 4,
            total_decisions: 8,
            total_evidence: 7,
            total_traces: 14,
        },
    };

    let d = diff(&v1, &v2);
    assert_eq!(d.policy_version_a, 1);
    assert_eq!(
        d.policy_version_b, 3,
        "diff must detect policy version change"
    );
    assert_eq!(d.jobs_delta, 7, "diff must compute +7 jobs");
    assert_eq!(d.evidence_delta, 4, "diff must compute +4 evidence items");
    assert_eq!(d.traces_delta, 8, "diff must compute +8 traces");
    assert_eq!(d.target_count, 2, "diff must show target count");
}

#[test]
fn validation_report_is_serializable() {
    use icebox::ai::CampaignReport;
    use icebox::ai::ValidationReport;

    let report = ValidationReport {
        ran_at: 12345,
        policy_version: 2,
        campaign: CampaignReport {
            targets: vec!["10.0.0.0/24".into()],
            summaries: vec!["all clear".into()],
            ok: 1,
            failed: 0,
            total_jobs: 3,
            total_sessions: 1,
            total_decisions: 2,
            total_evidence: 2,
            total_traces: 4,
        },
    };

    let json = serde_json::to_string_pretty(&report).expect("validation report must serialize");
    assert!(
        json.contains("\"policy_version\": 2"),
        "policy version must be in serialized form"
    );
    assert!(
        json.contains("\"ran_at\": 12345"),
        "timestamp must be in serialized form"
    );

    let deserialized: ValidationReport = serde_json::from_str(&json).expect("must deserialize");
    assert_eq!(deserialized.policy_version, 2);
    assert_eq!(deserialized.campaign.total_jobs, 3);
    assert_eq!(deserialized.campaign.total_evidence, 2);
}

#[tokio::test]
async fn multi_agent_policy_is_coherent() {
    let exec = ModuleExecutor::new(
        Charter::accept("eval", vec!["authorized".into()]),
        ScopeManager::new(vec!["127.0.0.1".into()]),
        RiskLevel::Critical,
    );
    let fw = new_shared_framework(exec);

    {
        let mut g = fw.lock().await;
        g.operator_role = Role::Operator;
        g.executor
            .policy_set
            .add_rule(PolicyRule::DenyCapability(Capability::CredentialAccess));
    }

    let loaded = icebox::modules::load("ssh_bruteforce").expect("module available");

    for i in 0..3 {
        let pf = {
            let g = fw.lock().await;
            g.executor
                .preflight(&loaded, "127.0.0.1", None, true, PolicyContext::Autonomous)
        };
        let policy = {
            let g = fw.lock().await;
            g.executor.policy(PolicyContext::Autonomous)
        };
        let decision = policy.evaluate(&pf.to_request());
        assert!(
            matches!(decision, PolicyDecision::Deny(ref r) if r.contains("denied by policy")),
            "agent {i} must see the same deny rule: got {decision:?}"
        );
    }
}

#[tokio::test]
async fn orchestrated_agents_share_audit_trail() {
    use icebox::ai::Orchestrator;
    use icebox::ai::StaticPlanner;

    let exec = ModuleExecutor::new(
        Charter::accept("eval", vec!["auth".into()]),
        ScopeManager::new(vec!["127.0.0.1".into()]),
        RiskLevel::Critical,
    );
    let fw = new_shared_framework(exec);
    {
        let mut g = fw.lock().await;
        g.operator_role = Role::Operator;
    }

    let mut orch = Orchestrator::new(fw.clone(), RiskLevel::Critical);
    orch.set_approved(true);
    let report = orch
        .run(&["127.0.0.1".to_string(), "127.0.0.1".to_string()], || {
            Box::new(StaticPlanner::new())
        })
        .await;

    let g = fw.lock().await;
    assert!(
        report.total_jobs > 0,
        "orchestrated agents must produce jobs"
    );
    assert!(
        g.executor.recent_decisions(50).len() >= 2,
        "both agents must produce decisions in the shared audit trail"
    );
    assert!(
        report.total_traces > 0,
        "orchestrated agents must produce traces"
    );
}

#[tokio::test]
async fn workspace_preserves_all_governance_state() {
    let fw = base_framework();
    let loaded = setup_module(&fw).await;

    {
        let mut g = fw.lock().await;
        g.executor
            .policy_set
            .add_rule(PolicyRule::MaxRisk(RiskLevel::High));
        g.policy_packs
            .insert("test-pack".into(), PolicyPack::new("test-pack", vec![]));
        g.executor.remember(MemoryKind::Fact, "test memory");
    }

    let _ = run_through_seam(&fw, &loaded, "127.0.0.1", false).await;

    let snap = {
        let g = fw.lock().await;
        WorkspaceSnapshot::from_framework(&g)
    };

    assert!(snap.charter.accepted, "charter must be preserved");
    assert_eq!(snap.charter.engagement, "dogfooding-e2e");
    assert!(snap.scope_allow.contains(&"127.0.0.1".to_string()));
    assert_eq!(snap.max_risk, RiskLevel::Critical);
    assert_eq!(
        snap.policy_rules.rules.len(),
        1,
        "policy rule must be preserved"
    );
    assert!(
        snap.policy_packs.contains_key("test-pack"),
        "policy packs must be preserved"
    );
    assert!(!snap.memories.is_empty(), "memories must be preserved");

    let json = serde_json::to_string_pretty(&snap).expect("must serialize");
    let deserialized: WorkspaceSnapshot = serde_json::from_str(&json).expect("must deserialize");
    assert!(deserialized.charter.accepted);
    assert_eq!(deserialized.policy_rules.version, snap.policy_rules.version);
}

#[test]
fn empty_scope_blocks_everything() {
    let scope = ScopeManager::new(vec![]);
    assert!(
        !scope.is_in_scope("10.0.0.1"),
        "empty scope must block everything"
    );
    assert!(
        !scope.is_in_scope("anything"),
        "empty scope must block everything"
    );
}

#[test]
fn scope_wildcards_work() {
    let scope = ScopeManager::new(vec!["10.0.0.*".into(), "192.168.1.100".into()]);
    assert!(scope.is_in_scope("10.0.0.5"), "wildcard should match");
    assert!(
        scope.is_in_scope("10.0.0.1"),
        "wildcard should match subnet"
    );
    assert!(
        scope.is_in_scope("192.168.1.100"),
        "exact match should work"
    );
    assert!(
        !scope.is_in_scope("10.0.1.1"),
        "different subnet should not match"
    );
    assert!(
        !scope.is_in_scope("192.168.1.101"),
        "non-wildcard exact should not match"
    );
}

#[test]
fn scope_cidr_works() {
    let scope = ScopeManager::new(vec!["10.0.0.0/24".into()]);
    assert!(scope.is_in_scope("10.0.0.1"), "CIDR /24 should match .1");
    assert!(
        scope.is_in_scope("10.0.0.255"),
        "CIDR /24 should match .255"
    );
    assert!(
        !scope.is_in_scope("10.0.1.1"),
        "CIDR /24 should not match different subnet"
    );
}

#[test]
fn destructive_keywords_are_detected() {
    use icebox::core::safety::is_destructive;

    assert!(is_destructive("wipe_disk"), "wipe must be destructive");
    assert!(
        is_destructive("format_volume"),
        "format must be destructive"
    );
    assert!(
        is_destructive("destroy_everything"),
        "destroy must be destructive"
    );
    assert!(is_destructive("delete_all"), "delete must be destructive");
    assert!(
        is_destructive("shutdown_system"),
        "shutdown must be destructive"
    );
    assert!(
        is_destructive("reboot_server"),
        "reboot must be destructive"
    );
    assert!(
        is_destructive("bruteforce_login"),
        "bruteforce must be destructive"
    );
    assert!(is_destructive("ransom_note"), "ransom must be destructive");

    assert!(
        !is_destructive("scan_ports"),
        "scan must not be destructive"
    );
    assert!(
        !is_destructive("resolve_dns"),
        "dns must not be destructive"
    );
    assert!(
        !is_destructive("probe_http"),
        "probe must not be destructive"
    );
}

#[test]
fn default_risk_evaluator_parses_evidence() {
    let evaluator = DefaultRiskEvaluator;

    let evidence = vec![
        icebox::core::Evidence::new(
            "cve_scanner",
            "10.0.0.5",
            r#"{"cve": "CVE-2024-1234", "cvss_v31": 9.8, "epss": 0.95, "kev": true}"#,
            Some(1),
            0,
        ),
        icebox::core::Evidence::new(
            "cve_scanner",
            "10.0.0.6",
            r#"{"cve": "CVE-2024-5678", "cvss": 5.5, "epss": 0.01}"#,
            Some(2),
            1,
        ),
        icebox::core::Evidence::new(
            "port_scanner",
            "10.0.0.7",
            "no vulnerabilities found",
            Some(3),
            2,
        ),
    ];

    let scored = evaluator.evaluate(&evidence);
    assert!(scored.is_some(), "must extract CVSS from evidence");
    let score = scored.unwrap();

    assert!(
        (score.effective_score() - 9.8).abs() < 0.01,
        "expected CVSS 9.8, got {}",
        score.effective_score()
    );
    assert!(score.kev, "CVE-2024-1234 must be KEV");
    assert!(
        (score.epss.unwrap_or(0.0) - 0.95).abs() < 0.01,
        "expected EPSS 0.95"
    );

    assert!(
        (score.weighted_risk() - 10.0).abs() < 0.01,
        "weighted risk should be clamped to 10.0"
    );
    assert_eq!(
        score.severity(),
        RiskLevel::Critical,
        "CVSS 9.8 must be Critical"
    );

    let no_vuln = evaluator.evaluate(&evidence[2..]);
    assert!(
        no_vuln.is_none(),
        "non-CVSS evidence should not produce a score"
    );
}

#[test]
fn cvss_score_to_severity_mapping() {
    assert_eq!(CvssScore::from_score(9.5).severity(), RiskLevel::Critical);
    assert_eq!(CvssScore::from_score(9.0).severity(), RiskLevel::Critical);
    assert_eq!(CvssScore::from_score(7.5).severity(), RiskLevel::High);
    assert_eq!(CvssScore::from_score(7.0).severity(), RiskLevel::High);
    assert_eq!(CvssScore::from_score(5.5).severity(), RiskLevel::Medium);
    assert_eq!(CvssScore::from_score(4.0).severity(), RiskLevel::Medium);
    assert_eq!(CvssScore::from_score(2.0).severity(), RiskLevel::Low);
    assert_eq!(CvssScore::from_score(0.1).severity(), RiskLevel::Low);
    assert_eq!(CvssScore::from_score(0.0).severity(), RiskLevel::None);
}

#[test]
fn cvss_effective_score_prefers_v4() {
    let score = CvssScore {
        cvss_v31: Some(7.5),
        cvss_v40: Some(8.2),
        epss: None,
        kev: false,
    };
    assert!(
        (score.effective_score() - 8.2).abs() < 0.01,
        "effective_score should prefer v4.0: got {}",
        score.effective_score()
    );
}

#[test]
fn cvss_weighted_risk_blends_all_factors() {
    let s1 = CvssScore::from_score(7.0);
    assert!((s1.weighted_risk() - 7.0).abs() < 0.01);

    let s2 = CvssScore {
        cvss_v31: Some(7.0),
        cvss_v40: None,
        epss: Some(0.5),
        kev: false,
    };
    assert!((s2.weighted_risk() - 8.0).abs() < 0.01);

    let s3 = CvssScore::kev(7.0);
    assert!(
        (s3.weighted_risk() - 10.0).abs() < 0.01,
        "KEV should push to 10.0"
    );
}

#[tokio::test]
async fn cvss_multi_condition_require_approval_if() {
    let fw = new_shared_framework(ModuleExecutor::new(
        Charter::accept("cvss-test", vec![]),
        ScopeManager::new(vec!["0.0.0.0/0".into()]),
        RiskLevel::Critical,
    ));
    {
        let mut g = fw.lock().await;
        g.operator_role = Role::Operator;
        g.executor
            .policy_set
            .add_rule(PolicyRule::RequireApprovalIf {
                cvss_above: Some(8.0),
                epss_above: Some(0.3),
                kev: true,
            });
    }

    let loaded = icebox::modules::load("tcp_port_scanner").expect("module available");

    let decision = {
        let g = fw.lock().await;
        let mut req = g
            .executor
            .preflight(&loaded, "10.0.0.5", None, false, PolicyContext::Autonomous)
            .to_request();
        req.cvss = Some(CvssScore {
            cvss_v31: Some(9.0),
            cvss_v40: None,
            epss: Some(0.1),
            kev: false,
        });
        let policy = g.executor.policy(PolicyContext::Autonomous);
        policy.evaluate(&req)
    };
    assert!(
        matches!(decision, PolicyDecision::RequireApproval(_)),
        "CVSS alone must trigger: got {decision:?}"
    );

    let decision = {
        let g = fw.lock().await;
        let mut req = g
            .executor
            .preflight(&loaded, "10.0.0.5", None, false, PolicyContext::Autonomous)
            .to_request();
        req.cvss = Some(CvssScore {
            cvss_v31: Some(6.0),
            cvss_v40: None,
            epss: Some(0.8),
            kev: false,
        });
        let policy = g.executor.policy(PolicyContext::Autonomous);
        policy.evaluate(&req)
    };
    assert!(
        matches!(decision, PolicyDecision::RequireApproval(_)),
        "EPSS alone must trigger: got {decision:?}"
    );

    let decision = {
        let g = fw.lock().await;
        let mut req = g
            .executor
            .preflight(&loaded, "10.0.0.5", None, false, PolicyContext::Autonomous)
            .to_request();
        req.cvss = Some(CvssScore {
            cvss_v31: Some(6.0),
            cvss_v40: None,
            epss: Some(0.1),
            kev: true,
        });
        let policy = g.executor.policy(PolicyContext::Autonomous);
        policy.evaluate(&req)
    };
    assert!(
        matches!(decision, PolicyDecision::RequireApproval(_)),
        "KEV alone must trigger: got {decision:?}"
    );

    let decision = {
        let g = fw.lock().await;
        let mut req = g
            .executor
            .preflight(&loaded, "10.0.0.5", None, true, PolicyContext::Autonomous)
            .to_request();
        req.cvss = Some(CvssScore {
            cvss_v31: Some(5.0),
            cvss_v40: None,
            epss: Some(0.1),
            kev: false,
        });
        let policy = g.executor.policy(PolicyContext::Autonomous);
        policy.evaluate(&req)
    };
    assert!(
        matches!(decision, PolicyDecision::Allow),
        "no trigger must allow: got {decision:?}"
    );
}

#[tokio::test]
async fn governance_runtime_enforces_cvss_rules() {
    use icebox::core::{GovernanceRuntime, TaskSpec};
    use serde_json::json;

    let rt = GovernanceRuntime::builder()
        .charter(Charter::accept("cvss-test", vec![]))
        .scope(vec!["0.0.0.0/0".into()])
        .max_risk(RiskLevel::Critical)
        .deny_if_cvss_above(9.0)
        .require_approval_if(Some(7.0), None, false)
        .build();

    let task = TaskSpec {
        name: "exploit".into(),
        target: "10.0.0.5".into(),
        capabilities: vec![Capability::PrivilegeEscalation],
        impact: RiskLevel::Medium,
        destructive: false,
        approved: true,
        cvss: Some(CvssScore::from_score(9.5)),
        ..Default::default()
    };
    let outcome = rt
        .execute(task, || async { Ok(json!({"exploited": true})) })
        .await;
    assert!(
        matches!(outcome, icebox::core::GovernedOutcome::Blocked { .. }),
        "CVSS 9.5 must be blocked by DenyIfCvssAbove(9.0): got {outcome:?}"
    );

    let task = TaskSpec {
        name: "exploit".into(),
        target: "10.0.0.5".into(),
        capabilities: vec![Capability::PrivilegeEscalation],
        impact: RiskLevel::Medium,
        destructive: false,
        approved: false,
        cvss: Some(CvssScore::from_score(8.0)),
        ..Default::default()
    };
    let outcome = rt
        .execute(task, || async { Ok(json!({"exploited": true})) })
        .await;
    assert!(
        matches!(outcome, icebox::core::GovernedOutcome::NeedsApproval { .. }),
        "CVSS 8.0 must require approval when threshold is 7.0: got {outcome:?}"
    );

    let task = TaskSpec {
        name: "low_risk".into(),
        target: "10.0.0.5".into(),
        capabilities: vec![Capability::NetworkScan],
        impact: RiskLevel::Low,
        destructive: false,
        approved: false,
        cvss: Some(CvssScore::from_score(5.0)),
        ..Default::default()
    };
    let outcome = rt.execute(task, || async { Ok(json!({"ok": true})) }).await;
    assert!(
        matches!(outcome, icebox::core::GovernedOutcome::Allowed { .. }),
        "CVSS 5.0 must be allowed with all thresholds above it: got {outcome:?}"
    );
}

#[tokio::test]
async fn cvss_appears_in_decision_context() {
    use icebox::core::{GovernanceRuntime, TaskSpec};
    use serde_json::json;

    let rt = GovernanceRuntime::builder()
        .charter(Charter::accept("cvss-test", vec![]))
        .scope(vec!["0.0.0.0/0".into()])
        .max_risk(RiskLevel::Critical)
        .deny_if_cvss_above(9.0)
        .build();

    let task = TaskSpec {
        name: "cve_exploit".into(),
        target: "10.0.0.5".into(),
        capabilities: vec![Capability::PrivilegeEscalation],
        impact: RiskLevel::High,
        destructive: false,
        approved: true,
        cvss: Some(CvssScore::from_score(9.8)),
        ..Default::default()
    };

    let _ = rt
        .execute(task, || async { Ok(json!({"result": true})) })
        .await;

    let audit = rt.audit().await;
    let blocked = audit
        .iter()
        .find(|d| matches!(d.decision, icebox::core::PolicyDecision::Deny(_)));
    assert!(blocked.is_some(), "must have a blocked decision record");
    if let Some(rec) = blocked {
        if let icebox::core::PolicyDecision::Deny(reason) = &rec.decision {
            assert!(
                reason.contains("CVSS"),
                "denied decision reason must mention CVSS: {reason}"
            );
        }
    }
}

/// Full pipeline: cargo metadata -> OSV.dev -> EPSS -> KEV -> CVSS policy gate.
#[tokio::test]
async fn governed_vuln_scan_blocks_high_cvss_exploit() {
    use icebox::core::{GovernanceRuntime, GovernedOutcome, TaskSpec};
    use serde_json::json;

    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let project_root = manifest_dir.to_string_lossy().to_string();

    let mut loaded =
        icebox::modules::load("vuln_scanner").expect("vuln_scanner module must be available");
    loaded
        .module
        .set_option("project_dir", &project_root)
        .expect("must set project_dir");
    loaded
        .module
        .set_option("timeout_ms", "20000")
        .expect("must set timeout");

    let mut exec = ModuleExecutor::new(
        Charter::accept("vuln-dogfood", vec!["authorized".into()]),
        ScopeManager::new(vec![project_root.clone()]),
        RiskLevel::Critical,
    );

    let (max_cvss, top_cve): (f64, String) = match exec
        .execute(
            &loaded,
            &project_root,
            None,
            true,
            PolicyContext::Autonomous,
            None,
            false,
        )
        .await
    {
        Ok(module_result) if module_result.success => {
            let findings = module_result.data["findings"]
                .as_array()
                .expect("findings must be an array");
            eprintln!(
                "[dogfood] vuln_scanner scanned ICEBOX project: {} deps, {} CVEs found",
                module_result.data["dependencies"].as_u64().unwrap_or(0),
                findings.len(),
            );
            if !findings.is_empty() {
                let max = findings
                    .iter()
                    .filter_map(|f| f["cvss_v31"].as_f64())
                    .max_by(|a, b| a.partial_cmp(b).unwrap())
                    .unwrap_or(0.0);
                let top = findings
                    .iter()
                    .find(|f| {
                        f["cvss_v31"]
                            .as_f64()
                            .is_some_and(|s| (s - max).abs() < 0.01)
                    })
                    .and_then(|f| f["cve"].as_str().map(|s| s.to_string()))
                    .unwrap_or_else(|| "CVE-UNKNOWN".into());
                (max, top)
            } else {
                eprintln!("[dogfood] no real CVEs found, using synthetic CVSS 9.5 for policy test");
                (9.5, "CVE-TEST-SYNTHETIC".into())
            }
        }
        other => {
            eprintln!(
                "[dogfood] vuln_scanner scan unavailable (transient or network): {:?}; using synthetic CVSS 9.5 for policy gate",
                other.err()
            );
            (9.5, "CVE-TEST-SYNTHETIC".into())
        }
    };

    assert!(
        (0.0..=10.0).contains(&max_cvss) && max_cvss > 0.0,
        "CVSS score must be in (0, 10], got {max_cvss}"
    );
    eprintln!(
        "[dogfood] exercising CVSS policy gate with max CVSS {:.1} ({})",
        max_cvss, top_cve
    );

    let rt = GovernanceRuntime::builder()
        .charter(Charter::accept("vuln-defence", vec!["authorized".into()]))
        .scope(vec!["0.0.0.0/0".into()])
        .max_risk(RiskLevel::Critical)
        .deny_if_cvss_above(7.0)
        .build();

    let exploit_task = TaskSpec {
        name: format!("exploit_{}", top_cve),
        target: "10.0.0.5".into(),
        capabilities: vec![Capability::PrivilegeEscalation],
        impact: RiskLevel::High,
        destructive: false,
        approved: true,
        cvss: Some(CvssScore::from_score(max_cvss)),
        ..Default::default()
    };

    let cve_for_closure = top_cve.clone();
    let outcome = rt
        .execute(exploit_task, move || {
            let cve = cve_for_closure.clone();
            async move { Ok(json!({"exploited": true, "cve": cve})) }
        })
        .await;

    assert!(
        matches!(outcome, GovernedOutcome::Blocked { .. }),
        "CVSS {:.1} must be BLOCKED by DenyIfCvssAbove(7.0): got {:?}",
        max_cvss,
        outcome
    );

    let safe_task = TaskSpec {
        name: "safe_query".into(),
        target: "10.0.0.5".into(),
        capabilities: vec![Capability::NetworkScan],
        impact: RiskLevel::Low,
        destructive: false,
        approved: false,
        cvss: Some(CvssScore::from_score(3.0)),
        ..Default::default()
    };

    let safe_outcome = rt
        .execute(safe_task, || async { Ok(json!({"queried": true})) })
        .await;

    assert!(
        matches!(safe_outcome, GovernedOutcome::Allowed { .. }),
        "low-CVSS (3.0) must be Allowed: got {:?}",
        safe_outcome
    );

    let audit = rt.audit().await;
    let blocked = audit
        .iter()
        .find(|d| matches!(d.decision, icebox::core::PolicyDecision::Deny(_)));
    assert!(
        blocked.is_some(),
        "audit must contain a Deny decision for the blocked exploit"
    );
    if let Some(rec) = blocked {
        if let icebox::core::PolicyDecision::Deny(reason) = &rec.decision {
            assert!(
                reason.contains("CVSS"),
                "Deny reason must mention CVSS: {reason}"
            );
        }
    }
}
