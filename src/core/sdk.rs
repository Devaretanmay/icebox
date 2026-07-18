use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::{broadcast, Mutex};

use crate::core::audit::HashChain;
use crate::core::executor::ModuleExecutor;
use crate::core::governance::{ApprovalQueue, ApprovalRequest, ApprovalStatus, Role};
use crate::core::module::{Capability, Intent};
use crate::core::safety::{
    now_secs, Charter, ConfigPolicy, CvssScore, DecisionRecord, PolicyContext, PolicyDecision,
    PolicyEngine, PolicyRequest, PolicyRule, PolicySet, RiskLevel, ScopeManager,
};

/// An action to be governed by ICEBOX — the "Stripe-style" request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernAction {
    pub action: String,
    pub target: String,
    pub capability: String,
    pub impact: RiskLevel,
    pub destructive: bool,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

/// Decision returned after running an action through the GEE lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernResult {
    pub approved: bool,
    pub decision: String,
    pub reason: Option<String>,
    pub decision_id: u64,
    pub chain_tip: String,
}

/// Outcome of executing an action outside ICEBOX, to be recorded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionOutcome {
    pub success: bool,
    pub evidence: Vec<String>,
    pub data: serde_json::Value,
}

/// Result after recording an action outcome into the audit chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordResult {
    pub decision_id: u64,
    pub chain_tip: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskSpec {
    pub name: String,
    pub target: String,
    pub capabilities: Vec<Capability>,
    pub impact: RiskLevel,
    pub destructive: bool,
    #[serde(default)]
    pub options: HashMap<String, String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub context: PolicyContext,
    #[serde(default)]
    pub approved: bool,
    #[serde(default)]
    pub cvss: Option<CvssScore>,
}

impl Default for TaskSpec {
    fn default() -> Self {
        TaskSpec {
            name: String::new(),
            target: String::new(),
            capabilities: Vec::new(),
            impact: RiskLevel::Low,
            destructive: false,
            options: HashMap::new(),
            agent_id: None,
            context: PolicyContext::Autonomous,
            approved: false,
            cvss: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceConfig {
    pub charter: Charter,
    pub scope: ScopeManager,
    #[serde(default)]
    pub max_risk: RiskLevel,
    #[serde(default)]
    pub role: Role,
    #[serde(default)]
    pub policy_set: PolicySet,
    #[serde(default)]
    pub rate_limits: HashMap<String, u64>,
}

impl Default for GovernanceConfig {
    fn default() -> Self {
        GovernanceConfig {
            charter: Charter::default(),
            scope: ScopeManager::default(),
            max_risk: RiskLevel::Critical,
            role: Role::Operator,
            policy_set: PolicySet::default(),
            rate_limits: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GovernedOutcome {
    Allowed {
        result: Value,
        decision_id: u64,
    },
    Blocked {
        reason: String,
        decision_id: u64,
    },
    NeedsApproval {
        reason: String,
        decision_id: u64,
        approval_id: u64,
    },
}

#[derive(Debug, Default)]
struct RateState {
    count: u64,
    window_start: u64,
}

#[derive(Debug)]
struct RuntimeState {
    config: GovernanceConfig,
    audit: HashChain,
    approvals: ApprovalQueue,
    rate: HashMap<String, RateState>,
    audit_tx: broadcast::Sender<DecisionRecord>,
    next_decision_id: u64,
}

impl RuntimeState {
    fn check_rate_limit(&mut self, name: &str) -> Option<String> {
        let limit = *self.config.rate_limits.get(name)?;
        let now = now_secs();
        let st = self.rate.entry(name.to_string()).or_default();
        if now.saturating_sub(st.window_start) >= 60 {
            st.count = 0;
            st.window_start = now;
        }
        if st.count >= limit {
            return Some(format!("rate limit of {limit}/min exceeded for {name}"));
        }
        st.count += 1;
        None
    }
}

fn derive_intents(caps: &[Capability]) -> Vec<Intent> {
    caps.iter().map(|c| c.intent()).collect()
}

#[derive(Debug, Clone)]
pub struct GovernanceRuntime {
    state: Arc<Mutex<RuntimeState>>,
}

impl GovernanceRuntime {
    pub fn builder() -> GovernanceBuilder {
        GovernanceBuilder::new()
    }

    pub async fn execute<F, Fut>(&self, task: TaskSpec, action: F) -> GovernedOutcome
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<Value, String>> + Send + 'static,
    {
        self.enforce(task, action, false).await
    }

    pub async fn execute_module(
        &self,
        name: &str,
        target: &str,
        options: &HashMap<String, String>,
    ) -> Result<String, String> {
        let cfg = self.state.lock().await.config.clone();
        let mut exec = ModuleExecutor::new(cfg.charter, cfg.scope, cfg.max_risk);
        exec.policy_set = cfg.policy_set;
        let Some(mut loaded) = crate::modules::load(name) else {
            return Err(format!("module not found: {name}"));
        };
        for (k, v) in options {
            let _ = loaded.module.set_option(k, v);
        }
        match exec
            .execute(
                &mut loaded,
                target,
                None,
                true,
                PolicyContext::Rest,
                None,
                false,
                None,
            )
            .await
        {
            Ok(r) => Ok(serde_json::to_string(&r).unwrap_or_default()),
            Err(e) => Err(e.to_string()),
        }
    }

    /// Evaluate policy and record the decision without running the action.
    /// Returns Allowed (with null result), Blocked, or NeedsApproval.
    /// The caller runs the action only when Allowed, then calls `complete()`.
    pub async fn preflight(&self, task: TaskSpec) -> GovernedOutcome {
        let mut st = self.state.lock().await;

        if let Some(reason) = st.check_rate_limit(&task.name) {
            return st.record_and_block(task, reason);
        }

        let approved = task.approved;
        let req = PolicyRequest {
            target: task.target.clone(),
            capabilities: task.capabilities.clone(),
            impact: task.impact,
            destructive: task.destructive,
            charter_accepted: st.config.charter.accepted,
            in_scope: st.config.scope.is_in_scope(&task.target),
            approved,
            context: task.context,
            cvss: None,
        };
        let policy = ConfigPolicy {
            max_risk: st.config.policy_set.max_risk(st.config.max_risk),
            context: task.context,
            rules: st.config.policy_set.clone(),
        };
        let decision = policy.evaluate(&req);
        let decision_id = st.next_decision_id;
        st.next_decision_id += 1;
        let rec = DecisionRecord {
            at: now_secs(),
            target: task.target.clone(),
            module: task.name.clone(),
            capabilities: task.capabilities.clone(),
            intents: derive_intents(&task.capabilities),
            impact: task.impact,
            context: task.context,
            decision: decision.clone(),
        };
        st.audit.append(rec.clone());
        let _ = st.audit_tx.send(rec);

        match decision {
            PolicyDecision::Deny(reason) => GovernedOutcome::Blocked {
                reason,
                decision_id,
            },
            PolicyDecision::RequireApproval(reason) if !approved => {
                let approval_id = st.approvals.request(
                    task.name.clone(),
                    task.target.clone(),
                    reason.clone(),
                    task.options.clone(),
                );
                GovernedOutcome::NeedsApproval {
                    reason,
                    decision_id,
                    approval_id,
                }
            }
            _ => GovernedOutcome::Allowed {
                result: Value::Null,
                decision_id,
            },
        }
    }

    /// Record that a preflighted action completed successfully.
    /// Creates a new audit entry linked to the preflight decision.
    pub async fn complete(
        &self,
        task: TaskSpec,
        result: Value,
    ) -> GovernedOutcome {
        let mut st = self.state.lock().await;
        let intents = derive_intents(&task.capabilities);
        let decision_id = st.next_decision_id;
        st.next_decision_id += 1;
        let rec = DecisionRecord {
            at: now_secs(),
            target: task.target,
            module: task.name,
            capabilities: task.capabilities,
            intents,
            impact: task.impact,
            context: task.context,
            decision: PolicyDecision::Allow,
        };
        st.audit.append(rec.clone());
        let _ = st.audit_tx.send(rec);
        GovernedOutcome::Allowed { result, decision_id }
    }

    pub async fn run<F, Fut>(&self, task: TaskSpec, action: F) -> GovernedOutcome
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<Value, String>> + Send + 'static,
    {
        self.enforce(task, action, true).await
    }

    async fn enforce<F, Fut>(
        &self,
        task: TaskSpec,
        action: F,
        auto_approve: bool,
    ) -> GovernedOutcome
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<Value, String>> + Send + 'static,
    {
        let mut st = self.state.lock().await;

        if let Some(reason) = st.check_rate_limit(&task.name) {
            return st.record_and_block(task, reason);
        }

        let approved = auto_approve || task.approved;
        let req = PolicyRequest {
            target: task.target.clone(),
            capabilities: task.capabilities.clone(),
            impact: task.impact,
            destructive: task.destructive,
            charter_accepted: st.config.charter.accepted,
            in_scope: st.config.scope.is_in_scope(&task.target),
            approved,
            context: task.context,
            cvss: task.cvss.clone(),
        };
        let policy = ConfigPolicy {
            max_risk: st.config.policy_set.max_risk(st.config.max_risk),
            context: task.context,
            rules: st.config.policy_set.clone(),
        };
        let decision = policy.evaluate(&req);
        let decision_id = st.next_decision_id;
        st.next_decision_id += 1;
        let rec = DecisionRecord {
            at: now_secs(),
            target: task.target.clone(),
            module: task.name.clone(),
            capabilities: task.capabilities.clone(),
            intents: derive_intents(&task.capabilities),
            impact: task.impact,
            context: task.context,
            decision: decision.clone(),
        };
        st.audit.append(rec.clone());
        let _ = st.audit_tx.send(rec);

        match decision {
            PolicyDecision::Deny(reason) => GovernedOutcome::Blocked {
                reason,
                decision_id,
            },
            PolicyDecision::RequireApproval(reason) if !approved => {
                let approval_id = st.approvals.request(
                    task.name.clone(),
                    task.target.clone(),
                    reason.clone(),
                    task.options.clone(),
                );
                GovernedOutcome::NeedsApproval {
                    reason,
                    decision_id,
                    approval_id,
                }
            }
            PolicyDecision::RequireApproval(_) | PolicyDecision::Allow => {
                drop(st);
                match action().await {
                    Ok(result) => GovernedOutcome::Allowed {
                        result,
                        decision_id,
                    },
                    Err(e) => GovernedOutcome::Blocked {
                        reason: format!("task action failed: {e}"),
                        decision_id,
                    },
                }
            }
        }
    }

    pub async fn approve(&self, id: u64) -> bool {
        self.state.lock().await.approvals.approve(id)
    }

    pub async fn deny(&self, id: u64) -> bool {
        self.state.lock().await.approvals.deny(id)
    }

    pub async fn pending_approvals(&self) -> Vec<ApprovalRequest> {
        self.state
            .lock()
            .await
            .approvals
            .list()
            .into_iter()
            .filter(|a| matches!(a.status, ApprovalStatus::Pending))
            .collect()
    }

    pub async fn audit(&self) -> Vec<DecisionRecord> {
        self.state.lock().await.audit.records()
    }

    pub async fn export_audit_json(&self) -> String {
        let d = self.state.lock().await.audit.records();
        serde_json::to_string_pretty(&d).unwrap_or_else(|_| "[]".into())
    }

    pub async fn export_audit_csv(&self) -> String {
        let d = self.state.lock().await.audit.records();
        crate::core::governance::audit_to_csv(&d)
    }

    pub async fn audit_stream(&self) -> broadcast::Receiver<DecisionRecord> {
        self.state.lock().await.audit_tx.subscribe()
    }

    pub async fn add_rule(&self, rule: PolicyRule) {
        self.state.lock().await.config.policy_set.add_rule(rule);
    }

    pub async fn policy_set(&self) -> PolicySet {
        self.state.lock().await.config.policy_set.clone()
    }

    pub async fn role(&self) -> Role {
        self.state.lock().await.config.role
    }

    pub async fn config(&self) -> GovernanceConfig {
        self.state.lock().await.config.clone()
    }
}

impl RuntimeState {
    fn record_and_block(&mut self, task: TaskSpec, reason: String) -> GovernedOutcome {
        let decision_id = self.next_decision_id;
        self.next_decision_id += 1;
        let rec = DecisionRecord {
            at: now_secs(),
            target: task.target.clone(),
            module: task.name.clone(),
            capabilities: task.capabilities.clone(),
            intents: derive_intents(&task.capabilities),
            impact: task.impact,
            context: task.context,
            decision: PolicyDecision::Deny(reason.clone()),
        };
        self.audit.append(rec.clone());
        let _ = self.audit_tx.send(rec);
        GovernedOutcome::Blocked {
            reason,
            decision_id,
        }
    }
}

pub fn govern(config: GovernanceConfig) -> GovernanceRuntime {
    let (audit_tx, _rx) = broadcast::channel(1024);
    GovernanceRuntime {
        state: Arc::new(Mutex::new(RuntimeState {
            config,
            audit: HashChain::new(),
            approvals: ApprovalQueue::default(),
            rate: HashMap::new(),
            audit_tx,
            next_decision_id: 1,
        })),
    }
}

pub struct GovernanceBuilder {
    config: GovernanceConfig,
}

impl GovernanceBuilder {
    pub fn new() -> Self {
        GovernanceBuilder {
            config: GovernanceConfig::default(),
        }
    }

    pub fn charter(mut self, charter: Charter) -> Self {
        self.config.charter = charter;
        self
    }

    pub fn scope(mut self, allow: Vec<String>) -> Self {
        self.config.scope = ScopeManager::new(allow);
        self
    }

    pub fn max_risk(mut self, max_risk: RiskLevel) -> Self {
        self.config.max_risk = max_risk;
        self
    }

    pub fn role(mut self, role: Role) -> Self {
        self.config.role = role;
        self
    }

    pub fn deny_capability(mut self, cap: Capability) -> Self {
        self.config
            .policy_set
            .add_rule(PolicyRule::DenyCapability(cap));
        self
    }

    pub fn allow_capability(mut self, cap: Capability) -> Self {
        self.config
            .policy_set
            .add_rule(PolicyRule::AllowCapability(cap));
        self
    }

    pub fn require_approval(mut self, cap: Capability, target_pattern: &str) -> Self {
        self.config
            .policy_set
            .add_rule(PolicyRule::RequireApproval {
                capability: cap,
                target_pattern: target_pattern.to_string(),
            });
        self
    }

    pub fn max_risk_ceiling(mut self, max_risk: RiskLevel) -> Self {
        self.config
            .policy_set
            .add_rule(PolicyRule::MaxRisk(max_risk));
        self
    }

    pub fn deny_if_cvss_above(mut self, threshold: f64) -> Self {
        self.config
            .policy_set
            .add_rule(PolicyRule::DenyIfCvssAbove(threshold));
        self
    }

    pub fn require_approval_if(
        mut self,
        cvss_above: Option<f64>,
        epss_above: Option<f64>,
        kev: bool,
    ) -> Self {
        self.config
            .policy_set
            .add_rule(PolicyRule::RequireApprovalIf {
                cvss_above,
                epss_above,
                kev,
            });
        self
    }

    pub fn rate_limit(mut self, name: &str, per_minute: u64) -> Self {
        self.config.rate_limits.insert(name.to_string(), per_minute);
        self
    }

    pub fn build(self) -> GovernanceRuntime {
        govern(self.config)
    }
}

impl Default for GovernanceBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn base_runtime() -> GovernanceRuntime {
        GovernanceRuntime::builder()
            .charter(Charter::accept("eng", vec!["no destruction".into()]))
            .scope(vec!["10.0.0.0/8".into()])
            .max_risk(RiskLevel::Critical)
            .role(Role::Admin)
            .build()
    }

    fn low_risk_task(target: &str) -> TaskSpec {
        TaskSpec {
            name: "scan".into(),
            target: target.into(),
            capabilities: vec![Capability::NetworkScan],
            impact: RiskLevel::Low,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn supervised_low_risk_runs_and_audits() {
        let rt = base_runtime();
        let out = rt
            .execute(low_risk_task("10.0.0.5"), || async {
                Ok(json!({"open_ports": [22, 80]}))
            })
            .await;
        match out {
            GovernedOutcome::Allowed { result, .. } => {
                assert_eq!(result["open_ports"][0], 22);
            }
            other => panic!("expected Allowed, got {other:?}"),
        }
        assert_eq!(rt.audit().await.len(), 1);
    }

    #[tokio::test]
    async fn out_of_scope_is_blocked() {
        let rt = base_runtime();
        let out = rt
            .execute(low_risk_task("8.8.8.8"), || async { Ok(json!(null)) })
            .await;
        assert!(matches!(out, GovernedOutcome::Blocked { .. }));
    }

    #[tokio::test]
    async fn deny_capability_blocks() {
        let rt = GovernanceRuntime::builder()
            .charter(Charter::accept("eng", vec![]))
            .scope(vec!["10.0.0.0/8".into()])
            .deny_capability(Capability::Persistence)
            .build();
        let task = TaskSpec {
            name: "implant".into(),
            target: "10.0.0.9".into(),
            capabilities: vec![Capability::Persistence],
            impact: RiskLevel::High,
            ..Default::default()
        };
        let out = rt.execute(task, || async { Ok(json!(null)) }).await;
        assert!(matches!(out, GovernedOutcome::Blocked { .. }));
    }

    #[tokio::test]
    async fn destructive_requires_approval_then_runs_after_approve() {
        let rt = base_runtime();
        let task = TaskSpec {
            name: "wipe".into(),
            target: "10.0.0.7".into(),
            capabilities: vec![Capability::FilesystemModification],
            impact: RiskLevel::High,
            destructive: true,
            ..Default::default()
        };
        let out = rt
            .execute(task.clone(), || async { Ok(json!({"wiped": true})) })
            .await;
        let id = match out {
            GovernedOutcome::NeedsApproval { approval_id, .. } => approval_id,
            other => panic!("expected NeedsApproval, got {other:?}"),
        };
        assert!(rt.approve(id).await);
        assert!(rt.pending_approvals().await.is_empty());
    }

    #[tokio::test]
    async fn require_approval_rule_gates_specific_target() {
        let rt = GovernanceRuntime::builder()
            .charter(Charter::accept("eng", vec![]))
            .scope(vec!["0.0.0.0/0".into()])
            .require_approval(Capability::CredentialAccess, "192.168.*")
            .build();
        let in_scope = TaskSpec {
            name: "dump".into(),
            target: "192.168.1.5".into(),
            capabilities: vec![Capability::CredentialAccess],
            impact: RiskLevel::Low,
            ..Default::default()
        };
        let out = rt.execute(in_scope, || async { Ok(json!(null)) }).await;
        assert!(matches!(out, GovernedOutcome::NeedsApproval { .. }));

        let other = TaskSpec {
            name: "dump".into(),
            target: "10.0.0.5".into(),
            capabilities: vec![Capability::CredentialAccess],
            impact: RiskLevel::Low,
            ..Default::default()
        };
        let out = rt.execute(other, || async { Ok(json!(null)) }).await;
        assert!(matches!(out, GovernedOutcome::Allowed { .. }));
    }

    #[tokio::test]
    async fn unsupervised_run_auto_grants_approval() {
        let rt = base_runtime();
        let task = TaskSpec {
            name: "wipe".into(),
            target: "10.0.0.7".into(),
            capabilities: vec![Capability::FilesystemModification],
            impact: RiskLevel::High,
            destructive: true,
            ..Default::default()
        };
        let out = rt.run(task, || async { Ok(json!({"ok": true})) }).await;
        assert!(matches!(out, GovernedOutcome::Allowed { .. }));
    }

    #[tokio::test]
    async fn rate_limit_blocks_after_ceiling() {
        let rt = GovernanceRuntime::builder()
            .charter(Charter::accept("eng", vec![]))
            .scope(vec!["0.0.0.0/0".into()])
            .rate_limit("scan", 2)
            .build();
        let task = low_risk_task("10.0.0.5");
        for _ in 0..2 {
            let out = rt.execute(task.clone(), || async { Ok(json!(null)) }).await;
            assert!(matches!(out, GovernedOutcome::Allowed { .. }));
        }
        let out = rt.execute(task.clone(), || async { Ok(json!(null)) }).await;
        assert!(matches!(out, GovernedOutcome::Blocked { .. }));
    }

    #[tokio::test]
    async fn audit_stream_delivers_records() {
        let rt = base_runtime();
        let mut rx = rt.audit_stream().await;
        let _ = rt
            .execute(low_risk_task("10.0.0.5"), || async { Ok(json!(null)) })
            .await;
        let rec = rx.recv().await.expect("audit record");
        assert_eq!(rec.target, "10.0.0.5");
    }

    #[tokio::test]
    async fn config_round_trips_through_json() {
        let rt = base_runtime();
        let json = serde_json::to_string(&rt.config().await).unwrap();
        let cfg: GovernanceConfig = serde_json::from_str(&json).unwrap();
        assert!(cfg.charter.accepted);
        assert_eq!(cfg.role, Role::Admin);
    }
}
