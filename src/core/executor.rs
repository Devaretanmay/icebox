use std::str::FromStr;
use tracing::info;

use crate::core::audit::HashChain;
use crate::core::gee::GeeStage;
use crate::core::module::{Capability, Intent, LoadedModule, ModuleError, ModuleResult};
use crate::core::safety::{
    make_config_policy, now_secs, Charter, ConfigPolicy, DecisionRecord, Evidence, MemoryEntry,
    MemoryKind, PolicyContext, PolicyDecision, PolicyEngine, PolicyRequest, PolicySet, Preflight,
    PreflightError, ReasoningTrace, RiskLevel, ScopeManager,
};
use crate::core::sdk::{ActionOutcome, GovernAction, GovernResult, RecordResult};

const MAX_EVIDENCE: usize = 2000;
const MAX_TRACES: usize = 1000;
const MAX_MEMORIES: usize = 1000;

#[derive(Debug, thiserror::Error)]
pub enum ExecutorError {
    #[error(transparent)]
    Preflight(#[from] PreflightError),
    #[error(transparent)]
    Module(#[from] ModuleError),
    #[error("sandbox error: {0}")]
    Sandbox(String),
}

/// The execution seam: owns the GEE lifecycle state and enforces it.
#[derive(Debug)]
pub struct ModuleExecutor {
    pub charter: Charter,
    pub scope: ScopeManager,
    pub max_risk: RiskLevel,
    pub policy_set: PolicySet,
    pub tier: crate::core::safety::Tier,
    pub audit: HashChain,
    /// Set when policy failed to load; engine denies everything (fail-closed).
    pub safe_mode: Option<String>,
    pub evidence: Vec<Evidence>,
    pub traces: Vec<ReasoningTrace>,
    pub memories: Vec<MemoryEntry>,
    pub stage: GeeStage,
}

impl ModuleExecutor {
    fn transition_to(&mut self, next: GeeStage) {
        let life = GeeStage::lifecycle();
        let cur_idx = life
            .iter()
            .position(|s| *s == self.stage)
            .expect("current stage must be in lifecycle");
        let next_idx = life
            .iter()
            .position(|s| *s == next)
            .expect("next stage must be in lifecycle");
        assert!(
            next_idx == cur_idx + 1,
            "GEE lifecycle violation: cannot transition from {:?} to {:?} (must be sequential)",
            self.stage,
            next
        );
        let prev = std::mem::replace(&mut self.stage, next);
        info!(
            from = %prev.as_str(),
            to = %next.as_str(),
            "gee lifecycle transition"
        );
    }

    pub fn new(charter: Charter, scope: ScopeManager, max_risk: RiskLevel) -> Self {
        ModuleExecutor {
            charter,
            scope,
            max_risk,
            policy_set: PolicySet::default(),
            tier: crate::core::safety::Tier::Fridge,
            audit: HashChain::new(),
            safe_mode: None,
            evidence: Vec::new(),
            traces: Vec::new(),
            memories: Vec::new(),
            stage: GeeStage::Request,
        }
    }

    /// Make the audit ledger durable: replay any existing on-disk entries and
    /// fsync every future decision. Safe to call before any decision is made.
    pub fn set_audit_path(&mut self, path: impl AsRef<std::path::Path>) -> Result<(), String> {
        self.audit = HashChain::with_path(path)?;
        Ok(())
    }

    pub fn policy(&self, context: PolicyContext) -> ConfigPolicy {
        let mut policy = make_config_policy(self.max_risk, context, &self.policy_set);
        policy.safe_mode = self.safe_mode.clone();
        if let Some(thr) = self.tier.cvss_threshold() {
            policy
                .rules
                .add_rule(crate::core::safety::PolicyRule::DenyIfCvssAbove(thr));
        }
        policy
    }

    pub fn recent_traces(&self, n: usize) -> Vec<ReasoningTrace> {
        let end = self.traces.len();
        let start = end.saturating_sub(n);
        self.traces[start..].to_vec()
    }

    pub fn recent_memories(&self, n: usize) -> Vec<MemoryEntry> {
        let end = self.memories.len();
        let start = end.saturating_sub(n);
        self.memories[start..].to_vec()
    }

    pub fn remember(&mut self, kind: MemoryKind, text: impl Into<String>) {
        self.memories.push(MemoryEntry {
            at: now_secs(),
            kind,
            text: text.into(),
        });
        let overflow = self.memories.len().saturating_sub(MAX_MEMORIES);
        if overflow > 0 {
            self.memories.drain(..overflow);
        }
    }

    pub fn record_trace(&mut self, trace: ReasoningTrace) {
        self.traces.push(trace);
        let overflow = self.traces.len().saturating_sub(MAX_TRACES);
        if overflow > 0 {
            self.traces.drain(..overflow);
        }
    }

    pub fn recent_decisions(&self, n: usize) -> Vec<DecisionRecord> {
        self.audit.recent(n)
    }

    pub fn decisions(&self) -> Vec<DecisionRecord> {
        self.audit.records()
    }

    pub fn append_decision(&mut self, record: DecisionRecord) -> u64 {
        self.audit.append(record)
    }

    pub fn verify_audit(&self) -> bool {
        self.audit.verify()
    }

    pub fn audit_chain(&self) -> &HashChain {
        &self.audit
    }

    pub fn govern_action(&mut self, action: &GovernAction, context: PolicyContext) -> GovernResult {
        let capability = match Capability::from_str(&action.capability) {
            Ok(c) => c,
            Err(e) => {
                let decision_id = self.audit.append(DecisionRecord {
                    at: now_secs(),
                    target: action.target.clone(),
                    module: action.action.clone(),
                    capabilities: vec![],
                    intents: vec![],
                    impact: action.impact,
                    context,
                    decision: PolicyDecision::Deny(format!("unknown capability: {e}")),
                });
                return GovernResult {
                    approved: false,
                    decision: "deny".into(),
                    reason: Some(format!("unknown capability: {}", action.capability)),
                    decision_id,
                    chain_tip: self.audit.tip_hex(),
                };
            }
        };

        let in_scope = self.scope.is_in_scope(&action.target);

        let req = PolicyRequest {
            target: action.target.clone(),
            capabilities: vec![capability],
            impact: action.impact,
            destructive: action.destructive,
            charter_accepted: self.charter.accepted,
            in_scope,
            approved: false,
            context,
            cvss: None,
        };

        let policy = self.policy(context);
        let decision = policy.evaluate(&req);

        let intents: Vec<Intent> = req.capabilities.iter().map(|c| c.intent()).collect();

        let decision_id = self.audit.append(DecisionRecord {
            at: now_secs(),
            target: action.target.clone(),
            module: action.action.clone(),
            capabilities: req.capabilities.clone(),
            intents,
            impact: action.impact,
            context,
            decision: decision.clone(),
        });

        match decision {
            PolicyDecision::Deny(reason) => GovernResult {
                approved: false,
                decision: "deny".into(),
                reason: Some(reason),
                decision_id,
                chain_tip: self.audit.tip_hex(),
            },
            PolicyDecision::RequireApproval(reason) => GovernResult {
                approved: false,
                decision: "require_approval".into(),
                reason: Some(reason),
                decision_id,
                chain_tip: self.audit.tip_hex(),
            },
            PolicyDecision::Allow => GovernResult {
                approved: true,
                decision: "allow".into(),
                reason: None,
                decision_id,
                chain_tip: self.audit.tip_hex(),
            },
        }
    }

    pub fn record_action(
        &mut self,
        action: &GovernAction,
        outcome: ActionOutcome,
        decision: PolicyDecision,
    ) -> RecordResult {
        for content in &outcome.evidence {
            let seq = self.evidence.len();
            self.evidence.push(Evidence::new(
                &action.action,
                &action.target,
                content,
                None,
                seq,
            ));
        }

        let capability =
            Capability::from_str(&action.capability).unwrap_or(Capability::NetworkScan);
        let intents = vec![capability.intent()];

        let decision_id = self.audit.append(DecisionRecord {
            at: now_secs(),
            target: action.target.clone(),
            module: action.action.clone(),
            capabilities: vec![capability],
            intents,
            impact: action.impact,
            context: PolicyContext::Rest,
            decision,
        });

        RecordResult {
            decision_id,
            chain_tip: self.audit.tip_hex(),
        }
    }

    pub fn recent_evidence(&self, n: usize) -> Vec<Evidence> {
        let end = self.evidence.len();
        let start = end.saturating_sub(n);
        self.evidence[start..].to_vec()
    }

    pub async fn preflight(
        &self,
        loaded: &LoadedModule,
        target: &str,
        destructive_override: Option<bool>,
        approved: bool,
        context: PolicyContext,
    ) -> Preflight {
        let destructive = destructive_override
            .unwrap_or_else(|| loaded.info.effective_intents().contains(&Intent::Modify));

        Preflight {
            target: target.to_string(),
            charter_accepted: self.charter.accepted,
            in_scope: self.scope.is_in_scope(target),
            risk: loaded.info.effective_impact(),
            destructive,
            approved,
            capabilities: loaded.info.capabilities.clone(),
            intents: loaded.info.effective_intents(),
            context,
            cvss: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn execute(
        &mut self,
        loaded: &mut LoadedModule,
        target: &str,
        destructive_override: Option<bool>,
        approved: bool,
        context: PolicyContext,
        job_id: Option<u64>,
        engine: Option<crate::core::sandbox::SandboxEngineType>,
    ) -> Result<ModuleResult, ExecutorError> {
        assert!(
            self.stage == GeeStage::Request,
            "execute must start from Request stage, current: {:?}",
            self.stage
        );

        self.transition_to(GeeStage::PolicyEvaluation);
        let pf = self
            .preflight(loaded, target, destructive_override, approved, context)
            .await;
        let policy = self.policy(context);
        let decision = policy.evaluate(&pf.to_request());
        self.record_decision(&loaded.info.name, &pf, &decision);
        if let PolicyDecision::Deny(reason) = decision {
            self.stage = GeeStage::Request;
            return Err(ExecutorError::Preflight(PreflightError::Denied(reason)));
        }

        self.transition_to(GeeStage::ScopeEnforcement);
        if !self.scope.is_in_scope(target) {
            let reason = format!("target {target} is out of scope");
            self.record_decision(
                &loaded.info.name,
                &pf,
                &PolicyDecision::Deny(reason.clone()),
            );
            self.stage = GeeStage::Request;
            return Err(ExecutorError::Preflight(PreflightError::Denied(reason)));
        }

        self.transition_to(GeeStage::SandboxProvisioning);
        let mut maybe_sandbox: Option<crate::core::sandbox::Sandbox> = None;
        if self.tier.requires_sandbox() {
            use crate::core::sandbox::Sandbox;
            let se = engine.unwrap_or(crate::core::sandbox::SandboxEngineType::Docker);
            let image = "icebox-sandbox:latest".to_string();
            match Sandbox::freeze(se, target, &image).await {
                Ok(s) => {
                    info!(
                        container = %s.container_id(),
                        "sandbox provisioned"
                    );
                    maybe_sandbox = Some(s);
                }
                Err(e) => {
                    let reason =
                        format!("Sandbox provisioning failed: {e}. Isolation is mandatory.");
                    self.record_failure(&loaded.info.name, target, &reason, context);
                    self.stage = GeeStage::Request;
                    return Err(ExecutorError::Sandbox(reason));
                }
            }
        }

        self.transition_to(GeeStage::ApprovalCheck);
        let needs_approval = matches!(decision, PolicyDecision::RequireApproval(_))
            || (self.tier.requires_explicit_approval());
        if needs_approval && !approved {
            let reason = if matches!(decision, PolicyDecision::RequireApproval(_)) {
                format!(
                    "policy requires approval for {} on {}",
                    loaded.info.name, target
                )
            } else {
                format!(
                    "operational tier {} requires explicit operator approval",
                    self.tier
                )
            };
            self.record_decision(
                &loaded.info.name,
                &pf,
                &PolicyDecision::RequireApproval(reason.clone()),
            );
            self.stage = GeeStage::Request;
            return Err(ExecutorError::Preflight(PreflightError::ApprovalRequired));
        }

        self.transition_to(GeeStage::Execute);
        info!(
            target = %target,
            module = %loaded.info.name,
            risk = %pf.risk.as_str(),
            destructive = pf.destructive,
            "governed execution: preflight passed"
        );

        if policy.has_deny_payload() {
            if let Ok(preview) = loaded.module.dry_run().await {
                let denied = policy.denied_payload(&preview);
                if !denied.is_empty() {
                    let reason =
                        format!("payload matched denied pattern (pre-execution): {denied}");
                    self.record_decision(
                        &loaded.info.name,
                        &pf,
                        &PolicyDecision::Deny(reason.clone()),
                    );
                    self.transition_to(GeeStage::CollectEvidence);
                    self.transition_to(GeeStage::Audit);
                    self.transition_to(GeeStage::Validate);
                    self.transition_to(GeeStage::Destroy);
                    self.teardown_sandbox(&mut maybe_sandbox, &loaded.info.name, target, job_id)
                        .await;
                    self.stage = GeeStage::Request;
                    return Ok(ModuleResult {
                        success: false,
                        evidence: vec![format!("[BLOCKED:payload] {denied}")],
                        data: serde_json::Value::Null,
                        ..Default::default()
                    });
                }
            }
        }

        let result = if let Some(ref sandbox) = maybe_sandbox {
            self.run_in_sandbox(sandbox, loaded, target, context)
                .await?
        } else {
            match loaded.module.run().await {
                Ok(r) => r,
                Err(e) => {
                    let reason = format!("module execution failed: {e}");
                    self.record_decision(
                        &loaded.info.name,
                        &pf,
                        &PolicyDecision::Deny(reason.clone()),
                    );
                    self.transition_to(GeeStage::CollectEvidence);
                    self.transition_to(GeeStage::Audit);
                    self.transition_to(GeeStage::Validate);
                    self.transition_to(GeeStage::Destroy);
                    self.teardown_sandbox(&mut maybe_sandbox, &loaded.info.name, target, job_id)
                        .await;
                    self.stage = GeeStage::Request;
                    return Err(ExecutorError::Module(e));
                }
            }
        };

        self.transition_to(GeeStage::CollectEvidence);
        let denied = policy.denied_payload(&result);
        if !denied.is_empty() {
            let reason = format!("payload matched denied pattern: {denied}");
            self.record_decision(
                &loaded.info.name,
                &pf,
                &PolicyDecision::Deny(reason.clone()),
            );
            let mut blocked = result;
            blocked.success = false;
            blocked.evidence.push(format!("[BLOCKED:payload] {denied}"));
            blocked.data = serde_json::Value::Null;
            self.record_evidence(&loaded.info.name, target, &blocked, job_id);
            self.transition_to(GeeStage::Audit);
            self.transition_to(GeeStage::Validate);
            self.transition_to(GeeStage::Destroy);
            self.teardown_sandbox(&mut maybe_sandbox, &loaded.info.name, target, job_id)
                .await;
            self.stage = GeeStage::Request;
            return Ok(blocked);
        }

        self.record_evidence(&loaded.info.name, target, &result, job_id);

        self.transition_to(GeeStage::Audit);

        self.transition_to(GeeStage::Validate);
        if !self.audit.verify() {
            let reason = "audit chain integrity check failed during Validate stage".to_string();
            self.record_failure(&loaded.info.name, target, &reason, context);
            self.transition_to(GeeStage::Destroy);
            self.teardown_sandbox(&mut maybe_sandbox, &loaded.info.name, target, job_id)
                .await;
            self.stage = GeeStage::Request;
            return Err(ExecutorError::Sandbox(reason));
        }
        for w in self.evidence.windows(2) {
            let ts_a = w[0]
                .id
                .split('-')
                .next()
                .and_then(|s| s.parse::<u64>().ok());
            let ts_b = w[1]
                .id
                .split('-')
                .next()
                .and_then(|s| s.parse::<u64>().ok());
            match (ts_a, ts_b) {
                (Some(a), Some(b)) if a > b => {
                    let reason = format!(
                        "evidence timestamp regression: {} ({}) > {} ({})",
                        w[0].id, a, w[1].id, b
                    );
                    self.record_failure(&loaded.info.name, target, &reason, context);
                    self.transition_to(GeeStage::Destroy);
                    self.teardown_sandbox(&mut maybe_sandbox, &loaded.info.name, target, job_id)
                        .await;
                    self.stage = GeeStage::Request;
                    return Err(ExecutorError::Sandbox(reason));
                }
                _ => {}
            }
        }
        if self.audit.records().is_empty() {
            let reason = "no decision records found after execution".to_string();
            self.record_failure(&loaded.info.name, target, &reason, context);
            self.transition_to(GeeStage::Destroy);
            self.teardown_sandbox(&mut maybe_sandbox, &loaded.info.name, target, job_id)
                .await;
            self.stage = GeeStage::Request;
            return Err(ExecutorError::Sandbox(reason));
        }

        self.transition_to(GeeStage::Destroy);
        self.teardown_sandbox(&mut maybe_sandbox, &loaded.info.name, target, job_id)
            .await;

        self.stage = GeeStage::Request;
        Ok(result)
    }

    /// Destroy a provisioned sandbox (if any) and capture its logs as evidence.
    async fn teardown_sandbox(
        &mut self,
        maybe_sandbox: &mut Option<crate::core::sandbox::Sandbox>,
        module: &str,
        target: &str,
        job_id: Option<u64>,
    ) {
        if let Some(sandbox) = maybe_sandbox.take() {
            let logs = sandbox.capture_logs().await;
            let cid = sandbox.container_id().to_string();
            if let Err(e) = sandbox.melt().await {
                let warn = format!("[SANDBOX] teardown warning for {cid}: {e}");
                info!("{warn}");
            }
            info!(container = %cid, "sandbox destroyed");
            if !logs.is_empty() {
                let seq_start = self.evidence.len();
                for (i, line) in logs.iter().enumerate() {
                    self.evidence
                        .push(Evidence::new(module, target, line, job_id, seq_start + i));
                }
            }
        }
    }

    fn record_decision(
        &mut self,
        module: &str,
        pf: &Preflight,
        decision: &crate::core::safety::PolicyDecision,
    ) {
        self.audit.append(DecisionRecord {
            at: now_secs(),
            target: pf.target.clone(),
            module: module.to_string(),
            capabilities: pf.capabilities.clone(),
            intents: pf.intents.clone(),
            impact: pf.risk,
            context: pf.context,
            decision: decision.clone(),
        });
    }

    fn record_evidence(
        &mut self,
        module: &str,
        target: &str,
        result: &ModuleResult,
        job_id: Option<u64>,
    ) {
        let seq_start = self.evidence.len();
        for (i, content) in result.evidence.iter().enumerate() {
            self.evidence.push(Evidence::new(
                module,
                target,
                content,
                job_id,
                seq_start + i,
            ));
        }
        let overflow = self.evidence.len().saturating_sub(MAX_EVIDENCE);
        if overflow > 0 {
            self.evidence.drain(..overflow);
        }
    }

    async fn run_in_sandbox(
        &mut self,
        sandbox: &crate::core::sandbox::Sandbox,
        loaded: &crate::core::module::LoadedModule,
        target: &str,
        context: PolicyContext,
    ) -> Result<ModuleResult, ExecutorError> {
        let options = loaded.module.options_json();
        let result = match sandbox
            .exec_module(&loaded.info.name, target, &options)
            .await
        {
            Ok(r) => r,
            Err(e) => ModuleResult {
                error: Some(format!("sandbox module exec failed: {e}")),
                ..Default::default()
            },
        };
        if result.error.is_some() {
            self.record_failure(
                &loaded.info.name,
                target,
                result.error.as_deref().unwrap_or("sandbox failure"),
                context,
            );
        }
        Ok(result)
    }

    fn record_failure(&mut self, module: &str, target: &str, reason: &str, context: PolicyContext) {
        self.audit.append(DecisionRecord {
            at: now_secs(),
            target: target.to_string(),
            module: module.to_string(),
            capabilities: Vec::new(),
            intents: Vec::new(),
            impact: RiskLevel::None,
            context,
            decision: PolicyDecision::Deny(reason.to_string()),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::safety::{PolicyContext, Tier};

    #[test]
    #[should_panic(expected = "GEE lifecycle violation")]
    fn transition_to_rejects_backwards() {
        let mut exec = ModuleExecutor::new(
            Charter::accept("test", vec!["auth".into()]),
            ScopeManager::new(vec!["127.0.0.1".into()]),
            RiskLevel::Low,
        );
        exec.transition_to(GeeStage::Execute);
        exec.transition_to(GeeStage::Request);
    }

    #[test]
    #[should_panic(expected = "GEE lifecycle violation")]
    fn transition_to_rejects_skip() {
        let mut exec = ModuleExecutor::new(
            Charter::accept("test", vec!["auth".into()]),
            ScopeManager::new(vec!["127.0.0.1".into()]),
            RiskLevel::Low,
        );
        exec.transition_to(GeeStage::Destroy);
    }

    #[tokio::test]
    async fn execute_completes_full_lifecycle_and_resets() {
        let mut exec = ModuleExecutor::new(
            Charter::accept("test", vec!["auth".into()]),
            ScopeManager::new(vec!["127.0.0.1".into()]),
            RiskLevel::Critical,
        );
        exec.tier = Tier::Fridge;
        let mut loaded = crate::modules::load("tcp_port_scanner").expect("module");
        let _ = loaded.module.set_option("host", "127.0.0.1");
        let _ = loaded.module.set_option("ports", "22");
        let result = exec
            .execute(
                &mut loaded,
                "127.0.0.1",
                None,
                true,
                PolicyContext::Cli,
                None,
                None,
            )
            .await;
        assert!(result.is_ok(), "in-scope approved low-risk run must pass");
        assert_eq!(exec.stage, GeeStage::Request);
        assert!(
            !exec.audit.is_empty(),
            "every execution leaves an audit trail"
        );
        assert!(
            exec.verify_audit(),
            "audit chain must verify after lifecycle"
        );
    }

    #[tokio::test]
    async fn execute_resets_stage_after_denial() {
        let mut exec = ModuleExecutor::new(
            Charter::accept("test", vec!["auth".into()]),
            ScopeManager::new(vec!["127.0.0.1".into()]),
            RiskLevel::Critical,
        );
        exec.tier = Tier::Fridge;
        let mut loaded = crate::modules::load("tcp_port_scanner").expect("module");
        let result = exec
            .execute(
                &mut loaded,
                "8.8.8.8",
                None,
                true,
                PolicyContext::Cli,
                None,
                None,
            )
            .await;
        assert!(result.is_err(), "out-of-scope target must be denied");
        assert_eq!(exec.stage, GeeStage::Request);
    }
}
