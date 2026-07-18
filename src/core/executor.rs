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

/// The execution seam of ICEBOX and its fundamental execution primitive:
/// every action runs as a Governed Execution Environment (GEE). This type owns
/// the GEE lifecycle (policy evaluation, sandbox provisioning, approval
/// gating, execution, evidence collection, audit, validation, and teardown)
/// and keeps the state required to enforce it.
#[derive(Debug)]
pub struct ModuleExecutor {
    pub charter: Charter,
    pub scope: ScopeManager,
    pub max_risk: RiskLevel,
    pub policy_set: PolicySet,
    pub sandbox_required: bool,
    pub tier: crate::core::safety::Tier,
    pub audit: HashChain,
    pub evidence: Vec<Evidence>,
    pub traces: Vec<ReasoningTrace>,
    pub memories: Vec<MemoryEntry>,
    pub stage: GeeStage,
}

impl ModuleExecutor {
    pub fn new(charter: Charter, scope: ScopeManager, max_risk: RiskLevel) -> Self {
        ModuleExecutor {
            charter,
            scope,
            max_risk,
            policy_set: PolicySet::default(),
            sandbox_required: false,
            tier: crate::core::safety::Tier::Fridge,
            audit: HashChain::new(),
            evidence: Vec::new(),
            traces: Vec::new(),
            memories: Vec::new(),
            stage: GeeStage::Request,
        }
    }

    pub fn policy(&self, context: PolicyContext) -> ConfigPolicy {
        let mut policy = make_config_policy(self.max_risk, context, &self.policy_set);
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

    /// Pure governance check: evaluate policy, scope, and approval gates
    /// without executing the action. Returns a decision the caller acts upon.
    /// This is the single-entry "Stripe-style" govern() call.
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

    /// Record completion of a prior governed action.
    /// Appends evidence and an audit-chain entry, then returns the chain tip.
    pub fn record_action(&mut self, action: &GovernAction, outcome: ActionOutcome) -> RecordResult {
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

        let capability = Capability::from_str(&action.capability).unwrap_or(Capability::NetworkScan);
        let intents = vec![capability.intent()];

        let decision_id = self.audit.append(DecisionRecord {
            at: now_secs(),
            target: action.target.clone(),
            module: action.action.clone(),
            capabilities: vec![capability],
            intents,
            impact: action.impact,
            context: PolicyContext::Rest,
            decision: PolicyDecision::Allow,
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
        sandbox: bool,
        engine: Option<crate::core::sandbox::SandboxEngineType>,
    ) -> Result<ModuleResult, ExecutorError> {
        self.stage = GeeStage::PolicyEvaluation;
        let pf = self
            .preflight(loaded, target, destructive_override, approved, context)
            .await;
        let policy = self.policy(context);
        let decision = policy.evaluate(&pf.to_request());
        self.record_decision(&loaded.info.name, &pf, &decision);
        pf.check(&policy)?;

        self.stage = GeeStage::ScopeEnforcement;
        if !self.scope.is_in_scope(target) {
            let reason = format!("target {target} is out of scope");
            self.record_decision(
                &loaded.info.name,
                &pf,
                &PolicyDecision::Deny(reason.clone()),
            );
            return Err(ExecutorError::Preflight(PreflightError::Denied(reason)));
        }

        self.stage = GeeStage::SandboxProvisioning;
        if (self.sandbox_required || self.tier.requires_sandbox()) && !sandbox {
            let reason = format!("operational tier {} requires sandbox isolation", self.tier);
            self.record_decision(
                &loaded.info.name,
                &pf,
                &PolicyDecision::Deny(reason.clone()),
            );
            return Err(ExecutorError::Preflight(PreflightError::Denied(reason)));
        }

        self.stage = GeeStage::ApprovalCheck;
        if self.tier.requires_explicit_approval() && !approved {
            let reason = format!(
                "operational tier {} requires explicit operator approval",
                self.tier
            );
            self.record_decision(
                &loaded.info.name,
                &pf,
                &PolicyDecision::RequireApproval(reason.clone()),
            );
            return Err(ExecutorError::Preflight(PreflightError::ApprovalRequired));
        }

        self.stage = GeeStage::Execute;
        info!(
            target = %target,
            module = %loaded.info.name,
            risk = %pf.risk.as_str(),
            destructive = pf.destructive,
            sandbox = sandbox,
            stage = %self.stage.as_str(),
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
                    return Ok(ModuleResult {
                        success: false,
                        evidence: vec![format!("[BLOCKED:payload] {denied}")],
                        data: serde_json::Value::Null,
                        ..Default::default()
                    });
                }
            }
        }

        let result = if sandbox {
            self.run_sandboxed(
                loaded,
                target,
                engine.unwrap_or(crate::core::sandbox::SandboxEngineType::Docker),
                context,
            )
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
                    return Err(ExecutorError::Module(e));
                }
            }
        };

        self.stage = GeeStage::CollectEvidence;
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
            self.stage = GeeStage::Audit;
            return Ok(blocked);
        }

        self.record_evidence(&loaded.info.name, target, &result, job_id);
        self.stage = GeeStage::Audit;
        Ok(result)
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

    async fn run_sandboxed(
        &mut self,
        loaded: &crate::core::module::LoadedModule,
        target: &str,
        engine: crate::core::sandbox::SandboxEngineType,
        context: PolicyContext,
    ) -> Result<ModuleResult, ExecutorError> {
        use crate::core::sandbox::Sandbox;
        let image = "icebox-sandbox:latest".to_string();
        let module_name = loaded.info.name.clone();
        match Sandbox::freeze(engine, target, &image).await {
            Ok(sandbox) => {
                info!(
                    container = %sandbox.container_id(),
                    stage = %GeeStage::SandboxProvisioning.as_str(),
                    "[SANDBOX] container frozen"
                );
                let options = loaded.module.options_json();
                let mut result = match sandbox
                    .exec_module(&loaded.info.name, target, &options)
                    .await
                {
                    Ok(r) => r,
                    Err(e) => ModuleResult {
                        error: Some(format!("sandbox module exec failed: {e}")),
                        ..Default::default()
                    },
                };
                let logs = sandbox.capture_logs().await;
                result.evidence.extend(logs);
                result.evidence.push(format!(
                    "[SANDBOX] Container melted: {}",
                    sandbox.container_id()
                ));
                if let Err(e) = sandbox.melt().await {
                    result
                        .evidence
                        .push(format!("[SANDBOX] Teardown warning: {e}"));
                }
                if result.error.is_some() {
                    self.record_failure(
                        &module_name,
                        target,
                        result.error.as_deref().unwrap_or("sandbox failure"),
                        context,
                    );
                }
                Ok(result)
            }
            Err(e) => {
                let reason = format!("Sandbox initialization failed: {e}. Isolation is mandatory.");
                self.record_failure(&module_name, target, &reason, context);
                Err(ExecutorError::Sandbox(reason))
            }
        }
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
