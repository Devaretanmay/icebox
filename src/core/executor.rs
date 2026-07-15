use tracing::info;

use crate::core::module::{LoadedModule, ModuleError, ModuleResult};
use crate::core::safety::{
    is_destructive, make_config_policy, now_secs, Charter, ConfigPolicy, DecisionRecord, Evidence,
    MemoryEntry, MemoryKind, PolicyContext, PolicyEngine, PolicySet, Preflight, PreflightError,
    ReasoningTrace, RiskLevel, ScopeManager,
};

const MAX_DECISIONS: usize = 1000;
const MAX_EVIDENCE: usize = 2000;
const MAX_TRACES: usize = 1000;
const MAX_MEMORIES: usize = 1000;

#[derive(Debug, thiserror::Error)]
pub enum ExecutorError {
    #[error(transparent)]
    Preflight(#[from] PreflightError),
    #[error(transparent)]
    Module(#[from] ModuleError),
}

/// Runs modules after enforcing charter / scope / risk / destructive gates.
#[derive(Debug)]
pub struct ModuleExecutor {
    pub charter: Charter,
    pub scope: ScopeManager,
    pub max_risk: RiskLevel,
    pub policy_set: PolicySet,
    pub decisions: Vec<DecisionRecord>,
    pub evidence: Vec<Evidence>,
    pub traces: Vec<ReasoningTrace>,
    pub memories: Vec<MemoryEntry>,
}

impl ModuleExecutor {
    pub fn new(charter: Charter, scope: ScopeManager, max_risk: RiskLevel) -> Self {
        ModuleExecutor {
            charter,
            scope,
            max_risk,
            policy_set: PolicySet::default(),
            decisions: Vec::new(),
            evidence: Vec::new(),
            traces: Vec::new(),
            memories: Vec::new(),
        }
    }

    pub fn policy(&self, context: PolicyContext) -> ConfigPolicy {
        make_config_policy(self.max_risk, context, &self.policy_set)
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

    /// Record a planner memory for later context (facts, decisions, failures).
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
        let end = self.decisions.len();
        let start = end.saturating_sub(n);
        self.decisions[start..].to_vec()
    }

    pub fn recent_evidence(&self, n: usize) -> Vec<Evidence> {
        let end = self.evidence.len();
        let start = end.saturating_sub(n);
        self.evidence[start..].to_vec()
    }

    /// Pre-computes the preflight report without enforcing, so callers can
    /// inspect *why* a run would be blocked before triggering it.
    pub fn preflight(
        &self,
        loaded: &LoadedModule,
        target: &str,
        destructive_override: Option<bool>,
        approved: bool,
        context: PolicyContext,
    ) -> Preflight {
        let base = RiskLevel::from_kind(loaded.info.kind);
        let cap_impact = loaded
            .info
            .capabilities
            .iter()
            .map(|c| c.impact())
            .max()
            .unwrap_or(base);
        let risk = loaded.info.impact.unwrap_or_else(|| base.max(cap_impact));
        let destructive = destructive_override.unwrap_or_else(|| {
            is_destructive(&loaded.info.name)
                || is_destructive(&loaded.info.description)
                || is_destructive(loaded.info.kind.as_str())
        });
        Preflight {
            target: target.to_string(),
            charter_accepted: self.charter.accepted,
            in_scope: self.scope.is_in_scope(target),
            risk,
            destructive,
            approved,
            capabilities: loaded.info.capabilities.clone(),
            intents: loaded.info.effective_intents(),
            context,
        }
    }

    pub async fn execute(
        &mut self,
        loaded: &LoadedModule,
        target: &str,
        destructive_override: Option<bool>,
        approved: bool,
        context: PolicyContext,
        job_id: Option<u64>,
    ) -> Result<ModuleResult, ExecutorError> {
        let pf = self.preflight(loaded, target, destructive_override, approved, context);
        let policy = self.policy(context);
        let decision = policy.evaluate(&pf.to_request());
        self.record_decision(&loaded.info.name, &pf, &decision);
        pf.check(&policy)?;
        info!(
            target = %target,
            module = %loaded.info.name,
            risk = %pf.risk.as_str(),
            destructive = pf.destructive,
            "executor: preflight passed"
        );
        let result = loaded.module.run().await?;
        self.record_evidence(&loaded.info.name, target, &result, job_id);
        Ok(result)
    }

    fn record_decision(
        &mut self,
        module: &str,
        pf: &Preflight,
        decision: &crate::core::safety::PolicyDecision,
    ) {
        self.decisions.push(DecisionRecord {
            at: now_secs(),
            target: pf.target.clone(),
            module: module.to_string(),
            capabilities: pf.capabilities.clone(),
            intents: pf.intents.clone(),
            impact: pf.risk,
            context: pf.context,
            decision: decision.clone(),
        });
        let overflow = self.decisions.len().saturating_sub(MAX_DECISIONS);
        if overflow > 0 {
            self.decisions.drain(..overflow);
        }
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
}
