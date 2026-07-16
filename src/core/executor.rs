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
        let pf = self.preflight(loaded, target, destructive_override, approved, context);
        let policy = self.policy(context);
        let decision = if sandbox {
            crate::core::safety::PolicyDecision::Allow
        } else {
            policy.evaluate(&pf.to_request())
        };
        self.record_decision(&loaded.info.name, &pf, &decision);
        if !sandbox {
            pf.check(&policy)?;
        }
        info!(
            target = %target,
            module = %loaded.info.name,
            risk = %pf.risk.as_str(),
            destructive = pf.destructive,
            sandbox = sandbox,
            "executor: preflight passed"
        );
        let result = if sandbox {
            self.run_sandboxed(
                loaded,
                target,
                engine.unwrap_or(crate::core::sandbox::SandboxEngineType::Docker),
            )
            .await
        } else {
            loaded.module.run().await?
        };
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
    async fn run_sandboxed(
        &self,
        loaded: &crate::core::module::LoadedModule,
        target: &str,
        engine: crate::core::sandbox::SandboxEngineType,
    ) -> ModuleResult {
        use crate::core::sandbox::Sandbox;
        let mut image = loaded
            .info
            .sandbox_image
            .as_deref()
            .unwrap_or("alpine:3.20")
            .to_string();

        if target.starts_with("target:") {
            let parts: Vec<&str> = target.split(':').collect();
            if parts.len() == 3 {
                image = format!("{}:{}", parts[1], parts[2]);
            }
        }

        match Sandbox::freeze(engine, target, &image).await {
            Ok(sandbox) => {
                info!(
                    container = %sandbox.container_id(),
                    "[SANDBOX] Docker container frozen"
                );

                let mut result = match sandbox.ip_address().await {
                    Ok(ip) => {
                        let mut new_mod =
                            crate::modules::load(&loaded.info.name).expect("module load failed");
                        let mut target_port = 80;
                        if let Some(opts) = loaded.module.options_json().as_object() {
                            for (k, v) in opts {
                                if let Some(s) = v.as_str() {
                                    new_mod.module.set_option(k, s).ok();
                                } else if let Some(n) = v.as_u64() {
                                    new_mod.module.set_option(k, &n.to_string()).ok();
                                } else if let Some(b) = v.as_bool() {
                                    new_mod.module.set_option(k, &b.to_string()).ok();
                                }
                            }
                            if let Some(p) = opts.get("port") {
                                target_port = p.as_str().unwrap_or("80").parse().unwrap_or(80);
                            }
                        }

                        let proxy = crate::core::proxy::ProxyListener::spawn(&ip, target_port)
                            .await
                            .expect("failed to spawn proxy");

                        new_mod
                            .module
                            .set_option("host", &proxy.local_addr.ip().to_string())
                            .ok();
                        new_mod
                            .module
                            .set_option("port", &proxy.local_addr.port().to_string())
                            .ok();
                        new_mod.module.run().await.unwrap_or_else(|e| ModuleResult {
                            error: Some(e.to_string()),
                            ..Default::default()
                        })
                    }
                    Err(e) => ModuleResult {
                        error: Some(format!("Failed to get sandbox IP: {e}")),
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
                result
            }
            Err(e) => ModuleResult {
                error: Some(format!(
                    "Sandbox initialization failed: {e}. Isolation is mandatory."
                )),
                ..Default::default()
            },
        }
    }
}
