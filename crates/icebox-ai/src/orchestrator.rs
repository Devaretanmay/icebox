//! Multi-agent orchestration: one Agent per target, shared audit trail.

use serde::{Deserialize, Serialize};
use tokio::task::JoinSet;

use icebox_core::framework::SharedFramework;
use icebox_core::safety::RiskLevel;

use crate::agent::{Agent, AlwaysApprove, AnalysisOutput, CampaignResult, DenyPlan, Planner, ReportOutput, Action};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignReport {
    pub targets: Vec<String>,
    pub summaries: Vec<String>,
    pub ok: usize,
    pub failed: usize,
    pub total_jobs: usize,
    pub total_sessions: usize,
    pub total_decisions: usize,
    pub total_evidence: usize,
    pub total_traces: usize,
}

pub struct Orchestrator {
    fw: SharedFramework,
    max_risk: RiskLevel,
    approved: bool,
}

impl Orchestrator {
    pub fn new(fw: SharedFramework, max_risk: RiskLevel) -> Self {
        Orchestrator { fw, max_risk, approved: false }
    }

    pub fn set_approved(&mut self, v: bool) {
        self.approved = v;
    }

    /// Run one Agent per target concurrently. `planner_factory` builds a fresh planner per agent.
    pub async fn run<F>(&self, targets: &[String], planner_factory: F) -> CampaignReport
    where
        F: Fn() -> Box<dyn Planner> + Send + Sync,
    {
        let mut set: JoinSet<anyhow::Result<CampaignResult>> = JoinSet::new();
        for t in targets {
            let planner = planner_factory();
            let mut agent = Agent::new(planner, self.fw.clone(), t.clone(), self.max_risk);
            agent.set_approved(self.approved);
            if self.approved {
                agent.set_plan_approver(Box::new(AlwaysApprove));
            } else {
                agent.set_plan_approver(Box::new(DenyPlan));
            }
            set.spawn(async move { agent.run().await });
        }

        let mut summaries: Vec<String> = Vec::new();
        let (mut ok, mut failed) = (0usize, 0usize);
        while let Some(res) = set.join_next().await {
            match res {
                Ok(Ok(cr)) => {
                    ok += 1;
                    summaries.push(cr.summary);
                }
                Ok(Err(e)) => {
                    failed += 1;
                    summaries.push(format!("error: {e}"));
                }
                Err(e) => {
                    failed += 1;
                    summaries.push(format!("join error: {e}"));
                }
            }
        }

        let fw = self.fw.lock().await;
        CampaignReport {
            targets: targets.to_vec(),
            summaries,
            ok,
            failed,
            total_jobs: fw.jobs.list_recent(usize::MAX).len(),
            total_sessions: fw.sessions.list().len(),
            total_decisions: fw.executor.recent_decisions(usize::MAX).len(),
            total_evidence: fw.executor.recent_evidence(usize::MAX).len(),
            total_traces: fw.executor.recent_traces(usize::MAX).len(),
        }
    }
}

/// Deterministic planner for tests and scripted runs.
pub struct StaticPlanner {
    pub actions: Vec<Action>,
}

impl StaticPlanner {
    pub fn new() -> Self {
        let mut options = std::collections::HashMap::new();
        options.insert("host".to_string(), String::new());
        options.insert("ports".to_string(), "1-1024".to_string());
        StaticPlanner {
            actions: vec![Action {
                module: "tcp_port_scanner".to_string(),
                options,
                target: String::new(),
                priority: 50,
                reason: "scripted recon".to_string(),
            }],
        }
    }
}

impl Default for StaticPlanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Planner for StaticPlanner {
    async fn analyze(&self, _ctx: &str) -> anyhow::Result<AnalysisOutput> {
        Ok(AnalysisOutput {
            summary: "scripted analysis".to_string(),
            vulnerabilities: vec![],
            recommended_modules: vec!["tcp_port_scanner".to_string()],
        })
    }
    async fn plan(&self, _ctx: &str) -> anyhow::Result<Vec<Action>> {
        Ok(self.actions.clone())
    }
    async fn summarize(&self, _ctx: &str) -> anyhow::Result<ReportOutput> {
        Ok(ReportOutput {
            title: "scripted".to_string(),
            summary: "scripted campaign".to_string(),
            findings: vec![],
            actions_taken: vec![],
            recommendations: vec![],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use icebox_core::executor::ModuleExecutor;
    use icebox_core::framework::new_shared_framework;
    use icebox_core::safety::{Charter, PolicyContext, PolicyDecision, ScopeManager};
    use icebox_modules;

    #[tokio::test]
    async fn fans_out_and_aggregates() {
        let exec = ModuleExecutor::new(
            Charter::accept("eval", vec!["auth".into()]),
            ScopeManager::new(vec!["127.0.0.1".into()]),
            RiskLevel::Critical,
        );
        let fw = new_shared_framework(exec);
        let mut orch = Orchestrator::new(fw, RiskLevel::Critical);
        orch.set_approved(true);

        let targets = vec!["127.0.0.1".to_string(), "127.0.0.1".to_string()];
        let report = orch.run(&targets, || Box::new(StaticPlanner::new())).await;

        assert_eq!(report.targets.len(), 2);
        assert_eq!(report.ok, 2);
        assert!(report.total_jobs > 0, "scan jobs should be recorded");
        assert!(report.total_traces > 0, "agent traces should be recorded");
    }

    #[tokio::test]
    async fn direct_seam_records_audit_and_allows_low_risk() {
        let exec = ModuleExecutor::new(
            Charter::accept("eval", vec!["auth".into()]),
            ScopeManager::new(vec!["127.0.0.1".into()]),
            RiskLevel::Critical,
        );
        let fw = new_shared_framework(exec);
        let mut loaded = icebox_modules::load("tcp_port_scanner").expect("module");
        let _ = loaded.module.set_option("host", "127.0.0.1");
        let _ = loaded.module.set_option("ports", "22");
        let res = fw
            .lock()
            .await
            .executor
            .execute(&loaded, "127.0.0.1", None, true, PolicyContext::Cli, None)
            .await;
        assert!(res.is_ok(), "in-scope, approved, low-risk run must pass the seam");
        let decs = fw.lock().await.executor.recent_decisions(10);
        assert_eq!(decs.len(), 1, "every execute must be audited");
        assert!(matches!(decs[0].decision, PolicyDecision::Allow));
    }

    #[tokio::test]
    async fn destructive_requires_approval_and_is_recorded() {
        let exec = ModuleExecutor::new(
            Charter::accept("eval", vec!["auth".into()]),
            ScopeManager::new(vec!["127.0.0.1".into()]),
            RiskLevel::Critical,
        );
        let fw = new_shared_framework(exec);
        let loaded = icebox_modules::load("reverse_shell_payload").expect("module");
        let res = fw
            .lock()
            .await
            .executor
            .execute(&loaded, "127.0.0.1", None, false, PolicyContext::Cli, None)
            .await;
        assert!(res.is_err(), "destructive module without approval must be denied");
        let decs = fw.lock().await.executor.recent_decisions(10);
        assert!(
            decs.iter().any(|d| matches!(d.decision, PolicyDecision::RequireApproval(_))),
            "the gate verdict must be recorded in the audit trail"
        );
    }

    #[tokio::test]
    async fn multi_agent_funnels_through_seam() {
        let exec = ModuleExecutor::new(
            Charter::accept("eval", vec!["auth".into()]),
            ScopeManager::new(vec!["127.0.0.1".into()]),
            RiskLevel::Critical,
        );
        let fw = new_shared_framework(exec);
        let mut orch = Orchestrator::new(fw.clone(), RiskLevel::Critical);
        orch.set_approved(true);
        let _ = orch
            .run(&["127.0.0.1".to_string()], || Box::new(StaticPlanner::new()))
            .await;
        let decs = fw.lock().await.executor.recent_decisions(50);
        assert!(
            !decs.is_empty(),
            "orchestrated agents must record every decision through the seam"
        );
    }
}
