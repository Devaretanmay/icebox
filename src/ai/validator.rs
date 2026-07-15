//! Continuous validation: governed campaign over targets, comparable report.

use crate::core::framework::SharedFramework;
use crate::core::safety::{now_secs, RiskLevel};

use crate::ai::agent::Planner;
use crate::ai::orchestrator::{CampaignReport, Orchestrator};

/// Validation run snapshot with policy version and timestamp for diffing.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ValidationReport {
    pub ran_at: u64,
    pub policy_version: u64,
    pub campaign: CampaignReport,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ValidationDiff {
    pub policy_version_a: u64,
    pub policy_version_b: u64,
    pub jobs_delta: i64,
    pub evidence_delta: i64,
    pub decisions_delta: i64,
    pub traces_delta: i64,
    pub target_count: usize,
}

pub async fn run_validation<F>(
    fw: SharedFramework,
    targets: &[String],
    max_risk: RiskLevel,
    planner_factory: F,
) -> ValidationReport
where
    F: Fn() -> Box<dyn Planner> + Send + Sync,
{
    let mut orch = Orchestrator::new(fw.clone(), max_risk);
    orch.set_approved(true);
    let campaign = orch.run(targets, planner_factory).await;

    let fw = fw.lock().await;
    ValidationReport {
        ran_at: now_secs(),
        policy_version: fw.executor.policy_set.version,
        campaign,
    }
}

pub fn diff(a: &ValidationReport, b: &ValidationReport) -> ValidationDiff {
    ValidationDiff {
        policy_version_a: a.policy_version,
        policy_version_b: b.policy_version,
        jobs_delta: b.campaign.total_jobs as i64 - a.campaign.total_jobs as i64,
        evidence_delta: b.campaign.total_evidence as i64 - a.campaign.total_evidence as i64,
        decisions_delta: b.campaign.total_decisions as i64 - a.campaign.total_decisions as i64,
        traces_delta: b.campaign.total_traces as i64 - a.campaign.total_traces as i64,
        target_count: b.campaign.targets.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::StaticPlanner;
    use crate::core::executor::ModuleExecutor;
    use crate::core::framework::new_shared_framework;
    use crate::core::safety::{Charter, ScopeManager};

    #[tokio::test]
    async fn validation_captures_policy_version_and_totals() {
        let exec = ModuleExecutor::new(
            Charter::accept("eval", vec!["auth".into()]),
            ScopeManager::new(vec!["127.0.0.1".into()]),
            RiskLevel::Critical,
        );
        let fw = new_shared_framework(exec);
        let targets = vec!["127.0.0.1".to_string()];
        let report = run_validation(fw, &targets, RiskLevel::Critical, || {
            Box::new(StaticPlanner::new())
        })
        .await;
        assert_eq!(report.policy_version, 1);
        assert!(report.campaign.total_jobs > 0);
    }

    #[test]
    fn diff_computes_deltas() {
        let base = ValidationReport {
            ran_at: 1,
            policy_version: 1,
            campaign: CampaignReport {
                targets: vec!["10.0.0.1".into()],
                summaries: vec!["ok".into()],
                ok: 1,
                failed: 0,
                total_jobs: 3,
                total_sessions: 1,
                total_decisions: 2,
                total_evidence: 2,
                total_traces: 4,
            },
        };
        let next = ValidationReport {
            ran_at: 2,
            policy_version: 2,
            campaign: CampaignReport {
                targets: vec!["10.0.0.1".into()],
                summaries: vec!["ok".into()],
                ok: 1,
                failed: 0,
                total_jobs: 5,
                total_sessions: 1,
                total_decisions: 3,
                total_evidence: 4,
                total_traces: 6,
            },
        };
        let d = diff(&base, &next);
        assert_eq!(d.policy_version_a, 1);
        assert_eq!(d.policy_version_b, 2);
        assert_eq!(d.jobs_delta, 2);
        assert_eq!(d.evidence_delta, 2);
        assert_eq!(d.traces_delta, 2);
    }
}
