use serde::{Deserialize, Serialize};

/// The 10-stage mandatory GEE lifecycle. Only moves forward.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeeStage {
    Request,
    PolicyEvaluation,
    ScopeEnforcement,
    SandboxProvisioning,
    ApprovalCheck,
    Execute,
    CollectEvidence,
    Audit,
    Validate,
    Destroy,
}

impl GeeStage {
    pub fn as_str(&self) -> &'static str {
        match self {
            GeeStage::Request => "request",
            GeeStage::PolicyEvaluation => "policy_evaluation",
            GeeStage::ScopeEnforcement => "scope_enforcement",
            GeeStage::SandboxProvisioning => "sandbox_provisioning",
            GeeStage::ApprovalCheck => "approval_check",
            GeeStage::Execute => "execute",
            GeeStage::CollectEvidence => "collect_evidence",
            GeeStage::Audit => "audit",
            GeeStage::Validate => "validate",
            GeeStage::Destroy => "destroy",
        }
    }

    pub fn lifecycle() -> &'static [GeeStage] {
        &[
            GeeStage::Request,
            GeeStage::PolicyEvaluation,
            GeeStage::ScopeEnforcement,
            GeeStage::SandboxProvisioning,
            GeeStage::ApprovalCheck,
            GeeStage::Execute,
            GeeStage::CollectEvidence,
            GeeStage::Audit,
            GeeStage::Validate,
            GeeStage::Destroy,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_proceeds_only_forward() {
        let order = GeeStage::lifecycle();
        assert_eq!(order.len(), 10);
        for w in order.windows(2) {
            assert!(w[0] < w[1], "stage {w:?} must be ordered");
        }
    }

    #[test]
    fn stage_names_are_stable_api() {
        assert_eq!(GeeStage::PolicyEvaluation.as_str(), "policy_evaluation");
        assert_eq!(
            GeeStage::SandboxProvisioning.as_str(),
            "sandbox_provisioning"
        );
        assert_eq!(GeeStage::Destroy.as_str(), "destroy");
    }
}
