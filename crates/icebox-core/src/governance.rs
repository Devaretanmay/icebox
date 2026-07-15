use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::module::{Capability, Intent};
use crate::safety::{DecisionRecord, PolicyDecision, PolicyRule};

/// Ordered so a required level can be compared with `>=`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Viewer,
    Operator,
    Admin,
}

impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Viewer => "viewer",
            Role::Operator => "operator",
            Role::Admin => "admin",
        }
    }
}

impl std::str::FromStr for Role {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "viewer" => Ok(Role::Viewer),
            "operator" => Ok(Role::Operator),
            "admin" => Ok(Role::Admin),
            other => Err(format!("unknown role: {other}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyPack {
    pub name: String,
    pub version: u64,
    pub rules: Vec<PolicyRule>,
}

impl PolicyPack {
    pub fn new(name: impl Into<String>, rules: Vec<PolicyRule>) -> Self {
        PolicyPack { name: name.into(), version: 1, rules }
    }

    /// Bumps version on every mutation so clients can detect policy drift.
    pub fn set_rules(&mut self, rules: Vec<PolicyRule>) {
        self.rules = rules;
        self.version += 1;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Denied,
}

impl ApprovalStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ApprovalStatus::Pending => "pending",
            ApprovalStatus::Approved => "approved",
            ApprovalStatus::Denied => "denied",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub id: u64,
    pub module: String,
    pub target: String,
    pub reason: String,
    /// Options to replay when the request is approved, reproducing the exact
    /// prior invocation rather than running with defaults.
    #[serde(default)]
    pub options: HashMap<String, String>,
    pub status: ApprovalStatus,
}

#[derive(Debug, Default)]
pub struct ApprovalQueue {
    items: Vec<ApprovalRequest>,
    next_id: u64,
}

impl ApprovalQueue {
    pub fn request(
        &mut self,
        module: String,
        target: String,
        reason: String,
        options: HashMap<String, String>,
    ) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.items.push(ApprovalRequest {
            id,
            module,
            target,
            reason,
            options,
            status: ApprovalStatus::Pending,
        });
        id
    }

    pub fn list(&self) -> Vec<ApprovalRequest> {
        self.items.clone()
    }

    pub fn get(&self, id: u64) -> Option<&ApprovalRequest> {
        self.items.iter().find(|i| i.id == id)
    }

    pub fn approve(&mut self, id: u64) -> bool {
        match self.items.iter_mut().find(|i| i.id == id) {
            Some(i) if i.status == ApprovalStatus::Pending => {
                i.status = ApprovalStatus::Approved;
                true
            }
            _ => false,
        }
    }

    pub fn deny(&mut self, id: u64) -> bool {
        match self.items.iter_mut().find(|i| i.id == id) {
            Some(i) if i.status == ApprovalStatus::Pending => {
                i.status = ApprovalStatus::Denied;
                true
            }
            _ => false,
        }
    }
}

fn csv_field(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// Render audit records as CSV for compliance export.
pub fn audit_to_csv(records: &[DecisionRecord]) -> String {
    let mut out = String::from("at,target,module,capabilities,intents,impact,context,decision,reason\n");
    for r in records {
        let (decision, reason) = match &r.decision {
            PolicyDecision::Allow => ("allow", String::new()),
            PolicyDecision::RequireApproval(s) => ("require_approval", s.clone()),
            PolicyDecision::Deny(s) => ("deny", s.clone()),
        };
        let caps: Vec<&str> = r.capabilities.iter().map(Capability::as_str).collect();
        let intents: Vec<&str> = r.intents.iter().map(Intent::as_str).collect();
        out.push_str(&[
            r.at.to_string(),
            csv_field(&r.target),
            csv_field(&r.module),
            csv_field(&caps.join("|")),
            csv_field(&intents.join("|")),
            r.impact.as_str().to_string(),
            format!("{:?}", r.context),
            decision.to_string(),
            csv_field(&reason),
        ]
        .join(","));
        out.push('\n');
    }
    out
}

pub type PolicyPackStore = HashMap<String, PolicyPack>;

pub fn role_allows(current: Role, required: Role) -> bool {
    current >= required
}
