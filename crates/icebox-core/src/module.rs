use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::safety::RiskLevel;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ModuleKind {
    Exploit,
    Payload,
    Listener,
    Post,
    Auxiliary,
    Scanner,
    Backdoor,
    Encoder,
    Transform,
    Analysis,
}

impl ModuleKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ModuleKind::Exploit => "exploit",
            ModuleKind::Payload => "payload",
            ModuleKind::Listener => "listener",
            ModuleKind::Post => "post",
            ModuleKind::Auxiliary => "auxiliary",
            ModuleKind::Scanner => "scanner",
            ModuleKind::Backdoor => "backdoor",
            ModuleKind::Encoder => "encoder",
            ModuleKind::Transform => "transform",
            ModuleKind::Analysis => "analysis",
        }
    }
}

/// Policy reasons over these instead of raw module kind so risk follows
/// behavior, not label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    NetworkScan,
    CredentialAccess,
    PrivilegeEscalation,
    Persistence,
    LateralMovement,
    DataCollection,
    FilesystemModification,
    CloudEnumeration,
}

impl Capability {
    pub fn as_str(&self) -> &'static str {
        match self {
            Capability::NetworkScan => "network_scan",
            Capability::CredentialAccess => "credential_access",
            Capability::PrivilegeEscalation => "privilege_escalation",
            Capability::Persistence => "persistence",
            Capability::LateralMovement => "lateral_movement",
            Capability::DataCollection => "data_collection",
            Capability::FilesystemModification => "filesystem_modification",
            Capability::CloudEnumeration => "cloud_enumeration",
        }
    }

    /// Maps capability to an access category (Read / Modify / Execute / Dump)
    /// for the explainability report.
    pub fn intent(&self) -> Intent {
        match self {
            Capability::CredentialAccess => Intent::Dump,
            Capability::FilesystemModification | Capability::Persistence => Intent::Modify,
            Capability::LateralMovement | Capability::PrivilegeEscalation => Intent::Execute,
            _ => Intent::Read,
        }
    }

    /// Default blast radius implied by the capability.
    pub fn impact(&self) -> RiskLevel {
        match self {
            Capability::NetworkScan | Capability::DataCollection | Capability::CloudEnumeration => {
                RiskLevel::Low
            }
            Capability::FilesystemModification => RiskLevel::Medium,
            Capability::PrivilegeEscalation
            | Capability::Persistence
            | Capability::LateralMovement => RiskLevel::High,
            Capability::CredentialAccess => RiskLevel::Critical,
        }
    }

    /// Fallback capabilities inferred from module kind when none are declared.
    pub fn from_kind(kind: ModuleKind) -> Vec<Capability> {
        match kind {
            ModuleKind::Scanner | ModuleKind::Auxiliary | ModuleKind::Analysis => {
                vec![Capability::NetworkScan]
            }
            ModuleKind::Exploit => vec![Capability::PrivilegeEscalation, Capability::CredentialAccess],
            ModuleKind::Post => vec![Capability::PrivilegeEscalation, Capability::DataCollection],
            ModuleKind::Payload => vec![Capability::Persistence, Capability::LateralMovement],
            ModuleKind::Listener => vec![Capability::Persistence],
            ModuleKind::Backdoor => vec![Capability::Persistence, Capability::LateralMovement],
            ModuleKind::Encoder | ModuleKind::Transform => vec![Capability::DataCollection],
        }
    }
}

impl std::str::FromStr for Capability {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_ascii_lowercase().as_str() {
            "networkscan" | "network_scan" => Capability::NetworkScan,
            "credentialaccess" | "credential_access" => Capability::CredentialAccess,
            "privilegeescalation" | "privilege_escalation" => Capability::PrivilegeEscalation,
            "persistence" => Capability::Persistence,
            "lateralmovement" | "lateral_movement" => Capability::LateralMovement,
            "datacollection" | "data_collection" => Capability::DataCollection,
            "filesystemmodification" | "filesystem_modification" => Capability::FilesystemModification,
            "cloudenumeration" | "cloud_enumeration" => Capability::CloudEnumeration,
            other => return Err(format!("unknown capability: {other}")),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Intent {
    Read,
    Modify,
    Execute,
    Dump,
}

impl Intent {
    pub fn as_str(&self) -> &'static str {
        match self {
            Intent::Read => "read",
            Intent::Modify => "modify",
            Intent::Execute => "execute",
            Intent::Dump => "dump",
        }
    }
}

impl std::str::FromStr for Intent {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_ascii_lowercase().as_str() {
            "read" => Intent::Read,
            "modify" => Intent::Modify,
            "execute" => Intent::Execute,
            "dump" => Intent::Dump,
            other => return Err(format!("unknown intent: {other}")),
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ModuleInfo {
    pub name: String,
    pub description: String,
    pub author: String,
    pub kind: ModuleKind,
    pub capabilities: Vec<Capability>,
    pub impact: Option<RiskLevel>,
    pub intent: Option<Intent>,
}

impl ModuleInfo {
    /// Declared impact if set, otherwise the max of kind and capability-derived risk.
    pub fn effective_impact(&self) -> RiskLevel {
        if let Some(i) = self.impact {
            return i;
        }
        let base = RiskLevel::from_kind(self.kind);
        self.capabilities
            .iter()
            .map(|c| c.impact())
            .max()
            .unwrap_or(base)
            .max(base)
    }

    /// Single declared intent if set, otherwise one intent per capability.
    pub fn effective_intents(&self) -> Vec<Intent> {
        if let Some(i) = self.intent {
            return vec![i];
        }
        self.capabilities.iter().map(|c| c.intent()).collect()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModuleResult {
    pub success: bool,
    pub finding: Option<String>,
    pub evidence: Vec<String>,
    pub error: Option<String>,
    pub session_id: Option<String>,
    pub data: serde_json::Value,
}

#[derive(Debug, thiserror::Error)]
pub enum ModuleError {
    #[error("missing required option: {0}")]
    MissingOption(String),
    #[error("option parse error: {0}")]
    Parse(String),
    #[error("{0}")]
    Other(String),
}

#[async_trait]
pub trait Module: Send + Sync {
    fn options_json(&self) -> serde_json::Value {
        serde_json::Value::Null
    }

    async fn run(&self) -> Result<ModuleResult, ModuleError>;

    fn set_option(&mut self, _name: &str, _value: &str) -> Result<(), ModuleError> {
        Err(ModuleError::Other("module does not accept options".into()))
    }

    fn validate(&self) -> Result<(), ModuleError> {
        Ok(())
    }
}

/// Plain `fn` pointers so entries are const-initializable and collectable by `linkme`.
#[derive(Clone, Copy)]
pub struct ModuleEntry {
    pub info: fn() -> ModuleInfo,
    pub make: fn() -> Box<dyn Module>,
}

pub struct LoadedModule {
    pub info: ModuleInfo,
    pub module: Box<dyn Module>,
}
