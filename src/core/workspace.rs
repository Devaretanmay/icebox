use serde::{Deserialize, Serialize};

use crate::core::framework::Framework;
use crate::core::governance::PolicyPackStore;
use crate::core::job::{Job, JobId, JobManager, JobStatus};
use crate::core::module::ModuleResult;
use crate::core::safety::{Charter, MemoryEntry, PolicySet, RiskLevel, ScopeManager};
use crate::core::session::{Session, SessionId, SessionKind, SessionManager};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceSnapshot {
    pub charter: Charter,
    pub scope_allow: Vec<String>,
    pub max_risk: RiskLevel,
    pub policy_rules: PolicySet,
    pub policy_packs: PolicyPackStore,
    pub memories: Vec<MemoryEntry>,
    pub jobs: Vec<JobSnapshot>,
    pub sessions: Vec<SessionSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobSnapshot {
    pub id: u64,
    pub module_name: String,
    pub target: String,
    pub status: JobStatus,
    pub elapsed_secs: u64,
    pub result: Option<ModuleResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSnapshot {
    pub id: u64,
    pub kind: SessionKind,
    pub target: String,
    pub module_name: String,
    pub elapsed_secs: u64,
    pub closed: bool,
}

impl WorkspaceSnapshot {
    pub fn from_framework(fw: &Framework) -> Self {
        let jobs: Vec<JobSnapshot> = fw
            .jobs
            .list_recent(usize::MAX)
            .iter()
            .map(|j| JobSnapshot {
                id: j.id.as_u64(),
                module_name: j.module_name.clone(),
                target: j.target.clone(),
                status: j.status,
                elapsed_secs: j.elapsed().as_secs(),
                result: j.result.clone(),
            })
            .collect();
        let sessions: Vec<SessionSnapshot> = fw
            .sessions
            .list_all()
            .iter()
            .map(|s| SessionSnapshot {
                id: s.id.as_u64(),
                kind: s.kind,
                target: s.target.clone(),
                module_name: s.module_name.clone(),
                elapsed_secs: s.elapsed().as_secs(),
                closed: s.closed,
            })
            .collect();
        WorkspaceSnapshot {
            charter: fw.executor.charter.clone(),
            scope_allow: fw.executor.scope.allow.clone(),
            max_risk: fw.executor.max_risk,
            policy_rules: fw.executor.policy_set.clone(),
            policy_packs: fw.policy_packs.clone(),
            memories: fw.executor.memories.clone(),
            jobs,
            sessions,
        }
    }

    pub fn save_to_file(&self, path: &str) -> Result<(), crate::core::WorkspaceError> {
        let json = serde_json::to_string_pretty(self).map_err(crate::core::WorkspaceError::Json)?;
        std::fs::write(path, &json).map_err(crate::core::WorkspaceError::Io)?;
        Ok(())
    }

    pub fn load_from_file(path: &str) -> Result<Self, crate::core::WorkspaceError> {
        let json = std::fs::read_to_string(path).map_err(crate::core::WorkspaceError::Io)?;
        let snap: WorkspaceSnapshot =
            serde_json::from_str(&json).map_err(crate::core::WorkspaceError::Json)?;
        Ok(snap)
    }

    pub fn apply_to_framework(&self, fw: &mut Framework) {
        fw.executor.charter = self.charter.clone();
        fw.executor.scope = ScopeManager::new(self.scope_allow.clone());
        fw.executor.max_risk = self.max_risk;
        fw.executor.policy_set = self.policy_rules.clone();
        fw.policy_packs = self.policy_packs.clone();
        fw.executor.memories = self.memories.clone();
        let max_job_id = self.jobs.iter().map(|j| j.id).max().unwrap_or(0);
        for js in &self.jobs {
            let mut j = Job::new(&js.module_name, &js.target);
            j.id = JobId(js.id);
            j.status = js.status;
            j.result = js.result.clone();
            fw.jobs.register(j);
        }
        JobManager::advance_counter(max_job_id);
        let max_sesh_id = self.sessions.iter().map(|s| s.id).max().unwrap_or(0);
        for ss in &self.sessions {
            let mut s = Session::new(ss.kind, &ss.target, &ss.module_name);
            s.id = SessionId(ss.id);
            s.closed = ss.closed;
            fw.sessions.register(s);
        }
        SessionManager::advance_counter(max_sesh_id);
    }
}

impl Default for WorkspaceSnapshot {
    fn default() -> Self {
        WorkspaceSnapshot {
            charter: Charter::default(),
            scope_allow: Vec::new(),
            max_risk: RiskLevel::Critical,
            policy_rules: PolicySet::default(),
            policy_packs: PolicyPackStore::new(),
            memories: Vec::new(),
            jobs: Vec::new(),
            sessions: Vec::new(),
        }
    }
}
