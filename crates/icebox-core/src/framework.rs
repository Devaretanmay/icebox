use std::sync::Arc;
use tokio::sync::Mutex;

use crate::executor::ModuleExecutor;
use crate::governance::{ApprovalQueue, PolicyPackStore, Role};
use crate::job::JobManager;
use crate::session::SessionManager;

/// Single source of truth for executor, sessions, jobs, and governance state.
#[derive(Debug)]
pub struct Framework {
    pub executor: ModuleExecutor,
    pub sessions: SessionManager,
    pub jobs: JobManager,
    pub operator_role: Role,
    pub policy_packs: PolicyPackStore,
    pub approval_queue: ApprovalQueue,
}

impl Framework {
    pub fn new(executor: ModuleExecutor) -> Self {
        Framework {
            executor,
            sessions: SessionManager::new(),
            jobs: JobManager::new(),
            operator_role: Role::Admin,
            policy_packs: PolicyPackStore::new(),
            approval_queue: ApprovalQueue::default(),
        }
    }
}

pub type SharedFramework = Arc<Mutex<Framework>>;

pub fn new_shared_framework(executor: ModuleExecutor) -> SharedFramework {
    Arc::new(Mutex::new(Framework::new(executor)))
}
