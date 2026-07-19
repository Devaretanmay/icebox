use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::core::executor::ModuleExecutor;
use crate::core::governance::{ApprovalQueue, PolicyPackStore, Role};
use crate::core::job::JobManager;
use crate::core::session::SessionManager;
use crate::core::workspace::GovernanceState;

pub struct Framework {
    pub executor: ModuleExecutor,
    pub sessions: SessionManager,
    pub jobs: JobManager,
    pub operator_role: Role,
    pub policy_packs: PolicyPackStore,
    pub approval_queue: ApprovalQueue,
    /// When set, charter/scope/policy are auto-persisted here on every change.
    pub state_path: Option<PathBuf>,
    #[allow(clippy::type_complexity)]
    pub proxies: std::collections::HashMap<
        u16,
        (
            String,
            Box<dyn crate::core::proxy::NetworkIsolator>,
            tokio::task::JoinHandle<()>,
        ),
    >,
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
            state_path: None,
            proxies: std::collections::HashMap::new(),
        }
    }

    /// Best-effort atomic persistence of governance state. Errors are logged,
    /// never fail the caller — durability must not block governance decisions.
    pub fn persist_state(&self) {
        if let Some(path) = &self.state_path {
            let state = GovernanceState::from_framework(self);
            if let Err(e) = state.save_to_file(&path.to_string_lossy()) {
                eprintln!("warn: failed to persist governance state: {e}");
            }
        }
    }
}

pub type SharedFramework = Arc<Mutex<Framework>>;

pub fn new_shared_framework(executor: ModuleExecutor) -> SharedFramework {
    Arc::new(Mutex::new(Framework::new(executor)))
}
