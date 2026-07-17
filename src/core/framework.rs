use std::sync::Arc;
use tokio::sync::Mutex;

use crate::core::executor::ModuleExecutor;
use crate::core::governance::{ApprovalQueue, PolicyPackStore, Role};
use crate::core::job::JobManager;
use crate::core::session::SessionManager;


pub struct Framework {
    pub executor: ModuleExecutor,
    pub sessions: SessionManager,
    pub jobs: JobManager,
    pub operator_role: Role,
    pub policy_packs: PolicyPackStore,
    pub approval_queue: ApprovalQueue,
    #[allow(clippy::type_complexity)]
    pub proxies: std::collections::HashMap<u16, (String, Box<dyn crate::core::proxy::NetworkIsolator>, tokio::task::JoinHandle<()>)>,
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
            proxies: std::collections::HashMap::new(),
        }
    }
}

pub type SharedFramework = Arc<Mutex<Framework>>;

pub fn new_shared_framework(executor: ModuleExecutor) -> SharedFramework {
    Arc::new(Mutex::new(Framework::new(executor)))
}
