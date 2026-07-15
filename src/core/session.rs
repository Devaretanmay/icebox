use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SessionId(pub u64);

impl SessionId {
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(1);

fn next_session_id() -> SessionId {
    SessionId(NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionKind {
    Shell,
    Unknown,
}

impl SessionKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            SessionKind::Shell => "shell",
            SessionKind::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Session {
    pub id: SessionId,
    pub kind: SessionKind,
    pub target: String,
    pub module_name: String,
    pub opened_at: Instant,
    pub closed: bool,
}

impl Session {
    pub fn new(
        kind: SessionKind,
        target: impl Into<String>,
        module_name: impl Into<String>,
    ) -> Self {
        let now = Instant::now();
        Session {
            id: next_session_id(),
            kind,
            target: target.into(),
            module_name: module_name.into(),
            opened_at: now,
            closed: false,
        }
    }

    pub fn elapsed(&self) -> Duration {
        Instant::now().duration_since(self.opened_at)
    }
}

#[derive(Debug, Default)]
pub struct SessionManager {
    sessions: HashMap<SessionId, Session>,
}

impl SessionManager {
    pub fn new() -> Self {
        SessionManager {
            sessions: HashMap::new(),
        }
    }

    pub fn register(&mut self, session: Session) -> SessionId {
        let id = session.id;
        self.sessions.insert(id, session);
        id
    }

    pub fn get(&self, id: SessionId) -> Option<&Session> {
        self.sessions.get(&id)
    }

    pub fn get_mut(&mut self, id: SessionId) -> Option<&mut Session> {
        self.sessions.get_mut(&id)
    }

    pub fn list(&self) -> Vec<&Session> {
        let mut v: Vec<&Session> = self.sessions.values().filter(|s| !s.closed).collect();
        v.sort_by_key(|s| s.id);
        v
    }

    pub fn list_all(&self) -> Vec<&Session> {
        let mut v: Vec<&Session> = self.sessions.values().collect();
        v.sort_by_key(|s| s.id);
        v
    }

    /// CAS loop to avoid ID collisions after restoring from a workspace snapshot.
    pub fn advance_counter(min: u64) {
        let mut prev = NEXT_SESSION_ID.load(Ordering::Relaxed);
        while prev <= min {
            match NEXT_SESSION_ID.compare_exchange(
                prev,
                min + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(current) => prev = current,
            }
        }
    }

    pub fn close(&mut self, id: SessionId) -> bool {
        if let Some(s) = self.sessions.get_mut(&id) {
            s.closed = true;
            true
        } else {
            false
        }
    }
}
