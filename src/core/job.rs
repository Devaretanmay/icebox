use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::core::module::ModuleResult;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct JobId(pub u64);

impl JobId {
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for JobId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

static NEXT_JOB_ID: AtomicU64 = AtomicU64::new(1);

fn next_job_id() -> JobId {
    JobId(NEXT_JOB_ID.fetch_add(1, Ordering::Relaxed))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JobStatus {
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl JobStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            JobStatus::Running => "running",
            JobStatus::Completed => "completed",
            JobStatus::Failed => "failed",
            JobStatus::Cancelled => "cancelled",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Job {
    pub id: JobId,
    pub module_name: String,
    pub target: String,
    pub status: JobStatus,
    pub started_at: Instant,
    pub finished_at: Option<Instant>,
    pub result: Option<ModuleResult>,
}

impl Job {
    pub fn new(module_name: impl Into<String>, target: impl Into<String>) -> Self {
        Job {
            id: next_job_id(),
            module_name: module_name.into(),
            target: target.into(),
            status: JobStatus::Running,
            started_at: Instant::now(),
            finished_at: None,
            result: None,
        }
    }

    pub fn elapsed(&self) -> Duration {
        let end = self.finished_at.unwrap_or(Instant::now());
        end.duration_since(self.started_at)
    }
}

#[derive(Debug, Default)]
pub struct JobManager {
    jobs: HashMap<JobId, Job>,
}

impl JobManager {
    pub fn new() -> Self {
        JobManager {
            jobs: HashMap::new(),
        }
    }

    pub fn register(&mut self, job: Job) -> JobId {
        let id = job.id;
        self.jobs.insert(id, job);
        id
    }

    pub fn get(&self, id: JobId) -> Option<&Job> {
        self.jobs.get(&id)
    }

    pub fn get_mut(&mut self, id: JobId) -> Option<&mut Job> {
        self.jobs.get_mut(&id)
    }

    pub fn list(&self) -> Vec<&Job> {
        let mut v: Vec<&Job> = self
            .jobs
            .values()
            .filter(|j| matches!(j.status, JobStatus::Running))
            .collect();
        v.sort_by_key(|j| j.id);
        v
    }

    pub fn list_recent(&self, n: usize) -> Vec<&Job> {
        let mut v: Vec<&Job> = self.jobs.values().collect();
        v.sort_by_key(|j| j.id);
        v.into_iter().rev().take(n).collect()
    }

    pub fn complete(&mut self, id: JobId, result: ModuleResult) -> bool {
        if let Some(job) = self.jobs.get_mut(&id) {
            job.status = if result.success {
                JobStatus::Completed
            } else {
                JobStatus::Failed
            };
            job.finished_at = Some(Instant::now());
            job.result = Some(result);
            true
        } else {
            false
        }
    }

    /// CAS loop to avoid ID collisions after restoring from a workspace snapshot.
    pub fn advance_counter(min: u64) {
        let mut prev = NEXT_JOB_ID.load(Ordering::Relaxed);
        while prev <= min {
            match NEXT_JOB_ID.compare_exchange(prev, min + 1, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => break,
                Err(current) => prev = current,
            }
        }
    }

    pub fn cancel(&mut self, id: JobId) -> bool {
        if let Some(job) = self.jobs.get_mut(&id) {
            job.status = JobStatus::Cancelled;
            job.finished_at = Some(Instant::now());
            true
        } else {
            false
        }
    }
}
