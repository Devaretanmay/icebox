//! Agent orchestration, Ollama client, and validation.

pub mod agent;
pub mod ollama;
pub mod orchestrator;
pub mod validator;

pub use orchestrator::{CampaignReport, Orchestrator, StaticPlanner};
pub use validator::{diff, run_validation, ValidationDiff, ValidationReport};
