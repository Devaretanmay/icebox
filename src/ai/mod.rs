pub mod agent;
pub mod ollama;
pub mod openai;
pub mod orchestrator;
pub mod validator;

pub use orchestrator::{CampaignReport, Orchestrator};
pub use validator::{diff, run_validation, ValidationDiff, ValidationReport};
