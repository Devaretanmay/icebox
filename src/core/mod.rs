pub mod module;
pub use module::*;

pub mod safety;
pub use safety::*;

pub mod executor;
pub use executor::*;

pub mod session;
pub use session::*;

pub mod job;
pub use job::*;

pub mod framework;
pub use framework::*;

pub mod governance;
pub use governance::*;

pub mod sdk;
pub use sdk::*;

pub mod workspace;

pub mod sandbox;

pub mod proxy;

#[derive(Debug, thiserror::Error)]
pub enum WorkspaceError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}
