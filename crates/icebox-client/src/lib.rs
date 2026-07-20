use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernAction {
    pub action: String,
    pub target: String,
    pub capability: String,
    pub impact: String,
    pub destructive: bool,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernResult {
    pub approved: bool,
    pub decision: String,
    pub reason: Option<String>,
    pub decision_id: u64,
    pub chain_tip: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionOutcome {
    pub success: bool,
    pub evidence: Vec<String>,
    pub data: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordResult {
    pub decision_id: u64,
    pub chain_tip: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("governance denied: {0}")]
    Denied(String),
    #[error("response parse error: {0}")]
    Parse(String),
}

/// ICEBOX Governance SDK client. Wraps any action in a single governance
/// check.
pub struct GovernClient {
    client: reqwest::Client,
    base_url: String,
}

impl GovernClient {
    pub fn new(base_url: &str) -> Result<Self, ClientError> {
        let client = reqwest::Client::builder().build()?;
        Ok(GovernClient {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
        })
    }

    pub async fn govern(&self, action: GovernAction) -> Result<GovernResult, ClientError> {
        let resp = self
            .client
            .post(format!("{}/api/v1/govern", self.base_url))
            .json(&action)
            .send()
            .await?;
        let result: GovernResult = resp.json().await?;
        Ok(result)
    }

    pub async fn record(
        &self,
        action: GovernAction,
        outcome: ActionOutcome,
    ) -> Result<RecordResult, ClientError> {
        let resp = self
            .client
            .post(format!("{}/api/v1/govern/record", self.base_url))
            .json(&(action, outcome))
            .send()
            .await?;
        let result: RecordResult = resp.json().await?;
        Ok(result)
    }
}
