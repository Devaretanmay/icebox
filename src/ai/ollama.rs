use serde::{Deserialize, Serialize};
use std::time::Duration;

pub struct OllamaClient {
    client: reqwest::Client,
    base_url: String,
    model: String,
}

pub struct ChatError {
    pub retryable: bool,
    pub message: String,
}

impl std::fmt::Display for ChatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::fmt::Debug for ChatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ChatError(retryable={}, {})",
            self.retryable, self.message
        )
    }
}

#[derive(Serialize)]
struct ChatRequest {
    model: String,
    messages: Vec<Message>,
    stream: bool,
    format: Option<serde_json::Value>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Message {
    pub role: String,
    pub content: String,
}

#[derive(Deserialize)]
struct ChatResponse {
    message: Message,
    #[allow(dead_code)]
    done: bool,
}

impl OllamaClient {
    pub fn new(model: impl Into<String>) -> Self {
        OllamaClient {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(120))
                .build()
                .expect("reqwest client"),
            base_url: "http://127.0.0.1:11434".into(),
            model: model.into(),
        }
    }

    pub async fn chat(
        &self,
        messages: Vec<Message>,
        format: Option<serde_json::Value>,
    ) -> anyhow::Result<Message> {
        let mut delay = Duration::from_secs(1);
        let max_retries = 3;
        let mut last_err: Option<ChatError> = None;
        for attempt in 0..max_retries {
            match self.chat_once(messages.clone(), format.clone()).await {
                Ok(msg) => return Ok(msg),
                Err(e) => {
                    if !e.retryable || attempt + 1 >= max_retries {
                        return Err(anyhow::anyhow!("{}", e.message));
                    }
                    tracing::warn!(
                        "ollama: attempt {} failed ({}), retrying in {:?}",
                        attempt + 1,
                        e.message,
                        delay
                    );
                    last_err = Some(e);
                    tokio::time::sleep(delay).await;
                    delay = delay.saturating_mul(3);
                }
            }
        }
        Err(anyhow::anyhow!(
            "Ollama: all {} attempts failed: {}",
            max_retries,
            last_err.map(|e| e.message).unwrap_or_default()
        ))
    }

    async fn chat_once(
        &self,
        messages: Vec<Message>,
        format: Option<serde_json::Value>,
    ) -> Result<Message, ChatError> {
        let body = ChatRequest {
            model: self.model.clone(),
            messages,
            stream: false,
            format,
        };
        let url = format!("{}/api/chat", self.base_url);
        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| ChatError {
                retryable: true,
                message: format!("Ollama HTTP error (url={url}): {e}"),
            })?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            let retryable = status.is_server_error();
            return Err(ChatError {
                retryable,
                message: format!("Ollama API error ({status}): {text}"),
            });
        }
        let cr: ChatResponse = resp.json().await.map_err(|e| ChatError {
            retryable: true,
            message: format!("Ollama JSON parse error: {e}"),
        })?;
        Ok(cr.message)
    }

    pub async fn prompt(
        &self,
        system: &str,
        user: &str,
        format: Option<serde_json::Value>,
    ) -> anyhow::Result<String> {
        let msgs = vec![
            Message {
                role: "system".into(),
                content: system.into(),
            },
            Message {
                role: "user".into(),
                content: user.into(),
            },
        ];
        let reply = self.chat(msgs, format).await?;
        Ok(reply.content)
    }
}
