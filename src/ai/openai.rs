use serde::{Deserialize, Serialize};
use std::time::Duration;

pub struct OpenAiClient {
    client: reqwest::Client,
    model: String,
    api_key: String,
}

#[derive(Serialize)]
struct ChatRequest {
    model: String,
    messages: Vec<crate::ai::ollama::Message>,
    response_format: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct ChatResponse {
    choices: Vec<Choice>,
}

#[derive(Deserialize)]
struct Choice {
    message: crate::ai::ollama::Message,
}

impl OpenAiClient {
    pub fn new(model: impl Into<String>, api_key: String) -> Self {
        OpenAiClient {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(120))
                .build()
                .expect("reqwest client"),
            model: model.into(),
            api_key,
        }
    }

    pub async fn chat(
        &self,
        messages: Vec<crate::ai::ollama::Message>,
        format: Option<serde_json::Value>,
    ) -> anyhow::Result<crate::ai::ollama::Message> {
        let response_format = format
            .map(|schema| {
                serde_json::json!({
                    "type": "json_schema",
                    "json_schema": {
                        "name": "schema",
                        "schema": schema,
                        "strict": true
                    }
                })
            })
            .or_else(|| Some(serde_json::json!({"type": "json_object"})));

        let body = ChatRequest {
            model: self.model.clone(),
            messages,
            response_format,
        };

        let resp = self
            .client
            .post("https://api.openai.com/v1/chat/completions")
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(&body)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("OpenAI HTTP error: {e}"))?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!("OpenAI API error ({status}): {text}"));
        }

        let mut cr: ChatResponse = resp
            .json()
            .await
            .map_err(|e| anyhow::anyhow!("OpenAI JSON parse error: {e}"))?;

        cr.choices
            .pop()
            .map(|c| c.message)
            .ok_or_else(|| anyhow::anyhow!("No choices returned from OpenAI"))
    }

    pub async fn prompt(
        &self,
        system: &str,
        user: &str,
        format: Option<serde_json::Value>,
    ) -> anyhow::Result<String> {
        let msgs = vec![
            crate::ai::ollama::Message {
                role: "system".into(),
                content: system.into(),
            },
            crate::ai::ollama::Message {
                role: "user".into(),
                content: user.into(),
            },
        ];
        let reply = self.chat(msgs, format).await?;
        Ok(reply.content)
    }
}
