use futures::Stream;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::pin::Pin;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use crate::config::Config;

/// Claude API streaming client
#[derive(Clone)]
pub struct ClaudeClient {
    http: Client,
    api_key: String,
    model: String,
}

#[derive(Debug, Serialize)]
struct ClaudeRequest {
    model: String,
    max_tokens: u32,
    messages: Vec<ClaudeMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    system: Option<String>,
    stream: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaudeMessage {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
#[allow(dead_code)]
pub enum StreamEvent {
    #[serde(rename = "message_start")]
    MessageStart { message: serde_json::Value },
    #[serde(rename = "content_block_start")]
    ContentBlockStart { index: u32, content_block: serde_json::Value },
    #[serde(rename = "content_block_delta")]
    ContentBlockDelta { index: u32, delta: ContentDelta },
    #[serde(rename = "content_block_stop")]
    ContentBlockStop { index: u32 },
    #[serde(rename = "message_delta")]
    MessageDelta { delta: serde_json::Value, usage: Option<serde_json::Value> },
    #[serde(rename = "message_stop")]
    MessageStop,
    #[serde(rename = "ping")]
    Ping,
    #[serde(rename = "error")]
    Error { error: serde_json::Value },
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct ContentDelta {
    #[serde(rename = "type")]
    pub delta_type: String,
    #[serde(default)]
    pub text: String,
}

/// Token representing a chunk of Claude's streaming response
#[derive(Debug, Clone)]
pub enum ClaudeChunk {
    Text(String),
    Done,
    Error(String),
}

impl ClaudeClient {
    pub fn new(config: &Config) -> Self {
        Self {
            http: Client::new(),
            api_key: config.anthropic_api_key.clone(),
            model: config.anthropic_model.clone(),
        }
    }

    /// Send a non-streaming request to Claude and return the full response
    pub async fn complete(
        &self,
        system: Option<&str>,
        messages: Vec<ClaudeMessage>,
        max_tokens: u32,
    ) -> Result<String, anyhow::Error> {
        let request = ClaudeRequest {
            model: self.model.clone(),
            max_tokens,
            messages,
            system: system.map(|s| s.to_string()),
            stream: false,
        };

        let response = self
            .http
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Claude API error {}: {}", status, body);
        }

        let body: serde_json::Value = response.json().await?;
        let text = body["content"]
            .as_array()
            .and_then(|arr| arr.first())
            .and_then(|block| block["text"].as_str())
            .unwrap_or("")
            .to_string();

        Ok(text)
    }

    /// Send a streaming request to Claude and return a stream of text chunks
    pub fn stream(
        &self,
        system: Option<&str>,
        messages: Vec<ClaudeMessage>,
        max_tokens: u32,
    ) -> Pin<Box<dyn Stream<Item = ClaudeChunk> + Send>> {
        let (tx, rx) = mpsc::channel(64);
        let client = self.clone();
        let system_owned = system.map(|s| s.to_string());

        tokio::spawn(async move {
            let request = ClaudeRequest {
                model: client.model.clone(),
                max_tokens,
                messages,
                system: system_owned,
                stream: true,
            };

            let response = match client
                .http
                .post("https://api.anthropic.com/v1/messages")
                .header("x-api-key", &client.api_key)
                .header("anthropic-version", "2023-06-01")
                .header("content-type", "application/json")
                .json(&request)
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    let _ = tx.send(ClaudeChunk::Error(e.to_string())).await;
                    return;
                }
            };

            if !response.status().is_success() {
                let body = response.text().await.unwrap_or_default();
                let _ = tx.send(ClaudeChunk::Error(body)).await;
                return;
            }

            // Read SSE stream
            let mut buffer = String::new();
            let mut bytes_stream = response.bytes_stream();
            use futures::StreamExt;

            while let Some(chunk_result) = bytes_stream.next().await {
                match chunk_result {
                    Ok(bytes) => {
                        buffer.push_str(&String::from_utf8_lossy(&bytes));

                        // Process complete SSE events in buffer
                        while let Some(pos) = buffer.find("\n\n") {
                            let event_str = buffer[..pos].to_string();
                            buffer = buffer[pos + 2..].to_string();

                            // Parse SSE event
                            let mut data_line = None;
                            for line in event_str.lines() {
                                if let Some(d) = line.strip_prefix("data: ") {
                                    data_line = Some(d.to_string());
                                }
                            }

                            if let Some(data) = data_line {
                                if data == "[DONE]" {
                                    let _ = tx.send(ClaudeChunk::Done).await;
                                    return;
                                }
                                if let Ok(event) = serde_json::from_str::<StreamEvent>(&data) {
                                    match event {
                                        StreamEvent::ContentBlockDelta { delta, .. } => {
                                            if !delta.text.is_empty() {
                                                if tx.send(ClaudeChunk::Text(delta.text)).await.is_err() {
                                                    return;
                                                }
                                            }
                                        }
                                        StreamEvent::MessageStop => {
                                            let _ = tx.send(ClaudeChunk::Done).await;
                                            return;
                                        }
                                        StreamEvent::Error { error } => {
                                            let msg = error.to_string();
                                            let _ = tx.send(ClaudeChunk::Error(msg)).await;
                                            return;
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(ClaudeChunk::Error(e.to_string())).await;
                        return;
                    }
                }
            }

            let _ = tx.send(ClaudeChunk::Done).await;
        });

        Box::pin(ReceiverStream::new(rx))
    }
}
