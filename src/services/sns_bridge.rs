use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::config::Config;

/// HTTP client for JECP → Next.js SNS Bridge communication.
///
/// The JECP server (Rust/Fly.io) is the brain — it generates strategies
/// and content. The Next.js server (Vercel) is the hands — it actually
/// posts to X/TikTok via their OAuth-authenticated clients.
#[derive(Clone)]
pub struct SnsBridge {
    http: Client,
    base_url: String,
    secret: String,
}

// ─── Request/Response types ────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct BridgePostRequest {
    pub platform: String,
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hashtags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_to_external_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct BridgePostResponse {
    pub success: bool,
    #[serde(default)]
    pub external_id: Option<String>,
    #[serde(default)]
    pub mock: Option<bool>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct BridgeScheduleRequest {
    pub id: String,
    pub campaign_id: Option<String>,
    pub platform: String,
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hashtags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_to_external_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_position: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_total: Option<i32>,
    pub language: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creative_angle: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_id: Option<String>,
    pub scheduled_at: String, // ISO 8601
}

#[derive(Debug, Deserialize)]
pub struct BridgeScheduleResponse {
    pub success: bool,
    pub id: String,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct BridgeMetricsResponse {
    pub success: bool,
    #[serde(default)]
    pub metrics: Option<Vec<PostMetric>>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostMetric {
    pub external_id: String,
    pub platform: String,
    #[serde(default)]
    pub views: u64,
    #[serde(default)]
    pub likes: u64,
    #[serde(default)]
    pub comments: u64,
    #[serde(default)]
    pub shares: u64,
    #[serde(default)]
    pub link_clicks: u64,
}

#[derive(Debug, Deserialize)]
pub struct BridgeTokenStatusResponse {
    pub success: bool,
    pub platforms: Vec<PlatformTokenStatus>,
}

#[derive(Debug, Deserialize)]
pub struct PlatformTokenStatus {
    pub platform: String,
    pub configured: bool,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub healthy: bool,
}

// ─── Implementation ────────────────────────────────────────────────

const MAX_RETRIES: u32 = 3;
const TIMEOUT_SECS: u64 = 30;

impl SnsBridge {
    pub fn new(config: &Config) -> Self {
        let http = Client::builder()
            .timeout(Duration::from_secs(TIMEOUT_SECS))
            .build()
            .expect("Failed to create HTTP client for SnsBridge");

        Self {
            http,
            base_url: config.nextjs_base_url.trim_end_matches('/').to_string(),
            secret: config.jecp_bridge_secret.clone(),
        }
    }

    /// Post a single message to a platform via the Next.js bridge.
    pub async fn post(&self, req: &BridgePostRequest) -> Result<BridgePostResponse, String> {
        let url = format!("{}/api/jecp/sns/post", self.base_url);
        self.request_with_retry::<_, BridgePostResponse>("POST", &url, Some(req)).await
    }

    /// Schedule a post for future publication.
    pub async fn schedule(&self, req: &BridgeScheduleRequest) -> Result<BridgeScheduleResponse, String> {
        let url = format!("{}/api/jecp/sns/schedule", self.base_url);
        self.request_with_retry::<_, BridgeScheduleResponse>("POST", &url, Some(req)).await
    }

    /// Fetch engagement metrics for posts.
    pub async fn fetch_metrics(
        &self,
        external_ids: &[String],
        platform: &str,
    ) -> Result<BridgeMetricsResponse, String> {
        let ids = external_ids.join(",");
        let url = format!(
            "{}/api/jecp/sns/metrics?platform={}&ids={}",
            self.base_url, platform, ids
        );
        self.request_with_retry::<(), BridgeMetricsResponse>("GET", &url, None).await
    }

    /// Check OAuth token health for all platforms.
    pub async fn check_tokens(&self) -> Result<BridgeTokenStatusResponse, String> {
        let url = format!("{}/api/jecp/sns/tokens/status", self.base_url);
        self.request_with_retry::<(), BridgeTokenStatusResponse>("GET", &url, None).await
    }

    /// Generic HTTP request with retry logic.
    async fn request_with_retry<B, R>(
        &self,
        method: &str,
        url: &str,
        body: Option<&B>,
    ) -> Result<R, String>
    where
        B: Serialize,
        R: for<'de> Deserialize<'de>,
    {
        let mut last_error = String::new();

        for attempt in 0..MAX_RETRIES {
            let req = match method {
                "GET" => self.http.get(url),
                _ => self.http.post(url),
            };

            let req = req.header("Authorization", format!("Bearer {}", self.secret));

            let req = if let Some(b) = body {
                req.json(b)
            } else {
                req
            };

            match req.send().await {
                Ok(resp) => {
                    if resp.status().is_success() {
                        match resp.json::<R>().await {
                            Ok(parsed) => return Ok(parsed),
                            Err(e) => {
                                last_error = format!("Failed to parse response: {}", e);
                            }
                        }
                    } else {
                        let status = resp.status().as_u16();
                        let body = resp.text().await.unwrap_or_default();
                        last_error = format!("Bridge returned {}: {}", status, body);

                        // Don't retry client errors (4xx)
                        if status >= 400 && status < 500 {
                            return Err(last_error);
                        }
                    }
                }
                Err(e) => {
                    last_error = format!("Bridge request failed: {}", e);
                }
            }

            // Exponential backoff before retry
            if attempt < MAX_RETRIES - 1 {
                let delay = Duration::from_millis(1000 * 2u64.pow(attempt));
                tokio::time::sleep(delay).await;
            }
        }

        Err(format!(
            "Bridge request failed after {} retries: {}",
            MAX_RETRIES, last_error
        ))
    }
}
