use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ─── JECP Request ───────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JecpRequest {
    /// Protocol version, must be "1.0"
    pub jecp: String,
    /// Unique request ID (client-generated)
    pub id: String,
    /// Target capability
    pub capability: Capability,
    /// Action within the capability
    pub action: String,
    /// Authentication & budget mandate
    #[serde(default)]
    pub mandate: Option<Mandate>,
    /// Action-specific input data
    pub input: serde_json::Value,
    /// How to deliver the result
    #[serde(default)]
    pub delivery: Delivery,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum Capability {
    DocumentPipeline,
    FileChain,
    ContentFactory,
    DataInsight,
    Workflow,
    SnsEngine,
}

impl Capability {
    pub fn as_str(&self) -> &'static str {
        match self {
            Capability::DocumentPipeline => "document-pipeline",
            Capability::FileChain => "file-chain",
            Capability::ContentFactory => "content-factory",
            Capability::DataInsight => "data-insight",
            Capability::Workflow => "workflow",
            Capability::SnsEngine => "sns-engine",
        }
    }

    pub fn all() -> Vec<Capability> {
        vec![
            Capability::DocumentPipeline,
            Capability::FileChain,
            Capability::ContentFactory,
            Capability::DataInsight,
            Capability::Workflow,
            Capability::SnsEngine,
        ]
    }
}

impl std::fmt::Display for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mandate {
    pub agent_id: String,
    pub api_key: String,
    #[serde(default)]
    pub budget_usdc: Option<f64>,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
    /// Provenance hash: SHA256(agent_id:total_calls:api_key_prefix)
    /// 身分偽装防止 — サーバー側の計算値と一致しなければ拒否
    #[serde(default)]
    pub provenance_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Delivery {
    #[serde(default = "default_delivery_mode")]
    pub mode: DeliveryMode,
    #[serde(default)]
    pub format: Option<String>,
}

impl Default for Delivery {
    fn default() -> Self {
        Self {
            mode: DeliveryMode::Sync,
            format: None,
        }
    }
}

fn default_delivery_mode() -> DeliveryMode {
    DeliveryMode::Sync
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum DeliveryMode {
    Sync,
    Stream,
    Async,
}

// ─── JECP Response ──────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JecpResponse {
    pub jecp: String,
    pub id: String,
    pub status: TaskStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<JecpResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JecpError>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub billing: Option<Billing>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution: Option<Execution>,
}

impl JecpResponse {
    pub fn success(id: String, result: JecpResult, billing: Billing, execution: Execution) -> Self {
        Self {
            jecp: "1.0".to_string(),
            id,
            status: TaskStatus::Completed,
            result: Some(result),
            error: None,
            billing: Some(billing),
            execution: Some(execution),
        }
    }

    pub fn error(id: String, error: JecpError) -> Self {
        Self {
            jecp: "1.0".to_string(),
            id,
            status: TaskStatus::Failed,
            result: None,
            error: Some(error),
            billing: None,
            execution: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JecpResult {
    pub capability: String,
    pub action: String,
    pub output: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JecpError {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TaskStatus {
    Submitted,
    Working,
    Completed,
    Failed,
}

impl TaskStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            TaskStatus::Submitted => "submitted",
            TaskStatus::Working => "working",
            TaskStatus::Completed => "completed",
            TaskStatus::Failed => "failed",
        }
    }
}

impl std::fmt::Display for TaskStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Billing {
    pub cost_usdc: f64,
    pub mandate_remaining: Option<f64>,
    pub method: String,
    /// Wallet balance after charge (only set when method == "wallet")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub balance_after: Option<f64>,
    /// Transaction ID in jecp.transactions (audit reference)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,
}

impl Billing {
    pub fn free(mandate_remaining: Option<f64>) -> Self {
        Self {
            cost_usdc: 0.0,
            mandate_remaining,
            method: "free_call".to_string(),
            balance_after: None,
            transaction_id: None,
        }
    }

    pub fn charged(cost: f64, remaining: Option<f64>) -> Self {
        Self {
            cost_usdc: cost,
            mandate_remaining: remaining,
            method: "api_key".to_string(),
            balance_after: None,
            transaction_id: None,
        }
    }

    /// Wallet-based payment (deducted from jecp.wallets)
    pub fn wallet(cost: f64, balance_after: f64, transaction_id: String) -> Self {
        Self {
            cost_usdc: cost,
            mandate_remaining: None,
            method: "wallet".to_string(),
            balance_after: Some(balance_after),
            transaction_id: Some(transaction_id),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Execution {
    pub duration_ms: u64,
    pub engine: String,
    pub steps_completed: u32,
}

impl Execution {
    pub fn new(duration_ms: u64, steps: u32) -> Self {
        Self {
            duration_ms,
            engine: "jecp-v1".to_string(),
            steps_completed: steps,
        }
    }
}

// ─── SSE Events ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SseStatusEvent {
    pub state: String,
    pub step: String,
    pub progress: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SseResultEvent {
    pub output: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SseDoneEvent {
    pub status: String,
    pub billing: Billing,
    pub execution: Execution,
}

// ─── Capabilities Catalog ───────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityCatalog {
    pub jecp: String,
    pub engine: String,
    pub capabilities: Vec<CapabilityInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityInfo {
    pub id: String,
    pub name: String,
    pub description: String,
    pub actions: Vec<ActionInfo>,
    pub pricing: PricingRange,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionInfo {
    pub id: String,
    pub name: String,
    pub description: String,
    pub input_schema: serde_json::Value,
    pub price_usdc: f64,
    /// v1.1.0 x402 — payment methods accepted by this action.
    /// Per locked-design v1.1.1 §3.6: optional field, default `["stripe"]` if absent.
    /// Built-in capabilities default to wallet (stripe) only; third-party
    /// capabilities source this from `manifest.actions[].pricing.payment_methods`.
    #[serde(default = "default_payment_methods", skip_serializing_if = "Vec::is_empty")]
    pub payment_methods: Vec<String>,
}

/// Default payment methods for built-in capabilities (locked-design v1.1.1 §3.6).
fn default_payment_methods() -> Vec<String> {
    vec!["stripe".to_string()]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PricingRange {
    pub min: String,
    pub max: String,
}

// ─── Pricing Table ──────────────────────────────────────────

pub fn get_action_price(capability: &Capability, action: &str) -> f64 {
    match (capability, action) {
        // Document Pipeline
        (Capability::DocumentPipeline, "generate-invoice") => 0.005,
        (Capability::DocumentPipeline, "generate-quote") => 0.005,
        (Capability::DocumentPipeline, "generate-report") => 0.02,
        (Capability::DocumentPipeline, "generate-contract") => 0.01,
        (Capability::DocumentPipeline, "generate-receipt") => 0.003,
        // File Chain
        (Capability::FileChain, "image-pipeline") => 0.01,
        (Capability::FileChain, "pdf-pipeline") => 0.01,
        (Capability::FileChain, "batch-convert") => 0.005,
        // Content Factory
        (Capability::ContentFactory, "generate-blog") => 0.02,
        (Capability::ContentFactory, "generate-social") => 0.01,
        (Capability::ContentFactory, "rewrite") => 0.005,
        (Capability::ContentFactory, "translate") => 0.005,
        (Capability::ContentFactory, "summarize") => 0.003,
        // Data Insight
        (Capability::DataInsight, "analyze-csv") => 0.01,
        (Capability::DataInsight, "analyze-json") => 0.005,
        (Capability::DataInsight, "forecast") => 0.02,
        // Workflow
        (Capability::Workflow, "invoice-and-notify") => 0.01,
        (Capability::Workflow, "content-campaign") => 0.05,
        (Capability::Workflow, "data-report-mail") => 0.03,
        // SNS Engine
        (Capability::SnsEngine, "campaign-orchestrate") => 0.10,
        (Capability::SnsEngine, "trend-pulse") => 0.03,
        (Capability::SnsEngine, "ab-test-launch") => 0.05,
        (Capability::SnsEngine, "engagement-analyze") => 0.02,
        (Capability::SnsEngine, "thread-weave") => 0.05,
        (Capability::SnsEngine, "growth-autopilot") => 0.15,
        // Default
        _ => 0.01,
    }
}

/// Build the full capabilities catalog
pub fn build_capabilities_catalog() -> CapabilityCatalog {
    let mut catalog = build_capabilities_catalog_inner();
    // v1.1.0 x402 (locked-design v1.1.1 §3.6): ensure every built-in action
    // exposes `payment_methods` (default ["stripe"]). Struct literals below
    // omit the field for compactness — fill it here.
    for cap in &mut catalog.capabilities {
        for act in &mut cap.actions {
            if act.payment_methods.is_empty() {
                act.payment_methods = default_payment_methods();
            }
        }
    }
    catalog
}

fn build_capabilities_catalog_inner() -> CapabilityCatalog {
    CapabilityCatalog {
        jecp: "1.0".to_string(),
        engine: "jecp-v1".to_string(),
        capabilities: vec![
            CapabilityInfo {
                id: "document-pipeline".to_string(),
                name: "AI Document Pipeline".to_string(),
                description: "Generate professional documents (invoices, quotes, reports) from structured data".to_string(),
                actions: vec![
                    ActionInfo {
                        id: "generate-invoice".to_string(),
                        name: "Generate Invoice".to_string(),
                        description: "Create a professional invoice PDF from line items and client info".to_string(),
                        input_schema: serde_json::json!({
                            "type": "object",
                            "required": ["items", "client_name"],
                            "properties": {
                                "client_name": { "type": "string" },
                                "client_address": { "type": "string" },
                                "items": {
                                    "type": "array",
                                    "items": {
                                        "type": "object",
                                        "properties": {
                                            "name": { "type": "string" },
                                            "quantity": { "type": "number" },
                                            "unit_price": { "type": "number" },
                                            "tax_rate": { "type": "number" }
                                        }
                                    }
                                },
                                "due_date": { "type": "string", "format": "date" },
                                "notes": { "type": "string" }
                            }
                        }),
                        price_usdc: 0.005,
                        payment_methods: vec![],
                    },
                    ActionInfo {
                        id: "generate-quote".to_string(),
                        name: "Generate Quote".to_string(),
                        description: "Create a quotation PDF with validity period".to_string(),
                        input_schema: serde_json::json!({
                            "type": "object",
                            "required": ["items", "client_name"],
                            "properties": {
                                "client_name": { "type": "string" },
                                "items": { "type": "array" },
                                "validity_days": { "type": "integer", "default": 30 }
                            }
                        }),
                        price_usdc: 0.005,
                        payment_methods: vec![],
                    },
                    ActionInfo {
                        id: "generate-report".to_string(),
                        name: "Generate Report".to_string(),
                        description: "Create a data-driven report with charts and insights".to_string(),
                        input_schema: serde_json::json!({
                            "type": "object",
                            "required": ["data", "title"],
                            "properties": {
                                "title": { "type": "string" },
                                "data": { "type": "object" },
                                "template": { "type": "string" },
                                "period": { "type": "string" }
                            }
                        }),
                        price_usdc: 0.02,
                        payment_methods: vec![],
                    },
                    ActionInfo {
                        id: "generate-contract".to_string(),
                        name: "Generate Contract".to_string(),
                        description: "Draft a contract PDF from parties and terms".to_string(),
                        input_schema: serde_json::json!({
                            "type": "object",
                            "required": ["parties", "terms"],
                            "properties": {
                                "parties": { "type": "array" },
                                "terms": { "type": "object" },
                                "clauses": { "type": "array" }
                            }
                        }),
                        price_usdc: 0.01,
                        payment_methods: vec![],
                    },
                    ActionInfo {
                        id: "generate-receipt".to_string(),
                        name: "Generate Receipt".to_string(),
                        description: "Create a receipt PDF from payment information".to_string(),
                        input_schema: serde_json::json!({
                            "type": "object",
                            "required": ["payment_info"],
                            "properties": {
                                "payment_info": { "type": "object" }
                            }
                        }),
                        price_usdc: 0.003,
                        payment_methods: vec![],
                    },
                ],
                pricing: PricingRange {
                    min: "$0.003".to_string(),
                    max: "$0.02".to_string(),
                },
            },
            CapabilityInfo {
                id: "file-chain".to_string(),
                name: "Intelligent File Chain".to_string(),
                description: "Chain multiple file processing steps into a single pipeline".to_string(),
                actions: vec![
                    ActionInfo {
                        id: "image-pipeline".to_string(),
                        name: "Image Pipeline".to_string(),
                        description: "Process an image through multiple steps (resize, convert, compress, etc.)".to_string(),
                        input_schema: serde_json::json!({
                            "type": "object",
                            "required": ["image", "steps"],
                            "properties": {
                                "image": { "type": "string", "description": "Base64-encoded image" },
                                "steps": { "type": "array", "items": { "type": "object" } }
                            }
                        }),
                        price_usdc: 0.01,
                        payment_methods: vec![],
                    },
                    ActionInfo {
                        id: "pdf-pipeline".to_string(),
                        name: "PDF Pipeline".to_string(),
                        description: "Process a PDF through multiple steps (merge, split, compress, etc.)".to_string(),
                        input_schema: serde_json::json!({
                            "type": "object",
                            "required": ["pdf", "steps"],
                            "properties": {
                                "pdf": { "type": "string", "description": "Base64-encoded PDF" },
                                "steps": { "type": "array", "items": { "type": "object" } }
                            }
                        }),
                        price_usdc: 0.01,
                        payment_methods: vec![],
                    },
                    ActionInfo {
                        id: "batch-convert".to_string(),
                        name: "Batch Convert".to_string(),
                        description: "Convert multiple files to a target format".to_string(),
                        input_schema: serde_json::json!({
                            "type": "object",
                            "required": ["files", "target_format"],
                            "properties": {
                                "files": { "type": "array" },
                                "target_format": { "type": "string" }
                            }
                        }),
                        price_usdc: 0.005,
                        payment_methods: vec![],
                    },
                ],
                pricing: PricingRange {
                    min: "$0.005".to_string(),
                    max: "$0.05".to_string(),
                },
            },
            CapabilityInfo {
                id: "content-factory".to_string(),
                name: "AI Content Factory".to_string(),
                description: "Generate structured content using AI (blog posts, social media, translations)".to_string(),
                actions: vec![
                    ActionInfo {
                        id: "generate-blog".to_string(),
                        name: "Generate Blog Post".to_string(),
                        description: "Generate a full blog post with title, body, meta description, and OGP data".to_string(),
                        input_schema: serde_json::json!({
                            "type": "object",
                            "required": ["topic"],
                            "properties": {
                                "topic": { "type": "string" },
                                "keywords": { "type": "array", "items": { "type": "string" } },
                                "length": { "type": "string", "enum": ["short", "medium", "long"] },
                                "language": { "type": "string", "default": "en" }
                            }
                        }),
                        price_usdc: 0.02,
                        payment_methods: vec![],
                    },
                    ActionInfo {
                        id: "generate-social".to_string(),
                        name: "Generate Social Posts".to_string(),
                        description: "Generate social media posts with hashtags and scheduling suggestions".to_string(),
                        input_schema: serde_json::json!({
                            "type": "object",
                            "required": ["topic"],
                            "properties": {
                                "topic": { "type": "string" },
                                "platforms": { "type": "array", "items": { "type": "string" } },
                                "count": { "type": "integer", "default": 5 }
                            }
                        }),
                        price_usdc: 0.01,
                        payment_methods: vec![],
                    },
                    ActionInfo {
                        id: "rewrite".to_string(),
                        name: "Rewrite Text".to_string(),
                        description: "Rewrite text in a different tone or for a different audience".to_string(),
                        input_schema: serde_json::json!({
                            "type": "object",
                            "required": ["text"],
                            "properties": {
                                "text": { "type": "string" },
                                "tone": { "type": "string" },
                                "target_audience": { "type": "string" }
                            }
                        }),
                        price_usdc: 0.005,
                        payment_methods: vec![],
                    },
                    ActionInfo {
                        id: "translate".to_string(),
                        name: "Translate".to_string(),
                        description: "Translate text between languages".to_string(),
                        input_schema: serde_json::json!({
                            "type": "object",
                            "required": ["text", "target_lang"],
                            "properties": {
                                "text": { "type": "string" },
                                "source_lang": { "type": "string" },
                                "target_lang": { "type": "string" }
                            }
                        }),
                        price_usdc: 0.005,
                        payment_methods: vec![],
                    },
                    ActionInfo {
                        id: "summarize".to_string(),
                        name: "Summarize".to_string(),
                        description: "Summarize text to a specified length".to_string(),
                        input_schema: serde_json::json!({
                            "type": "object",
                            "required": ["text"],
                            "properties": {
                                "text": { "type": "string" },
                                "max_length": { "type": "integer" }
                            }
                        }),
                        price_usdc: 0.003,
                        payment_methods: vec![],
                    },
                ],
                pricing: PricingRange {
                    min: "$0.003".to_string(),
                    max: "$0.02".to_string(),
                },
            },
            CapabilityInfo {
                id: "data-insight".to_string(),
                name: "Data Insight Engine".to_string(),
                description: "Analyze data and generate statistical summaries with actionable insights".to_string(),
                actions: vec![
                    ActionInfo {
                        id: "analyze-csv".to_string(),
                        name: "Analyze CSV".to_string(),
                        description: "Analyze CSV data and return statistics, trends, and recommendations".to_string(),
                        input_schema: serde_json::json!({
                            "type": "object",
                            "required": ["csv_data"],
                            "properties": {
                                "csv_data": { "type": "string" },
                                "question": { "type": "string" }
                            }
                        }),
                        price_usdc: 0.01,
                        payment_methods: vec![],
                    },
                    ActionInfo {
                        id: "analyze-json".to_string(),
                        name: "Analyze JSON".to_string(),
                        description: "Analyze JSON data structure and contents".to_string(),
                        input_schema: serde_json::json!({
                            "type": "object",
                            "required": ["json_data"],
                            "properties": {
                                "json_data": { "type": "object" },
                                "question": { "type": "string" }
                            }
                        }),
                        price_usdc: 0.005,
                        payment_methods: vec![],
                    },
                    ActionInfo {
                        id: "forecast".to_string(),
                        name: "Forecast".to_string(),
                        description: "Generate time-series forecasts with confidence intervals".to_string(),
                        input_schema: serde_json::json!({
                            "type": "object",
                            "required": ["time_series"],
                            "properties": {
                                "time_series": { "type": "array" },
                                "horizon": { "type": "integer" }
                            }
                        }),
                        price_usdc: 0.02,
                        payment_methods: vec![],
                    },
                ],
                pricing: PricingRange {
                    min: "$0.005".to_string(),
                    max: "$0.02".to_string(),
                },
            },
            CapabilityInfo {
                id: "workflow".to_string(),
                name: "Autonomous Workflow".to_string(),
                description: "Execute multi-step business workflows with budget control".to_string(),
                actions: vec![
                    ActionInfo {
                        id: "invoice-and-notify".to_string(),
                        name: "Invoice & Notify".to_string(),
                        description: "Generate an invoice and send notification to the client".to_string(),
                        input_schema: serde_json::json!({
                            "type": "object",
                            "required": ["client", "items"],
                            "properties": {
                                "client": { "type": "object" },
                                "items": { "type": "array" },
                                "email": { "type": "string" }
                            }
                        }),
                        price_usdc: 0.01,
                        payment_methods: vec![],
                    },
                    ActionInfo {
                        id: "content-campaign".to_string(),
                        name: "Content Campaign".to_string(),
                        description: "Generate a blog post plus social media posts with scheduling".to_string(),
                        input_schema: serde_json::json!({
                            "type": "object",
                            "required": ["topic"],
                            "properties": {
                                "topic": { "type": "string" },
                                "platforms": { "type": "array" }
                            }
                        }),
                        price_usdc: 0.05,
                        payment_methods: vec![],
                    },
                    ActionInfo {
                        id: "data-report-mail".to_string(),
                        name: "Data Report & Mail".to_string(),
                        description: "Analyze data, generate a PDF report, and email it to recipients".to_string(),
                        input_schema: serde_json::json!({
                            "type": "object",
                            "required": ["csv_data", "recipients"],
                            "properties": {
                                "csv_data": { "type": "string" },
                                "recipients": { "type": "array" }
                            }
                        }),
                        price_usdc: 0.03,
                        payment_methods: vec![],
                    },
                ],
                pricing: PricingRange {
                    min: "$0.01".to_string(),
                    max: "$0.05".to_string(),
                },
            },
            CapabilityInfo {
                id: "sns-engine".to_string(),
                name: "SNS Growth Engine".to_string(),
                description: "Autonomous SNS growth engine: content generation, scheduling, A/B testing, and analytics-driven optimization".to_string(),
                actions: vec![
                    ActionInfo {
                        id: "campaign-orchestrate".to_string(),
                        name: "Campaign Orchestrate".to_string(),
                        description: "Generate a full SNS campaign with AI-crafted posts, scheduling, and brand voice enforcement".to_string(),
                        input_schema: serde_json::json!({
                            "type": "object",
                            "required": ["goal", "platforms"],
                            "properties": {
                                "goal": { "type": "string", "description": "Campaign goal (e.g. 'Promote bg-remover tool')" },
                                "platforms": { "type": "array", "items": { "type": "string", "enum": ["x", "tiktok"] } },
                                "languages": { "type": "array", "items": { "type": "string" }, "default": ["ja"] },
                                "duration_days": { "type": "integer", "default": 7 },
                                "posts_per_day": { "type": "integer", "default": 3 },
                                "tool_ids": { "type": "array", "items": { "type": "string" } },
                                "tone": { "type": "string", "default": "confident" }
                            }
                        }),
                        price_usdc: 0.10,
                        payment_methods: vec![],
                    },
                    ActionInfo {
                        id: "trend-pulse".to_string(),
                        name: "Trend Pulse".to_string(),
                        description: "Detect trending topics and generate viral content using Hook→Pain→Solution→Result→CTA framework".to_string(),
                        input_schema: serde_json::json!({
                            "type": "object",
                            "properties": {
                                "platform": { "type": "string", "default": "x" },
                                "tool_ids": { "type": "array", "items": { "type": "string" } },
                                "auto_post": { "type": "boolean", "default": false }
                            }
                        }),
                        price_usdc: 0.03,
                        payment_methods: vec![],
                    },
                    ActionInfo {
                        id: "ab-test-launch".to_string(),
                        name: "A/B Test Launch".to_string(),
                        description: "Generate 2-4 content variants and post them at intervals to determine the best performer".to_string(),
                        input_schema: serde_json::json!({
                            "type": "object",
                            "required": ["topic", "platform"],
                            "properties": {
                                "topic": { "type": "string" },
                                "platform": { "type": "string" },
                                "variant_count": { "type": "integer", "default": 2, "minimum": 2, "maximum": 4 },
                                "test_duration_hours": { "type": "integer", "default": 24 }
                            }
                        }),
                        price_usdc: 0.05,
                        payment_methods: vec![],
                    },
                    ActionInfo {
                        id: "engagement-analyze".to_string(),
                        name: "Engagement Analyze".to_string(),
                        description: "Fetch metrics and generate AI-powered performance insights with optimization recommendations".to_string(),
                        input_schema: serde_json::json!({
                            "type": "object",
                            "properties": {
                                "campaign_id": { "type": "string" },
                                "period_days": { "type": "integer", "default": 7 },
                                "platform": { "type": "string" }
                            }
                        }),
                        price_usdc: 0.02,
                        payment_methods: vec![],
                    },
                    ActionInfo {
                        id: "thread-weave".to_string(),
                        name: "Thread Weave".to_string(),
                        description: "Generate multi-post threads (X 1/N format) or TikTok series that work individually and as a narrative".to_string(),
                        input_schema: serde_json::json!({
                            "type": "object",
                            "required": ["topic", "platform"],
                            "properties": {
                                "topic": { "type": "string" },
                                "platform": { "type": "string" },
                                "thread_length": { "type": "integer", "default": 5 },
                                "auto_post": { "type": "boolean", "default": false }
                            }
                        }),
                        price_usdc: 0.05,
                        payment_methods: vec![],
                    },
                    ActionInfo {
                        id: "growth-autopilot".to_string(),
                        name: "Growth Autopilot".to_string(),
                        description: "Fully autonomous daily cycle: analyze past performance, learn optimal parameters, generate and schedule next day's content".to_string(),
                        input_schema: serde_json::json!({
                            "type": "object",
                            "properties": {
                                "platforms": { "type": "array", "items": { "type": "string" }, "default": ["x"] },
                                "posts_per_day": { "type": "integer", "default": 3 },
                                "learning_window_days": { "type": "integer", "default": 7 }
                            }
                        }),
                        price_usdc: 0.15,
                        payment_methods: vec![],
                    },
                ],
                pricing: PricingRange {
                    min: "$0.02".to_string(),
                    max: "$0.15".to_string(),
                },
            },
        ],
    }
}
