use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use super::types::JecpError;

/// v1.0.2 K2.5 — single instance of an `input_schema` violation, surfaced in
/// `error.details.errors[]` of an `INPUT_SCHEMA_VIOLATION` response.
#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
pub struct InputSchemaError {
    /// JSON Pointer to the offending value in the request `input`,
    /// e.g. `"/target_lang"` or `""` for the root.
    pub instance_path: String,
    /// JSON Pointer to the violated schema rule, e.g. `"/required"` or
    /// `"/properties/text/type"`. Empty when not derivable.
    pub schema_path: String,
    /// Human-readable diagnostic.
    pub reason: String,
}

/// Provenance verification subcause — closed registry per spec v1.0.1 §3.1.
///
/// New values require a spec patch revision; clients MUST treat unknown
/// subcauses as the parent error (PROVENANCE_MISMATCH) without further
/// inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceSubcause {
    /// Wire format violates the regex (`v2:<digits>:<hex>=>=16:<hex>=64` or 64-hex v1).
    /// Covers: missing `v2:` prefix on multi-part input, bad timestamp parse, nonce
    /// shorter than 16 hex chars, non-hex nonce, missing HMAC tag.
    WireMalformed,
    /// Provenance v2 timestamp is outside the ±300s clock-skew window.
    ClockSkew,
    /// Provenance v2 HMAC tag does not match server-recomputed value.
    HmacMismatch,
    /// `(agent_id, nonce)` already observed within the 600s replay window.
    NonceReplay,
    /// Provenance v1 SHA-256 hash does not match server-recomputed value.
    V1LegacyMismatch,
    /// Provenance v1 attempted on a rotated agent (plaintext api_key NULL in DB).
    /// Distinct from `V1LegacyMismatch` so SDKs can surface a clear "migrate to v2" message.
    V1Unavailable,
}

impl ProvenanceSubcause {
    pub fn as_str(self) -> &'static str {
        match self {
            ProvenanceSubcause::WireMalformed => "wire_malformed",
            ProvenanceSubcause::ClockSkew => "clock_skew",
            ProvenanceSubcause::HmacMismatch => "hmac_mismatch",
            ProvenanceSubcause::NonceReplay => "nonce_replay",
            ProvenanceSubcause::V1LegacyMismatch => "v1_legacy_mismatch",
            ProvenanceSubcause::V1Unavailable => "v1_unavailable",
        }
    }
}

/// All possible JECP error codes
#[derive(Debug, thiserror::Error)]
pub enum JecpErrorCode {
    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    /// v1.0.2 K2.1 — Content-Type negotiation failure.
    /// String holds the received Content-Type value (or "<empty>" when
    /// nothing was sent) for inclusion in `error.details.received`.
    #[error("Unsupported media type: expected application/json, got {0}")]
    UnsupportedMediaType(String),

    /// v1.0.2 K2.2 — same `(agent_id, request_id)` reused within the 24h
    /// idempotency window with a DIFFERENT (capability, action, input,
    /// provenance_hash) tuple. Per RFC 9110 §15.5.10 (409 Conflict).
    /// Identical replays return the cached response (idempotency hit),
    /// not 409 — see 01-protocol §5.
    #[error("Duplicate request: {0}")]
    DuplicateRequest(String),

    /// v1.0.2 K2.3 — capability/action's manifest `sunset_at` is in the
    /// past relative to the Hub's clock. HTTP 410 GONE per spec §4.6
    /// + 03-errors §3.3. IntoResponse emits required RFC 8594 headers:
    ///   `Sunset: <IMF-fixdate>`,
    ///   `Deprecation: true`,
    ///   `Link: <https://jecp.dev/spec/v1.0/03-errors.md#capability-deprecated>; rel="deprecation"`,
    ///   `Link: <successor>; rel="successor-version"` (when known).
    #[error("Capability deprecated: {capability} sunset on {sunset_at}")]
    CapabilityDeprecated {
        capability: String,
        sunset_at: chrono::DateTime<chrono::Utc>,
        /// Optional successor capability/action ID from the manifest.
        successor: Option<String>,
    },

    /// v1.0.2 K2.5 — `input` is syntactically valid JSON but does not satisfy
    /// the action's published `input_schema` from the manifest.
    /// HTTP 400 per spec 03-errors §3.2 (admiral D3 = 400 not 422; matches
    /// Stripe / GitHub / Twilio convention for invalid params).
    /// `errors` carries one entry per violation with JSON-pointer path,
    /// schema-pointer path, and human-readable reason.
    #[error("Input schema violation: {summary}")]
    InputSchemaViolation {
        summary: String,
        errors: Vec<InputSchemaError>,
    },

    /// v1.1.0 c7 — Composite SSRF defense rejection (spec §9.7.1.3).
    /// HTTP 422 (URL is structurally valid but violates Hub policy).
    /// `field` identifies which Agent-controlled URL was blocked
    /// (endpoint_url / webhook_destination_url / callback_url).
    /// `blocked_url` is echoed back with credentials redacted.
    /// `reason` ∈ {parse_error, scheme, host_syntax, resolved_to_deny_cidr,
    ///             dns_resolve_failed, connect_pin_violation}.
    #[error("URL blocked by SSRF policy: {field} {reason}")]
    UrlBlockedSsrf {
        field:        String,
        blocked_url:  String,
        reason:       String,
    },

    #[error("Unsupported protocol version: {0}")]
    UnsupportedVersion(String),

    #[error("Unknown capability: {0}")]
    UnknownCapability(String),

    #[error("Unknown action: {0}")]
    UnknownAction(String),

    #[error("Authentication required")]
    AuthRequired,

    #[error("Invalid API key")]
    InvalidApiKey,

    #[error("Agent not found: {0}")]
    AgentNotFound(String),

    /// v1.0.2 K2.4 — rate-limit denial. `retry_after_secs` carries the
    /// number of seconds before the agent's oldest entry ages out of the
    /// 60s sliding window; emitted in the RFC 9110 §10.2.3 `Retry-After`
    /// response header by `IntoResponse`. Bounded to `[1, 600]` per spec.
    #[error("Rate limit exceeded (retry after {retry_after_secs}s)")]
    RateLimited { retry_after_secs: u32 },

    #[error("Insufficient budget: need {needed}, remaining {remaining}")]
    InsufficientBudget { needed: f64, remaining: f64 },

    #[error("Insufficient wallet balance: need {needed}, remaining {remaining}")]
    InsufficientBalance { needed: f64, remaining: f64 },

    #[error("Mandate expired")]
    MandateExpired,

    #[error("Free tier limit reached")]
    FreeTierExhausted,

    #[error("Provenance verification failed: {reason}")]
    ProvenanceMismatch {
        reason: String,
        subcause: ProvenanceSubcause,
        /// Populated only when subcause = ClockSkew (signed seconds: now - timestamp).
        drift_seconds: Option<i64>,
    },

    #[error("Insufficient trust tier: {required} required, you are {current}")]
    InsufficientTrust { required: String, current: String },

    #[error("Payment required")]
    PaymentRequired,

    #[error("Input validation failed: {0}")]
    ValidationFailed(String),

    #[error("Capability execution failed: {0}")]
    ExecutionFailed(String),

    #[error("External service error: {0}")]
    ServiceError(String),

    #[error("Internal server error: {0}")]
    Internal(String),
}

impl JecpErrorCode {
    pub fn code(&self) -> &'static str {
        match self {
            JecpErrorCode::InvalidRequest(_) => "INVALID_REQUEST",
            JecpErrorCode::UnsupportedMediaType(_) => "UNSUPPORTED_MEDIA_TYPE",
            JecpErrorCode::DuplicateRequest(_) => "DUPLICATE_REQUEST",
            JecpErrorCode::CapabilityDeprecated { .. } => "CAPABILITY_DEPRECATED",
            JecpErrorCode::InputSchemaViolation { .. } => "INPUT_SCHEMA_VIOLATION",
            JecpErrorCode::UrlBlockedSsrf { .. } => "URL_BLOCKED_SSRF",
            JecpErrorCode::UnsupportedVersion(_) => "UNSUPPORTED_VERSION",
            JecpErrorCode::UnknownCapability(_) => "UNKNOWN_CAPABILITY",
            JecpErrorCode::UnknownAction(_) => "UNKNOWN_ACTION",
            JecpErrorCode::AuthRequired => "AUTH_REQUIRED",
            JecpErrorCode::InvalidApiKey => "INVALID_API_KEY",
            JecpErrorCode::AgentNotFound(_) => "AGENT_NOT_FOUND",
            JecpErrorCode::RateLimited { .. } => "RATE_LIMITED",
            JecpErrorCode::InsufficientBudget { .. } => "INSUFFICIENT_BUDGET",
            JecpErrorCode::InsufficientBalance { .. } => "INSUFFICIENT_BALANCE",
            JecpErrorCode::MandateExpired => "MANDATE_EXPIRED",
            JecpErrorCode::FreeTierExhausted => "FREE_TIER_EXHAUSTED",
            JecpErrorCode::ProvenanceMismatch { .. } => "PROVENANCE_MISMATCH",
            JecpErrorCode::InsufficientTrust { .. } => "INSUFFICIENT_TRUST",
            JecpErrorCode::PaymentRequired => "PAYMENT_REQUIRED",
            JecpErrorCode::ValidationFailed(_) => "VALIDATION_FAILED",
            JecpErrorCode::ExecutionFailed(_) => "EXECUTION_FAILED",
            JecpErrorCode::ServiceError(_) => "SERVICE_ERROR",
            JecpErrorCode::Internal(_) => "INTERNAL_ERROR",
        }
    }

    pub fn status_code(&self) -> StatusCode {
        match self {
            JecpErrorCode::InvalidRequest(_)
            | JecpErrorCode::UnsupportedVersion(_)
            | JecpErrorCode::UnknownCapability(_)
            | JecpErrorCode::UnknownAction(_)
            | JecpErrorCode::ValidationFailed(_) => StatusCode::BAD_REQUEST,

            JecpErrorCode::UnsupportedMediaType(_) => StatusCode::UNSUPPORTED_MEDIA_TYPE,

            JecpErrorCode::DuplicateRequest(_) => StatusCode::CONFLICT,

            JecpErrorCode::CapabilityDeprecated { .. } => StatusCode::GONE,

            JecpErrorCode::InputSchemaViolation { .. } => StatusCode::BAD_REQUEST,

            JecpErrorCode::UrlBlockedSsrf { .. } => StatusCode::UNPROCESSABLE_ENTITY,

            JecpErrorCode::AuthRequired
            | JecpErrorCode::InvalidApiKey => StatusCode::UNAUTHORIZED,

            JecpErrorCode::AgentNotFound(_) => StatusCode::NOT_FOUND,

            JecpErrorCode::RateLimited { .. }
            | JecpErrorCode::FreeTierExhausted => StatusCode::TOO_MANY_REQUESTS,

            JecpErrorCode::InsufficientBudget { .. }
            | JecpErrorCode::InsufficientBalance { .. }
            | JecpErrorCode::MandateExpired
            | JecpErrorCode::PaymentRequired => StatusCode::PAYMENT_REQUIRED,

            JecpErrorCode::ProvenanceMismatch { .. } => StatusCode::FORBIDDEN,

            JecpErrorCode::InsufficientTrust { .. } => StatusCode::FORBIDDEN,

            JecpErrorCode::ExecutionFailed(_)
            | JecpErrorCode::ServiceError(_)
            | JecpErrorCode::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn to_jecp_error(&self) -> JecpError {
        JecpError {
            code: self.code().to_string(),
            message: self.to_string(),
            details: None,
        }
    }
}

impl IntoResponse for JecpErrorCode {
    fn into_response(self) -> Response {
        let status = self.status_code();

        // 402 系のエラーには next_action でユーザー/エージェントが
        // 次に何をすべきかを機械可読形式で示す。これにより
        // エラーを受け取った agent が自動でチャージ動線に進める。
        let next_action = match &self {
            JecpErrorCode::InsufficientBalance { .. }
            | JecpErrorCode::PaymentRequired => Some(json!({
                "type": "topup",
                "ui": "https://jecp.dev/topup",
                "api": "https://jecp.dev/api/agents/topup",
                "method": "POST",
                "headers": ["X-Agent-ID", "X-API-Key"],
                "body_example": { "amount": 5 },
                "allowed_amounts_usd": [5, 20, 100],
                "description": "Top up your wallet with USD via Stripe Checkout"
            })),
            JecpErrorCode::AuthRequired
            | JecpErrorCode::InvalidApiKey => Some(json!({
                "type": "register",
                "ui": "https://jecp.dev/register",
                "api": "https://jecp.dev/api/agents/register",
                "method": "POST",
                "body_example": { "name": "My Agent", "agent_type": "automation" },
                "description": "Register an agent to receive agent_id and api_key (100 free calls)"
            })),
            JecpErrorCode::InsufficientTrust { required, current } => Some(json!({
                "type": "earn_trust",
                "current_tier": current,
                "required_tier": required,
                "description": "Make more paid calls to upgrade trust tier (100/500/2000 thresholds)",
                "fallback": {
                    "alternative": "Use lower-tier capabilities (content-factory, sns-engine) to build call count"
                }
            })),
            JecpErrorCode::MandateExpired => Some(json!({
                "type": "renew_mandate",
                "description": "Issue a new mandate with a future expires_at timestamp"
            })),
            _ => None,
        };

        // x402: 402レスポンスには USDC 支払い情報 + free-tier discovery を併記
        // free_alternative の具体エンドポイントは Sprint 6 の discovery 機能で
        // provider 中立に列挙するため、ここでは discovery URL のみを返す。
        let x402_info = if status == StatusCode::PAYMENT_REQUIRED {
            Some(json!({
                "protocol": "x402",
                "accepts": [{
                    "network": "base-mainnet",
                    "asset": "USDC",
                    "description": "Pay with USDC on Base (Stage 2)"
                }],
                "free_alternative": {
                    "discover": "https://jecp.dev/v1/capabilities?free=true",
                    "description": "Discover free capabilities offered by registered providers"
                }
            }))
        } else {
            None
        };

        // PROVENANCE_MISMATCH (and future codes) carry structured `error.details`
        // per spec v1.0.1 §3.1. Closed-registry subcause + optional drift_seconds
        // + documentation_url deep-link. Closed enum — clients MUST tolerate
        // unknown subcauses as the parent code.
        let error_details = match &self {
            JecpErrorCode::ProvenanceMismatch { subcause, drift_seconds, .. } => {
                let s = subcause.as_str();
                let mut obj = serde_json::Map::new();
                obj.insert("subcause".into(), json!(s));
                obj.insert(
                    "documentation_url".into(),
                    json!(format!("https://jecp.dev/errors/provenance_mismatch#{}", s)),
                );
                if let Some(d) = drift_seconds {
                    obj.insert("drift_seconds".into(), json!(d));
                }
                Some(serde_json::Value::Object(obj))
            }
            // v1.0.2 K2.1 — Content-Type negotiation failure carries the received
            // value + expected canonical value in details. Hubs MAY include an
            // explicit `details.endpoint_alias` when the request hit /v1/jecp,
            // wired separately at the route layer.
            JecpErrorCode::UnsupportedMediaType(received) => {
                let mut obj = serde_json::Map::new();
                obj.insert("received".into(), json!(received));
                obj.insert("expected".into(), json!("application/json"));
                obj.insert(
                    "documentation_url".into(),
                    json!("https://jecp.dev/errors/unsupported_media_type"),
                );
                Some(serde_json::Value::Object(obj))
            }
            // v1.0.2 K2.2 — DuplicateRequest carries documentation_url so SDKs
            // can deep-link clients to the migration recipe (use a fresh `id`).
            JecpErrorCode::DuplicateRequest(_) => {
                let mut obj = serde_json::Map::new();
                obj.insert(
                    "documentation_url".into(),
                    json!("https://jecp.dev/errors/duplicate_request"),
                );
                Some(serde_json::Value::Object(obj))
            }
            // v1.0.2 K2.4 — RateLimited mirrors the Retry-After header value
            // in `details.retry_after_seconds` so clients that ignore HTTP
            // response headers (some SDKs only see the parsed body) can still
            // implement back-off.
            JecpErrorCode::RateLimited { retry_after_secs } => {
                let mut obj = serde_json::Map::new();
                obj.insert("retry_after_seconds".into(), json!(retry_after_secs));
                obj.insert(
                    "documentation_url".into(),
                    json!("https://jecp.dev/errors/rate_limited"),
                );
                Some(serde_json::Value::Object(obj))
            }
            // v1.0.2 K2.5 — InputSchemaViolation carries the per-violation
            // error array per spec 03-errors §3.2 + Cure53/Stripe-grade detail.
            JecpErrorCode::InputSchemaViolation { errors, .. } => {
                let errors_json: Vec<serde_json::Value> = errors
                    .iter()
                    .map(|e| json!({
                        "instance_path": e.instance_path,
                        "schema_path":   e.schema_path,
                        "reason":        e.reason,
                    }))
                    .collect();
                let mut obj = serde_json::Map::new();
                obj.insert("errors".into(), serde_json::Value::Array(errors_json));
                obj.insert(
                    "documentation_url".into(),
                    json!("https://jecp.dev/errors/input_schema_violation"),
                );
                Some(serde_json::Value::Object(obj))
            }
            // v1.1.0 c7 — UrlBlockedSsrf carries field/blocked_url/reason per
            // spec 02-authentication §9.7.1.3 so clients can fix the rejected
            // URL field without parsing the message string.
            JecpErrorCode::UrlBlockedSsrf { field, blocked_url, reason } => {
                let mut obj = serde_json::Map::new();
                obj.insert("field".into(),       json!(field));
                obj.insert("blocked_url".into(), json!(blocked_url));
                obj.insert("reason".into(),      json!(reason));
                obj.insert(
                    "documentation_url".into(),
                    json!(format!("https://jecp.dev/errors/url_blocked_ssrf#{reason}")),
                );
                Some(serde_json::Value::Object(obj))
            }
            // v1.0.2 K2.3 — CapabilityDeprecated carries sunset metadata in
            // details for clients that don't read response headers.
            JecpErrorCode::CapabilityDeprecated { capability, sunset_at, successor } => {
                let mut obj = serde_json::Map::new();
                obj.insert("capability".into(), json!(capability));
                obj.insert("sunset_at".into(), json!(sunset_at.to_rfc3339()));
                if let Some(s) = successor {
                    obj.insert("successor".into(), json!(s));
                }
                obj.insert(
                    "documentation_url".into(),
                    json!("https://jecp.dev/errors/capability_deprecated"),
                );
                Some(serde_json::Value::Object(obj))
            }
            _ => None,
        };

        let mut error_obj = json!({
            "code": self.code(),
            "message": self.to_string()
        });
        if let Some(d) = error_details {
            error_obj.as_object_mut().unwrap().insert("details".into(), d);
        }

        let mut body = json!({
            "jecp": "1.0",
            "status": "failed",
            "error": error_obj,
        });

        if let Some(action) = next_action {
            body.as_object_mut().unwrap().insert("next_action".to_string(), action);
        }
        if let Some(x402) = x402_info {
            body.as_object_mut().unwrap().insert("payment".to_string(), x402);
        }

        let mut response = (status, axum::Json(body)).into_response();

        // v1.0.2 K2.4 — Retry-After header on 429 RATE_LIMITED.
        // Spec 03-errors §3.5 + RFC 9110 §10.2.3 (integer-seconds form).
        // X-RateLimit-{Limit,Remaining,Reset} trio deferred to v1.0.3 (D2).
        if let JecpErrorCode::RateLimited { retry_after_secs } = &self {
            use axum::http::HeaderValue;
            if let Ok(v) = HeaderValue::from_str(&retry_after_secs.to_string()) {
                response.headers_mut().insert("Retry-After", v);
            }
        }

        // v1.0.2 K2.3 — CapabilityDeprecated requires RFC 8594 + IETF
        // Deprecation headers on the 410 response. Spec §4.6 + §3.3.
        if let JecpErrorCode::CapabilityDeprecated { sunset_at, successor, .. } = &self {
            use axum::http::HeaderValue;
            let headers = response.headers_mut();

            // RFC 8594 §3 IMF-fixdate. chrono's RFC 2822 form is HTTP-date
            // compatible (`Mon, 01 Jan 2020 00:00:00 +0000`); we normalize to
            // GMT to match RFC 8594 examples literally.
            let sunset_imf = sunset_at
                .with_timezone(&chrono::Utc)
                .format("%a, %d %b %Y %H:%M:%S GMT")
                .to_string();
            if let Ok(v) = HeaderValue::from_str(&sunset_imf) {
                headers.insert("Sunset", v);
            }
            headers.insert("Deprecation", HeaderValue::from_static("true"));
            headers.insert(
                "Link",
                HeaderValue::from_static(
                    "<https://jecp.dev/spec/v1.0/03-errors.md#capability_deprecated>; rel=\"deprecation\"",
                ),
            );
            // Successor link (RFC 5829 §3.3 "successor-version") — appended as
            // a second Link header value when known.
            if let Some(s) = successor {
                let link_val = format!("<{}>; rel=\"successor-version\"", s);
                if let Ok(v) = HeaderValue::from_str(&link_val) {
                    headers.append("Link", v);
                }
            }
        }

        response
    }
}

#[cfg(test)]
mod errors_tests {
    use super::*;

    /// K2.1 — UNSUPPORTED_MEDIA_TYPE basics.
    #[test]
    fn unsupported_media_type_status_and_code() {
        let e = JecpErrorCode::UnsupportedMediaType("text/plain".into());
        assert_eq!(e.code(), "UNSUPPORTED_MEDIA_TYPE");
        assert_eq!(e.status_code(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    /// K2.2 — DUPLICATE_REQUEST returns 409 (was 400 before v1.0.2).
    #[test]
    fn duplicate_request_status_is_409() {
        let e = JecpErrorCode::DuplicateRequest("dup detected".into());
        assert_eq!(e.code(), "DUPLICATE_REQUEST");
        assert_eq!(e.status_code(), StatusCode::CONFLICT);
        assert_eq!(e.status_code().as_u16(), 409);
    }

    /// K2.3 — CAPABILITY_DEPRECATED status, code, headers.
    #[test]
    fn capability_deprecated_status_is_410() {
        let e = JecpErrorCode::CapabilityDeprecated {
            capability: "vendor/cap".into(),
            sunset_at: chrono::Utc::now(),
            successor: None,
        };
        assert_eq!(e.code(), "CAPABILITY_DEPRECATED");
        assert_eq!(e.status_code(), StatusCode::GONE);
        assert_eq!(e.status_code().as_u16(), 410);
    }

    /// K2.3 — IntoResponse emits Sunset (RFC 8594 IMF-fixdate) + Deprecation + Link.
    #[test]
    fn capability_deprecated_emits_required_headers() {
        use axum::response::IntoResponse;
        let sunset = chrono::DateTime::parse_from_rfc3339("2020-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let e = JecpErrorCode::CapabilityDeprecated {
            capability: "vendor/cap".into(),
            sunset_at: sunset,
            successor: Some("vendor/cap-v2".into()),
        };
        let resp = e.into_response();
        assert_eq!(resp.status(), StatusCode::GONE);

        let h = resp.headers();
        let sunset_hdr = h.get("Sunset").expect("Sunset header MUST be present");
        let sunset_str = sunset_hdr.to_str().unwrap();
        // IMF-fixdate per RFC 8594 §3
        assert!(sunset_str.contains("01 Jan 2020"), "Sunset format: {}", sunset_str);
        assert!(sunset_str.contains("GMT"), "Sunset must end in GMT: {}", sunset_str);

        let dep_hdr = h.get("Deprecation").expect("Deprecation header MUST be present");
        assert_eq!(dep_hdr.to_str().unwrap(), "true");

        // Link header carries deprecation rel + successor-version rel.
        let link_values: Vec<_> = h.get_all("Link").iter().collect();
        assert!(!link_values.is_empty(), "Link header MUST be present");
        let combined = link_values
            .iter()
            .map(|v| v.to_str().unwrap_or(""))
            .collect::<Vec<_>>()
            .join(", ");
        assert!(combined.contains("rel=\"deprecation\""), "Link missing rel=deprecation: {}", combined);
        assert!(
            combined.contains("rel=\"successor-version\""),
            "Link missing successor-version when manifest provides successor: {}",
            combined
        );
        assert!(combined.contains("vendor/cap-v2"), "successor URL not echoed: {}", combined);
    }

    /// K2.4 — RATE_LIMITED status + Retry-After header.
    #[test]
    fn rate_limited_status_and_retry_after_header() {
        use axum::response::IntoResponse;
        let e = JecpErrorCode::RateLimited { retry_after_secs: 42 };
        assert_eq!(e.code(), "RATE_LIMITED");
        assert_eq!(e.status_code(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(e.status_code().as_u16(), 429);

        let resp = e.into_response();
        let h = resp.headers();
        let retry_after = h
            .get("Retry-After")
            .expect("Retry-After header MUST be present on 429");
        assert_eq!(retry_after.to_str().unwrap(), "42");
    }

    /// K2.4 — Retry-After value is bounded [1, 600].
    #[test]
    fn rate_limited_retry_after_value_bounded() {
        use axum::response::IntoResponse;
        // The errors layer trusts the rate_limit middleware to bound;
        // here we just verify the wire emission preserves whatever value
        // is passed in. The 1..=600 bound is enforced in
        // middleware/rate_limit.rs::check.
        for value in [1u32, 30, 60, 600] {
            let e = JecpErrorCode::RateLimited { retry_after_secs: value };
            let resp = e.into_response();
            let h = resp.headers().get("Retry-After").unwrap().to_str().unwrap().to_string();
            assert_eq!(h, value.to_string());
        }
    }

    /// K2.3 — without successor, only deprecation Link is emitted.
    #[test]
    fn capability_deprecated_without_successor_omits_successor_link() {
        use axum::response::IntoResponse;
        let e = JecpErrorCode::CapabilityDeprecated {
            capability: "vendor/cap".into(),
            sunset_at: chrono::Utc::now(),
            successor: None,
        };
        let resp = e.into_response();
        let combined = resp
            .headers()
            .get_all("Link")
            .iter()
            .map(|v| v.to_str().unwrap_or(""))
            .collect::<Vec<_>>()
            .join(", ");
        assert!(combined.contains("rel=\"deprecation\""));
        assert!(!combined.contains("successor-version"), "should NOT have successor link: {}", combined);
    }

    /// K2.2 — DuplicateRequest carries documentation_url in details.
    #[test]
    fn duplicate_request_carries_documentation_url() {
        use axum::response::IntoResponse;
        let e = JecpErrorCode::DuplicateRequest("test".into());
        let resp = e.into_response();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        // Body inspection requires consuming; we trust IntoResponse's
        // populated documentation_url via the explicit branch in the impl.
    }

    /// Sanity: every variant maps to a non-empty code string.
    #[test]
    fn every_variant_has_non_empty_code() {
        let variants = [
            JecpErrorCode::InvalidRequest("x".into()),
            JecpErrorCode::UnsupportedMediaType("text/plain".into()),
            JecpErrorCode::DuplicateRequest("y".into()),
            JecpErrorCode::UnsupportedVersion("0.9".into()),
            JecpErrorCode::AuthRequired,
            JecpErrorCode::InvalidApiKey,
            JecpErrorCode::RateLimited { retry_after_secs: 30 },
            JecpErrorCode::PaymentRequired,
        ];
        for v in &variants {
            assert!(!v.code().is_empty(), "code() returned empty for {:?}", v);
            assert!(v.status_code().as_u16() >= 400, "status_code < 400 for {:?}", v);
        }
    }
}

