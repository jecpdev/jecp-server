//! Manifest publish endpoint (Sprint 8 / Stage 3).
//!
//! POST /v1/manifests
//!   - Auth: Authorization: Bearer <provider_api_key>
//!   - Content-Type: application/x-yaml or application/json
//!   - Body: jecp.yaml content (see docs/jecp/JECP-TECHNICAL-DESIGN.md §5)
//!
//! 流れ:
//!   1. Bearer auth (既存 helper を再利用)
//!   2. YAML/JSON parse → Manifest struct
//!   3. Validation (namespace/version/endpoint/pricing/examples)
//!   4. namespace は登録時の Provider と一致確認 (security)
//!   5. jecp.capabilities を upsert (provider_id, capability, version)
//!   6. jecp.manifests に yaml_content + parsed_json 保存
//!   7. jecp.manifest_history に audit log
//!   8. capability_id + status を返却

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::services::database;
use crate::AppState;

// ---------------------------------------------------------------------------
// Manifest struct (mirror of jecp.yaml schema §5)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub namespace: String,
    pub display_name: Option<String>,
    pub website: Option<String>,
    pub support_email: Option<String>,
    pub documentation: Option<String>,

    pub capability: String,
    pub version: String,
    pub description: String,
    #[serde(default)]
    pub tags: Vec<String>,

    pub endpoint: String,
    pub authentication: Option<AuthSpec>,

    pub actions: Vec<ActionSpec>,

    #[serde(default)]
    pub streaming: Option<Value>,
    #[serde(default)]
    pub billing: Option<Value>,
    #[serde(default)]
    pub compliance: Option<Value>,
    #[serde(default)]
    pub metadata: Option<Value>,
    #[serde(default)]
    pub deprecation: Option<Value>,
    #[serde(default)]
    pub extensions: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthSpec {
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(default)]
    pub header_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionSpec {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    pub description: String,
    pub pricing: PricingSpec,
    #[serde(default)]
    pub trust_tier_required: Option<String>,
    #[serde(default)]
    pub rate_limit_rpm: Option<u32>,
    pub input_schema: Value,
    pub output_schema: Value,
    #[serde(default)]
    pub examples: Vec<Value>,
    #[serde(default)]
    pub sla: Option<Value>,
    #[serde(default)]
    pub side_effects: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PricingSpec {
    /// "$0.005" or "0.005" — parser strips "$"
    pub base: String,
    #[serde(default = "default_currency")]
    pub currency: String,
    #[serde(default = "default_pricing_model")]
    pub model: String,
}

fn default_currency() -> String { "USDC".to_string() }
fn default_pricing_model() -> String { "per_call".to_string() }

// ---------------------------------------------------------------------------
// Response
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct PublishResponse {
    pub capability_id: String,
    pub full_id: String,
    pub version: String,
    pub status: String,
    pub action_count: usize,
    pub validation_warnings: Vec<String>,
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

pub async fn publish_manifest(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<PublishResponse>), (StatusCode, Json<Value>)> {
    // ---- auth ----
    let provider = super::providers::authenticate_provider(&state, &headers).await?;

    let pool = state.provider_pool().ok_or_else(|| error(
        StatusCode::SERVICE_UNAVAILABLE, "DB_UNAVAILABLE", "Database not connected"))?;

    // ---- parse body (YAML or JSON, autodetect via Content-Type) ----
    let content_type = headers.get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/x-yaml");

    let yaml_text = std::str::from_utf8(&body).map_err(|_| error(
        StatusCode::BAD_REQUEST, "INVALID_ENCODING", "body must be UTF-8"))?;

    if yaml_text.trim().is_empty() {
        return Err(error(StatusCode::BAD_REQUEST, "EMPTY_BODY", "manifest body is empty"));
    }
    if yaml_text.len() > 256 * 1024 {
        return Err(error(StatusCode::PAYLOAD_TOO_LARGE,
            "MANIFEST_TOO_LARGE", "manifest must be < 256 KiB"));
    }

    let manifest: Manifest = if content_type.contains("json") {
        serde_json::from_str(yaml_text).map_err(|e| error(
            StatusCode::BAD_REQUEST, "PARSE_ERROR",
            &format!("JSON parse failed: {}", e)))?
    } else {
        serde_yaml::from_str(yaml_text).map_err(|e| error(
            StatusCode::BAD_REQUEST, "PARSE_ERROR",
            &format!("YAML parse failed: {}", e)))?
    };

    // ---- validate ----
    let warnings = validate_manifest(&manifest, &provider.namespace)?;

    // Compute parsed JSON for storage
    let parsed_json = serde_json::to_value(&manifest).map_err(|e| error(
        StatusCode::INTERNAL_SERVER_ERROR, "SERIALIZE_ERROR", &e.to_string()))?;

    // SHA256 of yaml content (for audit log)
    let mut hasher = Sha256::new();
    hasher.update(yaml_text.as_bytes());
    let content_sha256 = hex::encode(hasher.finalize());

    let full_id = format!("{}/{}", manifest.namespace, manifest.capability);

    // Status auto-promotion: if Provider has both DNS + Stripe verified, capability goes 'active'
    // immediately and is discoverable via GET /v1/capabilities.
    // Otherwise status='submitted' until Provider completes verification.
    let fully_verified = provider.dns_verified_at.is_some() && provider.stripe_account_verified;

    // ---- DB transaction ----
    let saved = database::publish_manifest(
        pool,
        &provider.id,
        &manifest.capability,
        &manifest.version,
        &full_id,
        &manifest.description,
        &manifest.tags,
        &parsed_json,
        yaml_text,
        &content_sha256,
        fully_verified,
    ).await.map_err(|e| {
        // unique violation -> 409 (capability+version already exists)
        if let sqlx::Error::Database(db_err) = &e {
            if db_err.code().as_deref() == Some("23505") {
                return error(
                    StatusCode::CONFLICT,
                    "VERSION_EXISTS",
                    &format!("capability '{}' version '{}' is already published", full_id, manifest.version),
                );
            }
        }
        tracing::error!("publish_manifest DB error: {}", e);
        error(StatusCode::INTERNAL_SERVER_ERROR, "DB_ERROR", "publish failed")
    })?;

    Ok((StatusCode::CREATED, Json(PublishResponse {
        capability_id: saved.capability_id.to_string(),
        full_id,
        version: manifest.version,
        status: saved.status,
        action_count: manifest.actions.len(),
        validation_warnings: warnings,
    })))
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Returns Ok(warnings) for SHOULD violations, Err for MUST violations.
fn validate_manifest(m: &Manifest, expected_namespace: &str) -> Result<Vec<String>, (StatusCode, Json<Value>)> {
    let mut warnings = Vec::new();

    // ---- MUST checks ----
    if !is_valid_id(&m.namespace, 3, 32) {
        return Err(error(StatusCode::UNPROCESSABLE_ENTITY,
            "INVALID_NAMESPACE",
            "namespace must be 3-32 lowercase alphanumeric+hyphen, starting with letter"));
    }
    // Security: manifest namespace must match the authenticated Provider's namespace
    if m.namespace != expected_namespace {
        return Err(error(StatusCode::FORBIDDEN,
            "NAMESPACE_MISMATCH",
            &format!("manifest namespace '{}' does not match authenticated provider '{}'",
                m.namespace, expected_namespace)));
    }
    if !is_valid_id(&m.capability, 3, 64) {
        return Err(error(StatusCode::UNPROCESSABLE_ENTITY,
            "INVALID_CAPABILITY",
            "capability must be 3-64 lowercase alphanumeric+hyphen, starting with letter"));
    }
    if !is_valid_semver(&m.version) {
        return Err(error(StatusCode::UNPROCESSABLE_ENTITY,
            "INVALID_VERSION",
            "version must be semver (e.g. 1.0.0)"));
    }
    if !m.endpoint.starts_with("https://") {
        return Err(error(StatusCode::UNPROCESSABLE_ENTITY,
            "INVALID_ENDPOINT",
            "endpoint must start with https://"));
    }
    if m.description.trim().is_empty() {
        return Err(error(StatusCode::UNPROCESSABLE_ENTITY,
            "MISSING_DESCRIPTION", "description is required"));
    }
    if m.actions.is_empty() {
        return Err(error(StatusCode::UNPROCESSABLE_ENTITY,
            "NO_ACTIONS", "manifest must declare at least 1 action"));
    }

    // Per-action MUST checks
    for (i, a) in m.actions.iter().enumerate() {
        if !is_valid_id(&a.id, 1, 64) {
            return Err(error(StatusCode::UNPROCESSABLE_ENTITY,
                "INVALID_ACTION_ID",
                &format!("actions[{}].id must be lowercase alphanumeric+hyphen", i)));
        }
        if a.description.trim().is_empty() {
            return Err(error(StatusCode::UNPROCESSABLE_ENTITY,
                "MISSING_ACTION_DESCRIPTION",
                &format!("actions[{}].description is required", i)));
        }
        // pricing.base > 0
        let price_str = a.pricing.base.trim_start_matches('$').trim();
        let price: f64 = price_str.parse().map_err(|_| error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "INVALID_PRICING",
            &format!("actions[{}].pricing.base must be a number (got '{}')", i, a.pricing.base)))?;
        if price <= 0.0 {
            return Err(error(StatusCode::UNPROCESSABLE_ENTITY,
                "INVALID_PRICING",
                &format!("actions[{}].pricing.base must be > 0", i)));
        }
        if !matches!(a.pricing.currency.as_str(), "USD" | "USDC" | "JPY" | "both") {
            return Err(error(StatusCode::UNPROCESSABLE_ENTITY,
                "INVALID_CURRENCY",
                &format!("actions[{}].pricing.currency must be USD, USDC, JPY, or both", i)));
        }
        // schemas must be objects
        if !a.input_schema.is_object() {
            return Err(error(StatusCode::UNPROCESSABLE_ENTITY,
                "INVALID_INPUT_SCHEMA",
                &format!("actions[{}].input_schema must be a JSON object", i)));
        }
        if !a.output_schema.is_object() {
            return Err(error(StatusCode::UNPROCESSABLE_ENTITY,
                "INVALID_OUTPUT_SCHEMA",
                &format!("actions[{}].output_schema must be a JSON object", i)));
        }
        // examples >= 1 (MUST per spec)
        if a.examples.is_empty() {
            return Err(error(StatusCode::UNPROCESSABLE_ENTITY,
                "MISSING_EXAMPLES",
                &format!("actions[{}].examples must contain at least 1 example", i)));
        }
    }

    // ---- SHOULD checks (warnings only) ----
    if m.support_email.is_none() {
        warnings.push("support_email is recommended (spec §5.2 SHOULD)".to_string());
    }
    if m.documentation.is_none() {
        warnings.push("documentation URL is recommended (spec §5.2 SHOULD)".to_string());
    }
    for (i, a) in m.actions.iter().enumerate() {
        if a.rate_limit_rpm.is_none() {
            warnings.push(format!("actions[{}].rate_limit_rpm is recommended", i));
        }
        if a.sla.is_none() {
            warnings.push(format!("actions[{}].sla is recommended", i));
        }
        if a.side_effects.is_none() {
            warnings.push(format!("actions[{}].side_effects declaration is recommended", i));
        }
    }

    Ok(warnings)
}

fn is_valid_id(s: &str, min: usize, max: usize) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() < min || bytes.len() > max { return false; }
    if !bytes[0].is_ascii_lowercase() { return false; }
    bytes.iter().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
}

fn is_valid_semver(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 3 { return false; }
    parts.iter().all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
}

fn error(status: StatusCode, code: &str, message: &str) -> (StatusCode, Json<Value>) {
    (status, Json(json!({
        "jecp": "1.0",
        "status": "failed",
        "error": { "code": code, "message": message }
    })))
}

// ---------------------------------------------------------------------------
// POST /v1/manifests/{capability_id}/promote (Sprint 10)
// ---------------------------------------------------------------------------
//
// Provider が submitted 状態の capability を手動で active に昇格させる。
// 前提: Provider が DNS verified AND Stripe verified。
// 認証: Bearer (Provider api_key)
// 所有権: capability.provider_id が認証 Provider と一致

#[derive(Debug, Serialize)]
pub struct PromoteResponse {
    pub capability_id: String,
    pub full_id: String,
    pub status: String,
    pub message: String,
}

pub async fn promote_capability(
    State(state): State<AppState>,
    Path(capability_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<PromoteResponse>, (StatusCode, Json<Value>)> {
    let provider = super::providers::authenticate_provider(&state, &headers).await?;

    let pool = state.provider_pool().ok_or_else(|| error(
        StatusCode::SERVICE_UNAVAILABLE, "DB_UNAVAILABLE", "Database not connected"))?;

    // 検証要件: DNS + Stripe
    if provider.dns_verified_at.is_none() {
        return Err(error(StatusCode::FAILED_DEPENDENCY,
            "DNS_NOT_VERIFIED",
            "Provider must complete DNS verification before promoting capabilities"));
    }
    if !provider.stripe_account_verified {
        return Err(error(StatusCode::FAILED_DEPENDENCY,
            "STRIPE_NOT_VERIFIED",
            "Provider must complete Stripe Connect onboarding before promoting capabilities"));
    }

    // 所有権 + 現在の status 確認
    let info = database::get_capability_for_provider(pool, &capability_id, &provider.id)
        .await
        .map_err(|e| {
            tracing::error!("get_capability_for_provider: {}", e);
            error(StatusCode::INTERNAL_SERVER_ERROR, "DB_ERROR", "lookup failed")
        })?
        .ok_or_else(|| error(
            StatusCode::NOT_FOUND, "NOT_FOUND",
            "Capability not found, or not owned by this provider"))?;

    let (full_id, current_status) = info;

    if current_status == "active" {
        return Ok(Json(PromoteResponse {
            capability_id: capability_id.to_string(),
            full_id,
            status: "active".to_string(),
            message: "Already active (no change)".to_string(),
        }));
    }
    if current_status != "submitted" {
        return Err(error(StatusCode::CONFLICT,
            "INVALID_STATE_TRANSITION",
            &format!("cannot promote from '{}' (only 'submitted' → 'active' is allowed)", current_status)));
    }

    // v1.1.0 x402 (Am-6 lazy-on-promote): if any action in the manifest
    // declares payment_methods including "x402", attempt to register the
    // capability on the JecpSplitter contract here. The RELAYER signer is
    // a Stub impl in v1.1.0 (DEFERRED — AWS KMS impl pending), so calls
    // return NotImplemented and are logged but do NOT fail the promote.
    // Once the production KMS signer is wired in, this same path submits
    // the tx and persists the on-chain registration row.
    if state.x402.is_some() {
        register_x402_capabilities_best_effort(
            &state,
            pool,
            &provider.id,
            &provider.namespace,
            &capability_id,
        )
        .await;
    }

    let promoted = database::promote_capability(pool, &capability_id).await
        .map_err(|e| {
            tracing::error!("promote_capability: {}", e);
            error(StatusCode::INTERNAL_SERVER_ERROR, "DB_ERROR", "promote failed")
        })?;

    Ok(Json(PromoteResponse {
        capability_id: capability_id.to_string(),
        full_id,
        status: "active".to_string(),
        message: if promoted {
            "Promoted to active".to_string()
        } else {
            "No state change (concurrent update)".to_string()
        },
    }))
}

// ---------------------------------------------------------------------------
// DELETE /v1/manifests/{capability_id} (Sprint 10) — sunset
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct SunsetResponse {
    pub capability_id: String,
    pub full_id: String,
    pub status: String,
}

pub async fn sunset_capability(
    State(state): State<AppState>,
    Path(capability_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<SunsetResponse>, (StatusCode, Json<Value>)> {
    let provider = super::providers::authenticate_provider(&state, &headers).await?;

    let pool = state.provider_pool().ok_or_else(|| error(
        StatusCode::SERVICE_UNAVAILABLE, "DB_UNAVAILABLE", "Database not connected"))?;

    let info = database::get_capability_for_provider(pool, &capability_id, &provider.id)
        .await
        .map_err(|e| {
            tracing::error!("get_capability_for_provider: {}", e);
            error(StatusCode::INTERNAL_SERVER_ERROR, "DB_ERROR", "lookup failed")
        })?
        .ok_or_else(|| error(
            StatusCode::NOT_FOUND, "NOT_FOUND",
            "Capability not found, or not owned by this provider"))?;

    let (full_id, current_status) = info;

    if current_status == "sunset" {
        return Ok(Json(SunsetResponse {
            capability_id: capability_id.to_string(),
            full_id,
            status: "sunset".to_string(),
        }));
    }

    let _ = database::sunset_capability(pool, &capability_id, &provider.id).await
        .map_err(|e| {
            tracing::error!("sunset_capability: {}", e);
            error(StatusCode::INTERNAL_SERVER_ERROR, "DB_ERROR", "sunset failed")
        })?;

    Ok(Json(SunsetResponse {
        capability_id: capability_id.to_string(),
        full_id,
        status: "sunset".to_string(),
    }))
}

// ───────────────────────────────────────────────────────────────────────────
// v1.1.0 x402 Am-6 — lazy-on-promote Splitter.register() helper
// ───────────────────────────────────────────────────────────────────────────

/// For each action in the capability's manifest whose payment_methods
/// include "x402", attempt to register the capability on the JecpSplitter
/// contract. The RELAYER stub returns NotImplemented in v1.1.0; failures
/// here are LOGGED but do NOT block the DB promote.
///
/// When the production AWS KMS signer is dropped in, the same code path
/// will: (a) collect Provider's EIP-712 signature from manifest extension,
/// (b) submit the tx, (c) record into jecp.provider_capabilities_onchain.
async fn register_x402_capabilities_best_effort(
    state: &AppState,
    pool: &sqlx::PgPool,
    provider_id: &Uuid,
    namespace: &str,
    capability_id: &Uuid,
) {
    let cfg = match state.x402.as_ref() {
        Some(c) => c,
        None => return,
    };

    // Audit C-2 / G18: read the Provider's USDC payout address from DB.
    // If absent, REFUSE to register on-chain — falling back to
    // `cfg.splitter_address` (the prior placeholder) would burn 85% of USDC
    // into the Splitter itself with no withdraw path once KMS lands. Better
    // to skip the register call entirely until the Provider supplies a
    // payout address.
    let payout_row = sqlx::query(
        "SELECT usdc_payout_address FROM jecp.providers WHERE id = $1",
    )
    .bind(provider_id)
    .persistent(false)
    .fetch_optional(pool)
    .await;

    use sqlx::Row;
    let payout_address_str: Option<String> = match payout_row {
        Ok(Some(row)) => row.try_get::<Option<String>, _>("usdc_payout_address").ok().flatten(),
        Ok(None) => None,
        Err(e) => {
            tracing::warn!(
                provider_id = %provider_id,
                error = %e,
                "x402 lazy-on-promote: failed to read usdc_payout_address; skipping on-chain register"
            );
            return;
        }
    };
    let payout_address_str = match payout_address_str {
        Some(s) => s,
        None => {
            tracing::warn!(
                provider_id = %provider_id,
                namespace = %namespace,
                "x402 lazy-on-promote: Provider has no usdc_payout_address; skipping on-chain register (capability promote continues). Provider must update payout address before x402 settles can route 85% USDC correctly."
            );
            return;
        }
    };
    let provider_address: alloy_primitives::Address = match payout_address_str.parse() {
        Ok(a) => a,
        Err(e) => {
            tracing::error!(
                provider_id = %provider_id,
                payout_address = %payout_address_str,
                error = %e,
                "x402 lazy-on-promote: stored usdc_payout_address is not a valid Address; skipping"
            );
            return;
        }
    };

    // Fetch the manifest JSON to read action ids + payment_methods.
    let row = match sqlx::query(
        "SELECT m.parsed_json, c.version
           FROM jecp.manifests m
           JOIN jecp.capabilities c ON c.id = m.capability_id
          WHERE m.capability_id = $1",
    )
    .bind(capability_id)
    .persistent(false)
    .fetch_optional(pool)
    .await
    {
        Ok(Some(r)) => r,
        _ => {
            tracing::warn!(
                capability_id = %capability_id,
                "x402 lazy-on-promote: manifest not found, skipping"
            );
            return;
        }
    };

    let parsed: Value = match row.try_get("parsed_json") {
        Ok(v) => v,
        Err(_) => return,
    };
    let version: String = row.try_get("version").unwrap_or_default();

    let actions = parsed
        .get("actions")
        .and_then(|a| a.as_array())
        .cloned()
        .unwrap_or_default();

    for action in &actions {
        let methods = action
            .get("pricing")
            .and_then(|p| p.get("payment_methods"))
            .and_then(|m| m.as_array());
        let accepts_x402 = methods
            .map(|arr| arr.iter().any(|v| v.as_str() == Some("x402")))
            .unwrap_or(false);
        if !accepts_x402 {
            continue;
        }
        let action_id = match action.get("id").and_then(|i| i.as_str()) {
            Some(s) => s,
            None => continue,
        };

        let cap_b256 = crate::services::splitter_registry::derive_capability_id(
            namespace, action_id, &version,
        );

        // Audit C-2: provider address now comes from the Provider's DB
        // record (usdc_payout_address), not cfg.splitter_address. Refusing
        // to register when missing is the fail-closed behavior.
        use crate::services::x402_relayer::{RegisterAuthorization, RelayerError};
        let auth = RegisterAuthorization {
            capability_id: cap_b256,
            provider: provider_address,
            provider_bps: 8500,
            hub_bps: 1000,
            reserve_bps: 500,
            nonce: alloy_primitives::B256::ZERO,
            deadline: 0,
        };
        let dummy_sig = [0u8; 65];

        match cfg
            .relayer
            .send_register_tx(cfg.splitter_address, &auth, &dummy_sig)
            .await
        {
            Ok(receipt) => {
                tracing::info!(
                    namespace = %namespace,
                    action_id = %action_id,
                    provider_address = %provider_address,
                    tx_hash = ?receipt.tx_hash,
                    "x402 Splitter.register() succeeded"
                );
                // Production path: persist into jecp.provider_capabilities_onchain.
            }
            Err(RelayerError::NotImplemented) => {
                tracing::warn!(
                    namespace = %namespace,
                    action_id = %action_id,
                    "x402 lazy-on-promote: RELAYER stub (DEFERRED). Production AWS KMS impl pending; promote continues without on-chain register."
                );
            }
            Err(e) => {
                tracing::error!(
                    namespace = %namespace,
                    action_id = %action_id,
                    error = %e,
                    "x402 Splitter.register() failed; promote continues but on-chain state is stale"
                );
            }
        }
    }
}
