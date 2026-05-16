//! Provider invocation routing (Sprint 11 / Stage 3).
//!
//! POST /v1/invoke
//!   - Auth: X-Agent-ID + X-API-Key (matching /v1/jecp pattern)
//!   - Body: { jecp, id, capability: "namespace/capability", action, input }
//!   - 流れ:
//!       1. Agent 認証 (agent_profiles)
//!       2. Capability lookup (jecp.capabilities + jecp.providers join)
//!       3. HMAC-SHA256 署名生成 (provider.hmac_secret 使用)
//!       4. Provider endpoint へ POST forward
//!       5. response 受信 → JECP envelope に wrap して agent に返却
//!       6. capability.total_calls / provider.total_calls をインクリメント
//!
//! Sprint 11 では billing は実装しない (Sprint 12 で wallet deduct + revenue split)

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::Json;
use futures::StreamExt;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::convert::Infallible;
use std::time::{Duration, Instant};

use crate::auth::agent::{authenticate_agent, verify_provenance, TrustTier};
use crate::auth::replay_cache::Replay;
use crate::protocol::errors::{JecpErrorCode, ProvenanceSubcause};
use crate::protocol::types::Mandate;
use crate::services::database;
use crate::AppState;

// W5 streaming constants (design doc §4)
const STREAM_NOPROGRESS_TIMEOUT_SECS: u64 = 30;
const STREAM_TOTAL_TIMEOUT_SECS: u64 = 300;

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct InvokeRequest {
    pub jecp: String,
    pub id: String,
    pub capability: String, // "namespace/capability" format
    pub action: String,
    #[serde(default)]
    pub input: Value,
    /// Optional pre-authorized budget cap (Sprint 14 / Spec §4)
    #[serde(default)]
    pub mandate: Option<Mandate>,
}

#[derive(Debug, Serialize)]
pub struct InvokeResponse {
    pub jecp: String,
    pub id: String,
    pub status: String,
    pub result: Value,
    pub provider: ProviderRef,
}

#[derive(Debug, Serialize)]
pub struct ProviderRef {
    pub namespace: String,
    pub capability: String,
    pub version: String,
}

// ---------------------------------------------------------------------------
// Handler — top-level dispatcher (Accept-header based content negotiation)
// ---------------------------------------------------------------------------

/// POST /v1/invoke — third-party capability invocation.
///
/// Content negotiation:
/// - `Accept: text/event-stream` → SSE streaming response (W5)
/// - default → single JSON response
pub async fn invoke_capability(
    state: State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // K2.1 (v1.0.2): Content-Type negotiation. Reject non-JSON with 415
    // before any further work. Tolerates missing CT (admiral D1).
    // Applied here at the dispatch boundary so both stream + non-stream
    // paths inherit the same wire-level guard.
    if let Err(e) = crate::protocol::http_guards::ensure_json_ct(&headers) {
        return e.into_response();
    }

    let wants_stream = headers
        .get("accept")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.contains("text/event-stream"))
        .unwrap_or(false);

    if wants_stream {
        invoke_capability_stream(state, headers, body).await
    } else {
        invoke_capability_json(state, headers, body).await.into_response()
    }
}

// ---------------------------------------------------------------------------
// JSON path (existing non-streaming flow)
// ---------------------------------------------------------------------------

async fn invoke_capability_json(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<Value>), axum::response::Response> {
    // ---- parse body ----
    let req: InvokeRequest = serde_json::from_slice(&body).map_err(|e| error(
        StatusCode::BAD_REQUEST, "PARSE_ERROR",
        &format!("Failed to parse JSON: {}", e)))?;

    if req.jecp != "1.0" {
        return Err(error(StatusCode::BAD_REQUEST,
            "UNSUPPORTED_PROTOCOL", "jecp version must be '1.0'"));
    }
    if req.id.is_empty() {
        return Err(error(StatusCode::BAD_REQUEST,
            "MISSING_ID", "id is required"));
    }
    if !req.capability.contains('/') {
        return Err(error(StatusCode::BAD_REQUEST,
            "INVALID_CAPABILITY",
            "capability must be in 'namespace/name' format (e.g., 'deepl/translate')"));
    }

    // ---- agent auth ----
    let agent_id = headers.get("x-agent-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or_else(|| error(
            StatusCode::UNAUTHORIZED, "AUTH_REQUIRED",
            "Missing X-Agent-ID header"))?;
    let api_key = headers.get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or_else(|| error(
            StatusCode::UNAUTHORIZED, "AUTH_REQUIRED",
            "Missing X-API-Key header"))?;

    let pool = state.invoke_pool().ok_or_else(|| error(
        StatusCode::SERVICE_UNAVAILABLE, "DB_UNAVAILABLE", "Database not connected"))?;

    let agent = authenticate_agent(pool, &agent_id, &api_key).await
        .map_err(|_| error(StatusCode::UNAUTHORIZED, "INVALID_AGENT", "Agent authentication failed"))?;

    // ---- Provenance verification (v1.0.1 / spec §5) ----
    // H1 from v1.0.1 design doc: /v1/invoke previously did NOT verify
    // mandate.provenance_hash. The spec is silent on which routes carry the
    // check; the only defensible reading is "every authenticated route that
    // accepts a Mandate". Wire it here so /v1/invoke and /v1/jecp share one
    // semantics.
    //
    // Subcause emission policy (spec §3.1): only after authenticate_agent
    // succeeds (which it just did above), so we are post-auth here — emitting
    // the closed-registry subcause is safe.
    // v1.0.1 Note: Deprecation/Sunset RFC 8594 response headers on v1
    // success are wired only on `/v1/jecp` for v1.0.1 (where v1 traffic
    // concentrates; this is the legacy route). `/v1/invoke` is the v2-primary
    // route and almost no v1 traffic reaches it; header support here lands in
    // v1.0.2 alongside a handler-signature refactor (Result<Response,...>).
    if let Some(ref mandate) = req.mandate {
        if let Some(ref claimed_hash) = mandate.provenance_hash {
            match verify_provenance(&agent, &mandate.api_key, claimed_hash) {
                Ok(Some((_ts, nonce))) => {
                    // v2 path — register (agent_id, nonce) in replay cache.
                    if state.replay_cache.check_and_insert(&agent_id, &nonce) == Replay::Replay {
                        return Err(jecp_provenance_error(
                            ProvenanceSubcause::NonceReplay,
                            "Provenance v2 nonce already observed within replay window — generate a fresh nonce per request.",
                            None,
                        ));
                    }
                }
                Ok(None) => {
                    // v1 path — no nonce, no replay defense (legacy semantics).
                }
                Err(JecpErrorCode::ProvenanceMismatch { reason, subcause, drift_seconds }) => {
                    return Err(jecp_provenance_error(subcause, &reason, drift_seconds));
                }
                Err(other) => {
                    // Defensive: verify_provenance only returns ProvenanceMismatch
                    // today, but if a future variant slips through we surface a
                    // generic error rather than dropping it.
                    return Err(error(StatusCode::FORBIDDEN, "PROVENANCE_MISMATCH", &other.to_string()));
                }
            }
        }
    }

    // ---- rate limit (P0 fix #4) ----
    // Default 60 RPM per agent (per-action overrides come from manifest at Sprint 13)
    // K2.4 (v1.0.2): emit Retry-After header per RFC 9110 §10.2.3 via JECP envelope.
    match state.rate_limiter.check(&agent_id, Some(60)).await {
        Ok(_) => {}
        Err(decision) => {
            return Err(JecpErrorCode::RateLimited {
                retry_after_secs: decision.retry_after_secs,
            }
            .into_response());
        }
    }

    // ---- idempotency cache (P0 fix #1) ----
    // JECP Spec §5: same (agent_id, request_id) within 24h MUST return cached response.
    // v1.1.0 x402 (ADR-0004 / Panel 2 TM-D2): input hash includes the X-Payment
    // header SHA-256 when present so a wallet→x402 retry on the same request_id
    // is treated as a distinct request (DUPLICATE_REQUEST) rather than a cache hit.
    let x_payment_header_raw = headers
        .get("x-payment")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let input_hash = compute_input_hash(&req, x_payment_header_raw.as_deref());
    if let Ok(Some(cached)) = database::cache_lookup(pool, &agent_id, &req.id, &input_hash).await {
        if cached.conflict {
            // K2.2 (v1.0.2): per RFC 9110 §15.5.10, same id + different
            // (capability, action, input, provenance_hash) → 409 CONFLICT,
            // NOT 400. Same id + identical payload returns the cached
            // response in the branch below (idempotency hit).
            return Err(error(
                StatusCode::CONFLICT,
                "DUPLICATE_REQUEST",
                "request id reused with different (capability, action, input) within idempotency window",
            ));
        }
        if let Some(body) = cached.response {
            tracing::info!("invoke idempotent hit agent={} id={}", agent_id, req.id);
            let status = StatusCode::from_u16(cached.http_status as u16).unwrap_or(StatusCode::OK);
            // H-2 / audit A-H3+A-H4: Cache-Control: no-store + CORS expose on
            // idempotent cache replays too (same wire shape as live response).
            let mut resp = (status, Json(body)).into_response();
            crate::protocol::x402_response_headers::apply_invoke_headers(resp.headers_mut());
            return Err(resp);
        }
    }

    // ---- capability lookup ----
    let resolved = database::resolve_capability_for_invoke(pool, &req.capability).await
        .map_err(|e| {
            tracing::error!("resolve_capability_for_invoke: {}", e);
            error(StatusCode::INTERNAL_SERVER_ERROR, "DB_ERROR", "lookup failed")
        })?
        .ok_or_else(|| error(
            StatusCode::NOT_FOUND, "CAPABILITY_NOT_FOUND",
            &format!("'{}' is not a published active capability", req.capability)))?;

    // ---- K2.3 (v1.0.2): capability sunset check ----
    // If the manifest's `sunset_at` has passed, the Hub MUST return 410 GONE
    // CAPABILITY_DEPRECATED with RFC 8594 + IETF Deprecation headers.
    // Spec §4.6 + 03-errors §3.3. Successor URL extraction is best-effort;
    // when the manifest declares `successor_version` we surface it as a
    // `Link rel="successor-version"` header.
    if let Some(sunset_at) = resolved.sunset_at {
        if sunset_at <= chrono::Utc::now() {
            let successor = resolved
                .parsed_json
                .get("deprecation")
                .and_then(|d| d.get("successor_version"))
                .and_then(|s| s.as_str())
                .map(|s| s.to_string());
            return Err(JecpErrorCode::CapabilityDeprecated {
                capability: req.capability.clone(),
                sunset_at,
                successor,
            }
            .into_response());
        }
        // TODO(v1.0.3): 30-day pre-sunset notice. Per spec §4.6, when
        // (sunset_at - now()) <= 30 days AND the request would otherwise
        // succeed, Hubs MUST also attach Sunset/Deprecation/Link headers
        // to the 2xx response. Implementation requires post-hoc header
        // injection on the success path — tracked for v1.0.3 alongside
        // the broader N6 invoke.rs Result<Response,_> refactor.
    }

    // ---- K2.5 (v1.0.2): input_schema validation against manifest ----
    // Per spec 01-protocol §4.5 + 03-errors §3.2. When the manifest declares
    // an input_schema for the action, the Hub MUST validate the request's
    // `input` against it and reject violators with HTTP 400
    // INPUT_SCHEMA_VIOLATION (admiral D3 = 400 not 422; matches Stripe /
    // GitHub / Twilio convention for invalid params). When no input_schema
    // is declared, validation is a graceful pass — preserves backward compat
    // for pre-v1.0.2 manifests.
    if let Err(e) = crate::protocol::schema_validator::validate_input_against_manifest(
        &*state.schema_cache,
        resolved.capability_id,
        &req.action,
        &resolved.parsed_json,
        &req.input,
    ) {
        return Err(e.into_response());
    }

    // ---- pricing resolution (Sprint 12) ----
    let price_usdc = extract_action_price(&resolved.parsed_json, &req.action)
        .ok_or_else(|| error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "ACTION_NOT_FOUND",
            &format!("action '{}' is not declared in capability '{}'",
                req.action, req.capability)))?;

    // ---- Trust Gate (Sprint 14 / Spec §5) ----
    // Read action.trust_tier_required from manifest. Default to "bronze".
    let required_tier_str = extract_action_trust_tier(&resolved.parsed_json, &req.action)
        .unwrap_or_else(|| "bronze".to_string());
    let required_tier = parse_trust_tier(&required_tier_str)
        .ok_or_else(|| error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "INVALID_TRUST_TIER",
            &format!("manifest action '{}' has unknown trust_tier_required '{}'",
                req.action, required_tier_str)))?;
    let current_tier = agent.trust_tier();
    if current_tier < required_tier {
        return Err(error(
            StatusCode::FORBIDDEN,
            "INSUFFICIENT_TRUST",
            &format!("action '{}' requires trust tier '{}' (you are '{}'). Earn trust by accumulating successful calls.",
                req.action, required_tier, current_tier),
        ));
    }

    // ---- Mandate budget check (Sprint 14 / Spec §4) ----
    if let Some(m) = &req.mandate {
        if let Some(expires) = m.expires_at {
            if expires < chrono::Utc::now() {
                return Err(error(
                    StatusCode::FORBIDDEN,
                    "MANDATE_EXPIRED",
                    "mandate.expires_at is in the past",
                ));
            }
        }
        if let Some(budget) = m.budget_usdc {
            if budget < price_usdc {
                // 402 PAYMENT_REQUIRED — extend with `payment.accepts[]` per
                // locked-design v1.1.1 §3.1 so the agent can immediately
                // retry over x402 (when capability accepts it) or top up.
                // Audit A-C7: omit x402 entry if the runtime kill switch is off.
                let x402_runtime_enabled = if state.x402.is_some() {
                    state.flags.is_enabled(&state.pool, "x402_enabled").await
                } else { false };
                return Err(payment_required_response(
                    &state,
                    x402_runtime_enabled,
                    &resolved.parsed_json,
                    &resolved.namespace,
                    &resolved.capability_name,
                    &req.action,
                    &resolved.version,
                    &req.id,
                    "INSUFFICIENT_BUDGET",
                    &format!("Mandate budget {:.6} USDC < required {:.6} USDC for this action.",
                        budget, price_usdc),
                    price_usdc,
                    Some(budget),
                ));
            }
        }
    }

    // ---- v1.1.0 x402 (locked-design §5.6) — payment-method dispatch ----
    // If the agent sent an X-Payment header AND state.x402 is configured
    // AND the capability accepts x402 AND the feature flag is on → run the
    // x402 settlement path. Otherwise fall through to the wallet path.
    //
    // Note: dispatch_x402 returns `NoXPayment` when the header is absent;
    // `FallthroughToWallet` when x402 isn't configured / feature off / not
    // accepted; `Settled(billing)` on success; or `Error(X402Error)` on
    // hard failure. Hard errors map to the 5 new error codes per §3.5.
    let x402_outcome = super::invoke_x402::dispatch_x402(
        &state,
        &headers,
        &resolved.namespace,
        &resolved.capability_name,
        &req.action,
        &resolved.version,
        &agent_id,
        &req.id,
        price_usdc,
        &resolved.parsed_json,
    )
    .await;

    let x402_billing = match x402_outcome {
        super::invoke_x402::X402Outcome::Settled(b) => Some(b),
        super::invoke_x402::X402Outcome::NoXPayment
        | super::invoke_x402::X402Outcome::FallthroughToWallet => None,
        super::invoke_x402::X402Outcome::Error(e) => {
            let facilitator_url = state
                .x402
                .as_ref()
                .map(|c| c.facilitator.base_url_str());
            return Err(x402_error_response(&e, &req.id, facilitator_url.as_deref()));
        }
    };

    // ---- pre-flight balance check (Sprint 12) — wallet path only ----
    if x402_billing.is_none() {
        let balance = database::get_wallet_balance(pool, &agent_id).await
            .map_err(|e| {
                tracing::error!("get_wallet_balance: {}", e);
                error(StatusCode::INTERNAL_SERVER_ERROR, "DB_ERROR", "balance lookup failed")
            })?;
        if balance < price_usdc {
            // 402 PAYMENT_REQUIRED — extend with `payment.accepts[]` per
            // locked-design v1.1.1 §3.1. Stripe top-up entry is included by
            // default; x402 entry is added when manifest declares it and the
            // Hub kill-switch is on (state.x402.is_some()).
            // Audit A-C7: omit x402 entry when the runtime kill switch is off.
            let x402_runtime_enabled = if state.x402.is_some() {
                state.flags.is_enabled(&state.pool, "x402_enabled").await
            } else { false };
            return Err(payment_required_response(
                &state,
                x402_runtime_enabled,
                &resolved.parsed_json,
                &resolved.namespace,
                &resolved.capability_name,
                &req.action,
                &resolved.version,
                &req.id,
                "INSUFFICIENT_BALANCE",
                &format!("Wallet balance {:.6} USDC < required {:.6} USDC. Top up at /v1/wallet/topup",
                    balance, price_usdc),
                price_usdc,
                Some(balance),
            ));
        }
    }

    // ---- HMAC sign ----
    let forward_body = json!({
        "jecp": "1.0",
        "id": req.id,
        "capability": req.capability,
        "action": req.action,
        "input": req.input,
    });
    let body_bytes = serde_json::to_vec(&forward_body).map_err(|e| error(
        StatusCode::INTERNAL_SERVER_ERROR, "SERIALIZE_ERROR", &e.to_string()))?;
    let timestamp = chrono::Utc::now().timestamp();
    let signature = compute_hmac_signature(
        &resolved.hmac_secret,
        timestamp,
        &body_bytes,
    ).map_err(|e| error(
        StatusCode::INTERNAL_SERVER_ERROR, "HMAC_ERROR", &e))?;

    // ---- forward to Provider ----
    // v1.1.0 c7 — SSRF defense at deref time. Validate + DNS resolve +
    // deny-CIDR check + IP pin. Spec §9.7.1.
    let validated = crate::protocol::url_guard::validate_outbound_url(&resolved.endpoint_url)
        .await
        .map_err(|e| {
            let safe_url = crate::protocol::url_guard::redact_url(&resolved.endpoint_url);
            let reason = e.reason().to_string();
            // Audit + log (best effort, fire-and-forget on a separate task
            // to keep the request path fast).
            if let Some(pool) = state.invoke_pool().cloned() {
                let aid = agent_id.clone();
                let pid = resolved.provider_id;
                let url_for_audit = safe_url.clone();
                let reason_for_audit = reason.clone();
                tokio::spawn(async move {
                    crate::protocol::url_guard::audit_log_rejection(
                        &pool, Some(&aid), Some(pid),
                        "endpoint_url", "invoke_forward",
                        &url_for_audit, &reason_for_audit, None,
                    ).await;
                });
            }
            crate::protocol::url_guard::url_blocked_ssrf_tuple(
                "endpoint_url", &safe_url, &reason,
            )
        })
        .map_err(|tuple| (tuple.0, tuple.1).into_response())?;

    let client = crate::protocol::url_guard::guarded_client(&validated.host, validated.pinned_addr)
        .map_err(|e| error(
            StatusCode::INTERNAL_SERVER_ERROR, "HTTP_CLIENT", &e.to_string()).into_response())?;

    let resp = client.post(&resolved.endpoint_url)
        .header("content-type", "application/json")
        .header("x-jecp-signature", &signature)
        .header("x-jecp-timestamp", timestamp.to_string())
        .header("x-jecp-namespace", &resolved.namespace)
        .header("x-jecp-action", &req.action)
        .body(body_bytes)
        .send()
        .await
        .map_err(|e| {
            tracing::warn!(
                "forward to {} failed: {}",
                resolved.endpoint_url, e
            );
            error(StatusCode::BAD_GATEWAY, "PROVIDER_UNREACHABLE",
                  &format!("Provider endpoint unreachable: {}", e))
        })?;

    let status_code = resp.status();

    // Capture Provider's response Content-Type for proper artifact handling
    let provider_content_type = resp.headers().get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json")
        .to_string();

    let resp_bytes = resp.bytes().await.unwrap_or_default();

    if !status_code.is_success() {
        let truncated_body = String::from_utf8_lossy(
            &resp_bytes[..std::cmp::min(500, resp_bytes.len())]
        ).into_owned();
        return Err(error(
            StatusCode::BAD_GATEWAY,
            "PROVIDER_ERROR",
            &format!("Provider returned {}: {}",
                     status_code, truncated_body),
        ));
    }

    // Sprint 15: Binary artifact support.
    // If Provider returns JSON or text → parse as JSON (existing behavior).
    // If Provider returns binary (image/pdf/etc) → wrap as artifact metadata
    // with base64 inline data. This makes Binary artifacts ✓ true on /v1/invoke.
    const MAX_INLINE_BINARY: usize = 10 * 1024 * 1024; // 10 MiB
    let is_textual = provider_content_type.starts_with("application/json")
        || provider_content_type.starts_with("text/")
        || provider_content_type.starts_with("application/xml");

    let provider_response: Value = if is_textual {
        let text = String::from_utf8_lossy(&resp_bytes).into_owned();
        serde_json::from_str(&text).unwrap_or_else(|_| json!({ "raw": text }))
    } else if resp_bytes.len() > MAX_INLINE_BINARY {
        // Too large to inline — surface metadata only with a note
        json!({
            "artifact": {
                "content_type": provider_content_type,
                "size_bytes": resp_bytes.len(),
                "inline": false,
                "note": "Artifact exceeds 10 MiB inline limit. Provider should return a URL via DeliveryMode::Url instead.",
            }
        })
    } else {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&resp_bytes);
        json!({
            "artifact": {
                "content_type": provider_content_type,
                "size_bytes": resp_bytes.len(),
                "inline": true,
                "data_base64": b64,
            }
        })
    };

    // ---- billing: atomic deduct + revenue split (P0 fix #2) ----
    // jecp.invoke_charge() function does deduct + split in single transaction.
    // Either both succeed, or neither does (no inconsistency window).
    let mut billing_summary = json!({
        "charged": false,
        "amount_usdc": price_usdc,
    });
    let mut new_balance: Option<f64> = None;

    // v1.1.0 x402: when x402 settled, the on-chain Splitter has already
    // distributed funds. Hub does NOT call invoke_charge() (wallet path);
    // billing summary is built from the settlement record.
    if let Some(ref b) = x402_billing {
        billing_summary = b.to_billing_summary();
    }

    let charge_result = if x402_billing.is_some() {
        // Skip wallet charge entirely — x402 path settled on-chain.
        Ok(None)
    } else {
        database::invoke_charge(
        pool,
        &agent_id,
        price_usdc,
        &resolved.capability_name,
        &req.action,
        &req.id,
        &resolved.provider_id,
        &resolved.capability_id,
    ).await
    };

    match charge_result {
        Ok(Some(c)) => {
            new_balance = Some(c.balance_after);
            billing_summary = json!({
                "charged": true,
                "amount_usdc": price_usdc,
                "transaction_id": c.transaction_id,
                "balance_after": c.balance_after,
                "provider_share_usdc": c.provider_share_usdc,
                "hub_fee_usdc": c.hub_fee_usdc,
                "payment_fee_usdc": c.payment_fee_usdc,
            });

            // W4 — fire invocation.completed events to both agent and provider
            let agent_id_clone = agent_id.clone();
            let provider_id_str = resolved.provider_id.to_string();
            let cap_id_str = resolved.capability_id.to_string();
            let action_clone = req.action.clone();
            let request_id_clone = req.id.clone();
            let pool_for_events = pool.clone();
            let payload = json!({
                "transaction_id": c.transaction_id,
                "agent_id": agent_id,
                "provider_id": provider_id_str,
                "capability_id": cap_id_str,
                "action": action_clone,
                "request_id": request_id_clone,
                "amount_usdc": price_usdc,
                "balance_after": c.balance_after,
                "provider_share_usdc": c.provider_share_usdc,
            });
            tokio::spawn(async move {
                crate::services::webhooks::enqueue(&pool_for_events, &agent_id_clone, "agent", "invocation.completed", payload.clone()).await;
                crate::services::webhooks::enqueue(&pool_for_events, &provider_id_str, "provider", "invocation.completed", payload.clone()).await;

                // Low-balance hint event (≤ $0.50)
                if c.balance_after < 0.50 {
                    let low_balance_payload = json!({
                        "agent_id": agent_id_clone,
                        "balance_after": c.balance_after,
                        "threshold_usdc": 0.50,
                    });
                    crate::services::webhooks::enqueue(&pool_for_events, &agent_id_clone, "agent", "wallet.low_balance", low_balance_payload).await;
                }
            });
        }
        Ok(None) => {
            // Insufficient balance race — Provider work done but no charge.
            // (rare, only happens if balance was depleted between pre-flight check and deduct)
            tracing::warn!(
                "atomic deduct race: agent={} amount={} cap={} (Provider invocation succeeded but charge failed)",
                agent_id, price_usdc, req.capability
            );
        }
        Err(e) => {
            tracing::error!("invoke_charge error (non-fatal): {}", e);
        }
    }

    // ---- update stats (async, non-blocking) ----
    let pool_clone = pool.clone();
    let cap_id = resolved.capability_id;
    let prov_id = resolved.provider_id;
    tokio::spawn(async move {
        if let Err(e) = database::increment_capability_calls(&pool_clone, &cap_id, &prov_id).await {
            tracing::warn!("increment_capability_calls failed: {}", e);
        }
    });

    // ---- assemble response ----
    let result = if let Some(r) = provider_response.get("result") {
        r.clone()
    } else {
        provider_response
    };

    let mut resp_obj = json!({
        "jecp": "1.0",
        "id": req.id,
        "status": "success",
        "result": result,
        "provider": {
            "namespace": resolved.namespace,
            "capability": resolved.capability_name,
            "version": resolved.version,
        },
        "billing": billing_summary,
    });
    if let Some(bal) = new_balance {
        resp_obj["wallet_balance_after"] = json!(bal);
    }

    // ---- idempotency cache store (P0 fix #1) ----
    // 24h 内の retry に同じレスポンスを返すため永続化
    if let Err(e) = database::cache_store(
        pool,
        &agent_id,
        &req.id,
        &resolved.capability_name,
        &req.action,
        &input_hash,
        &resp_obj,
        200,
    ).await {
        tracing::warn!("cache_store failed (non-fatal): {}", e);
    }

    // v1.1.0 x402 (locked-design §3.4): attach `X-Payment-Response`
    // header on x402-settled responses. We return through the Err arm of
    // the Result because the existing signature is
    // `Result<(StatusCode, Json<Value>), Response>` — and axum converts
    // both arms via IntoResponse identically. This avoids reshaping the
    // entire handler signature for a single header on the x402 branch.
    if let Some(b) = x402_billing.as_ref() {
        let mut resp = (StatusCode::OK, Json(resp_obj)).into_response();
        use axum::http::HeaderValue;
        if let Ok(v) = HeaderValue::from_str(&b.payment_response_b64) {
            resp.headers_mut().insert("x-payment-response", v);
        }
        // H-2 / audit A-H3+A-H4: Cache-Control: no-store + CORS expose on
        // every x402-settled 200 (spec §5 / §5.2).
        crate::protocol::x402_response_headers::apply_invoke_headers(resp.headers_mut());
        return Err(resp);
    }

    // H-2 / audit A-H3+A-H4: Cache-Control: no-store + CORS expose on every
    // /v1/invoke response — wallet path included.
    let mut resp = (StatusCode::OK, Json(resp_obj)).into_response();
    crate::protocol::x402_response_headers::apply_invoke_headers(resp.headers_mut());
    Err(resp)
}

// ─────────────────────────────────────────────────────────────────────────────
// v1.1.0 x402 — error envelope builder (locked-design §3.5)
// ─────────────────────────────────────────────────────────────────────────────

/// Build the JECP error envelope for an X402Error. Maps to one of the 5
/// new error codes from spec §3.5.
///
/// Variant-aware per Audit A-C5/A-C6/A-M1/A-M2/A-M3/A-M6: each error code
/// carries the spec-mandated `details.*` keys (accepted/received, facilitator_url,
/// last_error, elapsed_ms etc.) and HTTP headers (Retry-After) so SDKs can
/// recover deterministically.
fn x402_error_response(
    e: &crate::protocol::x402_types::X402Error,
    request_id: &str,
    facilitator_url: Option<&str>,
) -> axum::response::Response {
    use axum::http::StatusCode;
    use crate::protocol::x402_types::X402Error;
    let status = StatusCode::from_u16(e.http_status())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    let documentation_url = format!(
        "https://jecp.dev/errors/{}",
        e.code().to_lowercase()
    );

    // Build the `details` object per spec §3.5 — variant-specific keys.
    let mut details = serde_json::Map::new();
    details.insert("subcause".into(), json!(e.subcause()));
    details.insert("documentation_url".into(), json!(documentation_url));

    let mut next_action: Option<Value> = None;
    let mut retry_after_secs: Option<u32> = None;

    match e {
        X402Error::NotAccepted { .. } => {
            // Spec: `accepted: [...], received: "x402"` (Audit A-C5).
            details.insert("accepted".into(), json!(["stripe"]));
            details.insert("received".into(), json!("x402"));
        }
        X402Error::FacilitatorUnreachable { subcause, message } => {
            // Spec: facilitator_url + last_error + Retry-After + next_action (Audit A-C6).
            if let Some(url) = facilitator_url {
                details.insert("facilitator_url".into(), json!(url));
            }
            details.insert("last_error".into(), json!(format!("{}: {}", subcause, message)));
            retry_after_secs = Some(30);
            next_action = Some(json!({
                "type": "topup",
                "ui": "https://jecp.dev/account/topup",
                "hint": "x402 settlement is currently unavailable. Top up the wallet to continue.",
            }));
        }
        X402Error::SettlementTimeout { subcause, message, elapsed_ms } => {
            // Spec: facilitator_url + elapsed_ms + Retry-After + next_action.
            if let Some(url) = facilitator_url {
                details.insert("facilitator_url".into(), json!(url));
            }
            // Audit A-M2: surface measured wall-clock latency (when wired).
            if let Some(ms) = elapsed_ms {
                details.insert("elapsed_ms".into(), json!(ms));
            }
            details.insert(
                "last_error".into(),
                json!(format!("{}: {}", subcause, message)),
            );
            retry_after_secs = Some(30);
            next_action = Some(json!({
                "type": "topup",
                "ui": "https://jecp.dev/account/topup",
                "hint": "x402 facilitator timed out. Top up the wallet to continue or retry shortly.",
            }));
        }
        X402Error::SettlementReused { replay_info, .. } => {
            // Audit A-M1: surface the original-row fingerprint so SDKs can
            // detect "the same X-Payment was already settled" deterministically
            // and not retry blindly. Best-effort — when the lookup races a
            // GC / archival, we omit the fields rather than fabricate them.
            if let Some(info) = replay_info {
                details.insert("tx_hash".into(), json!(info.tx_hash));
                details.insert("original_request_id".into(), json!(info.original_request_id));
                details.insert(
                    "original_settled_at".into(),
                    json!(info.original_settled_at.to_rfc3339()),
                );
            }
            // Spec §9.4: agents auto-recover via `x402_settle` next_action.
            next_action = Some(json!({
                "type": "x402_settle",
                "hint": "Generate a new EIP-3009 authorization with a fresh nonce.",
            }));
        }
        X402Error::PaymentInvalid { message, .. } => {
            // Surface facilitator's invalid reason when present.
            details.insert("facilitator_message".into(), json!(message));
        }
    }

    let mut body = json!({
        "jecp": "1.0",
        "id": request_id,
        "status": "failed",
        "error": {
            "code": e.code(),
            "message": e.to_string(),
            "details": Value::Object(details),
        }
    });
    if let Some(action) = next_action {
        if let Some(obj) = body.as_object_mut() {
            obj.insert("next_action".into(), action);
        }
    }

    let json_resp = Json(body);
    let mut resp = (status, json_resp).into_response();
    if let Some(retry) = retry_after_secs {
        if let Ok(v) = axum::http::HeaderValue::from_str(&retry.to_string()) {
            resp.headers_mut().insert("retry-after", v);
        }
    }
    // H-2 / audit A-H3+A-H4: Cache-Control: no-store + CORS expose on every
    // x402 error envelope (spec §2.1 / §5 — no caching of paid/rejected flows).
    crate::protocol::x402_response_headers::apply_invoke_headers(resp.headers_mut());
    resp
}

/// Compute SHA256 of (capability + action + input + mandate.provenance_hash)
/// — used as idempotency key.
///
/// **v1.0.1 H2 fix**: `mandate.provenance_hash` is now part of the canonical
/// input. Without this, two requests with the same `id` + `input` but
/// different `provenance_hash` collide on the idempotency cache, returning a
/// cached response without re-verifying the new provenance — bypassing
/// Provenance verification entirely on cache hits. Documented in
/// jecp-spec §5.2.2 ("Idempotency vs Provenance interaction").
fn compute_input_hash(req: &InvokeRequest, x_payment_header: Option<&str>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(req.capability.as_bytes());
    hasher.update(b"|");
    hasher.update(req.action.as_bytes());
    hasher.update(b"|");
    hasher.update(serde_json::to_string(&req.input).unwrap_or_default().as_bytes());
    // Provenance hash is part of the canonical request identity — see H2.
    hasher.update(b"|");
    if let Some(ref m) = req.mandate {
        if let Some(ref ph) = m.provenance_hash {
            hasher.update(ph.as_bytes());
        }
    }
    // v1.1.0 x402 (ADR-0004 / Panel 2 TM-D2): X-Payment SHA-256 is part of
    // canonical request identity so wallet vs x402 path on the same request_id
    // do not silently cache-hit each other.
    hasher.update(b"|");
    if let Some(h) = x_payment_header {
        let mut inner = Sha256::new();
        inner.update(h.as_bytes());
        hasher.update(hex::encode(inner.finalize()).as_bytes());
    }
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// Pricing extraction (Sprint 12)
// ---------------------------------------------------------------------------

/// Extract action.pricing.base from manifest's parsed_json.
/// Returns USDC amount as f64. Strips leading '$'. Returns None if action not found
/// or pricing is malformed.
fn extract_action_price(manifest: &Value, action_id: &str) -> Option<f64> {
    let actions = manifest.get("actions")?.as_array()?;
    for a in actions {
        if a.get("id")?.as_str()? == action_id {
            let base = a.get("pricing")?.get("base")?;
            if let Some(n) = base.as_f64() {
                return Some(n);
            }
            if let Some(s) = base.as_str() {
                let stripped = s.trim_start_matches('$').trim();
                return stripped.parse::<f64>().ok();
            }
        }
    }
    None
}

/// Extract action.trust_tier_required from manifest's parsed_json.
/// Returns lowercase tier name (e.g. "bronze", "silver", "gold", "platinum")
/// or None if not declared.
fn extract_action_trust_tier(manifest: &Value, action_id: &str) -> Option<String> {
    let actions = manifest.get("actions")?.as_array()?;
    for a in actions {
        if a.get("id")?.as_str()? == action_id {
            return a.get("trust_tier_required")?.as_str().map(|s| s.to_lowercase());
        }
    }
    None
}

/// Parse a trust tier string into the TrustTier enum.
fn parse_trust_tier(s: &str) -> Option<TrustTier> {
    match s.trim().to_lowercase().as_str() {
        "bronze" => Some(TrustTier::Bronze),
        "silver" => Some(TrustTier::Silver),
        "gold" => Some(TrustTier::Gold),
        "platinum" => Some(TrustTier::Platinum),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// HMAC-SHA256 signature: base64(hmac(secret, timestamp + "." + body))
fn compute_hmac_signature(secret: &str, timestamp: i64, body: &[u8]) -> Result<String, String> {
    use base64::Engine;
    type HmacSha256 = Hmac<Sha256>;

    // Decode the base64 secret stored at register time.
    let secret_bytes = base64::engine::general_purpose::STANDARD
        .decode(secret)
        .map_err(|e| format!("hmac_secret base64 decode: {}", e))?;

    let mut mac = HmacSha256::new_from_slice(&secret_bytes)
        .map_err(|e| format!("hmac init: {}", e))?;
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    let sig = mac.finalize().into_bytes();
    Ok(format!("v1={}", base64::engine::general_purpose::STANDARD.encode(sig)))
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max { s.to_string() } else { format!("{}...", &s[..max]) }
}

fn error(status: StatusCode, code: &str, message: &str) -> axum::response::Response {
    let mut body = json!({
        "jecp": "1.0",
        "status": "failed",
        "error": { "code": code, "message": message }
    });
    // Sprint 15: machine-readable next_action for common error codes
    // Lets agents auto-recover (top up wallet, register, discover capabilities, etc.)
    if let Some(action) = next_action_for(code) {
        body.as_object_mut().unwrap().insert("next_action".to_string(), action);
    }
    (status, Json(body)).into_response()
}

/// Build the `payment.accepts[]` array for a 402 PAYMENT_REQUIRED response
/// per locked-design v1.1.1 §3.1.
///
/// Ordering: Stripe first, x402 second (admiral decision D — locked-design §2).
/// Backward compat: the `payment` field is additive on the existing error
/// envelope (sibling to `error.details`), so old SDKs continue to parse the
/// body unchanged.
///
/// Filtering rules:
/// - x402 entry is included only when `state.x402.is_some()` (kill-switch on)
///   AND the action manifest's `payment_methods` array contains `"x402"`.
/// - Stripe entry is included unless `payment_methods` is set to `["x402"]`
///   exclusively (i.e. x402-only capability — wallet path is then closed).
///
/// `splitter_capability_id` is the keccak256-derived capability id used by
/// the on-chain JecpSplitter contract (locked-design §3.1 / §7.2).
#[allow(clippy::too_many_arguments)]
fn build_payment_accepts(
    state: &AppState,
    x402_runtime_enabled: bool,
    manifest: &Value,
    namespace: &str,
    capability_id_str: &str,
    action_id: &str,
    version: &str,
    request_id: &str,
    price_usdc: f64,
) -> Value {
    // Audit A-C7: even if `state.x402` is configured at boot, runtime
    // kill-switch (`feature_flags.x402_enabled = false`) MUST suppress the
    // `exact` entry from `accepts[]` (spec §6.3).
    let x402_entry = if x402_runtime_enabled {
        state.x402.as_ref().map(|cfg| X402AcceptParams {
            network: cfg.network.clone(),
            asset: format!("{}", cfg.usdc_asset),
            pay_to: format!("{}", cfg.splitter_address),
            facilitator_url: cfg.facilitator.base_url_str(),
        })
    } else {
        None
    };
    build_payment_accepts_inner(
        x402_entry.as_ref(),
        manifest,
        namespace,
        capability_id_str,
        action_id,
        version,
        request_id,
        price_usdc,
    )
}

/// Pure projection of `X402Config` to the fields that flow into `accepts[]`.
/// Split out so unit tests can exercise `build_payment_accepts_inner` without
/// constructing a full `X402Config` (which requires alloy `Address` values,
/// a live `FacilitatorClient`, and on-chain RPC endpoints).
struct X402AcceptParams {
    network: String,
    asset: String,
    pay_to: String,
    facilitator_url: String,
}

#[allow(clippy::too_many_arguments)]
fn build_payment_accepts_inner(
    x402: Option<&X402AcceptParams>,
    manifest: &Value,
    namespace: &str,
    capability_id_str: &str,
    action_id: &str,
    version: &str,
    request_id: &str,
    price_usdc: f64,
) -> Value {
    let methods = extract_payment_methods(manifest, action_id);
    let allow_stripe = methods.iter().any(|m| m == "stripe") || methods.is_empty();
    let allow_x402 = methods.iter().any(|m| m == "x402");

    let mut accepts: Vec<Value> = Vec::with_capacity(2);

    // Stripe entry first (admiral D — locked-design v1.1.1 §2 Tension D).
    //
    // Audit A-H2 (spec §2.2.1): for v1.1.0, USD ≡ USDC at 1:1 — `amount_usd`
    // is the same value as the x402 `max_amount_required` divided by 10^6.
    // No Stripe fee uplift on the per-call wire; the wallet is pre-funded via
    // top-up flows that absorb processing fees at top-up time. serde_json
    // emits f64 with full precision, so sub-cent prices like $0.005 round-trip
    // as `0.005` (not truncated to `0`). Clients MUST NOT cast to int cents.
    if allow_stripe {
        accepts.push(json!({
            "scheme": "stripe-wallet",
            "amount_usd": price_usdc,
            "topup_url": format!(
                "https://jecp.dev/account/topup?return={}",
                urlencoding_lite(request_id),
            ),
        }));
    }

    // x402 entry second — only when Hub kill-switch is on AND manifest
    // accepts it (locked-design v1.1.1 §3.1).
    if allow_x402 {
        if let Some(cfg) = x402 {
            let amount_micro = (price_usdc * 1_000_000.0).round() as i64;
            let splitter_cap_id = crate::services::splitter_registry::derive_capability_id(
                namespace, action_id, version,
            );
            let splitter_cap_id_hex = format!("0x{}", hex::encode(splitter_cap_id.as_slice()));

            // Audit A-H1 (spec §2.2): when the asset is canonical Base USDC,
            // emit the EIP-712 domain separator fields (`name`, `version`).
            // These are required for facilitator EIP-712 signature verify;
            // without them facilitators fall back to defaults that may not
            // match real USDC issuance. Skip for non-USDC assets (no curated
            // EIP-712 metadata available for arbitrary ERC-20s in v1.1.0).
            let mut extra = serde_json::Map::new();
            if is_canonical_base_usdc(&cfg.asset) {
                extra.insert("name".into(), json!("USD Coin"));
                extra.insert("version".into(), json!("2"));
            }
            extra.insert("splitter_capability_id".into(), json!(splitter_cap_id_hex));
            extra.insert("facilitator_url".into(), json!(cfg.facilitator_url.clone()));

            accepts.push(json!({
                "scheme": "exact",
                "network": cfg.network,
                "asset": cfg.asset,
                "asset_symbol": "USDC",
                "asset_decimals": 6,
                "amount": amount_micro.to_string(),
                "max_amount_required": amount_micro.to_string(),
                "pay_to": cfg.pay_to,
                "resource": "https://jecp.dev/v1/invoke",
                "description": format!("Payment for capability {}", capability_id_str),
                "mime_type": "application/json",
                "max_timeout_seconds": 60,
                "extra": Value::Object(extra),
            }));
        }
    }

    json!({
        "accepts": accepts,
        "ttl_seconds": 30,
    })
}

/// Returns true when the given asset string equals the canonical Base
/// mainnet USDC contract address (case-insensitive). Used to decide whether
/// to emit the EIP-712 domain separator fields (`extra.name`, `extra.version`)
/// in 402 `accepts[]` entries — see Audit A-H1.
fn is_canonical_base_usdc(asset: &str) -> bool {
    const BASE_MAINNET_USDC: &str = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
    asset.trim().to_lowercase() == BASE_MAINNET_USDC
}

/// Read `actions[].pricing.payment_methods` from a manifest. Returns the raw
/// string array (empty when absent — caller treats empty as default = stripe).
fn extract_payment_methods(manifest: &Value, action_id: &str) -> Vec<String> {
    manifest
        .get("actions")
        .and_then(|a| a.as_array())
        .and_then(|arr| {
            arr.iter().find(|x| {
                x.get("id").and_then(|i| i.as_str()) == Some(action_id)
            })
        })
        .and_then(|a| a.get("pricing"))
        .and_then(|p| p.get("payment_methods"))
        .and_then(|m| m.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

/// Minimal URL-safe escaper for the `return=<request_id>` query value.
/// We control the request_id charset upstream (UUID / `req_*`), so this is
/// defensive — covers `+`/`&`/`=`/`#`/space if a non-conforming id slips in.
fn urlencoding_lite(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~') {
            out.push(c);
        } else {
            for b in c.to_string().as_bytes() {
                out.push_str(&format!("%{:02X}", b));
            }
        }
    }
    out
}

/// Build a JECP error envelope for 402 PAYMENT_REQUIRED with the additive
/// `payment.accepts[]` array (locked-design v1.1.1 §3.1).
///
/// `details` carries the legacy wallet-balance breakdown so existing SDKs
/// keep parsing it unchanged. `payment` is a sibling field; the canonical
/// error envelope (`jecp`, `status`, `error`, `next_action`) is untouched.
#[allow(clippy::too_many_arguments)]
fn payment_required_response(
    state: &AppState,
    x402_runtime_enabled: bool,
    manifest: &Value,
    namespace: &str,
    capability_id_str: &str,
    action_id: &str,
    version: &str,
    request_id: &str,
    code: &str,
    message: &str,
    price_usdc: f64,
    wallet_balance: Option<f64>,
) -> axum::response::Response {
    let mut body = json!({
        "jecp": "1.0",
        "id": request_id,
        "status": "failed",
        "error": {
            "code": code,
            "message": message,
            "details": {
                "amount_usd": price_usdc,
                "amount_usdc": format!("{}", (price_usdc * 1_000_000.0).round() as i64),
                "wallet_balance_usd": wallet_balance.unwrap_or(0.0),
            }
        }
    });
    if let Some(action) = next_action_for(code) {
        body.as_object_mut().unwrap().insert("next_action".to_string(), action);
    }
    let payment = build_payment_accepts(
        state, x402_runtime_enabled, manifest, namespace, capability_id_str, action_id, version, request_id, price_usdc,
    );
    body.as_object_mut().unwrap().insert("payment".to_string(), payment);

    // H-2 / audit A-H3+A-H4+A-H5: Cache-Control: no-store + CORS expose +
    // WWW-Authenticate. The challenge value depends on which schemes the
    // capability accepts AND whether the runtime kill-switch is on.
    let manifest_methods = extract_payment_methods(manifest, action_id);
    let mut accepted: Vec<&str> = Vec::with_capacity(2);
    let allow_stripe = manifest_methods.iter().any(|m| m == "stripe") || manifest_methods.is_empty();
    let allow_x402 = manifest_methods.iter().any(|m| m == "x402") && x402_runtime_enabled && state.x402.is_some();
    if allow_stripe { accepted.push("stripe"); }
    if allow_x402 { accepted.push("x402"); }
    let mut resp = (StatusCode::PAYMENT_REQUIRED, Json(body)).into_response();
    crate::protocol::x402_response_headers::apply_402_headers(resp.headers_mut(), &accepted);
    resp
}

/// v1.0.1: PROVENANCE_MISMATCH error builder with the `details.subcause`
/// closed registry per spec §3.1. Mirrors what `JecpErrorCode::IntoResponse`
/// produces in `/v1/jecp` so the two routes return byte-identical bodies.
fn jecp_provenance_error(
    subcause: ProvenanceSubcause,
    message: &str,
    drift_seconds: Option<i64>,
) -> axum::response::Response {
    let s = subcause.as_str();
    let mut details = serde_json::Map::new();
    details.insert("subcause".into(), json!(s));
    details.insert(
        "documentation_url".into(),
        json!(format!("https://jecp.dev/errors/provenance_mismatch#{}", s)),
    );
    if let Some(d) = drift_seconds {
        details.insert("drift_seconds".into(), json!(d));
    }
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "jecp": "1.0",
            "status": "failed",
            "error": {
                "code": "PROVENANCE_MISMATCH",
                "message": message,
                "details": details,
            }
        })),
    ).into_response()
}

/// Maps an error code to a JSON next_action telling the agent how to recover.
/// Spec §6: agents SHOULD honor next_action when present.
fn next_action_for(code: &str) -> Option<Value> {
    match code {
        "INSUFFICIENT_BALANCE" => Some(json!({
            "type": "topup",
            "ui":   "https://jecp.dev/topup",
            "api":  "https://jecp.dev/api/agents/topup",
            "hint": "Top up the agent's wallet via Stripe Checkout."
        })),
        "INSUFFICIENT_BUDGET" => Some(json!({
            "type": "increase_mandate",
            "hint": "The mandate.budget_usdc is below the action's price. Increase the budget or omit the mandate field."
        })),
        "MANDATE_EXPIRED" => Some(json!({
            "type": "refresh_mandate",
            "hint": "Issue a new mandate with a future expires_at."
        })),
        "AUTH_REQUIRED" | "INVALID_AGENT" => Some(json!({
            "type": "register",
            "ui":   "https://jecp.dev/register",
            "api":  "https://jecp.dev/api/agents/register",
            "hint": "Register an agent to obtain agent_id + api_key (100 free calls)."
        })),
        "RATE_LIMITED" => Some(json!({
            "type": "retry_after",
            "hint": "Reduce request rate. Default 60 RPM/agent. Earn higher rate limits via Trust Tier promotion."
        })),
        "CAPABILITY_NOT_FOUND" => Some(json!({
            "type": "discover",
            "api":  "https://jecp.dev/v1/capabilities",
            "hint": "List active capabilities. Verify namespace/capability spelling."
        })),
        "ACTION_NOT_FOUND" => Some(json!({
            "type": "see_manifest",
            "api":  "https://jecp.dev/v1/capabilities",
            "hint": "Inspect the capability's manifest in the catalog to find valid action ids."
        })),
        "INSUFFICIENT_TRUST" => Some(json!({
            "type": "earn_trust",
            "hint": "Trust tier is based on total_calls (Bronze<100, Silver<500, Gold<2000, Platinum). Use lower-tier capabilities until promoted."
        })),
        "PROVIDER_UNREACHABLE" | "PROVIDER_ERROR" => Some(json!({
            "type": "try_alternative_provider",
            "api":  "https://jecp.dev/v1/capabilities",
            "hint": "Provider endpoint failed. Discover alternative providers offering similar capabilities."
        })),
        "UNSUPPORTED_PROTOCOL" => Some(json!({
            "type": "upgrade_client",
            "spec": "https://github.com/jecpdev/jecp-spec",
            "hint": "Send `\"jecp\": \"1.0\"` in the request body."
        })),
        "NOT_STREAMABLE" => Some(json!({
            "type": "drop_streaming_accept",
            "hint": "This capability action does not support streaming. Re-send without 'Accept: text/event-stream' or pick a streaming-capable action."
        })),
        "STREAM_TIMEOUT" | "PROVIDER_TIMEOUT" => Some(json!({
            "type": "retry_or_alternative",
            "api":  "https://jecp.dev/v1/capabilities",
            "hint": "Stream stalled. Retry; if it persists, discover alternative providers."
        })),
        _ => None,
    }
}

// ===========================================================================
// SSE streaming path (W5 / Phase A)
// ===========================================================================

/// Streaming branch of POST /v1/invoke.
///
/// Pre-flight (auth / capability / pricing / trust / mandate / balance) returns
/// a JSON 4xx so EventSource clients can read the error body. Once the upstream
/// connection to Provider is open, all errors are delivered as SSE events
/// (`error` / `cancelled`) and the HTTP status is 200.
///
/// Phase A scope (per design doc §13):
/// - Pure pass-through of `chunk`, `meter`, custom event types
/// - Hub intercepts `completed` to run `invoke_charge` and re-emit with billing
/// - 30s no-progress timeout + 5min total stream timeout
/// - 406 NOT_STREAMABLE if action manifest does not declare `streaming: true`
///
/// Phase B (deferred — see design doc §14):
/// - per-token / per-second / per-chunk variable pricing engine
/// - mid-stream Mandate enforcement based on running meter sum
/// - stream replay caching for idempotency
/// - `invocation.cancelled` webhook events for partial bills
async fn invoke_capability_stream(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // ---- pre-flight (same shape as JSON path; errors return JSON 4xx) ----
    let pre = match preflight_for_stream(&state, &headers, &body).await {
        Ok(p) => p,
        Err((status, body)) => {
            // H-2 / audit A-H3+A-H4: same header policy on streaming preflight errors.
            let mut resp = (status, Json(body)).into_response();
            crate::protocol::x402_response_headers::apply_invoke_headers(resp.headers_mut());
            return resp;
        }
    };

    // ---- HMAC sign + open Provider SSE connection ----
    let forward_body = json!({
        "jecp": "1.0",
        "id": pre.req.id,
        "capability": pre.req.capability,
        "action": pre.req.action,
        "input": pre.req.input,
        "streaming": true,
    });
    let body_bytes = match serde_json::to_vec(&forward_body) {
        Ok(b) => b,
        Err(e) => return error_response(
            StatusCode::INTERNAL_SERVER_ERROR, "SERIALIZE_ERROR", &e.to_string()),
    };
    let timestamp = chrono::Utc::now().timestamp();
    let signature = match compute_hmac_signature(&pre.resolved.hmac_secret, timestamp, &body_bytes) {
        Ok(s) => s,
        Err(e) => return error_response(
            StatusCode::INTERNAL_SERVER_ERROR, "HMAC_ERROR", &e),
    };

    // v1.1.0 c7 — SSRF defense for stream forward path.
    let validated = match crate::protocol::url_guard::validate_outbound_url(&pre.resolved.endpoint_url).await {
        Ok(v) => v,
        Err(e) => {
            let safe_url = crate::protocol::url_guard::redact_url(&pre.resolved.endpoint_url);
            let reason = e.reason().to_string();
            if let Some(pool) = state.invoke_pool().cloned() {
                let aid = pre.agent_id.clone();
                let pid = pre.resolved.provider_id;
                let url_for_audit = safe_url.clone();
                let reason_for_audit = reason.clone();
                tokio::spawn(async move {
                    crate::protocol::url_guard::audit_log_rejection(
                        &pool, Some(&aid), Some(pid),
                        "endpoint_url", "invoke_stream_forward",
                        &url_for_audit, &reason_for_audit, None,
                    ).await;
                });
            }
            let (status, body) = crate::protocol::url_guard::url_blocked_ssrf_tuple(
                "endpoint_url", &safe_url, &reason,
            );
            return (status, body).into_response();
        }
    };

    // No overall timeout on the client — we manage stream timeouts inside the loop.
    // Pinned-IP client per spec §9.7.1 step 6 (closes DNS-rebind window).
    let client = match crate::protocol::url_guard::guarded_client(&validated.host, validated.pinned_addr) {
        Ok(c) => c,
        Err(e) => return error_response(
            StatusCode::INTERNAL_SERVER_ERROR, "HTTP_CLIENT", &e.to_string()),
    };

    let resp = match client
        .post(&pre.resolved.endpoint_url)
        .header("content-type", "application/json")
        .header("accept", "text/event-stream")
        .header("x-jecp-signature", &signature)
        .header("x-jecp-timestamp", timestamp.to_string())
        .header("x-jecp-namespace", &pre.resolved.namespace)
        .header("x-jecp-action", &pre.req.action)
        .body(body_bytes)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("stream forward to {} failed: {}", pre.resolved.endpoint_url, e);
            return error_response(
                StatusCode::BAD_GATEWAY, "PROVIDER_UNREACHABLE",
                &format!("Provider endpoint unreachable: {}", e));
        }
    };

    let upstream_status = resp.status();
    if !upstream_status.is_success() {
        let resp_bytes = resp.bytes().await.unwrap_or_default();
        let truncated = String::from_utf8_lossy(
            &resp_bytes[..std::cmp::min(500, resp_bytes.len())]
        ).into_owned();
        return error_response(
            StatusCode::BAD_GATEWAY, "PROVIDER_ERROR",
            &format!("Provider returned {}: {}", upstream_status, truncated));
    }

    // Pull async data we will need inside the stream closure.
    let pool = state.invoke_pool().expect("pool checked in preflight").clone();
    let agent_id = pre.agent_id.clone();
    let request_id = pre.req.id.clone();
    let capability_full = pre.req.capability.clone();
    let action_id = pre.req.action.clone();
    let provider_id = pre.resolved.provider_id;
    let capability_id = pre.resolved.capability_id;
    let capability_name = pre.resolved.capability_name.clone();
    let namespace = pre.resolved.namespace.clone();
    let version = pre.resolved.version.clone();
    let price_usdc = pre.price_usdc;

    let mut bytes_stream = resp.bytes_stream();

    // Build the outbound SSE stream
    let stream = async_stream::stream! {
        // Send an open marker so clients know the upstream connection is live.
        yield Ok::<_, Infallible>(
            Event::default().event("open").data(json!({
                "request_id": request_id,
                "capability": capability_full,
                "action": action_id,
            }).to_string())
        );

        let started_at = Instant::now();
        let mut parser = SseParser::new();
        let mut accumulated = AccumulatedMeter::default();
        let mut completed_seen = false;
        let mut terminated = false;

        loop {
            // Total stream timeout
            if started_at.elapsed() >= Duration::from_secs(STREAM_TOTAL_TIMEOUT_SECS) {
                yield Ok(Event::default().event("cancelled").data(json!({
                    "reason": "STREAM_TIMEOUT",
                    "message": format!("Total stream timeout ({}s) exceeded", STREAM_TOTAL_TIMEOUT_SECS),
                }).to_string()));
                terminated = true;
                break;
            }

            // Per-chunk no-progress timeout
            let next = tokio::time::timeout(
                Duration::from_secs(STREAM_NOPROGRESS_TIMEOUT_SECS),
                bytes_stream.next(),
            ).await;

            match next {
                Ok(Some(Ok(bytes))) => {
                    parser.feed(&bytes);
                    while let Some(ev) = parser.pop() {
                        // Track meter accumulator (Phase B will use this for variable pricing).
                        if ev.event == "meter" {
                            if let Ok(v) = serde_json::from_str::<Value>(&ev.data) {
                                accumulated.update(&v);
                            }
                        }

                        // Intercept terminal events (completed / error / cancelled).
                        match ev.event.as_str() {
                            "completed" => {
                                completed_seen = true;
                                let provider_payload: Value = serde_json::from_str(&ev.data)
                                    .unwrap_or(Value::Null);

                                // Phase A: charge the flat action.pricing.base regardless of
                                // meter accumulation (Phase B layers in variable pricing).
                                let billing_summary = run_invoke_charge(
                                    &pool, &agent_id, price_usdc,
                                    &capability_name, &action_id, &request_id,
                                    &provider_id, &capability_id,
                                ).await;

                                let final_payload = json!({
                                    "result": provider_payload.get("result").cloned()
                                        .unwrap_or(provider_payload),
                                    "billing": billing_summary,
                                    "provider": {
                                        "namespace": namespace,
                                        "capability": capability_name,
                                        "version": version,
                                    },
                                    "meter_summary": accumulated.summary(),
                                });
                                yield Ok(Event::default().event("completed")
                                    .data(final_payload.to_string()));
                                terminated = true;
                                break;
                            }
                            "error" | "cancelled" => {
                                // Forward terminal event from Provider as-is.
                                yield Ok(Event::default().event(&ev.event).data(ev.data.clone()));
                                terminated = true;
                                break;
                            }
                            _ => {
                                yield Ok(Event::default().event(&ev.event).data(ev.data.clone()));
                            }
                        }
                    }
                    if terminated { break; }
                }
                Ok(Some(Err(e))) => {
                    tracing::warn!(
                        "stream upstream read error agent={} cap={}: {}",
                        agent_id, capability_full, e
                    );
                    yield Ok(Event::default().event("error").data(json!({
                        "error": {
                            "code": "PROVIDER_DISCONNECT",
                            "message": e.to_string(),
                        }
                    }).to_string()));
                    terminated = true;
                    break;
                }
                Ok(None) => {
                    if !completed_seen {
                        yield Ok(Event::default().event("error").data(json!({
                            "error": {
                                "code": "STREAM_INCOMPLETE",
                                "message": "Provider closed stream without a completed/error/cancelled event",
                            }
                        }).to_string()));
                    }
                    terminated = true;
                    break;
                }
                Err(_) => {
                    yield Ok(Event::default().event("cancelled").data(json!({
                        "reason": "PROVIDER_TIMEOUT",
                        "message": format!("No progress from Provider for {}s",
                            STREAM_NOPROGRESS_TIMEOUT_SECS),
                    }).to_string()));
                    terminated = true;
                    break;
                }
            }
        }

        // Trailing newline guarantees buffered SSE delivery on some intermediaries.
        let _ = terminated;
    };

    let mut resp = Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
        .into_response();
    // H-2 / audit A-H3+A-H4: Cache-Control: no-store + CORS expose on the
    // streaming response so a CDN cannot cache the SSE body and browser fetch()
    // can read the receipt header should an x402-settled stream emit one.
    crate::protocol::x402_response_headers::apply_invoke_headers(resp.headers_mut());
    resp
}

// ---------------------------------------------------------------------------
// Pre-flight for streaming branch
// ---------------------------------------------------------------------------

struct StreamPreflight {
    req: InvokeRequest,
    agent_id: String,
    resolved: database::ResolvedCapability,
    price_usdc: f64,
}

async fn preflight_for_stream(
    state: &AppState,
    headers: &HeaderMap,
    body: &Bytes,
) -> Result<StreamPreflight, (StatusCode, Value)> {
    let req: InvokeRequest = serde_json::from_slice(body).map_err(|e| {
        (StatusCode::BAD_REQUEST, error_body("PARSE_ERROR",
            &format!("Failed to parse JSON: {}", e)))
    })?;

    if req.jecp != "1.0" {
        return Err((StatusCode::BAD_REQUEST,
            error_body("UNSUPPORTED_PROTOCOL", "jecp version must be '1.0'")));
    }
    if req.id.is_empty() {
        return Err((StatusCode::BAD_REQUEST, error_body("MISSING_ID", "id is required")));
    }
    if !req.capability.contains('/') {
        return Err((StatusCode::BAD_REQUEST, error_body("INVALID_CAPABILITY",
            "capability must be in 'namespace/name' format")));
    }

    let agent_id = headers.get("x-agent-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or_else(|| (StatusCode::UNAUTHORIZED,
            error_body("AUTH_REQUIRED", "Missing X-Agent-ID header")))?;
    let api_key = headers.get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or_else(|| (StatusCode::UNAUTHORIZED,
            error_body("AUTH_REQUIRED", "Missing X-API-Key header")))?;

    let pool = state.invoke_pool().ok_or_else(|| (
        StatusCode::SERVICE_UNAVAILABLE,
        error_body("DB_UNAVAILABLE", "Database not connected")))?;

    let agent = authenticate_agent(pool, &agent_id, &api_key).await
        .map_err(|_| (StatusCode::UNAUTHORIZED,
            error_body("INVALID_AGENT", "Agent authentication failed")))?;

    if state.rate_limiter.check(&agent_id, Some(60)).await.is_err() {
        return Err((StatusCode::TOO_MANY_REQUESTS,
            error_body("RATE_LIMITED",
                "Too many requests. Default rate limit is 60 RPM per agent.")));
    }

    let resolved = database::resolve_capability_for_invoke(pool, &req.capability)
        .await
        .map_err(|e| {
            tracing::error!("resolve_capability_for_invoke (stream): {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR,
                error_body("DB_ERROR", "lookup failed"))
        })?
        .ok_or_else(|| (StatusCode::NOT_FOUND, error_body(
            "CAPABILITY_NOT_FOUND",
            &format!("'{}' is not a published active capability", req.capability))))?;

    // 406 NOT_STREAMABLE if the action does not opt into streaming.
    if !extract_action_streaming(&resolved.parsed_json, &req.action) {
        return Err((StatusCode::NOT_ACCEPTABLE, error_body(
            "NOT_STREAMABLE",
            &format!("action '{}' on '{}' does not declare streaming: true",
                req.action, req.capability))));
    }

    let price_usdc = extract_action_price(&resolved.parsed_json, &req.action)
        .ok_or_else(|| (StatusCode::UNPROCESSABLE_ENTITY, error_body(
            "ACTION_NOT_FOUND",
            &format!("action '{}' is not declared in capability '{}'",
                req.action, req.capability))))?;

    let required_tier_str = extract_action_trust_tier(&resolved.parsed_json, &req.action)
        .unwrap_or_else(|| "bronze".to_string());
    let required_tier = parse_trust_tier(&required_tier_str)
        .ok_or_else(|| (StatusCode::UNPROCESSABLE_ENTITY, error_body(
            "INVALID_TRUST_TIER",
            &format!("manifest action '{}' has unknown trust_tier_required '{}'",
                req.action, required_tier_str))))?;
    let current_tier = agent.trust_tier();
    if current_tier < required_tier {
        return Err((StatusCode::FORBIDDEN, error_body(
            "INSUFFICIENT_TRUST",
            &format!("action '{}' requires trust tier '{}' (you are '{}').",
                req.action, required_tier, current_tier))));
    }

    // Audit A-C7: consult the runtime kill switch once for both 402 branches.
    let x402_runtime_enabled = if state.x402.is_some() {
        state.flags.is_enabled(&state.pool, "x402_enabled").await
    } else { false };

    if let Some(m) = &req.mandate {
        if let Some(expires) = m.expires_at {
            if expires < chrono::Utc::now() {
                return Err((StatusCode::FORBIDDEN, error_body(
                    "MANDATE_EXPIRED", "mandate.expires_at is in the past")));
            }
        }
        if let Some(budget) = m.budget_usdc {
            if budget < price_usdc {
                return Err((StatusCode::PAYMENT_REQUIRED, payment_required_body(
                    state,
                    x402_runtime_enabled,
                    &resolved.parsed_json,
                    &resolved.namespace,
                    &resolved.capability_name,
                    &req.action,
                    &resolved.version,
                    &req.id,
                    "INSUFFICIENT_BUDGET",
                    &format!("Mandate budget {:.6} USDC < required {:.6} USDC.",
                        budget, price_usdc),
                    price_usdc,
                    Some(budget),
                )));
            }
        }
    }

    let balance = database::get_wallet_balance(pool, &agent_id).await
        .map_err(|e| {
            tracing::error!("get_wallet_balance (stream): {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR,
                error_body("DB_ERROR", "balance lookup failed"))
        })?;
    if balance < price_usdc {
        return Err((StatusCode::PAYMENT_REQUIRED, payment_required_body(
            state,
            x402_runtime_enabled,
            &resolved.parsed_json,
            &resolved.namespace,
            &resolved.capability_name,
            &req.action,
            &resolved.version,
            &req.id,
            "INSUFFICIENT_BALANCE",
            &format!("Wallet balance {:.6} USDC < required {:.6} USDC.",
                balance, price_usdc),
            price_usdc,
            Some(balance),
        )));
    }

    Ok(StreamPreflight { req, agent_id, resolved, price_usdc })
}

/// Run jecp.invoke_charge() and fire webhook events. Returns billing summary.
#[allow(clippy::too_many_arguments)]
async fn run_invoke_charge(
    pool: &sqlx::PgPool,
    agent_id: &str,
    price_usdc: f64,
    capability_name: &str,
    action_id: &str,
    request_id: &str,
    provider_id: &uuid::Uuid,
    capability_id: &uuid::Uuid,
) -> Value {
    match database::invoke_charge(
        pool, agent_id, price_usdc, capability_name, action_id, request_id,
        provider_id, capability_id,
    ).await {
        Ok(Some(c)) => {
            // Fire webhook events fire-and-forget (mirrors JSON path).
            let pool_clone = pool.clone();
            let agent_id_owned = agent_id.to_string();
            let provider_id_str = provider_id.to_string();
            let cap_id_str = capability_id.to_string();
            let action_owned = action_id.to_string();
            let request_id_owned = request_id.to_string();
            let payload = json!({
                "transaction_id": c.transaction_id,
                "agent_id": agent_id,
                "provider_id": provider_id_str,
                "capability_id": cap_id_str,
                "action": action_owned,
                "request_id": request_id_owned,
                "amount_usdc": price_usdc,
                "balance_after": c.balance_after,
                "provider_share_usdc": c.provider_share_usdc,
                "streaming": true,
            });
            let balance_after = c.balance_after;
            tokio::spawn(async move {
                crate::services::webhooks::enqueue(
                    &pool_clone, &agent_id_owned, "agent",
                    "invocation.completed", payload.clone()).await;
                crate::services::webhooks::enqueue(
                    &pool_clone, &provider_id_str, "provider",
                    "invocation.completed", payload).await;
                if balance_after < 0.50 {
                    crate::services::webhooks::enqueue(
                        &pool_clone, &agent_id_owned, "agent",
                        "wallet.low_balance", json!({
                            "agent_id": agent_id_owned,
                            "balance_after": balance_after,
                            "threshold_usdc": 0.50,
                        })).await;
                }
            });
            json!({
                "charged": true,
                "amount_usdc": price_usdc,
                "transaction_id": c.transaction_id,
                "balance_after": c.balance_after,
                "provider_share_usdc": c.provider_share_usdc,
                "hub_fee_usdc": c.hub_fee_usdc,
                "payment_fee_usdc": c.payment_fee_usdc,
            })
        }
        Ok(None) => {
            tracing::warn!(
                "stream invoke_charge insufficient balance race: agent={} amount={}",
                agent_id, price_usdc);
            json!({
                "charged": false,
                "amount_usdc": price_usdc,
                "note": "balance race — Provider stream completed but charge skipped",
            })
        }
        Err(e) => {
            tracing::error!("stream invoke_charge error: {}", e);
            json!({
                "charged": false,
                "amount_usdc": price_usdc,
                "note": "billing temporarily unavailable",
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Streaming helpers
// ---------------------------------------------------------------------------

fn extract_action_streaming(manifest: &Value, action_id: &str) -> bool {
    manifest.get("actions")
        .and_then(|a| a.as_array())
        .and_then(|arr| arr.iter().find(|x|
            x.get("id").and_then(|i| i.as_str()) == Some(action_id)))
        .and_then(|a| a.get("streaming"))
        .and_then(|s| s.as_bool())
        .unwrap_or(false)
}

fn error_body(code: &str, message: &str) -> Value {
    let mut body = json!({
        "jecp": "1.0",
        "status": "failed",
        "error": { "code": code, "message": message },
    });
    if let Some(action) = next_action_for(code) {
        body.as_object_mut().unwrap().insert("next_action".to_string(), action);
    }
    body
}

/// 402 PAYMENT_REQUIRED body for the streaming preflight path. Matches the
/// JSON shape produced by `payment_required_response` (locked-design v1.1.1 §3.1).
#[allow(clippy::too_many_arguments)]
fn payment_required_body(
    state: &AppState,
    x402_runtime_enabled: bool,
    manifest: &Value,
    namespace: &str,
    capability_id_str: &str,
    action_id: &str,
    version: &str,
    request_id: &str,
    code: &str,
    message: &str,
    price_usdc: f64,
    wallet_balance: Option<f64>,
) -> Value {
    let mut body = json!({
        "jecp": "1.0",
        "id": request_id,
        "status": "failed",
        "error": {
            "code": code,
            "message": message,
            "details": {
                "amount_usd": price_usdc,
                "amount_usdc": format!("{}", (price_usdc * 1_000_000.0).round() as i64),
                "wallet_balance_usd": wallet_balance.unwrap_or(0.0),
            }
        }
    });
    if let Some(action) = next_action_for(code) {
        body.as_object_mut().unwrap().insert("next_action".to_string(), action);
    }
    let payment = build_payment_accepts(
        state, x402_runtime_enabled, manifest, namespace, capability_id_str, action_id, version, request_id, price_usdc,
    );
    body.as_object_mut().unwrap().insert("payment".to_string(), payment);
    body
}

fn error_response(status: StatusCode, code: &str, message: &str) -> Response {
    // H-2 / audit A-H3+A-H4: streaming-path errors share the same Cache-Control
    // + CORS-expose policy as the sync path. Browser agents and intermediaries
    // see identical headers regardless of which branch failed.
    let mut resp = (status, Json(error_body(code, message))).into_response();
    crate::protocol::x402_response_headers::apply_invoke_headers(resp.headers_mut());
    resp
}

// ---------------------------------------------------------------------------
// Minimal SSE parser (W3C SSE — RFC-style)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct ParsedSseEvent {
    event: String,
    data: String,
}

#[derive(Default)]
struct SseParser {
    buf: String,
    pending_event: Option<String>,
    pending_data: Vec<String>,
    queue: std::collections::VecDeque<ParsedSseEvent>,
}

impl SseParser {
    fn new() -> Self { Self::default() }

    fn feed(&mut self, bytes: &[u8]) {
        // Replace \r\n with \n for unified parsing.
        let chunk = String::from_utf8_lossy(bytes).replace("\r\n", "\n");
        self.buf.push_str(&chunk);

        while let Some(idx) = self.buf.find('\n') {
            let line: String = self.buf.drain(..=idx).collect();
            // strip trailing \n
            let line = line.trim_end_matches('\n').to_string();
            self.process_line(&line);
        }
    }

    fn process_line(&mut self, line: &str) {
        if line.is_empty() {
            // dispatch event
            if self.pending_event.is_some() || !self.pending_data.is_empty() {
                let event = self.pending_event.take().unwrap_or_else(|| "message".to_string());
                let data = self.pending_data.join("\n");
                self.pending_data.clear();
                self.queue.push_back(ParsedSseEvent { event, data });
            }
            return;
        }
        if line.starts_with(':') {
            // SSE comment / heartbeat — ignore
            return;
        }
        let (field, value) = match line.find(':') {
            Some(i) => {
                let f = &line[..i];
                let mut v = &line[i + 1..];
                if v.starts_with(' ') { v = &v[1..]; }
                (f, v)
            }
            None => (line, ""),
        };
        match field {
            "event" => self.pending_event = Some(value.to_string()),
            "data" => self.pending_data.push(value.to_string()),
            // id / retry / unknown — ignored for Phase A
            _ => {}
        }
    }

    fn pop(&mut self) -> Option<ParsedSseEvent> {
        self.queue.pop_front()
    }
}

// ---------------------------------------------------------------------------
// Meter accumulator (Phase A: tracks counts; Phase B will drive variable pricing)
// ---------------------------------------------------------------------------

#[derive(Default, Debug, Clone)]
struct AccumulatedMeter {
    tokens: f64,
    chunks: u64,
    elapsed_ms: f64,
    audio_seconds: f64,
}

impl AccumulatedMeter {
    fn update(&mut self, ev: &Value) {
        if let Some(n) = ev.get("tokens").and_then(|v| v.as_f64()) { self.tokens += n; }
        if let Some(n) = ev.get("chunks").and_then(|v| v.as_f64()) { self.chunks += n as u64; }
        if let Some(n) = ev.get("elapsed_ms").and_then(|v| v.as_f64()) {
            self.elapsed_ms = self.elapsed_ms.max(n);
        }
        if let Some(n) = ev.get("audio_seconds").and_then(|v| v.as_f64()) { self.audio_seconds += n; }
    }

    fn summary(&self) -> Value {
        json!({
            "tokens": self.tokens,
            "chunks": self.chunks,
            "elapsed_ms": self.elapsed_ms,
            "audio_seconds": self.audio_seconds,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sse_parser_basic() {
        let mut p = SseParser::new();
        p.feed(b"event: chunk\ndata: {\"delta\":\"hi\"}\n\n");
        let ev = p.pop().expect("event");
        assert_eq!(ev.event, "chunk");
        assert_eq!(ev.data, "{\"delta\":\"hi\"}");
        assert!(p.pop().is_none());
    }

    #[test]
    fn sse_parser_split_chunks() {
        let mut p = SseParser::new();
        p.feed(b"event: chu");
        p.feed(b"nk\ndata: 1\n\n");
        let ev = p.pop().expect("event");
        assert_eq!(ev.event, "chunk");
        assert_eq!(ev.data, "1");
    }

    #[test]
    fn sse_parser_default_event_type() {
        let mut p = SseParser::new();
        p.feed(b"data: hello\n\n");
        let ev = p.pop().expect("event");
        assert_eq!(ev.event, "message");
        assert_eq!(ev.data, "hello");
    }

    #[test]
    fn sse_parser_multiline_data() {
        let mut p = SseParser::new();
        p.feed(b"data: line1\ndata: line2\n\n");
        let ev = p.pop().expect("event");
        assert_eq!(ev.data, "line1\nline2");
    }

    #[test]
    fn sse_parser_comment_ignored() {
        let mut p = SseParser::new();
        p.feed(b": keepalive\nevent: chunk\ndata: x\n\n");
        let ev = p.pop().expect("event");
        assert_eq!(ev.event, "chunk");
    }

    #[test]
    fn sse_parser_crlf() {
        let mut p = SseParser::new();
        p.feed(b"event: chunk\r\ndata: ok\r\n\r\n");
        let ev = p.pop().expect("event");
        assert_eq!(ev.event, "chunk");
        assert_eq!(ev.data, "ok");
    }

    #[test]
    fn meter_accumulator() {
        let mut m = AccumulatedMeter::default();
        m.update(&json!({"tokens": 12, "elapsed_ms": 100}));
        m.update(&json!({"tokens": 8, "elapsed_ms": 250}));
        assert_eq!(m.tokens, 20.0);
        assert_eq!(m.elapsed_ms, 250.0); // max, not sum
    }

    #[test]
    fn streaming_flag_extraction() {
        let manifest = json!({
            "actions": [
                {"id": "chat", "streaming": true},
                {"id": "translate"},
            ]
        });
        assert!(extract_action_streaming(&manifest, "chat"));
        assert!(!extract_action_streaming(&manifest, "translate"));
        assert!(!extract_action_streaming(&manifest, "missing"));
    }

    // -----------------------------------------------------------------------
    // v1.1.0 x402 — 402 PAYMENT_REQUIRED `payment.accepts[]` builder tests
    // locked-design v1.1.1 §3.1 + §3.6 + admiral D
    // -----------------------------------------------------------------------

    fn x402_params() -> X402AcceptParams {
        X402AcceptParams {
            network: "base".into(),
            asset: "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913".into(),
            pay_to: "0x0000000000000000000000000000000000000001".into(),
            facilitator_url: "https://x402.org/facilitator".into(),
        }
    }

    fn manifest_with_methods(action: &str, methods: Option<Vec<&str>>) -> Value {
        let mut pricing = serde_json::Map::new();
        pricing.insert("base".into(), json!(0.20));
        if let Some(m) = methods {
            pricing.insert("payment_methods".into(),
                json!(m.iter().map(|s| s.to_string()).collect::<Vec<_>>()));
        }
        json!({
            "actions": [
                { "id": action, "pricing": Value::Object(pricing) }
            ]
        })
    }

    #[test]
    fn accepts_both_when_x402_enabled_and_manifest_lists_both() {
        // Stripe + x402 capability with Hub kill-switch on → both entries,
        // Stripe first (admiral D).
        let m = manifest_with_methods("bg-remover-pro", Some(vec!["stripe", "x402"]));
        let params = x402_params();
        let v = build_payment_accepts_inner(
            Some(&params), &m,
            "jobdonebot", "jobdonebot/bg-remover-pro", "bg-remover-pro", "1.0.0",
            "req_abc123", 0.20,
        );
        let accepts = v["accepts"].as_array().unwrap();
        assert_eq!(accepts.len(), 2);
        assert_eq!(accepts[0]["scheme"], "stripe-wallet");
        assert_eq!(accepts[0]["amount_usd"], 0.20);
        assert_eq!(accepts[1]["scheme"], "exact");
        assert_eq!(accepts[1]["network"], "base");
        assert_eq!(accepts[1]["asset_symbol"], "USDC");
        assert_eq!(accepts[1]["amount"], "200000");
        assert_eq!(accepts[1]["pay_to"], params.pay_to);
        assert_eq!(accepts[1]["extra"]["facilitator_url"], params.facilitator_url);
        assert!(accepts[1]["extra"]["splitter_capability_id"]
            .as_str().unwrap().starts_with("0x"));
        assert_eq!(v["ttl_seconds"], 30);
    }

    #[test]
    fn accepts_only_stripe_when_capability_is_wallet_only() {
        // Capability declares `payment_methods: ["stripe"]` → x402 entry must
        // be absent even if the Hub kill-switch is on.
        let m = manifest_with_methods("invoice", Some(vec!["stripe"]));
        let params = x402_params();
        let v = build_payment_accepts_inner(
            Some(&params), &m,
            "jobdonebot", "jobdonebot/invoice", "invoice", "1.0.0",
            "req_x", 0.005,
        );
        let accepts = v["accepts"].as_array().unwrap();
        assert_eq!(accepts.len(), 1);
        assert_eq!(accepts[0]["scheme"], "stripe-wallet");
    }

    #[test]
    fn accepts_only_stripe_when_x402_kill_switch_off() {
        // Hub kill-switch off (state.x402 == None) → x402 entry must be
        // absent even if the manifest declares "x402".
        let m = manifest_with_methods("any", Some(vec!["stripe", "x402"]));
        let v = build_payment_accepts_inner(
            None, &m,
            "ns", "ns/cap", "any", "1.0.0",
            "req_y", 0.01,
        );
        let accepts = v["accepts"].as_array().unwrap();
        assert_eq!(accepts.len(), 1);
        assert_eq!(accepts[0]["scheme"], "stripe-wallet");
    }

    #[test]
    fn accepts_only_x402_when_capability_is_x402_only() {
        // Locked-design v1.1.1 §3.6: capability may opt out of Stripe entirely.
        let m = manifest_with_methods("stream", Some(vec!["x402"]));
        let params = x402_params();
        let v = build_payment_accepts_inner(
            Some(&params), &m,
            "ns", "ns/cap", "stream", "1.0.0",
            "req_z", 0.001,
        );
        let accepts = v["accepts"].as_array().unwrap();
        assert_eq!(accepts.len(), 1);
        assert_eq!(accepts[0]["scheme"], "exact");
    }

    #[test]
    fn accepts_default_is_stripe_when_manifest_omits_payment_methods() {
        // Locked-design v1.1.1 §3.6: omitted field defaults to ["stripe"].
        let m = manifest_with_methods("legacy-action", None);
        let params = x402_params();
        let v = build_payment_accepts_inner(
            Some(&params), &m,
            "ns", "ns/cap", "legacy-action", "1.0.0",
            "req_w", 0.01,
        );
        let accepts = v["accepts"].as_array().unwrap();
        assert_eq!(accepts.len(), 1);
        assert_eq!(accepts[0]["scheme"], "stripe-wallet");
    }

    #[test]
    fn extract_payment_methods_finds_array() {
        let m = manifest_with_methods("a", Some(vec!["stripe", "x402"]));
        let got = extract_payment_methods(&m, "a");
        assert_eq!(got, vec!["stripe".to_string(), "x402".to_string()]);
    }

    #[test]
    fn extract_payment_methods_absent_returns_empty() {
        let m = manifest_with_methods("a", None);
        let got = extract_payment_methods(&m, "a");
        assert!(got.is_empty());
    }

    #[test]
    fn urlencoding_lite_handles_specials() {
        // Defensive escaper for the `return=<req_id>` query value.
        assert_eq!(urlencoding_lite("req_abc-123.xyz~"), "req_abc-123.xyz~");
        assert_eq!(urlencoding_lite("a b"), "a%20b");
        assert_eq!(urlencoding_lite("x&y=z"), "x%26y%3Dz");
    }

    // -----------------------------------------------------------------------
    // H-2 (audit-A H3/H4/H5) — Cache-Control / CORS-expose / WWW-Authenticate
    // -----------------------------------------------------------------------
    //
    // We exercise the two response-builder sites whose wire shape changed:
    //   • x402_error_response → 402/422/502/504 envelopes (H3 + H4)
    //   • error_response      → all streaming-path errors (H3 + H4)
    // The 402-specific WWW-Authenticate branching is asserted at the helper
    // module level (`protocol::x402_response_headers::tests`); we cover the
    // full per-handler integration here.

    use crate::protocol::x402_types::X402Error as XErr;

    #[test]
    fn cache_control_no_store_on_x402_error_response() {
        // H3: every x402 422/502/504 envelope emits Cache-Control: no-store.
        let e = XErr::PaymentInvalid {
            subcause: "amount_mismatch",
            message: "verified amount < required".into(),
        };
        let resp = x402_error_response(&e, "req_abc123", Some("https://x402.org/facilitator"));
        let cc = resp.headers().get(axum::http::header::CACHE_CONTROL).unwrap();
        assert_eq!(cc, "no-store");
    }

    #[test]
    fn expose_headers_includes_x_payment_response_on_x402_error() {
        // H4: CORS expose list contains X-Payment-Response on every x402 envelope.
        let e = XErr::SettlementTimeout {
            subcause: "facilitator_slow",
            message: "5000ms".into(),
            elapsed_ms: Some(5000),
        };
        let resp = x402_error_response(&e, "req_t", Some("https://x402.org/facilitator"));
        let exp = resp
            .headers()
            .get(axum::http::header::ACCESS_CONTROL_EXPOSE_HEADERS)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(exp.contains("X-Payment-Response"));
        assert!(exp.contains("X-Request-Id"));
        assert!(exp.contains("Retry-After"));
        assert!(exp.contains("WWW-Authenticate"));
        // The Retry-After header itself MUST still be set for SettlementTimeout
        // (preserves the prior contract).
        assert_eq!(
            resp.headers().get(axum::http::header::RETRY_AFTER).unwrap(),
            "30"
        );
    }

    #[test]
    fn cache_control_no_store_on_stream_error_response() {
        // H3: streaming preflight errors share the no-store policy.
        let resp = error_response(
            axum::http::StatusCode::BAD_REQUEST,
            "PARSE_ERROR",
            "broken",
        );
        let cc = resp.headers().get(axum::http::header::CACHE_CONTROL).unwrap();
        assert_eq!(cc, "no-store");
        let exp = resp
            .headers()
            .get(axum::http::header::ACCESS_CONTROL_EXPOSE_HEADERS)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(exp.contains("X-Payment-Response"));
    }

    #[test]
    fn www_authenticate_x402_only_branch() {
        // H5: x402-only capability → `x402, scheme="exact", network="base"`.
        use crate::protocol::x402_response_headers::apply_402_headers;
        let mut h = axum::http::HeaderMap::new();
        apply_402_headers(&mut h, &["x402"]);
        let v = h
            .get(axum::http::header::WWW_AUTHENTICATE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(v.contains("x402"));
        assert!(v.contains(r#"scheme="exact""#));
        assert!(v.contains(r#"network="base""#));
        // Cache-Control + expose MUST be set too (combined helper).
        assert_eq!(h.get(axum::http::header::CACHE_CONTROL).unwrap(), "no-store");
    }

    #[test]
    fn www_authenticate_x402_plus_bearer_branch() {
        // H5: both stripe+x402 → `x402, Bearer` (no realm collision).
        use crate::protocol::x402_response_headers::apply_402_headers;
        let mut h = axum::http::HeaderMap::new();
        apply_402_headers(&mut h, &["stripe", "x402"]);
        let v = h
            .get(axum::http::header::WWW_AUTHENTICATE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(v.contains("x402"));
        assert!(v.contains("Bearer"));
    }

    // -----------------------------------------------------------------------
    // Audit A residual fix sweep — H1 / H2 / M1 / M2 / M6 / L1
    // -----------------------------------------------------------------------

    #[test]
    fn extra_emits_eip712_domain_for_canonical_base_usdc() {
        // Audit A-H1 (spec §2.2): when the asset matches Base mainnet USDC,
        // the 402 `accepts[].extra` MUST include `name="USD Coin"`, `version="2"`
        // (EIP-712 domain separator) so the facilitator can verify signatures.
        let m = manifest_with_methods("translate", Some(vec!["x402"]));
        let params = X402AcceptParams {
            network: "base".into(),
            asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913".into(),
            pay_to: "0x000000000000000000000000000000000000C0DE".into(),
            facilitator_url: "https://x402.org/facilitator".into(),
        };
        let v = build_payment_accepts_inner(
            Some(&params), &m,
            "ns", "ns/cap", "translate", "1.0.0",
            "req_h1", 0.005,
        );
        let extra = &v["accepts"][0]["extra"];
        assert_eq!(extra["name"], "USD Coin");
        assert_eq!(extra["version"], "2");
        assert_eq!(extra["facilitator_url"], params.facilitator_url);
        assert!(extra["splitter_capability_id"].as_str().unwrap().starts_with("0x"));
    }

    #[test]
    fn extra_skips_eip712_domain_for_non_canonical_asset() {
        // Audit A-H1: only emit EIP-712 domain fields when the asset is
        // a known one (canonical Base USDC). For arbitrary ERC-20s we have
        // no curated metadata in v1.1.0 — better to omit than to lie.
        let m = manifest_with_methods("translate", Some(vec!["x402"]));
        let params = X402AcceptParams {
            network: "base".into(),
            // Random non-USDC address.
            asset: "0xDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF".into(),
            pay_to: "0x000000000000000000000000000000000000C0DE".into(),
            facilitator_url: "https://x402.org/facilitator".into(),
        };
        let v = build_payment_accepts_inner(
            Some(&params), &m,
            "ns", "ns/cap", "translate", "1.0.0",
            "req_h1b", 0.005,
        );
        let extra = &v["accepts"][0]["extra"];
        assert!(extra.get("name").is_none(), "non-USDC asset must NOT carry EIP-712 name");
        assert!(extra.get("version").is_none(), "non-USDC asset must NOT carry EIP-712 version");
    }

    #[test]
    fn is_canonical_base_usdc_case_insensitive() {
        // Real-world facilitator/Hub configs disagree on checksum casing —
        // the comparison MUST be case-insensitive so the EIP-712 domain
        // fields fire regardless of how the operator wrote the env var.
        assert!(is_canonical_base_usdc("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"));
        assert!(is_canonical_base_usdc("0x833589FCD6EDB6E08F4C7C32D4F71B54BDA02913"));
        assert!(is_canonical_base_usdc("0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"));
        assert!(!is_canonical_base_usdc("0x0000000000000000000000000000000000000000"));
    }

    #[test]
    fn amount_usd_serializes_subcent_precision() {
        // Audit A-H2 (spec §2.2.1): USDC has 6 decimals, $0.005 must
        // serialize cleanly. f64 0.005 → JSON "0.005" (not "0" or "5e-3").
        let m = manifest_with_methods("translate", Some(vec!["stripe", "x402"]));
        let params = x402_params();
        let v = build_payment_accepts_inner(
            Some(&params), &m,
            "ns", "ns/cap", "translate", "1.0.0",
            "req_h2", 0.005,
        );
        let amount = &v["accepts"][0]["amount_usd"];
        // Must not be 0 (truncation), must equal 0.005.
        assert_eq!(amount.as_f64().unwrap(), 0.005);
        // Stringified JSON must contain "0.005".
        let s = serde_json::to_string(&v).unwrap();
        assert!(
            s.contains("\"amount_usd\":0.005"),
            "expected sub-cent serialization, got: {}",
            s
        );
    }

    #[test]
    fn settlement_reused_envelope_carries_replay_info() {
        // Audit A-M1 (spec §3.5): X402_SETTLEMENT_REUSED MUST include
        // `details.tx_hash`, `details.original_request_id`, `details.original_settled_at`
        // when the lookup succeeds.
        use crate::protocol::x402_types::ReplayInfo;
        let settled_at = chrono::DateTime::parse_from_rfc3339("2026-05-11T10:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let e = XErr::SettlementReused {
            subcause: "nonce_reused",
            message: "replay".into(),
            replay_info: Some(ReplayInfo {
                tx_hash: "0xabc123".into(),
                original_request_id: "req_first_001".into(),
                original_settled_at: settled_at,
            }),
        };
        let resp = x402_error_response(&e, "req_replay_002", None);
        assert_eq!(resp.status().as_u16(), 409);
        let bytes = futures::executor::block_on(async {
            axum::body::to_bytes(resp.into_body(), 1024 * 32).await.unwrap()
        });
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["id"], "req_replay_002");
        let details = &body["error"]["details"];
        assert_eq!(details["tx_hash"], "0xabc123");
        assert_eq!(details["original_request_id"], "req_first_001");
        assert_eq!(details["original_settled_at"], "2026-05-11T10:00:00+00:00");
        assert_eq!(details["subcause"], "nonce_reused");
        // Audit A-M6: next_action.type = "x402_settle"
        assert_eq!(body["next_action"]["type"], "x402_settle");
        assert!(body["next_action"]["hint"].as_str().unwrap().contains("fresh nonce"));
    }

    #[test]
    fn settlement_timeout_envelope_carries_elapsed_ms() {
        // Audit A-M2 (spec §3.5): X402_SETTLEMENT_TIMEOUT MUST include
        // `details.elapsed_ms` when measured.
        let e = XErr::SettlementTimeout {
            subcause: "facilitator_slow",
            message: "5023ms".into(),
            elapsed_ms: Some(5023),
        };
        let resp = x402_error_response(&e, "req_timeout", Some("https://x402.org/facilitator"));
        let bytes = futures::executor::block_on(async {
            axum::body::to_bytes(resp.into_body(), 1024 * 32).await.unwrap()
        });
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let details = &body["error"]["details"];
        assert_eq!(details["elapsed_ms"], 5023);
        assert_eq!(details["facilitator_url"], "https://x402.org/facilitator");
    }

    #[test]
    fn payment_requirements_serializes_snake_case() {
        // Audit A-L1 (spec §2.2 / §4.2): the canonical wire form is snake_case.
        // We accept camelCase via aliases for legacy facilitator interop, but
        // outbound MUST be snake_case.
        use crate::protocol::x402_types::PaymentRequirements;
        use alloy_primitives::Address;
        let pr = PaymentRequirements {
            scheme: "exact".into(),
            network: "base".into(),
            max_amount_required: "200000".into(),
            asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913".parse::<Address>().unwrap(),
            pay_to: "0x000000000000000000000000000000000000C0DE".parse::<Address>().unwrap(),
            resource: "https://jecp.dev/v1/invoke".into(),
            description: "test".into(),
            mime_type: "application/json".into(),
            max_timeout_seconds: 60,
            extra: serde_json::json!({}),
        };
        let s = serde_json::to_string(&pr).unwrap();
        assert!(s.contains("\"max_amount_required\""), "outbound must be snake_case: {}", s);
        assert!(s.contains("\"pay_to\""));
        assert!(s.contains("\"mime_type\""));
        assert!(s.contains("\"max_timeout_seconds\""));
        // camelCase aliases MUST still parse on inbound (legacy interop).
        let camel = r#"{"scheme":"exact","network":"base","maxAmountRequired":"200000",
            "asset":"0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
            "payTo":"0x000000000000000000000000000000000000C0DE",
            "resource":"https://jecp.dev/v1/invoke","description":"t",
            "mimeType":"application/json","maxTimeoutSeconds":60,"extra":{}}"#;
        let parsed: PaymentRequirements = serde_json::from_str(camel).unwrap();
        assert_eq!(parsed.max_amount_required, "200000");
        assert_eq!(parsed.max_timeout_seconds, 60);
    }
}
