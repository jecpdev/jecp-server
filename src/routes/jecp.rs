use axum::body::Bytes;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::sse::{Event, Sse};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::convert::Infallible;
use std::time::Instant;

use crate::auth::agent::{authenticate_agent, check_trust_gate, complete_task, consume_free_call, increment_agent_calls, record_task, verify_provenance};
use crate::auth::mandate::validate_mandate;
use crate::auth::replay_cache::Replay;
use crate::middleware::deprecation::ProvenanceVersion;
use crate::protocol::errors::ProvenanceSubcause;
use crate::capabilities::{execute_capability, CapabilityContext};
use crate::protocol::errors::JecpErrorCode;
use crate::protocol::types::*;
use crate::protocol::validator::validate_request;
use crate::services::database::{cache_lookup, cache_store, deduct_wallet, get_wallet_balance};
use crate::AppState;

/// POST /v1/jecp — Main JECP execution endpoint
///
/// Sprint 4.5 fix C3: Receive raw Bytes and parse manually so JSON deserialize
/// errors are returned in JECP error format (instead of Axum's default 422 plaintext).
pub async fn execute_jecp(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // K2.1 (v1.0.2): Content-Type negotiation. Reject non-JSON with 415 before
    // attempting to parse. Tolerates missing CT (admiral D1).
    if let Err(e) = crate::protocol::http_guards::ensure_json_ct(&headers) {
        return e.into_response();
    }

    // 0. Manual JSON parse — return JECP-formatted error on failure (Spec compliance)
    let req: JecpRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return JecpErrorCode::InvalidRequest(format!(
                "Failed to parse request body as JSON: {}",
                e
            ))
            .into_response();
        }
    };

    // 1. Validate request structure
    if let Err(e) = validate_request(&req) {
        return e.into_response();
    }

    // 2. Authenticate agent (requires DB)
    let (agent_id, api_key) = extract_auth(&headers, &req);

    let billing_method;

    // v1.0.1 c3: which Provenance version verified successfully (if any).
    // Set by the verify path inside the auth block below; read at the
    // success-response site to attach the ProvenanceVersion extension that
    // DeprecationLayer (RFC 8594 headers) reads.
    let mut provenance_version_used: Option<ProvenanceVersion> = None;

    if let Some(pool) = state.invoke_pool() {
        if agent_id.is_empty() || api_key.is_empty() {
            return JecpErrorCode::AuthRequired.into_response();
        }

        let agent = match authenticate_agent(pool, &agent_id, &api_key).await {
            Ok(a) => a,
            Err(e) => return e.into_response(),
        };

        // 2.5 Idempotency check (Sprint 4.5 / Spec compliance C1)
        //     Spec 01-protocol Section 5: same (agent_id, id) within 24h
        //     MUST return cached response, MUST NOT re-charge.
        let input_hash = compute_input_hash(&req);
        match cache_lookup(pool, &agent_id, &req.id, &input_hash).await {
            Ok(Some(cached)) => {
                tracing::info!(
                    "idempotent hit agent={} id={} status={}",
                    agent_id, req.id, cached.http_status
                );
                if cached.conflict {
                    // K2.2 (v1.0.2): same id + different (capability, action,
                    // input, provenance_hash) within the idempotency window
                    // returns 409 CONFLICT (per RFC 9110 §15.5.10), NOT 400.
                    // Identical replays return the cached response — that path
                    // is handled below.
                    return JecpErrorCode::DuplicateRequest(
                        "request id reused with different (capability, action, input) within idempotency window".to_string(),
                    )
                    .into_response();
                }
                if let Some(body) = cached.response {
                    let status = axum::http::StatusCode::from_u16(cached.http_status as u16)
                        .unwrap_or(axum::http::StatusCode::OK);
                    return (status, axum::Json(body)).into_response();
                }
            }
            Ok(None) => {} // cache miss — proceed
            Err(e) => {
                tracing::warn!("cache_lookup failed (non-fatal): {}", e);
            }
        }

        // 3. Provenance検証 — 嘘を許さない
        // mandate.provenance_hash がある場合、サーバー計算値と照合する。
        // v1 (legacy SHA256, sunset 2026-11-01) と v2 (HMAC-SHA256) の両対応:
        //   verify_provenance は wire string の "v2:" prefix で dispatch。
        // v1.0.1 c2: v2 success の場合 (timestamp, nonce) を replay cache に
        //   登録し、二重実行を `nonce_replay` subcause で reject する。
        // v1.0.1 c3: v1 success の場合は provenance_version_used = V1 を flag。
        //   middleware (DeprecationLayer) が成功レスポンスに RFC 8594 ヘッダーを付与。
        if let Some(ref mandate) = req.mandate {
            if let Some(ref claimed_hash) = mandate.provenance_hash {
                match verify_provenance(&agent, &mandate.api_key, claimed_hash) {
                    Ok(Some((_ts, nonce))) => {
                        // v2 path — register nonce in replay cache.
                        if state.replay_cache.check_and_insert(&agent_id, &nonce) == Replay::Replay {
                            return JecpErrorCode::ProvenanceMismatch {
                                reason: "Provenance v2 nonce already observed within replay window — generate a fresh nonce per request.".into(),
                                subcause: ProvenanceSubcause::NonceReplay,
                                drift_seconds: None,
                            }
                            .into_response();
                        }
                        provenance_version_used = Some(ProvenanceVersion::V2);
                    }
                    Ok(None) => {
                        // v1 path — no nonce, no replay defense (legacy semantics).
                        provenance_version_used = Some(ProvenanceVersion::V1);
                    }
                    Err(e) => return e.into_response(),
                }
            }
        }

        // 4. 信頼ゲート — 常連を優遇する
        // TrustTier が能力の要求水準を満たさなければ拒否
        if let Err(e) = check_trust_gate(&agent, &req.capability) {
            return e.into_response();
        }

        // 5. Rate limit check (K2.4 v1.0.2: emit Retry-After per RFC 9110 §10.2.3)
        match state.rate_limiter.check(&agent_id, Some(agent.trust_tier().rate_limit_rpm())).await {
            Ok(_) => {}
            Err(decision) => {
                return JecpErrorCode::RateLimited {
                    retry_after_secs: decision.retry_after_secs,
                }
                .into_response();
            }
        }

        // 6. Validate mandate (budget)
        let validated_mandate = match validate_mandate(&req.mandate, &req.capability, &req.action) {
            Ok(vm) => vm,
            Err(e) => return e.into_response(),
        };

        // 7. 支払い検査 — 優先順位: free_call → wallet → mandate → 402
        // 無料枠あり / コスト 0 → free_call
        // 無料枠尽きた + wallet 残高あり → wallet (実引き落とし)
        // mandate に予算あり → mandate (autonomous agent flow)
        // 支払い手段なし → 402 PaymentRequired
        billing_method = if validated_mandate.cost == 0.0 || agent.free_calls_remaining > 0 {
            if agent.free_calls_remaining > 0 {
                let _ = consume_free_call(pool, &agent_id).await;
            }
            "free_call"
        } else {
            // 残高チェック (cost > 0 で free_calls 尽きた場合)
            let balance = get_wallet_balance(pool, &agent_id).await.unwrap_or(0.0);
            if balance >= validated_mandate.cost {
                "wallet"
            } else if validated_mandate.budget_remaining.is_some() {
                "mandate"
            } else {
                // 支払い手段なし → 402
                return JecpErrorCode::PaymentRequired.into_response();
            }
        };

        // 8. Record task
        let task_id = format!("jecp_{}", &uuid::Uuid::new_v4().to_string().replace('-', "")[..12]);
        let _ = record_task(pool, &task_id, &agent_id, req.capability.as_str(), &req.action, &req.input, "working").await;
    } else {
        // DB unavailable — degraded mode (no auth, no billing, no recording)
        billing_method = "free_call";
    }

    // 7. Execute capability
    let start = Instant::now();
    let task_id = format!("jecp_{}", &uuid::Uuid::new_v4().to_string().replace('-', "")[..12]);

    let cap_ctx = CapabilityContext {
        claude: state.claude.clone(),
        storage: state.storage.clone(),
        pool: state.invoke_pool().cloned(),
        sns_bridge: state.sns_bridge.clone(),
    };

    // Handle streaming vs sync
    if req.delivery.mode == DeliveryMode::Stream {
        return execute_streaming(state, cap_ctx, req, task_id, billing_method, start).await;
    }

    // Sync execution
    let cost = get_action_price(&req.capability, &req.action);

    match execute_capability(&cap_ctx, &req).await {
        Ok(result) => {
            let duration_ms = start.elapsed().as_millis() as u64;
            let execution = Execution::new(duration_ms, 1);

            // Build billing based on chosen method, performing wallet deduction if needed
            let agent_id_for_charge = agent_id_for_billing(&req, &headers);
            let billing = match billing_method {
                "wallet" => {
                    if let Some(pool) = state.invoke_pool() {
                        match deduct_wallet(
                            pool,
                            &agent_id_for_charge,
                            cost,
                            req.capability.as_str(),
                            &req.action,
                            Some(&req.id),
                        ).await {
                            Ok(Some(deduct)) => {
                                // wallet 課金成功 → total_calls もインクリメント (Trust Tier 昇格用)
                                let _ = increment_agent_calls(pool, &agent_id_for_charge).await;
                                Billing::wallet(cost, deduct.balance_after, deduct.transaction_id)
                            }
                            Ok(None) => {
                                // Race condition: 残高が他のリクエストで先に消費された
                                let response = JecpResponse::error(
                                    req.id.clone(),
                                    JecpErrorCode::InsufficientBalance { needed: cost, remaining: 0.0 }.to_jecp_error(),
                                );
                                return Json(response).into_response();
                            }
                            Err(e) => {
                                tracing::error!("deduct_wallet failed: {}", e);
                                // 引き落としに失敗 = 結果は返すが billing は free 扱い (DB 障害時の保守的対応)
                                Billing::free(None)
                            }
                        }
                    } else {
                        Billing::free(None)
                    }
                }
                "mandate" => {
                    if let Some(pool) = state.invoke_pool() {
                        let _ = increment_agent_calls(pool, &agent_id_for_charge).await;
                    }
                    Billing::charged(cost, None)
                }
                _ => Billing::free(None),
            };

            // Record completion if DB available
            if let Some(pool) = state.invoke_pool() {
                let _ = complete_task(
                    pool, &task_id, "completed",
                    Some(&serde_json::to_value(&result).unwrap_or_default()),
                    Some(&serde_json::to_value(&billing).unwrap_or_default()),
                    Some(&serde_json::to_value(&execution).unwrap_or_default()),
                    None,
                ).await;
            }

            let response = JecpResponse::success(req.id.clone(), result, billing, execution);

            // Sprint 4.5 / C1: cache for idempotency (24h TTL)
            if let Some(pool) = state.invoke_pool() {
                let input_hash = compute_input_hash(&req);
                let body_json = serde_json::to_value(&response).unwrap_or_default();
                let _ = cache_store(
                    pool,
                    &agent_id_for_charge,
                    &req.id,
                    req.capability.as_str(),
                    &req.action,
                    &input_hash,
                    &body_json,
                    200,
                ).await;
            }

            let mut resp = Json(response).into_response();
            // v1.0.1 c3: tag the response with the provenance version used,
            // so DeprecationLayer middleware can attach RFC 8594 headers
            // on v1 acceptance.
            if let Some(pv) = provenance_version_used {
                resp.extensions_mut().insert(pv);
            }
            resp
        }
        Err(e) => {
            if let Some(pool) = state.invoke_pool() {
                let _ = complete_task(pool, &task_id, "failed", None, None, None, Some(&e.to_string())).await;
            }

            let response = JecpResponse::error(req.id.clone(), e.to_jecp_error());
            Json(response).into_response()
        }
    }
}

/// Compute SHA256 hash of canonical request representation for idempotency.
/// (Sprint 4.5 / C1)
fn compute_input_hash(req: &JecpRequest) -> String {
    let canonical = format!(
        "{}|{}|{}",
        req.capability.as_str(),
        req.action,
        serde_json::to_string(&req.input).unwrap_or_default(),
    );
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Helper: agent_id を mandate / headers から取得 (wallet deduction で使用)
fn agent_id_for_billing(req: &JecpRequest, headers: &HeaderMap) -> String {
    if let Some(ref m) = req.mandate {
        m.agent_id.clone()
    } else {
        headers.get("x-agent-id").and_then(|v| v.to_str().ok()).unwrap_or("").to_string()
    }
}

/// Stream execution via SSE
async fn execute_streaming(
    state: AppState,
    cap_ctx: CapabilityContext,
    req: JecpRequest,
    task_id: String,
    billing_method: &str,
    start: Instant,
) -> Response {
    let billing_method = billing_method.to_string();
    let action = req.action.clone();
    let cost = get_action_price(&req.capability, &req.action);

    let stream = async_stream::stream! {
        yield Ok::<_, Infallible>(Event::default()
            .event("status")
            .data(json!({
                "state": "working",
                "step": format!("executing-{}", action),
                "progress": 0.1
            }).to_string()));

        match execute_capability(&cap_ctx, &req).await {
            Ok(result) => {
                yield Ok(Event::default()
                    .event("status")
                    .data(json!({ "state": "working", "step": "finalizing", "progress": 0.9 }).to_string()));

                yield Ok(Event::default()
                    .event("result")
                    .data(json!({ "output": result.output }).to_string()));

                let duration_ms = start.elapsed().as_millis() as u64;
                let billing = if billing_method == "free_call" {
                    Billing::free(None)
                } else {
                    Billing::charged(cost, None)
                };
                let execution = Execution::new(duration_ms, 1);

                yield Ok(Event::default()
                    .event("done")
                    .data(json!({ "status": "completed", "billing": billing, "execution": execution }).to_string()));

                if let Some(pool) = state.invoke_pool() {
                    let _ = complete_task(
                        pool, &task_id, "completed",
                        Some(&serde_json::to_value(&result).unwrap_or_default()),
                        Some(&serde_json::to_value(&billing).unwrap_or_default()),
                        Some(&serde_json::to_value(&execution).unwrap_or_default()),
                        None,
                    ).await;
                }
            }
            Err(e) => {
                yield Ok(Event::default()
                    .event("error")
                    .data(json!({ "code": e.code(), "message": e.to_string() }).to_string()));

                if let Some(pool) = state.invoke_pool() {
                    let _ = complete_task(pool, &task_id, "failed", None, None, None, Some(&e.to_string())).await;
                }
            }
        }
    };

    Sse::new(stream).into_response()
}

/// Extract agent_id and api_key from headers or mandate
fn extract_auth(headers: &HeaderMap, req: &JecpRequest) -> (String, String) {
    if let Some(ref mandate) = req.mandate {
        return (mandate.agent_id.clone(), mandate.api_key.clone());
    }

    let agent_id = headers.get("x-agent-id").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let api_key = headers.get("x-api-key").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();

    (agent_id, api_key)
}
