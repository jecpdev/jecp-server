//! W2 — Refund API (Spec §3.4 — programmatic refunds within 30 days)
//!
//! Endpoints:
//!   POST /v1/refunds                         (agent requests)
//!   GET  /v1/refunds                         (list mine)
//!   GET  /v1/refunds/<id>                    (read one)
//!   POST /v1/refunds/<id>/approve            (provider approves)
//!   POST /v1/refunds/<id>/deny               (provider denies)
//!
//! Lifecycle: requested → approved | auto_approved | denied
//! Auto-approval after 24h with no Provider response (background cron).
//! Hub keeps 10% fee even on refund (processing cost). Agent gets back 90%.
//!
//! Webhook events (W4): refund.requested, invocation.refunded, refund.denied

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::Row;

use crate::AppState;

const REFUND_WINDOW_DAYS: i64 = 30;
const RATE_LIMIT_PER_DAY: i64 = 5;

// ───────────────────────────────────────────────────────────────
// Request/response types
// ───────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct RequestRefundBody {
    pub transaction_id: String,
    pub reason: String,
    pub evidence_url: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RefundResponse {
    pub jecp: &'static str,
    pub refund_id: String,
    pub status: String,
    pub transaction_id: String,
    pub agent_id: String,
    pub amount_usdc: f64,
    pub reason: String,
    pub requested_at: String,
    pub estimated_resolution: Option<String>,
    pub resolved_at: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct DenyBody {
    pub reason: String,
}

// ───────────────────────────────────────────────────────────────
// Auth helpers — match patterns in providers.rs / invoke.rs
// ───────────────────────────────────────────────────────────────

fn extract_agent_creds(headers: &HeaderMap) -> Option<(String, String)> {
    let agent_id = headers.get("x-agent-id")?.to_str().ok()?.to_string();
    let api_key = headers.get("x-api-key")?.to_str().ok()?.to_string();
    Some((agent_id, api_key))
}

fn extract_provider_token(headers: &HeaderMap) -> Option<String> {
    let auth = headers.get("authorization")?.to_str().ok()?;
    auth.strip_prefix("Bearer ").map(|s| s.to_string())
}

// ───────────────────────────────────────────────────────────────
// Error helpers
// ───────────────────────────────────────────────────────────────

fn err_response(code: &str, message: &str, status: StatusCode, next_action: Option<serde_json::Value>) -> Response {
    let mut body = json!({
        "jecp": "1.0",
        "status": "failed",
        "error": { "code": code, "message": message },
    });
    if let Some(na) = next_action {
        body["next_action"] = na;
    }
    (status, Json(body)).into_response()
}

// ───────────────────────────────────────────────────────────────
// POST /v1/refunds — agent requests refund
// ───────────────────────────────────────────────────────────────
pub async fn request_refund(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    // K2.1 (v1.0.2): Content-Type negotiation — 415 on non-JSON.
    if let Err(e) = crate::protocol::http_guards::ensure_json_ct(&headers) {
        return e.into_response();
    }

    // ❶ Auth check FIRST — before body parse, so unauthenticated calls get clean 401.
    let Some((agent_id, api_key)) = extract_agent_creds(&headers) else {
        return err_response(
            "AUTH_REQUIRED",
            "X-Agent-ID and X-API-Key headers required",
            StatusCode::UNAUTHORIZED,
            Some(json!({ "type": "register", "ui": "https://jecp.dev/register" })),
        );
    };

    // ❷ Parse body
    let body: RequestRefundBody = match serde_json::from_slice(&body) {
        Ok(b) => b,
        Err(e) => return err_response(
            "INVALID_BODY",
            &format!("body must be valid JSON: {}", e),
            StatusCode::BAD_REQUEST,
            None,
        ),
    };

    // K3: POST /v1/refunds is agent-initiated (writes refund_request + Stripe
    // trigger), so it shares the hot invoke path. Per locked routing table
    // (phase0-locked-design.md §4): invoke pool, NOT provider pool.
    let Some(pool) = state.invoke_pool() else {
        return err_response("DB_UNAVAILABLE", "database not configured", StatusCode::INTERNAL_SERVER_ERROR, None);
    };

    // Validate agent + verify api_key (bcrypt comparison via existing helper pattern)
    let agent_row = sqlx::query("SELECT api_key_hash FROM jecp.agent_profiles WHERE agent_id = $1")
        .bind(&agent_id)
        .fetch_optional(pool)
        .await;
    let api_key_hash: Option<String> = match agent_row {
        Ok(Some(r)) => r.try_get("api_key_hash").ok(),
        _ => None,
    };
    let Some(hash) = api_key_hash else {
        return err_response("INVALID_AGENT", "agent not found or invalid api_key", StatusCode::UNAUTHORIZED, None);
    };
    if !bcrypt::verify(&api_key, &hash).unwrap_or(false) {
        return err_response("INVALID_AGENT", "agent not found or invalid api_key", StatusCode::UNAUTHORIZED, None);
    }

    // Validate transaction_id, ownership, age, type, not yet refunded
    let tx = sqlx::query(
        "SELECT id, agent_id, type, amount_usdc, capability, action, created_at, refunded_at
           FROM jecp.transactions WHERE id::TEXT = $1",
    )
    .bind(&body.transaction_id)
    .fetch_optional(pool)
    .await;
    let Ok(Some(tx_row)) = tx else {
        return err_response("TRANSACTION_NOT_FOUND", "transaction not found", StatusCode::NOT_FOUND, None);
    };
    let tx_agent: String = tx_row.try_get("agent_id").unwrap_or_default();
    if tx_agent != agent_id {
        return err_response("FORBIDDEN", "transaction does not belong to this agent", StatusCode::FORBIDDEN, None);
    }
    let tx_type: String = tx_row.try_get("type").unwrap_or_default();
    if tx_type != "charge" {
        return err_response("INVALID_TRANSACTION", "only charge transactions can be refunded", StatusCode::BAD_REQUEST, None);
    }
    let already_refunded: Option<chrono::DateTime<chrono::Utc>> = tx_row.try_get("refunded_at").ok();
    if already_refunded.is_some() {
        return err_response("ALREADY_REFUNDED", "this transaction has already been refunded", StatusCode::CONFLICT, None);
    }

    let created_at: chrono::DateTime<chrono::Utc> = tx_row.try_get("created_at").unwrap_or_else(|_| chrono::Utc::now());
    let age = chrono::Utc::now() - created_at;
    if age > chrono::Duration::days(REFUND_WINDOW_DAYS) {
        return err_response(
            "REFUND_WINDOW_EXPIRED",
            &format!("transaction is older than {} days", REFUND_WINDOW_DAYS),
            StatusCode::BAD_REQUEST,
            None,
        );
    }

    // Rate limit: max 5 refund requests per agent per day
    let recent_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::BIGINT FROM jecp.refunds WHERE agent_id = $1 AND requested_at > NOW() - INTERVAL '24 hours'",
    )
    .bind(&agent_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0);
    if recent_count >= RATE_LIMIT_PER_DAY {
        return err_response(
            "RATE_LIMITED",
            "too many refund requests in the last 24 hours",
            StatusCode::TOO_MANY_REQUESTS,
            Some(json!({ "type": "retry_after", "hint": "max 5 refund requests per day" })),
        );
    }

    // Resolve provider_id from the original capability
    let capability: Option<String> = tx_row.try_get("capability").ok();
    let amount_usdc: rust_decimal::Decimal = tx_row.try_get("amount_usdc").unwrap_or_default();

    let provider_id_row = match &capability {
        Some(cap) => sqlx::query("SELECT provider_id FROM jecp.capabilities WHERE full_id = $1 LIMIT 1")
            .bind(cap)
            .fetch_optional(pool)
            .await
            .ok()
            .flatten(),
        None => None,
    };
    let provider_id: Option<uuid::Uuid> = provider_id_row.and_then(|r| r.try_get("provider_id").ok());

    let Some(provider_id) = provider_id else {
        return err_response(
            "PROVIDER_NOT_RESOLVABLE",
            "could not resolve provider for this transaction",
            StatusCode::BAD_REQUEST,
            None,
        );
    };

    // S1 / P0-6 — per-(agent, provider) refund rate limit. Stops a single
    // agent from concentration-firing a single Provider's pending revenue.
    let pair_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::BIGINT FROM jecp.refunds
          WHERE agent_id = $1 AND provider_id = $2
            AND requested_at > NOW() - INTERVAL '24 hours'",
    )
    .bind(&agent_id)
    .bind(provider_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0);
    const PAIR_LIMIT: i64 = 3;
    if pair_count >= PAIR_LIMIT {
        return err_response(
            "REFUND_RATE_LIMITED",
            &format!("too many refunds against this provider in the last 24 hours (max {} / agent / provider / 24 h)", PAIR_LIMIT),
            StatusCode::TOO_MANY_REQUESTS,
            Some(json!({
                "type": "retry_after",
                "hint": format!("Limit is {} refunds per (agent, provider) pair per 24 h. Concentrating refunds on a single Provider is rate-limited to prevent abuse. Either wait or contact the Provider directly to dispute.", PAIR_LIMIT),
            })),
        );
    }

    // Insert refund row (UNIQUE on transaction_id prevents double request)
    let insert = sqlx::query(
        "INSERT INTO jecp.refunds
           (transaction_id, agent_id, provider_id, amount_usdc, reason, evidence_url, status)
         VALUES ($1::UUID, $2, $3, $4, $5, $6, 'requested')
         RETURNING id, requested_at",
    )
    .bind(&body.transaction_id)
    .bind(&agent_id)
    .bind(provider_id)
    .bind(amount_usdc)
    .bind(&body.reason)
    .bind(&body.evidence_url)
    .fetch_one(pool)
    .await;

    let row = match insert {
        Ok(r) => r,
        Err(sqlx::Error::Database(db_err)) if db_err.constraint().map_or(false, |c| c.contains("one_refund_per_tx")) => {
            return err_response("DUPLICATE_REFUND", "refund already requested for this transaction", StatusCode::CONFLICT, None);
        }
        Err(e) => {
            tracing::error!("refund insert failed: {}", e);
            return err_response("DB_ERROR", "could not create refund", StatusCode::INTERNAL_SERVER_ERROR, None);
        }
    };

    let refund_id: String = row.try_get("id").unwrap_or_default();
    let requested_at: chrono::DateTime<chrono::Utc> = row.try_get("requested_at").unwrap_or_else(|_| chrono::Utc::now());
    // S1 / P0-6: 7-day window aligns with chargeback dispute industry standard,
    // closes the 24h auto-approve abuse vector.
    let auto_approve_hours: i64 = std::env::var("JECP_REFUND_AUTO_APPROVE_HOURS")
        .ok().and_then(|s| s.parse().ok()).unwrap_or(168);
    let estimated = requested_at + chrono::Duration::hours(auto_approve_hours);

    let amount_f64: f64 = amount_usdc.to_string().parse().unwrap_or(0.0);

    // W4 — fire refund.requested event to provider
    let pool_for_event = pool.clone();
    let provider_id_str = provider_id.to_string();
    let agent_id_for_event = agent_id.clone();
    let refund_id_for_event = refund_id.clone();
    let tx_id_for_event = body.transaction_id.clone();
    let reason_for_event = body.reason.clone();
    let auto_approve_at = (chrono::Utc::now() + chrono::Duration::hours(auto_approve_hours)).to_rfc3339();
    tokio::spawn(async move {
        let payload = json!({
            "refund_id": refund_id_for_event,
            "transaction_id": tx_id_for_event,
            "agent_id": agent_id_for_event,
            "provider_id": provider_id_str,
            "amount_usdc": amount_f64,
            "reason": reason_for_event,
            "auto_approve_at": auto_approve_at,
        });
        crate::services::webhooks::enqueue(&pool_for_event, &provider_id_str, "provider", "refund.requested", payload).await;
    });

    let resp = RefundResponse {
        jecp: "1.0",
        refund_id,
        status: "requested".to_string(),
        transaction_id: body.transaction_id,
        agent_id,
        amount_usdc: amount_f64,
        reason: body.reason,
        requested_at: requested_at.to_rfc3339(),
        estimated_resolution: Some(estimated.to_rfc3339()),
        resolved_at: None,
    };
    (StatusCode::CREATED, Json(resp)).into_response()
}

// ───────────────────────────────────────────────────────────────
// GET /v1/refunds/<id> — read one
// ───────────────────────────────────────────────────────────────
pub async fn get_refund(
    State(state): State<AppState>,
    Path(refund_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    // TIER A.7 — read pool for GET (separate from invoke / provider write paths).
    let Some(pool) = state.read_pool() else {
        return err_response("DB_UNAVAILABLE", "database not configured", StatusCode::INTERNAL_SERVER_ERROR, None);
    };

    // Either agent or provider can view their own refunds
    let agent_creds = extract_agent_creds(&headers);
    let provider_token = extract_provider_token(&headers);

    if agent_creds.is_none() && provider_token.is_none() {
        return err_response("AUTH_REQUIRED", "agent or provider auth required", StatusCode::UNAUTHORIZED, None);
    }

    let row = sqlx::query(
        "SELECT id, transaction_id::TEXT, agent_id, provider_id::TEXT, amount_usdc,
                reason, evidence_url, status, requested_at, resolved_at, resolution_note
           FROM jecp.refunds WHERE id = $1",
    )
    .bind(&refund_id)
    .fetch_optional(pool)
    .await;

    let Ok(Some(r)) = row else {
        return err_response("REFUND_NOT_FOUND", "refund not found", StatusCode::NOT_FOUND, None);
    };

    let agent_id_in_db: String = r.try_get("agent_id").unwrap_or_default();
    let provider_id_in_db: String = r.try_get("provider_id").unwrap_or_default();

    // Authorization check
    let authorized = match (&agent_creds, &provider_token) {
        (Some((aid, _)), _) if aid == &agent_id_in_db => true,
        (_, Some(token)) => {
            // Verify token matches the provider that owns this refund
            verify_provider_token(pool, token, &provider_id_in_db).await
        }
        _ => false,
    };

    if !authorized {
        return err_response("FORBIDDEN", "you cannot view this refund", StatusCode::FORBIDDEN, None);
    }

    let amount: rust_decimal::Decimal = r.try_get("amount_usdc").unwrap_or_default();
    let amount_f64: f64 = amount.to_string().parse().unwrap_or(0.0);

    Json(json!({
        "jecp": "1.0",
        "refund_id": r.try_get::<String, _>("id").unwrap_or_default(),
        "transaction_id": r.try_get::<String, _>("transaction_id").unwrap_or_default(),
        "agent_id": agent_id_in_db,
        "provider_id": provider_id_in_db,
        "amount_usdc": amount_f64,
        "reason": r.try_get::<String, _>("reason").unwrap_or_default(),
        "evidence_url": r.try_get::<Option<String>, _>("evidence_url").ok().flatten(),
        "status": r.try_get::<String, _>("status").unwrap_or_default(),
        "requested_at": r.try_get::<chrono::DateTime<chrono::Utc>, _>("requested_at").map(|t| t.to_rfc3339()).unwrap_or_default(),
        "resolved_at": r.try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("resolved_at").ok().flatten().map(|t| t.to_rfc3339()),
        "resolution_note": r.try_get::<Option<String>, _>("resolution_note").ok().flatten(),
    })).into_response()
}

// ───────────────────────────────────────────────────────────────
// GET /v1/refunds — list mine (agent or provider)
// ───────────────────────────────────────────────────────────────
pub async fn list_refunds(
    State(state): State<AppState>,
    Query(q): Query<ListQuery>,
    headers: HeaderMap,
) -> Response {
    // TIER A.7 — read pool for GET list.
    let Some(pool) = state.read_pool() else {
        return err_response("DB_UNAVAILABLE", "database not configured", StatusCode::INTERNAL_SERVER_ERROR, None);
    };

    let limit = q.limit.unwrap_or(50).clamp(1, 200);

    let agent_creds = extract_agent_creds(&headers);
    let provider_token = extract_provider_token(&headers);

    let rows = if let Some((agent_id, _)) = &agent_creds {
        sqlx::query(
            "SELECT id, transaction_id::TEXT, agent_id, provider_id::TEXT,
                    amount_usdc, reason, status, requested_at, resolved_at
               FROM jecp.refunds WHERE agent_id = $1
              ORDER BY requested_at DESC LIMIT $2",
        )
        .bind(agent_id)
        .bind(limit)
        .fetch_all(pool)
        .await
    } else if let Some(token) = &provider_token {
        // Resolve provider_id from token
        let pid = lookup_provider_by_token(pool, token).await;
        match pid {
            Some(pid) => sqlx::query(
                "SELECT id, transaction_id::TEXT, agent_id, provider_id::TEXT,
                        amount_usdc, reason, status, requested_at, resolved_at
                   FROM jecp.refunds WHERE provider_id = $1
                  ORDER BY requested_at DESC LIMIT $2",
            )
            .bind(pid)
            .bind(limit)
            .fetch_all(pool)
            .await,
            None => return err_response("INVALID_TOKEN", "provider token invalid", StatusCode::UNAUTHORIZED, None),
        }
    } else {
        return err_response("AUTH_REQUIRED", "agent or provider auth required", StatusCode::UNAUTHORIZED, None);
    };

    let rows = match rows {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("refund list failed: {}", e);
            return err_response("DB_ERROR", "list query failed", StatusCode::INTERNAL_SERVER_ERROR, None);
        }
    };

    let items: Vec<serde_json::Value> = rows.iter().map(|r| {
        let amount: rust_decimal::Decimal = r.try_get("amount_usdc").unwrap_or_default();
        let amount_f64: f64 = amount.to_string().parse().unwrap_or(0.0);
        json!({
            "refund_id": r.try_get::<String, _>("id").unwrap_or_default(),
            "transaction_id": r.try_get::<String, _>("transaction_id").unwrap_or_default(),
            "agent_id": r.try_get::<String, _>("agent_id").unwrap_or_default(),
            "amount_usdc": amount_f64,
            "reason": r.try_get::<String, _>("reason").unwrap_or_default(),
            "status": r.try_get::<String, _>("status").unwrap_or_default(),
            "requested_at": r.try_get::<chrono::DateTime<chrono::Utc>, _>("requested_at").map(|t| t.to_rfc3339()).unwrap_or_default(),
            "resolved_at": r.try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("resolved_at").ok().flatten().map(|t| t.to_rfc3339()),
        })
    }).collect();

    Json(json!({
        "jecp": "1.0",
        "refunds": items,
        "count": rows.len(),
    })).into_response()
}

// ───────────────────────────────────────────────────────────────
// POST /v1/refunds/<id>/approve  (provider only)
// ───────────────────────────────────────────────────────────────
pub async fn approve_refund(
    State(state): State<AppState>,
    Path(refund_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(pool) = state.provider_pool() else {
        return err_response("DB_UNAVAILABLE", "database not configured", StatusCode::INTERNAL_SERVER_ERROR, None);
    };
    let Some(token) = extract_provider_token(&headers) else {
        return err_response("AUTH_REQUIRED", "provider Authorization Bearer required", StatusCode::UNAUTHORIZED, None);
    };

    // Lookup provider_id, verify ownership
    let row = sqlx::query("SELECT provider_id::TEXT, status FROM jecp.refunds WHERE id = $1")
        .bind(&refund_id)
        .fetch_optional(pool)
        .await;
    let Ok(Some(r)) = row else {
        return err_response("REFUND_NOT_FOUND", "refund not found", StatusCode::NOT_FOUND, None);
    };
    let provider_id: String = r.try_get("provider_id").unwrap_or_default();
    let status: String = r.try_get("status").unwrap_or_default();

    if !verify_provider_token(pool, &token, &provider_id).await {
        return err_response("FORBIDDEN", "provider does not own this refund", StatusCode::FORBIDDEN, None);
    }
    if status != "requested" {
        return err_response("INVALID_STATE", &format!("refund is already {}", status), StatusCode::CONFLICT, None);
    }

    let _ = sqlx::query("UPDATE jecp.refunds SET status = 'approved' WHERE id = $1")
        .bind(&refund_id)
        .execute(pool)
        .await;

    // Trigger atomic refund processing
    let proc = sqlx::query("SELECT * FROM jecp.process_refund($1)")
        .bind(&refund_id)
        .fetch_optional(pool)
        .await;
    if let Err(e) = proc {
        tracing::error!("process_refund failed: {}", e);
        return err_response("PROCESS_FAILED", "refund approved but processing failed", StatusCode::INTERNAL_SERVER_ERROR, None);
    }

    // W4 — fire invocation.refunded event after processing
    fire_refund_resolution_events(pool, &refund_id, "approved").await;

    Json(json!({
        "jecp": "1.0",
        "refund_id": refund_id,
        "status": "approved",
    })).into_response()
}

// ───────────────────────────────────────────────────────────────
// POST /v1/refunds/<id>/deny  (provider only)
// ───────────────────────────────────────────────────────────────
pub async fn deny_refund(
    State(state): State<AppState>,
    Path(refund_id): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let Some(pool) = state.provider_pool() else {
        return err_response("DB_UNAVAILABLE", "database not configured", StatusCode::INTERNAL_SERVER_ERROR, None);
    };
    let Some(token) = extract_provider_token(&headers) else {
        return err_response("AUTH_REQUIRED", "provider Authorization Bearer required", StatusCode::UNAUTHORIZED, None);
    };
    let body: DenyBody = match serde_json::from_slice(&body) {
        Ok(b) => b,
        Err(e) => return err_response("INVALID_BODY", &format!("body must be valid JSON: {}", e), StatusCode::BAD_REQUEST, None),
    };

    let row = sqlx::query("SELECT provider_id::TEXT, status FROM jecp.refunds WHERE id = $1")
        .bind(&refund_id)
        .fetch_optional(pool)
        .await;
    let Ok(Some(r)) = row else {
        return err_response("REFUND_NOT_FOUND", "refund not found", StatusCode::NOT_FOUND, None);
    };
    let provider_id: String = r.try_get("provider_id").unwrap_or_default();
    let status: String = r.try_get("status").unwrap_or_default();
    if !verify_provider_token(pool, &token, &provider_id).await {
        return err_response("FORBIDDEN", "provider does not own this refund", StatusCode::FORBIDDEN, None);
    }
    if status != "requested" {
        return err_response("INVALID_STATE", &format!("refund is already {}", status), StatusCode::CONFLICT, None);
    }

    let _ = sqlx::query("UPDATE jecp.refunds SET status = 'denied', resolved_at = NOW(), resolution_note = $2 WHERE id = $1")
        .bind(&refund_id)
        .bind(&body.reason)
        .execute(pool)
        .await;

    // W4 — fire refund.denied event
    fire_refund_resolution_events(pool, &refund_id, "denied").await;

    Json(json!({
        "jecp": "1.0",
        "refund_id": refund_id,
        "status": "denied",
    })).into_response()
}

/// Fire invocation.refunded (or refund.denied) events to both agent + provider after resolution.
async fn fire_refund_resolution_events(pool: &sqlx::PgPool, refund_id: &str, status: &str) {
    let row = sqlx::query(
        "SELECT agent_id, provider_id::TEXT, transaction_id::TEXT, amount_usdc, reason, status, resolved_at
           FROM jecp.refunds WHERE id = $1",
    )
    .bind(refund_id)
    .fetch_optional(pool)
    .await;
    let Ok(Some(r)) = row else { return };
    let agent_id: String = r.try_get("agent_id").unwrap_or_default();
    let provider_id: String = r.try_get("provider_id").unwrap_or_default();
    let tx_id: String = r.try_get("transaction_id").unwrap_or_default();
    let amount: rust_decimal::Decimal = r.try_get("amount_usdc").unwrap_or_default();
    let amount_f64: f64 = amount.to_string().parse().unwrap_or(0.0);

    let event_type = if status == "denied" { "refund.denied" } else { "invocation.refunded" };
    let payload = json!({
        "refund_id": refund_id,
        "transaction_id": tx_id,
        "agent_id": agent_id,
        "provider_id": provider_id,
        "amount_usdc": amount_f64,
        "agent_credit_usdc": if status == "denied" { 0.0 } else { amount_f64 * 0.9 },
        "status": status,
    });
    crate::services::webhooks::enqueue(pool, &agent_id, "agent", event_type, payload.clone()).await;
    crate::services::webhooks::enqueue(pool, &provider_id, "provider", event_type, payload).await;
}

// ───────────────────────────────────────────────────────────────
// helpers
// ───────────────────────────────────────────────────────────────

async fn verify_provider_token(pool: &sqlx::PgPool, token: &str, expected_provider_id: &str) -> bool {
    let row = sqlx::query("SELECT id::TEXT, api_key_hash FROM jecp.providers WHERE id::TEXT = $1")
        .bind(expected_provider_id)
        .fetch_optional(pool)
        .await;
    let Ok(Some(r)) = row else { return false; };
    let hash: String = match r.try_get("api_key_hash") {
        Ok(h) => h,
        Err(_) => return false,
    };
    bcrypt::verify(token, &hash).unwrap_or(false)
}

/// Resolve a Provider api_key (jdb_pk_…) to its id.
///
/// S1 / TIER A.2 fix (2026-05-09 critical audit):
/// The previous implementation SELECTed every active Provider and ran
/// bcrypt::verify against each — O(N) bcrypt per request. With 1000
/// Providers and bcrypt cost=10 (~80 ms/op), 50 unauthenticated requests
/// per minute pegged a single CPU at 100% and killed the Hub.
///
/// Fix: use the api_key_prefix index (12-char prefix of the token, present
/// since register-time). Single SELECT, single bcrypt verify on the matched
/// row's hash. Returns None if no row matches the prefix, even if the
/// token is otherwise well-formed — same observable behaviour for clients.
async fn lookup_provider_by_token(pool: &sqlx::PgPool, token: &str) -> Option<uuid::Uuid> {
    if !token.starts_with("jdb_pk_") || token.len() < 12 {
        return None;
    }
    let prefix: String = token.chars().take(12).collect();

    // Includes both the active key and the rotation grace key (M2). We try
    // active first; if it doesn't match we try the previous (grace) prefix.
    let row = sqlx::query(
        "SELECT id, api_key_hash, previous_api_key_hash, previous_key_valid_until
           FROM jecp.providers
          WHERE (api_key_prefix = $1
                 OR (previous_api_key_prefix = $1 AND previous_key_valid_until > NOW()))
            AND status != 'deleted'
          LIMIT 1",
    )
    .bind(&prefix)
    .persistent(false)
    .fetch_optional(pool)
    .await
    .ok()??;

    let id: uuid::Uuid = row.try_get("id").ok()?;
    let active_hash: Option<String> = row.try_get("api_key_hash").ok();
    let prev_hash: Option<String> = row.try_get("previous_api_key_hash").ok();

    if let Some(h) = active_hash {
        if bcrypt::verify(token, &h).unwrap_or(false) {
            return Some(id);
        }
    }
    if let Some(h) = prev_hash {
        if bcrypt::verify(token, &h).unwrap_or(false) {
            return Some(id);
        }
    }
    None
}

// ───────────────────────────────────────────────────────────────
// Background auto-approval task — call from main.rs
// ───────────────────────────────────────────────────────────────
//
// S1 / P0-6 mitigation — refund auto-approve window extended from 24 h to
// 168 h (7 days). The previous 24 h window let an attacker drain a
// Provider's pending revenue by issuing a flood of refund claims that
// the Provider had no time to dispute. 7 days is the standard window
// for chargeback dispute in the card-payment industry; aligning here
// closes the abuse vector while still resolving in a bounded time.
//
// Configurable via env JECP_REFUND_AUTO_APPROVE_HOURS (default 168).
const REFUND_AUTO_APPROVE_HOURS_DEFAULT: i32 = 168; // 7 days

pub async fn auto_approve_loop(pool: sqlx::PgPool) {
    use tokio::time::{sleep, Duration};

    let auto_approve_hours: i32 = std::env::var("JECP_REFUND_AUTO_APPROVE_HOURS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(REFUND_AUTO_APPROVE_HOURS_DEFAULT);

    tracing::info!(
        "refund auto-approve loop starting (window: {} h)",
        auto_approve_hours
    );

    loop {
        sleep(Duration::from_secs(300)).await; // every 5 min
        let result = sqlx::query("SELECT id FROM jecp.auto_approve_pending_refunds($1)")
            .bind(auto_approve_hours)
            .fetch_all(&pool)
            .await;
        if let Ok(rows) = result {
            if !rows.is_empty() {
                tracing::info!("auto-approved {} refunds (window: {} h)", rows.len(), auto_approve_hours);
                for row in rows {
                    let id: String = row.try_get("id").unwrap_or_default();
                    let _ = sqlx::query("SELECT * FROM jecp.process_refund($1)")
                        .bind(&id)
                        .fetch_optional(&pool)
                        .await;
                    // W4 — fire invocation.refunded after auto-approval
                    fire_refund_resolution_events(&pool, &id, "auto_approved").await;
                }
            }
        }
    }
}
