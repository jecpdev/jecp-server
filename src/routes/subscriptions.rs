//! W4 — Webhook subscription management API.
//!
//! Endpoints:
//!   POST   /v1/subscriptions          — subscribe to events
//!   GET    /v1/subscriptions          — list mine
//!   PATCH  /v1/subscriptions/<id>     — update endpoint, events, pause/resume
//!   DELETE /v1/subscriptions/<id>     — delete
//!   POST   /v1/subscriptions/<id>/test — send a synthetic test event

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::Engine as _;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::Row;

use crate::AppState;

#[derive(Debug, Deserialize)]
pub struct CreateSubscriptionBody {
    pub endpoint_url: String,
    pub events: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateSubscriptionBody {
    pub endpoint_url: Option<String>,
    pub events: Option<Vec<String>>,
    pub status: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SubscriptionResponse {
    pub jecp: &'static str,
    pub subscription_id: String,
    pub endpoint_url: String,
    pub events: Vec<String>,
    pub status: String,
    pub hmac_secret: Option<String>, // populated only on create
    pub created_at: String,
}

fn err(code: &str, msg: &str, status: StatusCode) -> Response {
    (status, Json(json!({
        "jecp": "1.0",
        "status": "failed",
        "error": { "code": code, "message": msg },
    }))).into_response()
}

fn extract_subscriber(headers: &HeaderMap) -> Option<(String, String)> {
    if let (Some(aid), Some(_ak)) = (headers.get("x-agent-id"), headers.get("x-api-key")) {
        return Some(("agent".into(), aid.to_str().ok()?.to_string()));
    }
    if let Some(auth) = headers.get("authorization") {
        if let Some(token) = auth.to_str().ok().and_then(|s| s.strip_prefix("Bearer ")) {
            // We rely on the worker to validate provider_id resolution downstream;
            // here we encode "provider:<token-prefix>" until we resolve. To keep this
            // route simple, we resolve provider_id inside the handler.
            return Some(("provider".into(), token.to_string()));
        }
    }
    None
}

async fn resolve_subscriber_id(pool: &sqlx::PgPool, kind: &str, raw: &str) -> Option<String> {
    match kind {
        "agent" => Some(raw.to_string()), // agent_id is the literal id
        "provider" => {
            // Slow lookup by token (small Provider count)
            let rows = sqlx::query("SELECT id, api_key_hash FROM jecp.providers WHERE status IN ('verified','active')")
                .fetch_all(pool).await.ok()?;
            for r in rows {
                let hash: String = r.try_get("api_key_hash").ok()?;
                if bcrypt::verify(raw, &hash).unwrap_or(false) {
                    let id: uuid::Uuid = r.try_get("id").ok()?;
                    return Some(id.to_string());
                }
            }
            None
        }
        _ => None,
    }
}

// POST /v1/subscriptions
pub async fn create_subscription(
    State(state): State<AppState>,
    headers: HeaderMap,
    raw_body: axum::body::Bytes,
) -> Response {
    // K2.1 (v1.0.2): 415 on non-JSON Content-Type with JECP envelope.
    if let Err(r) = crate::protocol::http_guards::ensure_json_ct_response(&headers) {
        return r;
    }

    let body: CreateSubscriptionBody = match serde_json::from_slice(&raw_body) {
        Ok(b) => b,
        Err(e) => return err("INVALID_REQUEST", &format!("body is not valid JSON: {}", e), StatusCode::BAD_REQUEST),
    };

    let Some(pool) = state.provider_pool() else {
        return err("DB_UNAVAILABLE", "database not configured", StatusCode::INTERNAL_SERVER_ERROR);
    };
    let Some((kind, raw)) = extract_subscriber(&headers) else {
        return err("AUTH_REQUIRED", "agent or provider auth required", StatusCode::UNAUTHORIZED);
    };
    let Some(subscriber_id) = resolve_subscriber_id(pool, &kind, &raw).await else {
        return err("INVALID_AUTH", "could not resolve subscriber identity", StatusCode::UNAUTHORIZED);
    };

    // v1.1.0 c7 — SSRF full validation at register time (parse + scheme +
    // DNS resolve + deny CIDR). Closes hostname-to-deny-CIDR at register
    // so callers get fast 422 feedback. Deref-time re-validation in
    // services/webhooks.rs is still REQUIRED to catch DNS rebinding
    // between subscribe and deliver (per spec §9.7.1.1 step 6).
    if let Err(e) = crate::protocol::url_guard::validate_outbound_url(&body.endpoint_url).await {
        let safe_url = crate::protocol::url_guard::redact_url(&body.endpoint_url);
        let reason = e.reason().to_string();
        crate::protocol::url_guard::audit_log_rejection(
            pool, Some(&subscriber_id), None,
            "webhook_destination_url", "subscribe",
            &safe_url, &reason, None,
        ).await;
        let (status, body_json) = crate::protocol::url_guard::url_blocked_ssrf_tuple(
            "webhook_destination_url", &safe_url, &reason,
        );
        return (status, body_json).into_response();
    }

    // Generate per-subscription HMAC secret
    let mut secret_bytes = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut secret_bytes);
    let hmac_secret = base64::engine::general_purpose::STANDARD.encode(&secret_bytes);

    let events = body.events.unwrap_or_default();
    let row = sqlx::query(
        "INSERT INTO jecp.webhook_subscriptions
           (subscriber_id, subscriber_kind, endpoint_url, hmac_secret, events, status)
         VALUES ($1, $2, $3, $4, $5, 'active')
         ON CONFLICT (subscriber_id, endpoint_url) DO UPDATE
           SET events = EXCLUDED.events, status = 'active'
         RETURNING id::TEXT, created_at",
    )
    .bind(&subscriber_id)
    .bind(&kind)
    .bind(&body.endpoint_url)
    .bind(&hmac_secret)
    .bind(&events)
    .fetch_one(pool)
    .await;

    let row = match row {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("subscription insert failed: {}", e);
            return err("DB_ERROR", "insert failed", StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let id: String = row.try_get("id").unwrap_or_default();
    let created_at: chrono::DateTime<chrono::Utc> = row.try_get("created_at").unwrap_or_else(|_| chrono::Utc::now());

    (StatusCode::CREATED, Json(SubscriptionResponse {
        jecp: "1.0",
        subscription_id: id,
        endpoint_url: body.endpoint_url,
        events,
        status: "active".into(),
        hmac_secret: Some(hmac_secret),
        created_at: created_at.to_rfc3339(),
    })).into_response()
}

// GET /v1/subscriptions
pub async fn list_subscriptions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    // TIER A.7 — read pool for GET list.
    let Some(pool) = state.read_pool() else {
        return err("DB_UNAVAILABLE", "database not configured", StatusCode::INTERNAL_SERVER_ERROR);
    };
    let Some((kind, raw)) = extract_subscriber(&headers) else {
        return err("AUTH_REQUIRED", "agent or provider auth required", StatusCode::UNAUTHORIZED);
    };
    let Some(subscriber_id) = resolve_subscriber_id(pool, &kind, &raw).await else {
        return err("INVALID_AUTH", "could not resolve subscriber identity", StatusCode::UNAUTHORIZED);
    };

    let rows = sqlx::query(
        "SELECT id::TEXT, endpoint_url, events, status, created_at, last_success_at, failures_consecutive
           FROM jecp.webhook_subscriptions
          WHERE subscriber_id = $1 AND subscriber_kind = $2
          ORDER BY created_at DESC",
    )
    .bind(&subscriber_id)
    .bind(&kind)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let items: Vec<serde_json::Value> = rows.iter().map(|r| json!({
        "subscription_id": r.try_get::<String, _>("id").unwrap_or_default(),
        "endpoint_url": r.try_get::<String, _>("endpoint_url").unwrap_or_default(),
        "events": r.try_get::<Vec<String>, _>("events").unwrap_or_default(),
        "status": r.try_get::<String, _>("status").unwrap_or_default(),
        "created_at": r.try_get::<chrono::DateTime<chrono::Utc>, _>("created_at").map(|t| t.to_rfc3339()).unwrap_or_default(),
        "last_success_at": r.try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("last_success_at").ok().flatten().map(|t| t.to_rfc3339()),
        "failures_consecutive": r.try_get::<i32, _>("failures_consecutive").unwrap_or(0),
    })).collect();

    Json(json!({ "jecp": "1.0", "subscriptions": items, "count": items.len() })).into_response()
}

// PATCH /v1/subscriptions/<id>
pub async fn update_subscription(
    State(state): State<AppState>,
    Path(sub_id): Path<String>,
    headers: HeaderMap,
    raw_body: axum::body::Bytes,
) -> Response {
    // K2.1 (v1.0.2): 415 on non-JSON Content-Type with JECP envelope.
    if let Err(r) = crate::protocol::http_guards::ensure_json_ct_response(&headers) {
        return r;
    }

    let body: UpdateSubscriptionBody = match serde_json::from_slice(&raw_body) {
        Ok(b) => b,
        Err(e) => return err("INVALID_REQUEST", &format!("body is not valid JSON: {}", e), StatusCode::BAD_REQUEST),
    };

    let Some(pool) = state.provider_pool() else {
        return err("DB_UNAVAILABLE", "database not configured", StatusCode::INTERNAL_SERVER_ERROR);
    };
    let Some((kind, raw)) = extract_subscriber(&headers) else {
        return err("AUTH_REQUIRED", "agent or provider auth required", StatusCode::UNAUTHORIZED);
    };
    let Some(subscriber_id) = resolve_subscriber_id(pool, &kind, &raw).await else {
        return err("INVALID_AUTH", "could not resolve subscriber identity", StatusCode::UNAUTHORIZED);
    };

    // Verify ownership
    let owner = sqlx::query("SELECT subscriber_id, subscriber_kind FROM jecp.webhook_subscriptions WHERE id::TEXT = $1")
        .bind(&sub_id).fetch_optional(pool).await;
    let Ok(Some(o)) = owner else {
        return err("NOT_FOUND", "subscription not found", StatusCode::NOT_FOUND);
    };
    if o.try_get::<String, _>("subscriber_id").unwrap_or_default() != subscriber_id
        || o.try_get::<String, _>("subscriber_kind").unwrap_or_default() != kind {
        return err("FORBIDDEN", "you do not own this subscription", StatusCode::FORBIDDEN);
    }

    if let Some(url) = &body.endpoint_url {
        // v1.1.0 c7 — SSRF full validation on UPDATE (caller may try to
        // redirect a verified subscription's endpoint_url to a private host).
        if let Err(e) = crate::protocol::url_guard::validate_outbound_url(url).await {
            let safe_url = crate::protocol::url_guard::redact_url(url);
            let reason = e.reason().to_string();
            crate::protocol::url_guard::audit_log_rejection(
                pool, Some(&subscriber_id), None,
                "webhook_destination_url", "subscribe_update",
                &safe_url, &reason, None,
            ).await;
            let (status, body_json) = crate::protocol::url_guard::url_blocked_ssrf_tuple(
                "webhook_destination_url", &safe_url, &reason,
            );
            return (status, body_json).into_response();
        }
    }
    if let Some(s) = &body.status {
        if !["active", "paused"].contains(&s.as_str()) {
            return err("INVALID_STATUS", "status must be active or paused", StatusCode::BAD_REQUEST);
        }
    }

    let _ = sqlx::query(
        "UPDATE jecp.webhook_subscriptions SET
           endpoint_url = COALESCE($2, endpoint_url),
           events       = COALESCE($3, events),
           status       = COALESCE($4, status)
         WHERE id::TEXT = $1",
    )
    .bind(&sub_id)
    .bind(&body.endpoint_url)
    .bind(&body.events)
    .bind(&body.status)
    .execute(pool)
    .await;

    Json(json!({ "jecp": "1.0", "subscription_id": sub_id, "updated": true })).into_response()
}

// DELETE /v1/subscriptions/<id>
pub async fn delete_subscription(
    State(state): State<AppState>,
    Path(sub_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(pool) = state.provider_pool() else {
        return err("DB_UNAVAILABLE", "database not configured", StatusCode::INTERNAL_SERVER_ERROR);
    };
    let Some((kind, raw)) = extract_subscriber(&headers) else {
        return err("AUTH_REQUIRED", "agent or provider auth required", StatusCode::UNAUTHORIZED);
    };
    let Some(subscriber_id) = resolve_subscriber_id(pool, &kind, &raw).await else {
        return err("INVALID_AUTH", "could not resolve subscriber identity", StatusCode::UNAUTHORIZED);
    };

    let res = sqlx::query(
        "DELETE FROM jecp.webhook_subscriptions
         WHERE id::TEXT = $1 AND subscriber_id = $2 AND subscriber_kind = $3",
    )
    .bind(&sub_id)
    .bind(&subscriber_id)
    .bind(&kind)
    .execute(pool)
    .await;

    match res {
        Ok(r) if r.rows_affected() > 0 => {
            Json(json!({ "jecp": "1.0", "subscription_id": sub_id, "deleted": true })).into_response()
        }
        Ok(_) => err("NOT_FOUND", "subscription not found", StatusCode::NOT_FOUND),
        Err(e) => {
            tracing::error!("subscription delete failed: {}", e);
            err("DB_ERROR", "delete failed", StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// POST /v1/subscriptions/<id>/test
pub async fn test_subscription(
    State(state): State<AppState>,
    Path(sub_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(pool) = state.provider_pool() else {
        return err("DB_UNAVAILABLE", "database not configured", StatusCode::INTERNAL_SERVER_ERROR);
    };
    let Some((kind, raw)) = extract_subscriber(&headers) else {
        return err("AUTH_REQUIRED", "agent or provider auth required", StatusCode::UNAUTHORIZED);
    };
    let Some(subscriber_id) = resolve_subscriber_id(pool, &kind, &raw).await else {
        return err("INVALID_AUTH", "could not resolve subscriber identity", StatusCode::UNAUTHORIZED);
    };

    // Verify ownership and enqueue a synthetic event
    let owner = sqlx::query(
        "SELECT id FROM jecp.webhook_subscriptions
           WHERE id::TEXT = $1 AND subscriber_id = $2 AND subscriber_kind = $3",
    )
    .bind(&sub_id).bind(&subscriber_id).bind(&kind)
    .fetch_optional(pool).await;
    let Ok(Some(_)) = owner else {
        return err("NOT_FOUND", "subscription not found", StatusCode::NOT_FOUND);
    };

    let event_id = format!("evt_test_{}", uuid::Uuid::new_v4().simple());
    let _ = sqlx::query(
        "INSERT INTO jecp.webhook_outbox (subscription_id, event_id, event_type, payload)
         VALUES ($1::UUID, $2, 'test.synthetic',
                 jsonb_build_object('type','test.synthetic','id',$2,'created_at',NOW(),'data',jsonb_build_object('msg','hello from JECP')))",
    )
    .bind(&sub_id)
    .bind(&event_id)
    .execute(pool).await;

    Json(json!({ "jecp": "1.0", "subscription_id": sub_id, "event_id": event_id, "enqueued": true })).into_response()
}
