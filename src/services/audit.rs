//! S1 — Audit log helper (jecp.audit_log).
//!
//! Append-only forensic record of compliance/financial/security events.
//! Used by rotate-key endpoints (S1) and by the rotation rate-limiter
//! (P0-2 mitigation: 24h cap of 3 rotations per actor).
//!
//! All writes are best-effort: an audit log failure MUST NOT block the
//! caller's primary operation. We log the error and continue. (For
//! mutations that need guaranteed recording, the caller should call
//! `record` inside its own transaction — not used currently.)

use axum::http::HeaderMap;
use serde_json::Value;
use sqlx::PgPool;

#[derive(Debug, Clone, Copy)]
pub enum ActorType {
    Agent,
    Provider,
    Operator,
    System,
}

impl ActorType {
    fn as_str(self) -> &'static str {
        match self {
            ActorType::Agent => "agent",
            ActorType::Provider => "provider",
            ActorType::Operator => "operator",
            ActorType::System => "system",
        }
    }
}

/// Insert one audit_log row. Best-effort — never errors out to the caller.
#[allow(clippy::too_many_arguments)]
pub async fn record(
    pool: &PgPool,
    actor_type: ActorType,
    actor_id: &str,
    action: &str,
    target_type: Option<&str>,
    target_id: Option<&str>,
    headers: Option<&HeaderMap>,
    metadata: Value,
) {
    let (ip, user_agent) = headers
        .map(|h| (extract_ip(h), extract_user_agent(h)))
        .unwrap_or_default();

    let result = sqlx::query(
        "INSERT INTO jecp.audit_log
           (actor_type, actor_id, action, target_type, target_id,
            ip_address, user_agent, metadata)
         VALUES ($1, $2, $3, $4, $5, $6::INET, $7, $8::JSONB)",
    )
    .bind(actor_type.as_str())
    .bind(actor_id)
    .bind(action)
    .bind(target_type)
    .bind(target_id)
    .bind(ip.as_deref())
    .bind(user_agent.as_deref())
    .bind(metadata)
    .persistent(false)
    .execute(pool)
    .await;

    if let Err(e) = result {
        tracing::warn!(
            actor = actor_id,
            action = action,
            error = %e,
            "audit_log insert failed (non-fatal)"
        );
    }
}

/// Count audit_log rows for the given (actor_type, actor_id, action) tuple
/// within the last `within_seconds`. Used by rotation 24h cap.
///
/// Returns 0 on DB errors (fail-open) to avoid breaking legitimate flows
/// when the DB is degraded. The caller can layer on additional protection.
pub async fn count_recent(
    pool: &PgPool,
    actor_type: ActorType,
    actor_id: &str,
    action: &str,
    within_seconds: i32,
) -> i64 {
    let result = sqlx::query_scalar::<_, i64>(
        "SELECT jecp.count_recent_rotations($1, $2, $3, $4)",
    )
    .bind(actor_type.as_str())
    .bind(actor_id)
    .bind(action)
    .bind(within_seconds)
    .persistent(false)
    .fetch_one(pool)
    .await;

    match result {
        Ok(n) => n,
        Err(e) => {
            tracing::warn!(
                actor = actor_id,
                action = action,
                error = %e,
                "count_recent_rotations failed (fail-open: returning 0)"
            );
            0
        }
    }
}

fn extract_ip(headers: &HeaderMap) -> Option<String> {
    // Trust Fly's own header first (set by the platform, not user-controllable
    // when the request enters our edge).
    for key in ["fly-client-ip", "x-real-ip"] {
        if let Some(v) = headers.get(key).and_then(|v| v.to_str().ok()) {
            let trimmed = v.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    // x-forwarded-for: take the RIGHTMOST entry (closest to our edge proxy),
    // not the leftmost which a client can spoof. The leftmost entry is what
    // the client claims; the rightmost is what our edge actually saw.
    // (TIER A "details" #1 finding — left-most XFF is a classic spoof bug.)
    if let Some(v) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(last) = v.split(',').last() {
            let trimmed = last.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

fn extract_user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.chars().take(500).collect())
}
