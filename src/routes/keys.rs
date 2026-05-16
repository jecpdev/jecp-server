//! M2 — API key rotation endpoints (Phase B / W5+).
//!
//! POST /v1/agents/me/rotate-key
//!   Auth: X-Agent-ID + X-API-Key
//!   Action: generate new api_key, retain previous key for 7 days
//!   Body: optional { grace_seconds: <int>, max 604800 (7d) }
//!   Response: { agent_id, api_key, previous_key_valid_until }
//!
//! POST /v1/providers/me/rotate-key
//!   Auth: Authorization: Bearer <jdb_pk_…>
//!   Action: same — bcrypt new key, retain previous hash for 7 days
//!   Body: optional { grace_seconds }
//!   Response: { provider_id, api_key, previous_key_valid_until }
//!
//! IMPORTANT: the new api_key is shown only ONCE in the response — the
//! caller must persist it immediately. Subsequent requests with the previous
//! key continue to work until previous_key_valid_until.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::auth::agent::authenticate_agent;
use crate::routes::providers::authenticate_provider;
use crate::services::database;
use crate::AppState;

const GRACE_DEFAULT_SECONDS: i32 = 604_800; // 7 days
const GRACE_MAX_SECONDS: i32 = 604_800;
const GRACE_MIN_SECONDS: i32 = 60; // 1 minute floor — prevents accidental zero

// S1 / P0-2 — rotation rate limit: max 3 rotations per actor per 24 h.
// Enforced inside the SQL function rotate_*_api_key_atomic which acquires
// FOR UPDATE on the actor row, so concurrent callers serialise on the lock
// and see consistent counts. (TIER A.4 fix — old TOCTOU between count and
// UPDATE is gone.)
const ROTATION_24H_CAP: i32 = 3;

#[derive(Deserialize)]
pub struct RotateBody {
    #[serde(default)]
    pub grace_seconds: Option<i32>,
    /// P0-1 full: when TRUE, the previous key is rejected immediately
    /// (no grace period). Use when compromise is suspected.
    #[serde(default)]
    pub revoke_old: Option<bool>,
}

// ────────────────────────────────────────────────────────────────────────────
// Agent rotation
// ────────────────────────────────────────────────────────────────────────────

pub async fn rotate_agent_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    raw_body: axum::body::Bytes,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    // K2.1 (v1.0.2): 415 on non-JSON Content-Type with JECP envelope.
    // Empirically axum 0.8's Option<Json<T>> does NOT swallow MissingJsonContentType
    // — it returns axum-default plain-text 415 BEFORE our handler runs. The fix
    // is to take raw Bytes here and parse manually, identical to /v1/invoke +
    // /v1/jecp pattern.
    crate::protocol::http_guards::ensure_json_ct_tuple(&headers)?;

    let body: Option<RotateBody> = if raw_body.is_empty() {
        None
    } else {
        Some(serde_json::from_slice(&raw_body).map_err(|e| error(
            StatusCode::BAD_REQUEST, "INVALID_REQUEST",
            &format!("body is not valid JSON: {}", e)))?)
    };

    let agent_id = headers.get("x-agent-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or_else(|| error(
            StatusCode::UNAUTHORIZED, "AUTH_REQUIRED", "Missing X-Agent-ID header"))?;
    let api_key = headers.get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or_else(|| error(
            StatusCode::UNAUTHORIZED, "AUTH_REQUIRED", "Missing X-API-Key header"))?;

    // K3: rotate_agent_key serves agent traffic — must coexist with /v1/invoke
    // surge → invoke pool.
    let pool = state.invoke_pool().ok_or_else(|| error(
        StatusCode::SERVICE_UNAVAILABLE, "DB_UNAVAILABLE", "Database not connected"))?;

    // Verify the current key matches (and is not just a still-valid previous key —
    // rotating from a grace key would be confusing).
    let _ = authenticate_agent(pool, &agent_id, &api_key).await
        .map_err(|_| error(
            StatusCode::UNAUTHORIZED, "INVALID_API_KEY", "Agent authentication failed"))?;

    let revoke_old = body.as_ref().and_then(|b| b.revoke_old).unwrap_or(false);
    let grace = clamp_grace(body.as_ref().and_then(|b| b.grace_seconds));
    let effective_grace = if revoke_old { 0 } else { grace };
    let new_api_key = format!("jdb_ak_{}", random_hex_48());
    let new_prefix: String = new_api_key.chars().take(12).collect();
    // TIER A.5 — bcrypt the new key Hub-side so the SQL row lock window
    // is short. Cost 10 ≈ 80 ms; acceptable for an explicit rotation.
    let new_hash = bcrypt::hash(&new_api_key, 10)
        .map_err(|e| error(
            StatusCode::INTERNAL_SERVER_ERROR, "BCRYPT_ERROR", &e.to_string()))?;

    let ip = extract_ip(&headers);
    let user_agent = extract_user_agent(&headers);

    // TIER A.5 — atomic_v2 rotation with bcrypt verify of the current key
    // inside the SQL function. Replaces atomic_v1's plaintext compare.
    let result = database::rotate_agent_api_key_atomic_v2(
        pool, &agent_id, &api_key, &new_hash, &new_prefix,
        grace, revoke_old, ROTATION_24H_CAP,
        ip.as_deref(), user_agent.as_deref(),
        json!({}),
    )
    .await
    .map_err(|e| {
        tracing::error!("rotate_agent_api_key_atomic_v2 db error: {}", e);
        error(StatusCode::INTERNAL_SERVER_ERROR, "DB_ERROR", "rotation failed")
    })?;

    if result.cap_exceeded {
        return Err(error(
            StatusCode::TOO_MANY_REQUESTS,
            "ROTATION_24H_CAP",
            &format!(
                "Rotation limit exceeded ({} rotations in the last 24 h). \
                Wait for the oldest rotation to age out before rotating again. \
                If you suspect compromise, contact hello@jecp.dev to revoke immediately.",
                ROTATION_24H_CAP
            ),
        ));
    }
    if !result.success {
        return Err(error(
            StatusCode::CONFLICT,
            "ROTATION_RACE",
            "Key changed between authentication and rotation. Retry with current key.",
        ));
    }

    tracing::info!(
        "agent key rotated: agent_id={} previous_valid_until={:?} revoke_old={} rotations_in_last_24h={}",
        agent_id, result.previous_key_valid_until, revoke_old, result.rotations_in_last_24h
    );

    let warning = if revoke_old {
        "This api_key is shown only once. The previous key has been revoked immediately (no grace period)."
    } else {
        "This api_key is shown only once. Store it now. The previous key remains valid until previous_key_valid_until."
    };

    Ok((StatusCode::OK, Json(json!({
        "jecp": "1.0",
        "agent_id": agent_id,
        "api_key": new_api_key,
        "previous_key_valid_until": result.previous_key_valid_until,
        "grace_seconds": effective_grace,
        "revoke_old": revoke_old,
        "rotations_in_last_24h": result.rotations_in_last_24h,
        "warning": warning,
    }))))
}

// ────────────────────────────────────────────────────────────────────────────
// Provider rotation
// ────────────────────────────────────────────────────────────────────────────

pub async fn rotate_provider_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    raw_body: axum::body::Bytes,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    // K2.1 (v1.0.2): 415 on non-JSON Content-Type with JECP envelope.
    // See rotate_agent_key for the axum 0.8 Option<Json<T>> rationale.
    crate::protocol::http_guards::ensure_json_ct_tuple(&headers)?;

    let body: Option<RotateBody> = if raw_body.is_empty() {
        None
    } else {
        Some(serde_json::from_slice(&raw_body).map_err(|e| error(
            StatusCode::BAD_REQUEST, "INVALID_REQUEST",
            &format!("body is not valid JSON: {}", e)))?)
    };

    let provider = authenticate_provider(&state, &headers).await?;
    // K3: rotate_provider_key is provider-side surface → provider pool.
    let pool = state.provider_pool().ok_or_else(|| error(
        StatusCode::SERVICE_UNAVAILABLE, "DB_UNAVAILABLE", "Database not connected"))?;

    let provider_id_str = provider.id.to_string();
    let revoke_old = body.as_ref().and_then(|b| b.revoke_old).unwrap_or(false);
    let grace = clamp_grace(body.as_ref().and_then(|b| b.grace_seconds));
    let effective_grace = if revoke_old { 0 } else { grace };
    let new_api_key = format!("jdb_pk_{}", random_hex_48());
    let new_prefix = new_api_key.chars().take(12).collect::<String>();
    let new_hash = bcrypt::hash(&new_api_key, 10)
        .map_err(|e| error(
            StatusCode::INTERNAL_SERVER_ERROR, "BCRYPT_ERROR", &e.to_string()))?;

    let ip = extract_ip(&headers);
    let user_agent = extract_user_agent(&headers);

    // TIER A.4 — atomic rotation (count + UPDATE + audit insert in one TX).
    let result = database::rotate_provider_api_key_atomic(
        pool, &provider.id, &new_hash, &new_prefix, grace, revoke_old,
        ROTATION_24H_CAP,
        ip.as_deref(), user_agent.as_deref(),
        json!({ "namespace": provider.namespace }),
    )
    .await
    .map_err(|e| {
        tracing::error!("rotate_provider_api_key_atomic db error: {}", e);
        error(StatusCode::INTERNAL_SERVER_ERROR, "DB_ERROR", "rotation failed")
    })?;

    if result.cap_exceeded {
        return Err(error(
            StatusCode::TOO_MANY_REQUESTS,
            "ROTATION_24H_CAP",
            &format!(
                "Rotation limit exceeded ({} rotations in the last 24 h). \
                Wait for the oldest rotation to age out before rotating again. \
                If you suspect compromise, contact hello@jecp.dev to revoke immediately.",
                ROTATION_24H_CAP
            ),
        ));
    }
    if !result.success {
        return Err(error(
            StatusCode::CONFLICT, "ROTATION_RACE",
            "Provider not found during rotation.",
        ));
    }

    tracing::info!(
        "provider key rotated: provider_id={} namespace={} previous_valid_until={:?} revoke_old={} rotations_in_last_24h={}",
        provider.id, provider.namespace, result.previous_key_valid_until, revoke_old, result.rotations_in_last_24h
    );

    let warning = if revoke_old {
        "This api_key is shown only once. The previous key has been revoked immediately (no grace period)."
    } else {
        "This api_key is shown only once. Store it now. The previous key remains valid until previous_key_valid_until."
    };

    let _ = provider_id_str; // referenced in atomic function metadata

    Ok((StatusCode::OK, Json(json!({
        "jecp": "1.0",
        "provider_id": provider.id,
        "namespace": provider.namespace,
        "api_key": new_api_key,
        "api_key_prefix": new_prefix,
        "previous_key_valid_until": result.previous_key_valid_until,
        "grace_seconds": effective_grace,
        "revoke_old": revoke_old,
        "rotations_in_last_24h": result.rotations_in_last_24h,
        "warning": warning,
    }))))
}

// Helper: extract client IP from common forwarded headers.
fn extract_ip(headers: &HeaderMap) -> Option<String> {
    for key in ["fly-client-ip", "x-real-ip"] {
        if let Some(v) = headers.get(key).and_then(|v| v.to_str().ok()) {
            let trimmed = v.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    // x-forwarded-for: trust the rightmost (closest to our edge) entry, not
    // the leftmost which a client can spoof. (TIER A "details" §1 finding.)
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

// ────────────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────────────

fn clamp_grace(requested: Option<i32>) -> i32 {
    let v = requested.unwrap_or(GRACE_DEFAULT_SECONDS);
    v.clamp(GRACE_MIN_SECONDS, GRACE_MAX_SECONDS)
}

fn random_hex_48() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn error(status: StatusCode, code: &str, message: &str) -> (StatusCode, Json<Value>) {
    (status, Json(json!({
        "jecp": "1.0",
        "status": "failed",
        "error": { "code": code, "message": message },
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamp_grace_default() {
        assert_eq!(clamp_grace(None), GRACE_DEFAULT_SECONDS);
    }

    #[test]
    fn clamp_grace_below_min() {
        assert_eq!(clamp_grace(Some(0)), GRACE_MIN_SECONDS);
        assert_eq!(clamp_grace(Some(-100)), GRACE_MIN_SECONDS);
    }

    #[test]
    fn clamp_grace_above_max() {
        assert_eq!(clamp_grace(Some(99_999_999)), GRACE_MAX_SECONDS);
    }

    #[test]
    fn clamp_grace_in_range() {
        assert_eq!(clamp_grace(Some(3600)), 3600);
    }

    #[test]
    fn random_hex_48_is_48_chars() {
        let s = random_hex_48();
        assert_eq!(s.len(), 48);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
