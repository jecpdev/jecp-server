use hmac::{Hmac, Mac};
use sha2::{Sha256, Digest};
use sqlx::PgPool;

use crate::protocol::errors::{JecpErrorCode, ProvenanceSubcause};
use crate::protocol::types::Capability;

type HmacSha256 = Hmac<Sha256>;

/// Agent profile from Supabase agent_profiles table
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AgentProfile {
    pub agent_id: String,
    pub api_key: String,
    pub name: Option<String>,
    pub agent_type: Option<String>,
    pub total_calls: i32,
    pub free_calls_remaining: i32,
    pub metadata: Option<serde_json::Value>,
}

impl AgentProfile {
    pub fn trust_tier(&self) -> TrustTier {
        // Derive tier from total_calls: Bronze < 100, Silver < 500, Gold < 2000, Platinum >= 2000
        match self.total_calls {
            0..=99 => TrustTier::Bronze,
            100..=499 => TrustTier::Silver,
            500..=1999 => TrustTier::Gold,
            _ => TrustTier::Platinum,
        }
    }

    pub fn is_active(&self) -> bool {
        // Active if free calls remain or they have paid (metadata check)
        self.free_calls_remaining > 0
            || self.metadata.as_ref().map_or(false, |m| m.get("paid").is_some())
            || self.total_calls > 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrustTier {
    Bronze,
    Silver,
    Gold,
    Platinum,
}

impl std::fmt::Display for TrustTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrustTier::Bronze => write!(f, "bronze"),
            TrustTier::Silver => write!(f, "silver"),
            TrustTier::Gold => write!(f, "gold"),
            TrustTier::Platinum => write!(f, "platinum"),
        }
    }
}

impl TrustTier {
    /// Rate limit: requests per minute
    pub fn rate_limit_rpm(&self) -> u32 {
        match self {
            TrustTier::Bronze => 10,
            TrustTier::Silver => 30,
            TrustTier::Gold => 100,
            TrustTier::Platinum => 500,
        }
    }

    /// Minimum tier required for a given capability
    pub fn required_for(capability: &Capability) -> TrustTier {
        match capability {
            // Bronze: 軽量な変換・計算系
            Capability::ContentFactory => TrustTier::Bronze,
            // Silver: 文書生成・データ分析
            Capability::DocumentPipeline => TrustTier::Silver,
            Capability::DataInsight => TrustTier::Silver,
            // Gold: ファイル処理チェーン
            Capability::FileChain => TrustTier::Gold,
            // Platinum: 自律ワークフロー（最高権限）
            Capability::Workflow => TrustTier::Platinum,
            // Bronze: SNSエンジン（自社dogfooding用に低く設定）
            Capability::SnsEngine => TrustTier::Bronze,
        }
    }
}

/// 信頼ゲート: エージェントのティアが能力の要求を満たすか検査
pub fn check_trust_gate(
    agent: &AgentProfile,
    capability: &Capability,
) -> Result<(), JecpErrorCode> {
    let required = TrustTier::required_for(capability);
    let current = agent.trust_tier();
    if current >= required {
        Ok(())
    } else {
        Err(JecpErrorCode::InsufficientTrust {
            required: required.to_string(),
            current: current.to_string(),
        })
    }
}

/// Provenance v1 (legacy, sunset 2026-11-01).
///
/// hash = SHA256(agent_id + ":" + total_calls + ":" + api_key_prefix)
///
/// Known weaknesses (see TIER A.8 / Provenance v2 errata):
///   1. `api_key[..8]` leaks key prefix into any v1 hash output.
///   2. Two agents with the same `total_calls` and same prefix can collide.
///   3. After A.5 rotation the plaintext column is NULL, so v1 cannot be
///      computed on rotated agents. v2 is mandatory for those.
///
/// New deployments MUST use Provenance v2. v1 is kept only to verify hashes
/// produced before the sunset date.
pub fn compute_provenance_hash(agent: &AgentProfile) -> String {
    let api_key_prefix = if agent.api_key.len() >= 8 {
        &agent.api_key[..8]
    } else {
        &agent.api_key
    };
    let input = format!("{}:{}:{}", agent.agent_id, agent.total_calls, api_key_prefix);
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Provenance v2: HMAC-SHA256(api_key, agent_id || ":" || timestamp || ":" || nonce).
///
/// Wire format: `"v2:<unix_seconds>:<nonce_hex>:<hmac_hex>"` — the `"v2:"`
/// prefix is what `verify_provenance` uses to dispatch.
///
/// The agent picks `timestamp` (unix seconds) and `nonce` (>= 16 random hex
/// chars). The Hub recomputes the HMAC using the plaintext api_key it just
/// authenticated against bcrypt, and compares constant-time.
///
/// Replay defense (rejecting reused nonces) is the **caller's** responsibility
/// — this function only validates the cryptographic binding and timestamp
/// skew. See `routes/invoke.rs` for the (agent_id, nonce) cache wiring.
pub fn compute_provenance_hash_v2(
    api_key: &str,
    agent_id: &str,
    timestamp: i64,
    nonce: &str,
) -> String {
    let msg = format!("{}:{}:{}", agent_id, timestamp, nonce);
    let mut mac = HmacSha256::new_from_slice(api_key.as_bytes())
        .expect("HMAC-SHA256 accepts any key length");
    mac.update(msg.as_bytes());
    let tag = mac.finalize().into_bytes();
    format!("v2:{}:{}:{}", timestamp, nonce, hex::encode(tag))
}

/// Verify a Provenance v2 wire string.
///
/// `skew_seconds` is the symmetric clock-skew window (recommend 300s).
/// Caller is responsible for nonce replay defense.
pub fn verify_provenance_v2(
    api_key: &str,
    agent_id: &str,
    claimed: &str,
    skew_seconds: i64,
) -> Result<(i64, String), JecpErrorCode> {
    let parts: Vec<&str> = claimed.splitn(4, ':').collect();
    if parts.len() != 4 || parts[0] != "v2" {
        return Err(JecpErrorCode::ProvenanceMismatch {
            reason: "v2 format invalid — expected v2:<timestamp>:<nonce>:<hmac_hex>".into(),
            subcause: ProvenanceSubcause::WireMalformed,
            drift_seconds: None,
        });
    }
    let timestamp: i64 = parts[1].parse().map_err(|_| JecpErrorCode::ProvenanceMismatch {
        reason: "v2 timestamp not a unix-seconds integer".into(),
        subcause: ProvenanceSubcause::WireMalformed,
        drift_seconds: None,
    })?;
    let nonce = parts[2];
    let claimed_tag = parts[3];

    if nonce.len() < 16 || !nonce.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(JecpErrorCode::ProvenanceMismatch {
            reason: "v2 nonce must be >= 16 hex chars".into(),
            subcause: ProvenanceSubcause::WireMalformed,
            drift_seconds: None,
        });
    }

    // v1.0.1: tag length/hex validation BEFORE timestamp skew check, so
    // wire-malformed cases (wrong tag size, non-hex chars) are reported as
    // such regardless of how stale the timestamp is. Matches SDK ordering
    // and aligns with the cross-stack fixture (test_fixtures/provenance-v2-vectors.json).
    if claimed_tag.len() != 64 || !claimed_tag.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(JecpErrorCode::ProvenanceMismatch {
            reason: "v2 HMAC tag must be exactly 64 hex characters (SHA-256)".into(),
            subcause: ProvenanceSubcause::WireMalformed,
            drift_seconds: None,
        });
    }

    let now = chrono::Utc::now().timestamp();
    let drift = now - timestamp;
    if drift.abs() > skew_seconds {
        return Err(JecpErrorCode::ProvenanceMismatch {
            reason: format!("v2 timestamp out of ±{}s window (drift={}s)", skew_seconds, drift),
            subcause: ProvenanceSubcause::ClockSkew,
            drift_seconds: Some(drift),
        });
    }

    let msg = format!("{}:{}:{}", agent_id, timestamp, nonce);
    let mut mac = HmacSha256::new_from_slice(api_key.as_bytes())
        .expect("HMAC-SHA256 accepts any key length");
    mac.update(msg.as_bytes());
    let expected_tag = hex::encode(mac.finalize().into_bytes());

    if !constant_time_eq(expected_tag.as_bytes(), claimed_tag.as_bytes()) {
        return Err(JecpErrorCode::ProvenanceMismatch {
            reason: "v2 HMAC mismatch — provenance verification failed".into(),
            subcause: ProvenanceSubcause::HmacMismatch,
            drift_seconds: None,
        });
    }

    Ok((timestamp, nonce.to_string()))
}

/// Provenance 検証 dispatcher (v1/v2 dual-path).
///
/// Detects format from the `"v2:"` prefix. v2 path requires `plaintext_api_key`
/// (taken from `Mandate.api_key`, which the agent always supplies on invoke).
/// v1 path uses `agent.api_key` from the authenticated profile — note this
/// will be empty for rotated agents, in which case v1 always fails and the
/// agent must upgrade to v2.
///
/// On success for v2, returns `Some((timestamp, nonce))` so the caller can
/// register them in the replay cache. v1 returns `None`.
pub fn verify_provenance(
    agent: &AgentProfile,
    plaintext_api_key: &str,
    claimed_hash: &str,
) -> Result<Option<(i64, String)>, JecpErrorCode> {
    if claimed_hash.starts_with("v2:") {
        let (ts, nonce) = verify_provenance_v2(plaintext_api_key, &agent.agent_id, claimed_hash, 300)?;
        Ok(Some((ts, nonce)))
    } else {
        // v1 legacy path — deprecated 2026-05-10, sunset 2026-11-01.
        // If the agent was rotated to bcrypt-only storage (post-A.5), the
        // plaintext column is NULL and AgentProfile.api_key is "". v1 cannot
        // be computed without the plaintext prefix — emit a distinct
        // V1Unavailable subcause so SDKs can prompt migration.
        if agent.api_key.is_empty() {
            return Err(JecpErrorCode::ProvenanceMismatch {
                reason: "v1 provenance unavailable — agent's plaintext api_key is no longer stored after key rotation. Migrate to v2 (https://jecp.dev/spec/v1.0/02-authentication.md#5.8).".into(),
                subcause: ProvenanceSubcause::V1Unavailable,
                drift_seconds: None,
            });
        }
        let expected = compute_provenance_hash(agent);
        if constant_time_eq(expected.as_bytes(), claimed_hash.as_bytes()) {
            Ok(None)
        } else {
            Err(JecpErrorCode::ProvenanceMismatch {
                reason: "v1 provenance_hash does not match — agent identity check failed (note: v1 sunsets 2026-11-01, migrate to v2)".into(),
                subcause: ProvenanceSubcause::V1LegacyMismatch,
                drift_seconds: None,
            })
        }
    }
}

/// Authenticate an agent by API key against Supabase.
///
/// TIER A.5 (2026-05-09 critical audit): agent api_key is now stored as a
/// bcrypt hash, mirroring the Provider side. We SELECT the hash columns by
/// agent_id (PK lookup, fast) then bcrypt::verify in Rust. Both the active
/// hash and the rotation grace hash are checked.
///
/// During the migration window (rolling deploy), some rows may have only
/// the legacy plaintext column populated. We tolerate that by falling
/// back to a constant-time string compare against `api_key` if `api_key_hash`
/// is NULL — the next migration drops the plaintext column once all live
/// rows have been backfilled.
pub async fn authenticate_agent(
    pool: &PgPool,
    agent_id: &str,
    api_key: &str,
) -> Result<AgentProfile, JecpErrorCode> {
    use sqlx::Row;

    let row = sqlx::query(
        r#"
        SELECT agent_id, api_key, api_key_hash, previous_api_key, previous_api_key_hash,
               previous_key_valid_until,
               name, agent_type, total_calls, free_calls_remaining, metadata
        FROM agent_profiles
        WHERE agent_id = $1
        "#,
    )
    .persistent(false)
    .bind(agent_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| JecpErrorCode::Internal(format!("Database error: {}", e)))?;

    let row = row.ok_or(JecpErrorCode::InvalidApiKey)?;

    let active_hash: Option<String> = row.try_get("api_key_hash").ok().flatten();
    let previous_hash: Option<String> = row.try_get("previous_api_key_hash").ok().flatten();
    let previous_valid_until: Option<chrono::DateTime<chrono::Utc>> =
        row.try_get("previous_key_valid_until").ok().flatten();
    let active_plain: Option<String> = row.try_get("api_key").ok().flatten();
    let previous_plain: Option<String> = row.try_get("previous_api_key").ok().flatten();

    let now = chrono::Utc::now();
    let mut authenticated = false;

    // Active hash path (preferred, post-migration).
    if let Some(h) = &active_hash {
        if bcrypt::verify(api_key, h).unwrap_or(false) {
            authenticated = true;
        }
    }

    // Active plaintext fallback (legacy, pre-migration row).
    if !authenticated {
        if let Some(p) = &active_plain {
            if constant_time_eq(p.as_bytes(), api_key.as_bytes()) {
                authenticated = true;
            }
        }
    }

    // Grace path — previous key, only if not yet expired.
    let grace_active = previous_valid_until.map(|t| t > now).unwrap_or(false);
    if !authenticated && grace_active {
        if let Some(h) = &previous_hash {
            if bcrypt::verify(api_key, h).unwrap_or(false) {
                authenticated = true;
            }
        }
        if !authenticated {
            if let Some(p) = &previous_plain {
                if constant_time_eq(p.as_bytes(), api_key.as_bytes()) {
                    authenticated = true;
                }
            }
        }
    }

    if !authenticated {
        return Err(JecpErrorCode::InvalidApiKey);
    }

    Ok(AgentProfile {
        agent_id:               row.try_get("agent_id").unwrap_or_default(),
        // The plaintext field is preserved on the struct for legacy callers
        // (provenance hash uses api_key[..8]). Once Provenance v2 ships
        // (TIER A.8) this can be deprecated entirely.
        api_key:                active_plain.unwrap_or_default(),
        name:                   row.try_get("name").ok(),
        agent_type:             row.try_get("agent_type").ok(),
        total_calls:            row.try_get("total_calls").unwrap_or(0),
        free_calls_remaining:   row.try_get("free_calls_remaining").unwrap_or(0),
        metadata:               row.try_get("metadata").ok(),
    })
}

/// Constant-time bytes comparison. Avoids the timing leak of `==` on
/// short-circuit string compares — important during the migration window
/// when some rows still verify against plaintext.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Increment total_calls for an agent (called on wallet/mandate billing success).
/// Note: consume_free_call already increments total_calls for free-tier path.
pub async fn increment_agent_calls(
    pool: &PgPool,
    agent_id: &str,
) -> Result<(), JecpErrorCode> {
    sqlx::query(
        r#"
        UPDATE agent_profiles
        SET total_calls = total_calls + 1,
            last_seen_at = NOW()
        WHERE agent_id = $1
        "#,
    )
    .persistent(false)
    .bind(agent_id)
    .execute(pool)
    .await
    .map_err(|e| JecpErrorCode::Internal(format!("Database error: {}", e)))?;

    Ok(())
}

/// Check if agent can make a free call (decrement counter)
pub async fn consume_free_call(
    pool: &PgPool,
    agent_id: &str,
) -> Result<bool, JecpErrorCode> {
    let result = sqlx::query_scalar::<_, i32>(
        r#"
        UPDATE agent_profiles
        SET free_calls_remaining = free_calls_remaining - 1,
            total_calls = total_calls + 1
        WHERE agent_id = $1 AND free_calls_remaining > 0
        RETURNING free_calls_remaining
        "#,
    )
    .persistent(false)
    .bind(agent_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| JecpErrorCode::Internal(format!("Database error: {}", e)))?;

    Ok(result.is_some())
}

/// Record a JECP task execution in the database
pub async fn record_task(
    pool: &PgPool,
    task_id: &str,
    agent_id: &str,
    capability: &str,
    action: &str,
    input: &serde_json::Value,
    state: &str,
) -> Result<(), JecpErrorCode> {
    sqlx::query(
        r#"
        INSERT INTO jecp_tasks (id, agent_id, capability, action, state, input, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, NOW())
        "#,
    )
    .persistent(false)
    .bind(task_id)
    .bind(agent_id)
    .bind(capability)
    .bind(action)
    .bind(state)
    .bind(input)
    .execute(pool)
    .await
    .map_err(|e| JecpErrorCode::Internal(format!("Failed to record task: {}", e)))?;

    Ok(())
}

/// Update task completion status
pub async fn complete_task(
    pool: &PgPool,
    task_id: &str,
    state: &str,
    output: Option<&serde_json::Value>,
    billing: Option<&serde_json::Value>,
    execution: Option<&serde_json::Value>,
    error_message: Option<&str>,
) -> Result<(), JecpErrorCode> {
    sqlx::query(
        r#"
        UPDATE jecp_tasks
        SET state = $2, output = $3, billing = $4, execution = $5,
            error_message = $6, completed_at = NOW()
        WHERE id = $1
        "#,
    )
    .persistent(false)
    .bind(task_id)
    .bind(state)
    .bind(output)
    .bind(billing)
    .bind(execution)
    .bind(error_message)
    .execute(pool)
    .await
    .map_err(|e| JecpErrorCode::Internal(format!("Failed to update task: {}", e)))?;

    Ok(())
}

#[cfg(test)]
mod provenance_tests {
    use super::*;

    fn fake_agent(api_key: &str, total_calls: i32) -> AgentProfile {
        AgentProfile {
            agent_id: "jdb_ag_test123".to_string(),
            api_key: api_key.to_string(),
            name: None,
            agent_type: None,
            total_calls,
            free_calls_remaining: 0,
            metadata: None,
        }
    }

    #[test]
    fn v1_compute_is_deterministic() {
        let a = fake_agent("jdb_ak_secret_xyz", 42);
        let h1 = compute_provenance_hash(&a);
        let h2 = compute_provenance_hash(&a);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // SHA-256 hex
    }

    #[test]
    fn v1_verify_via_dispatcher() {
        let a = fake_agent("jdb_ak_secret_xyz", 42);
        let h = compute_provenance_hash(&a);
        // dispatcher: v1 path (no "v2:" prefix)
        let result = verify_provenance(&a, &a.api_key, &h);
        assert!(matches!(result, Ok(None)));
    }

    #[test]
    fn v1_verify_rejects_tampered_hash() {
        let a = fake_agent("jdb_ak_secret_xyz", 42);
        let mut h = compute_provenance_hash(&a);
        h.replace_range(0..1, "0");
        assert!(verify_provenance(&a, &a.api_key, &h).is_err());
    }

    #[test]
    fn v2_round_trip() {
        let api_key = "jdb_ak_supersecret_abcdef0123";
        let agent_id = "jdb_ag_test123";
        let ts = chrono::Utc::now().timestamp();
        let nonce = "deadbeef0123456789abcdef01234567";
        let wire = compute_provenance_hash_v2(api_key, agent_id, ts, nonce);
        assert!(wire.starts_with("v2:"));
        let parts: Vec<&str> = wire.splitn(4, ':').collect();
        assert_eq!(parts.len(), 4);
        assert_eq!(parts[1].parse::<i64>().unwrap(), ts);
        assert_eq!(parts[2], nonce);
        assert_eq!(parts[3].len(), 64); // HMAC-SHA256 hex

        let result = verify_provenance_v2(api_key, agent_id, &wire, 300);
        assert!(result.is_ok());
        let (got_ts, got_nonce) = result.unwrap();
        assert_eq!(got_ts, ts);
        assert_eq!(got_nonce, nonce);
    }

    #[test]
    fn v2_rejects_wrong_key() {
        let agent_id = "jdb_ag_test123";
        let ts = chrono::Utc::now().timestamp();
        let nonce = "deadbeef0123456789abcdef01234567";
        let wire = compute_provenance_hash_v2("real-key", agent_id, ts, nonce);
        let result = verify_provenance_v2("attacker-key", agent_id, &wire, 300);
        assert!(result.is_err());
    }

    #[test]
    fn v2_rejects_stale_timestamp() {
        let api_key = "jdb_ak_secret";
        let agent_id = "jdb_ag_test123";
        let stale_ts = chrono::Utc::now().timestamp() - 3600; // 1h old
        let nonce = "deadbeef0123456789abcdef01234567";
        let wire = compute_provenance_hash_v2(api_key, agent_id, stale_ts, nonce);
        let result = verify_provenance_v2(api_key, agent_id, &wire, 300);
        assert!(result.is_err());
    }

    #[test]
    fn v2_rejects_short_nonce() {
        let api_key = "jdb_ak_secret";
        let agent_id = "jdb_ag_test123";
        let ts = chrono::Utc::now().timestamp();
        // Hand-craft wire with a 4-char nonce (HMAC will not match anyway,
        // but the format guard should fire first).
        let wire = format!("v2:{}:abcd:{}", ts, "0".repeat(64));
        let result = verify_provenance_v2(api_key, agent_id, &wire, 300);
        let err = result.unwrap_err();
        assert!(format!("{:?}", err).contains("nonce"));
    }

    #[test]
    fn v2_rejects_malformed_wire() {
        let api_key = "jdb_ak_secret";
        let agent_id = "jdb_ag_test123";
        for bad in &[
            "not-v2-format",
            "v2:no-timestamp:nonce:hmac",   // timestamp parse fails
            "v2:1234567890:short:hmac",      // nonce too short, then would fail HMAC
            "v2:only:three:",                // empty hmac
        ] {
            let result = verify_provenance_v2(api_key, agent_id, bad, 300);
            assert!(result.is_err(), "expected reject for: {}", bad);
        }
    }

    #[test]
    fn dispatcher_picks_v2_on_prefix() {
        let api_key = "jdb_ak_routing_test";
        let a = fake_agent(api_key, 7);
        let ts = chrono::Utc::now().timestamp();
        let nonce = "deadbeef0123456789abcdef01234567";
        let wire = compute_provenance_hash_v2(api_key, &a.agent_id, ts, nonce);

        let result = verify_provenance(&a, api_key, &wire);
        assert!(matches!(result, Ok(Some(_))));
        let (got_ts, got_nonce) = result.unwrap().unwrap();
        assert_eq!(got_ts, ts);
        assert_eq!(got_nonce, nonce);
    }

    /// v1.0.1: subcause emission per spec §3.1 closed registry.
    #[test]
    fn v2_subcauses_are_routed_correctly() {
        let api_key = "jdb_ak_secret";
        let agent_id = "jdb_ag_test";
        let ts = chrono::Utc::now().timestamp();
        let nonce = "deadbeef0123456789abcdef01234567";

        // WireMalformed — bad format
        match verify_provenance_v2(api_key, agent_id, "not-v2-format", 300).unwrap_err() {
            JecpErrorCode::ProvenanceMismatch { subcause, .. } => {
                assert_eq!(subcause, ProvenanceSubcause::WireMalformed);
            }
            other => panic!("expected ProvenanceMismatch, got {:?}", other),
        }

        // WireMalformed — short nonce
        let bad_wire = format!("v2:{}:abc:{}", ts, "0".repeat(64));
        match verify_provenance_v2(api_key, agent_id, &bad_wire, 300).unwrap_err() {
            JecpErrorCode::ProvenanceMismatch { subcause, .. } => {
                assert_eq!(subcause, ProvenanceSubcause::WireMalformed);
            }
            other => panic!("expected ProvenanceMismatch, got {:?}", other),
        }

        // HmacMismatch — correct format but wrong key
        let wire = compute_provenance_hash_v2("real-key", agent_id, ts, nonce);
        match verify_provenance_v2("attacker-key", agent_id, &wire, 300).unwrap_err() {
            JecpErrorCode::ProvenanceMismatch { subcause, .. } => {
                assert_eq!(subcause, ProvenanceSubcause::HmacMismatch);
            }
            other => panic!("expected ProvenanceMismatch, got {:?}", other),
        }
    }

    /// v1.0.1: clock_skew populates drift_seconds in error details.
    #[test]
    fn v2_clock_skew_emits_drift_seconds() {
        let api_key = "jdb_ak_secret";
        let agent_id = "jdb_ag_test";
        let stale_ts = chrono::Utc::now().timestamp() - 3600; // 1h old
        let nonce = "deadbeef0123456789abcdef01234567";
        let wire = compute_provenance_hash_v2(api_key, agent_id, stale_ts, nonce);

        match verify_provenance_v2(api_key, agent_id, &wire, 300).unwrap_err() {
            JecpErrorCode::ProvenanceMismatch { subcause, drift_seconds, .. } => {
                assert_eq!(subcause, ProvenanceSubcause::ClockSkew);
                let drift = drift_seconds.expect("drift_seconds must be populated for clock_skew");
                assert!(
                    (drift - 3600).abs() < 5,
                    "drift_seconds should be ~3600, got {}",
                    drift
                );
            }
            other => panic!("expected ProvenanceMismatch, got {:?}", other),
        }
    }

    /// v1.0.1: rotated agent with v1 hash gets V1Unavailable, NOT generic mismatch.
    #[test]
    fn v1_on_rotated_agent_emits_v1_unavailable() {
        let mut a = fake_agent("", 0); // plaintext NULL → empty
        a.agent_id = "jdb_ag_rotated".to_string();
        let claimed_v1 = "0".repeat(64); // valid v1 wire shape (64 hex)

        match verify_provenance(&a, "any-plaintext", &claimed_v1).unwrap_err() {
            JecpErrorCode::ProvenanceMismatch { subcause, .. } => {
                assert_eq!(subcause, ProvenanceSubcause::V1Unavailable);
            }
            other => panic!("expected ProvenanceMismatch, got {:?}", other),
        }
    }

    /// v1.0.1 / H3: cross-stack conformance against the canonical fixture
    /// shipped in `jecp-spec/fixtures/provenance-v2-vectors.json`.
    /// The fixture is vendored at `jecp/test_fixtures/` (CI verifies sha256
    /// match against jecp-spec).
    #[test]
    fn provenance_v2_fixture_vectors_match() {
        let fixture = std::fs::read_to_string("test_fixtures/provenance-v2-vectors.json")
            .expect("fixture file must exist at jecp/test_fixtures/");
        let doc: serde_json::Value = serde_json::from_str(&fixture).unwrap();

        // Valid vectors: compute_v2 output MUST equal expected_wire byte-for-byte.
        for v in doc["valid"].as_array().unwrap() {
            let name = v["name"].as_str().unwrap();
            let i = &v["input"];
            let wire = compute_provenance_hash_v2(
                i["api_key"].as_str().unwrap(),
                i["agent_id"].as_str().unwrap(),
                i["timestamp"].as_i64().unwrap(),
                i["nonce"].as_str().unwrap(),
            );
            assert_eq!(
                wire,
                v["expected_wire"].as_str().unwrap(),
                "fixture vector '{}' wire mismatch",
                name
            );
        }

        // Invalid vectors: verify_provenance_v2 MUST reject with the documented
        // subcause. The fixture's `now` field is the reference time the wire
        // was produced against; we use i64::MAX/2 as the skew window so the
        // clock check doesn't fire for fixed-wire cases (we test clock_skew
        // separately via the `clock_skew` block below).
        for v in doc["invalid"].as_array().unwrap() {
            let name = v["name"].as_str().unwrap();
            let i = &v["input"];
            let wire = v["wire"].as_str().unwrap();
            let expected = v["expected_subcause"].as_str().unwrap();
            let result = verify_provenance_v2(
                i["api_key"].as_str().unwrap(),
                i["agent_id"].as_str().unwrap(),
                wire,
                i64::MAX / 2,
            );
            match result.unwrap_err() {
                JecpErrorCode::ProvenanceMismatch { subcause, .. } => {
                    let got = subcause.as_str();
                    assert_eq!(got, expected, "fixture vector '{}' subcause mismatch", name);
                }
                other => panic!("vector '{}' returned non-PROV error: {:?}", name, other),
            }
        }

        // clock_skew vectors: dynamically compute a wire whose timestamp is
        // off by `skew_offset_sec` from "now", then verify with the standard
        // 300s window. Outside ±300s → clock_skew; inside (or boundary) → ok.
        for v in doc["clock_skew"].as_array().unwrap() {
            let name = v["name"].as_str().unwrap();
            let offset = v["skew_offset_sec"].as_i64().unwrap();
            let now = chrono::Utc::now().timestamp();
            let api_key = "jdb_ak_skew_test";
            let agent_id = "jdb_ag_skew_test";
            let nonce = "abcdef0123456789abcdef0123456789";
            let wire = compute_provenance_hash_v2(api_key, agent_id, now + offset, nonce);
            let result = verify_provenance_v2(api_key, agent_id, &wire, 300);

            match v["expected_subcause"].as_str() {
                Some(expected) => {
                    let err = result.unwrap_err();
                    if let JecpErrorCode::ProvenanceMismatch { subcause, .. } = err {
                        assert_eq!(subcause.as_str(), expected, "skew vector '{}' subcause", name);
                    } else {
                        panic!("skew vector '{}' returned non-PROV error", name);
                    }
                }
                None => {
                    assert!(result.is_ok(), "skew vector '{}' should be accepted (boundary inclusive)", name);
                }
            }
        }
    }

    /// v1.0.1: tampered v1 (non-rotated agent) gets V1LegacyMismatch.
    #[test]
    fn v1_tampered_emits_v1_legacy_mismatch() {
        let a = fake_agent("jdb_ak_secret_xyz", 42);
        let mut h = compute_provenance_hash(&a);
        h.replace_range(0..1, "0");

        match verify_provenance(&a, &a.api_key, &h).unwrap_err() {
            JecpErrorCode::ProvenanceMismatch { subcause, .. } => {
                assert_eq!(subcause, ProvenanceSubcause::V1LegacyMismatch);
            }
            other => panic!("expected ProvenanceMismatch, got {:?}", other),
        }
    }

    #[test]
    fn v2_works_for_rotated_agent_with_empty_profile_key() {
        // Post-A.5 rotated row: agent.api_key is "" but Mandate.api_key has plaintext.
        // v2 path uses plaintext_api_key arg, so it must succeed.
        let plaintext_api_key = "jdb_ak_freshly_rotated";
        let mut a = fake_agent("", 10); // simulate hash-only row
        a.agent_id = "jdb_ag_rotated_user".to_string();
        let ts = chrono::Utc::now().timestamp();
        let nonce = "0123456789abcdef0123456789abcdef";
        let wire = compute_provenance_hash_v2(plaintext_api_key, &a.agent_id, ts, nonce);

        let result = verify_provenance(&a, plaintext_api_key, &wire);
        assert!(result.is_ok(), "v2 must work even when AgentProfile.api_key is empty");
    }
}

