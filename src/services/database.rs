use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use sqlx::{PgPool, Row};
use std::str::FromStr;
use std::time::Duration;

use crate::config::Config;

/// Create a PostgreSQL connection pool with the given max_connections.
async fn build_pool(config: &Config, max_connections: u32) -> Result<PgPool, sqlx::Error> {
    let ssl_mode = if config.database_url.contains("sslmode=disable") {
        PgSslMode::Disable
    } else {
        PgSslMode::Prefer
    };

    // Disable statement caching for PgBouncer (transaction mode) compatibility
    let connect_options = PgConnectOptions::from_str(&config.database_url)?
        .ssl_mode(ssl_mode)
        .statement_cache_capacity(0);

    let pool = PgPoolOptions::new()
        .max_connections(max_connections)
        .acquire_timeout(Duration::from_secs(10))
        .connect_with(connect_options)
        .await?;

    Ok(pool)
}

/// Legacy single-pool constructor (kept for compatibility — wraps build_pool).
pub async fn create_pool(config: &Config) -> Result<PgPool, sqlx::Error> {
    let pool = build_pool(config, config.db_max_connections).await?;
    tracing::info!(
        "Database pool created (max_connections: {})",
        config.db_max_connections
    );
    Ok(pool)
}

/// S0 Sprint — partitioned pools for in-process bulkhead.
///
/// Splits the database connection budget into 4 isolated pools so a
/// single feature consuming all its connections cannot starve other
/// features. Allocations are proportional to expected load with a floor.
///
/// | Pool       | Share | Used by                                            |
/// |------------|-------|----------------------------------------------------|
/// | invoke     | 50%   | /v1/invoke, /v1/jecp (hot path)                    |
/// | provider   | 20%   | register, manifests, keys, refunds, subscriptions  |
/// | background | 15%   | webhook delivery, refund cron                      |
/// | read       | 15%   | /v1/capabilities, /health, GET /v1/refunds         |
#[derive(Clone)]
pub struct PartitionedPools {
    pub invoke: PgPool,
    pub provider: PgPool,
    pub background: PgPool,
    pub read: PgPool,
}

/// Minimum total pool budget. Below this, the floors collide and the sum
/// would exceed total. We require operators to allocate at least 14
/// connections, which is the smallest budget where the proportional split
/// + floor ≥ 2 is consistent (50/20/15/15 of 14 = 7+2+2+2 = 13, floors apply
/// → 7+2+2+2 = 13 ≤ 14 ✓). Lower budgets risk DB connection exhaustion
/// and false-isolation between pools.
const MIN_TOTAL_POOL_BUDGET: u32 = 14;

impl PartitionedPools {
    pub async fn create(config: &Config) -> Result<Self, sqlx::Error> {
        let total = config.db_max_connections.max(MIN_TOTAL_POOL_BUDGET);

        let (invoke_size, provider_size, background_size, read_size) = compute_budget(total);

        let sum = invoke_size + provider_size + background_size + read_size;
        if sum > total {
            // Floor collision exceeded the total budget. This is a config bug
            // that would silently exhaust Supabase connections at boot. Fail
            // loudly so deploy gating catches it.
            return Err(sqlx::Error::Configuration(
                format!(
                    "Pool budget overflow: invoke={} + provider={} + background={} + read={} = {} > total={}. \
                     Increase DB_MAX_CONNECTIONS to at least {}.",
                    invoke_size, provider_size, background_size, read_size, sum, total,
                    MIN_TOTAL_POOL_BUDGET
                ).into(),
            ));
        }

        let invoke = build_pool(config, invoke_size).await?;
        let provider = build_pool(config, provider_size).await?;
        let background = build_pool(config, background_size).await?;
        let read = build_pool(config, read_size).await?;

        tracing::info!(
            invoke = invoke_size,
            provider = provider_size,
            background = background_size,
            read = read_size,
            sum = sum,
            total_budget = total,
            "S0 partitioned DB pools created"
        );

        Ok(Self { invoke, provider, background, read })
    }

    /// Snapshot of pool utilisation, exposed via /health.
    pub fn stats(&self) -> serde_json::Value {
        serde_json::json!({
            "invoke":     pool_stat(&self.invoke),
            "provider":   pool_stat(&self.provider),
            "background": pool_stat(&self.background),
            "read":       pool_stat(&self.read),
        })
    }
}

fn pool_stat(p: &PgPool) -> serde_json::Value {
    serde_json::json!({
        "size":     p.size(),
        "idle":     p.num_idle(),
    })
}

/// Compute per-pool sizes respecting both the proportional split and the
/// per-pool floor. Returns (invoke, provider, background, read).
///
/// At total < MIN_TOTAL_POOL_BUDGET the floors are applied but the sum may
/// still overflow; the caller is responsible for clamping `total` to at
/// least MIN_TOTAL_POOL_BUDGET *before* calling this. The unit tests
/// confirm that for every total >= MIN_TOTAL_POOL_BUDGET, sum <= total.
fn compute_budget(total: u32) -> (u32, u32, u32, u32) {
    let invoke = std::cmp::max(total * 50 / 100, 4);
    let provider = std::cmp::max(total * 20 / 100, 2);
    let background = std::cmp::max(total * 15 / 100, 2);
    let read = std::cmp::max(total * 15 / 100, 2);
    (invoke, provider, background, read)
}

#[cfg(test)]
mod pool_budget_tests {
    use super::{compute_budget, MIN_TOTAL_POOL_BUDGET};

    #[test]
    fn budget_never_overflows_at_or_above_minimum() {
        // Walk every total from MIN to 200 (Supabase pooler max) and verify
        // sum <= total.
        for total in MIN_TOTAL_POOL_BUDGET..=200 {
            let (i, p, b, r) = compute_budget(total);
            let sum = i + p + b + r;
            assert!(
                sum <= total,
                "total={} produced sum={} (i={} p={} b={} r={})",
                total, sum, i, p, b, r,
            );
        }
    }

    #[test]
    fn each_pool_meets_floor() {
        let (i, p, b, r) = compute_budget(14);
        assert!(i >= 4);
        assert!(p >= 2);
        assert!(b >= 2);
        assert!(r >= 2);
    }

    #[test]
    fn proportional_at_high_budget() {
        // total = 60 (Supabase Pro direct cap)
        let (i, p, b, r) = compute_budget(60);
        assert_eq!(i, 30);  // 50%
        assert_eq!(p, 12);  // 20%
        assert_eq!(b, 9);   // 15%
        assert_eq!(r, 9);   // 15%
        assert_eq!(i + p + b + r, 60);
    }

    #[test]
    fn proportional_at_minimum_budget() {
        let (i, p, b, r) = compute_budget(MIN_TOTAL_POOL_BUDGET);
        // 14 → 50%=7, 20%=2, 15%=2, 15%=2 → sum = 13 ≤ 14 ✓
        assert!(i + p + b + r <= MIN_TOTAL_POOL_BUDGET);
    }
}

/// Check database connectivity
pub async fn health_check(pool: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT 1").persistent(false).execute(pool).await?;
    Ok(())
}

// ────────────────────────────────────────────────────────────────────────────
// Wallet operations (jecp.wallets / jecp.transactions)
// ────────────────────────────────────────────────────────────────────────────

/// Result of a successful wallet deduction
#[derive(Debug, Clone)]
pub struct DeductResult {
    pub balance_after: f64,
    pub transaction_id: String,
}

/// Get current wallet balance (USDC). Returns 0.0 if wallet not yet created.
pub async fn get_wallet_balance(pool: &PgPool, agent_id: &str) -> Result<f64, sqlx::Error> {
    let row = sqlx::query("SELECT balance_usdc FROM jecp.wallets WHERE agent_id = $1")
        .bind(agent_id)
        .persistent(false)
        .fetch_optional(pool)
        .await?;

    match row {
        Some(r) => {
            let balance: rust_decimal::Decimal = r.try_get("balance_usdc")?;
            Ok(decimal_to_f64(balance))
        }
        None => Ok(0.0),
    }
}

/// Atomically deduct from wallet and record transaction.
/// Returns Ok(Some(DeductResult)) on success, Ok(None) if insufficient balance.
pub async fn deduct_wallet(
    pool: &PgPool,
    agent_id: &str,
    amount: f64,
    capability: &str,
    action: &str,
    request_id: Option<&str>,
) -> Result<Option<DeductResult>, sqlx::Error> {
    // Use the SQL function jecp.deduct_balance which handles atomicity
    let row = sqlx::query(
        "SELECT success, balance_after, transaction_id
         FROM jecp.deduct_balance($1, $2::DECIMAL, $3, $4, $5)",
    )
    .bind(agent_id)
    .bind(amount)
    .bind(capability)
    .bind(action)
    .bind(request_id)
    .persistent(false)
    .fetch_one(pool)
    .await?;

    let success: bool = row.try_get("success")?;
    if !success {
        return Ok(None);
    }

    let balance_after_dec: rust_decimal::Decimal = row.try_get("balance_after")?;
    let tx_id: uuid::Uuid = row.try_get("transaction_id")?;

    Ok(Some(DeductResult {
        balance_after: decimal_to_f64(balance_after_dec),
        transaction_id: tx_id.to_string(),
    }))
}

/// Add funds to wallet (called from Stripe webhook).
/// Idempotent on stripe_session_id.
pub async fn topup_wallet(
    pool: &PgPool,
    agent_id: &str,
    amount: f64,
    stripe_session_id: Option<&str>,
    stripe_payment_intent_id: Option<&str>,
    payment_method: &str,
) -> Result<(f64, String), sqlx::Error> {
    let row = sqlx::query(
        "SELECT balance_after, transaction_id
         FROM jecp.topup_balance($1, $2::DECIMAL, $3, $4, $5)",
    )
    .bind(agent_id)
    .bind(amount)
    .bind(stripe_session_id)
    .bind(stripe_payment_intent_id)
    .bind(payment_method)
    .persistent(false)
    .fetch_one(pool)
    .await?;

    let balance: rust_decimal::Decimal = row.try_get("balance_after")?;
    let tx_id: uuid::Uuid = row.try_get("transaction_id")?;

    Ok((decimal_to_f64(balance), tx_id.to_string()))
}

fn decimal_to_f64(d: rust_decimal::Decimal) -> f64 {
    use std::str::FromStr;
    f64::from_str(&d.to_string()).unwrap_or(0.0)
}

// ────────────────────────────────────────────────────────────────────────────
// Idempotency cache (Sprint 4.5 / Spec compliance C1)
// jecp.request_cache lookup/store via SQL functions
// ────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CachedResponse {
    pub response: Option<serde_json::Value>,
    pub http_status: i32,
    pub conflict: bool,
}

pub async fn cache_lookup(
    pool: &PgPool,
    agent_id: &str,
    request_id: &str,
    input_hash: &str,
) -> Result<Option<CachedResponse>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT found, response, http_status, conflict FROM jecp.cache_lookup($1, $2, $3)",
    )
    .bind(agent_id)
    .bind(request_id)
    .bind(input_hash)
    .persistent(false)
    .fetch_one(pool)
    .await?;

    let found: bool = row.try_get("found")?;
    if !found {
        return Ok(None);
    }
    let response: Option<serde_json::Value> = row.try_get("response").ok();
    let http_status: i32 = row.try_get("http_status").unwrap_or(200);
    let conflict: bool = row.try_get("conflict").unwrap_or(false);

    Ok(Some(CachedResponse {
        response,
        http_status,
        conflict,
    }))
}

pub async fn cache_store(
    pool: &PgPool,
    agent_id: &str,
    request_id: &str,
    capability: &str,
    action: &str,
    input_hash: &str,
    response_body: &serde_json::Value,
    http_status: i32,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "SELECT jecp.cache_store($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(agent_id)
    .bind(request_id)
    .bind(capability)
    .bind(action)
    .bind(input_hash)
    .bind(response_body)
    .bind(http_status)
    .persistent(false)
    .execute(pool)
    .await?;

    Ok(())
}

// ────────────────────────────────────────────────────────────────────────────
// Provider operations (Sprint 6 / Stage 3)
// jecp.providers + manifest_history + DNS verification
// ────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ProviderRow {
    pub id: uuid::Uuid,
    pub namespace: String,
    pub display_name: String,
    pub status: String,
    pub api_key_prefix: String,
    pub endpoint_url: Option<String>,
    pub dns_verified_at: Option<chrono::DateTime<chrono::Utc>>,
    pub stripe_account_verified: bool,
    pub total_calls: i64,
}

#[derive(Debug, Clone)]
pub struct CreatedProvider {
    pub id: uuid::Uuid,
    pub namespace: String,
    pub api_key_prefix: String,
    pub dns_verification_token: String,
    pub dns_verification_nonce: String,
}

/// Insert a new provider row. Caller passes pre-generated key/secret values.
/// api_key_hash MUST be a bcrypt hash of the api_key.
#[allow(clippy::too_many_arguments)]
pub async fn register_provider(
    pool: &PgPool,
    namespace: &str,
    display_name: &str,
    owner_email: &str,
    website: Option<&str>,
    endpoint_url: &str,
    country_code: &str,
    api_key_hash: &str,
    api_key_prefix: &str,
    hmac_secret: &str,
    dns_verification_token: &str,
    dns_verification_nonce: &str,
) -> Result<CreatedProvider, sqlx::Error> {
    let row = sqlx::query(
        "INSERT INTO jecp.providers (
            namespace, display_name, website, owner_email,
            api_key_hash, api_key_prefix, hmac_secret,
            endpoint_url, authentication_type, country_code,
            dns_verification_token, dns_verification_nonce
         )
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'api_key', $9, $10, $11)
         RETURNING id, namespace, api_key_prefix, dns_verification_token, dns_verification_nonce",
    )
    .bind(namespace)
    .bind(display_name)
    .bind(website)
    .bind(owner_email)
    .bind(api_key_hash)
    .bind(api_key_prefix)
    .bind(hmac_secret)
    .bind(endpoint_url)
    .bind(country_code)
    .bind(dns_verification_token)
    .bind(dns_verification_nonce)
    .persistent(false)
    .fetch_one(pool)
    .await?;

    Ok(CreatedProvider {
        id: row.try_get("id")?,
        namespace: row.try_get("namespace")?,
        api_key_prefix: row.try_get("api_key_prefix")?,
        dns_verification_token: row.try_get("dns_verification_token")?,
        dns_verification_nonce: row.try_get("dns_verification_nonce")?,
    })
}

/// Provider auth lookup result. Returns the hash to verify against —
/// either the current one (if `prefix` matches `api_key_prefix`) or the
/// previous one (if it matches `previous_api_key_prefix` AND
/// `previous_key_valid_until > NOW()`).
///
/// `is_grace_match = true` indicates the caller authenticated with the
/// previous (rotation) key — surface this in logs for visibility.
#[derive(Debug, Clone)]
pub struct ProviderAuthMatch {
    pub provider: ProviderRow,
    pub hash: String,
    pub is_grace_match: bool,
}

/// Look up a provider by api_key prefix. Returns row + the bcrypt hash for
/// verification. Tries the active prefix first, then the previous prefix
/// (within grace window). Caller MUST bcrypt-verify the returned hash.
pub async fn get_provider_for_auth(
    pool: &PgPool,
    api_key_prefix: &str,
) -> Result<Option<ProviderAuthMatch>, sqlx::Error> {
    // Try the current prefix first.
    let row = sqlx::query(
        "SELECT id, namespace, display_name, status, api_key_prefix, api_key_hash,
                endpoint_url, dns_verified_at, stripe_account_verified, total_calls
           FROM jecp.providers
          WHERE api_key_prefix = $1
            AND status != 'deleted'
          LIMIT 1",
    )
    .bind(api_key_prefix)
    .persistent(false)
    .fetch_optional(pool)
    .await?;

    if let Some(r) = row {
        let provider = ProviderRow {
            id: r.try_get("id")?,
            namespace: r.try_get("namespace")?,
            display_name: r.try_get("display_name")?,
            status: r.try_get("status")?,
            api_key_prefix: r.try_get("api_key_prefix")?,
            endpoint_url: r.try_get("endpoint_url").ok(),
            dns_verified_at: r.try_get("dns_verified_at").ok(),
            stripe_account_verified: r.try_get("stripe_account_verified").unwrap_or(false),
            total_calls: r.try_get("total_calls").unwrap_or(0),
        };
        let hash: String = r.try_get("api_key_hash")?;
        return Ok(Some(ProviderAuthMatch { provider, hash, is_grace_match: false }));
    }

    // Fall back to the previous (rotation) prefix within grace window.
    let row = sqlx::query(
        "SELECT id, namespace, display_name, status, api_key_prefix,
                previous_api_key_hash,
                endpoint_url, dns_verified_at, stripe_account_verified, total_calls
           FROM jecp.providers
          WHERE previous_api_key_prefix = $1
            AND previous_key_valid_until > NOW()
            AND status != 'deleted'
          LIMIT 1",
    )
    .bind(api_key_prefix)
    .persistent(false)
    .fetch_optional(pool)
    .await?;

    let Some(r) = row else { return Ok(None); };
    let provider = ProviderRow {
        id: r.try_get("id")?,
        namespace: r.try_get("namespace")?,
        display_name: r.try_get("display_name")?,
        status: r.try_get("status")?,
        api_key_prefix: r.try_get("api_key_prefix")?,
        endpoint_url: r.try_get("endpoint_url").ok(),
        dns_verified_at: r.try_get("dns_verified_at").ok(),
        stripe_account_verified: r.try_get("stripe_account_verified").unwrap_or(false),
        total_calls: r.try_get("total_calls").unwrap_or(0),
    };
    let hash: String = r.try_get("previous_api_key_hash")?;
    Ok(Some(ProviderAuthMatch { provider, hash, is_grace_match: true }))
}

/// Get provider by ID(authenticated user 用)
pub async fn get_provider_by_id(
    pool: &PgPool,
    provider_id: &uuid::Uuid,
) -> Result<Option<ProviderRow>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT id, namespace, display_name, status, api_key_prefix,
                endpoint_url, dns_verified_at, stripe_account_verified, total_calls
           FROM jecp.providers
          WHERE id = $1
            AND status != 'deleted'",
    )
    .bind(provider_id)
    .persistent(false)
    .fetch_optional(pool)
    .await?;

    let Some(r) = row else { return Ok(None); };
    Ok(Some(ProviderRow {
        id: r.try_get("id")?,
        namespace: r.try_get("namespace")?,
        display_name: r.try_get("display_name")?,
        status: r.try_get("status")?,
        api_key_prefix: r.try_get("api_key_prefix")?,
        endpoint_url: r.try_get("endpoint_url").ok(),
        dns_verified_at: r.try_get("dns_verified_at").ok(),
        stripe_account_verified: r.try_get("stripe_account_verified").unwrap_or(false),
        total_calls: r.try_get("total_calls").unwrap_or(0),
    }))
}

/// Provider row with full detail (used by stripe-connect bridge).
#[derive(Debug, Clone)]
pub struct ProviderDetail {
    pub id: uuid::Uuid,
    pub namespace: String,
    pub owner_email: Option<String>,
    pub country_code: Option<String>,
    pub stripe_account_id: Option<String>,
}

/// Get full provider row (with country / email / stripe id) by ID.
pub async fn get_provider_full(
    pool: &PgPool,
    provider_id: &uuid::Uuid,
) -> Result<Option<ProviderDetail>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT id, namespace, owner_email, country_code, stripe_account_id
           FROM jecp.providers
          WHERE id = $1
            AND status != 'deleted'",
    )
    .bind(provider_id)
    .persistent(false)
    .fetch_optional(pool)
    .await?;

    let Some(r) = row else { return Ok(None); };
    Ok(Some(ProviderDetail {
        id: r.try_get("id")?,
        namespace: r.try_get("namespace")?,
        owner_email: r.try_get("owner_email").ok(),
        country_code: r.try_get("country_code").ok(),
        stripe_account_id: r.try_get("stripe_account_id").ok(),
    }))
}

/// Mark DNS as verified and transition status pending → verified.
pub async fn mark_dns_verified(
    pool: &PgPool,
    provider_id: &uuid::Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE jecp.providers
            SET dns_verified_at = NOW(),
                status = CASE WHEN status = 'pending' THEN 'verified' ELSE status END,
                updated_at = NOW()
          WHERE id = $1",
    )
    .bind(provider_id)
    .persistent(false)
    .execute(pool)
    .await?;
    Ok(())
}

// ────────────────────────────────────────────────────────────────────────────
// Capability discovery (Sprint 9 / Stage 3)
// ────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PublishedCapabilityInfo {
    pub provider_namespace: String,
    pub provider_display_name: Option<String>,
    pub capability_name: String,
    pub version: String,
    pub full_id: String,
    pub description: String,
    pub status: String,
    pub tags: Vec<String>,
    pub parsed_json: serde_json::Value,
    pub total_calls: i64,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub capability_id: uuid::Uuid,
}

/// Cursor for catalog pagination — opaque to clients (base64-encoded JSON).
/// Sorts deterministic by (total_calls DESC, created_at DESC, capability_id DESC).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CatalogCursor {
    pub last_total_calls: i64,
    pub last_created_at: chrono::DateTime<chrono::Utc>,
    pub last_capability_id: uuid::Uuid,
}

impl CatalogCursor {
    pub fn encode(&self) -> String {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        let json = serde_json::to_vec(self).unwrap_or_default();
        URL_SAFE_NO_PAD.encode(json)
    }

    pub fn decode(s: &str) -> Result<Self, String> {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        let bytes = URL_SAFE_NO_PAD.decode(s).map_err(|e| format!("invalid cursor base64: {}", e))?;
        serde_json::from_slice(&bytes).map_err(|e| format!("invalid cursor json: {}", e))
    }
}

#[derive(Debug, Default)]
pub struct CatalogFilter {
    pub namespace: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Debug)]
pub struct CatalogPage {
    pub items: Vec<PublishedCapabilityInfo>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

/// List third-party capabilities for the public catalog.
/// Returns rows joined with provider info, filtered to status='active'.
pub async fn list_active_capabilities(
    pool: &PgPool,
    limit: i64,
) -> Result<Vec<PublishedCapabilityInfo>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT
             c.capability_name, c.version, c.full_id, c.description, c.status,
             c.tags, c.total_calls,
             p.namespace AS provider_namespace,
             p.display_name AS provider_display_name,
             m.parsed_json
           FROM jecp.capabilities c
           JOIN jecp.providers p ON p.id = c.provider_id
           JOIN jecp.manifests m ON m.capability_id = c.id
          WHERE c.status = 'active'
            AND p.status IN ('verified', 'active')
          ORDER BY c.total_calls DESC, c.created_at DESC
          LIMIT $1",
    )
    .bind(limit)
    .persistent(false)
    .fetch_all(pool)
    .await?;

    let mut result = Vec::with_capacity(rows.len());
    for r in rows {
        let tags: Vec<String> = r.try_get("tags").unwrap_or_default();
        result.push(PublishedCapabilityInfo {
            provider_namespace: r.try_get("provider_namespace")?,
            provider_display_name: r.try_get("provider_display_name").ok(),
            capability_name: r.try_get("capability_name")?,
            version: r.try_get("version")?,
            full_id: r.try_get("full_id")?,
            description: r.try_get("description")?,
            status: r.try_get("status")?,
            tags,
            parsed_json: r.try_get("parsed_json")?,
            total_calls: r.try_get("total_calls").unwrap_or(0),
            created_at: r.try_get("created_at").unwrap_or_else(|_| chrono::Utc::now()),
            capability_id: r.try_get("capability_id").unwrap_or_else(|_| uuid::Uuid::nil()),
        });
    }
    Ok(result)
}

/// Cursor-based paginated list of active third-party capabilities (W3).
///
/// Sort: (total_calls DESC, created_at DESC, capability_id DESC) — deterministic,
/// most-popular-first ordering.
///
/// `page_size` is clamped to [1, 200].
pub async fn list_active_capabilities_paginated(
    pool: &PgPool,
    cursor: Option<CatalogCursor>,
    page_size: i64,
    filter: &CatalogFilter,
) -> Result<CatalogPage, sqlx::Error> {
    let page_size = page_size.clamp(1, 200);
    let limit = page_size + 1; // +1 to detect has_more

    // Cursor predicate uses 3-tuple compare (total_calls, created_at, id) DESC
    let (cur_calls, cur_created, cur_id) = match &cursor {
        Some(c) => (Some(c.last_total_calls), Some(c.last_created_at), Some(c.last_capability_id)),
        None => (None, None, None),
    };
    let ns_filter = filter.namespace.clone();
    let tags_filter = if filter.tags.is_empty() { None } else { Some(filter.tags.clone()) };

    let rows = sqlx::query(
        "SELECT
             c.id AS capability_id, c.capability_name, c.version, c.full_id,
             c.description, c.status, c.tags, c.total_calls, c.created_at,
             p.namespace AS provider_namespace,
             p.display_name AS provider_display_name,
             m.parsed_json
           FROM jecp.capabilities c
           JOIN jecp.providers p ON p.id = c.provider_id
           JOIN jecp.manifests m ON m.capability_id = c.id
          WHERE c.status = 'active'
            AND p.status IN ('verified', 'active')
            AND ($1::TEXT IS NULL OR p.namespace = $1)
            AND ($2::TEXT[] IS NULL OR c.tags && $2)
            AND (
              $3::BIGINT IS NULL
              OR (c.total_calls, c.created_at, c.id) <
                 ($3::BIGINT, $4::TIMESTAMPTZ, $5::UUID)
            )
          ORDER BY c.total_calls DESC, c.created_at DESC, c.id DESC
          LIMIT $6",
    )
    .bind(ns_filter)
    .bind(tags_filter)
    .bind(cur_calls)
    .bind(cur_created)
    .bind(cur_id)
    .bind(limit)
    .persistent(false)
    .fetch_all(pool)
    .await?;

    let has_more = rows.len() as i64 > page_size;
    let items_to_keep = if has_more { page_size as usize } else { rows.len() };

    let mut items = Vec::with_capacity(items_to_keep);
    for r in rows.iter().take(items_to_keep) {
        let tags: Vec<String> = r.try_get("tags").unwrap_or_default();
        items.push(PublishedCapabilityInfo {
            provider_namespace: r.try_get("provider_namespace")?,
            provider_display_name: r.try_get("provider_display_name").ok(),
            capability_name: r.try_get("capability_name")?,
            version: r.try_get("version")?,
            full_id: r.try_get("full_id")?,
            description: r.try_get("description")?,
            status: r.try_get("status")?,
            tags,
            parsed_json: r.try_get("parsed_json")?,
            total_calls: r.try_get("total_calls").unwrap_or(0),
            created_at: r.try_get("created_at").unwrap_or_else(|_| chrono::Utc::now()),
            capability_id: r.try_get("capability_id").unwrap_or_else(|_| uuid::Uuid::nil()),
        });
    }

    let next_cursor = if has_more && !items.is_empty() {
        let last = items.last().unwrap();
        Some(CatalogCursor {
            last_total_calls: last.total_calls,
            last_created_at: last.created_at,
            last_capability_id: last.capability_id,
        }.encode())
    } else {
        None
    };

    Ok(CatalogPage { items, next_cursor, has_more })
}

// ────────────────────────────────────────────────────────────────────────────
// Provider invocation routing (Sprint 11 / Stage 3)
// ────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ResolvedCapability {
    pub capability_id: uuid::Uuid,
    pub provider_id: uuid::Uuid,
    pub capability_name: String,
    pub version: String,
    pub namespace: String,
    pub endpoint_url: String,
    pub hmac_secret: String,
    /// Manifest content (parsed_json) — used to resolve action pricing
    pub parsed_json: serde_json::Value,
    /// v1.0.2 K2.3 — capability lifecycle status. Possible values:
    ///   `active`     — normal operation, serve invocations
    ///   `deprecated` — still serving but Hub MAY warn (Phase 0 v1.0.2 does not
    ///                  use this state distinct from `active`)
    ///   `sunset`     — `sunset_at` may be in the past; route layer MUST return
    ///                  410 CAPABILITY_DEPRECATED on invoke
    pub status: String,
    /// v1.0.2 K2.3 — RFC 3339 timestamp at which this capability is gone.
    /// When in the past relative to the Hub clock, /v1/invoke MUST return 410.
    pub sunset_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Resolve a third-party capability for invocation.
///
/// v1.0.2 K2.3: returns rows with `status IN ('active','deprecated','sunset')`
/// so the route layer can detect a sunset capability and return 410
/// CAPABILITY_DEPRECATED with required Sunset/Deprecation/Link headers per
/// spec §4.6 + 03-errors §3.3. Pre-v1.0.2 the query filtered to status='active'
/// only, which silently 404'd sunset capabilities and lost the deprecation
/// signal.
pub async fn resolve_capability_for_invoke(
    pool: &PgPool,
    full_id: &str,
) -> Result<Option<ResolvedCapability>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT
             c.id AS capability_id,
             c.capability_name, c.version, c.status, c.sunset_at,
             p.id AS provider_id,
             p.namespace,
             p.endpoint_url,
             p.hmac_secret,
             m.parsed_json
           FROM jecp.capabilities c
           JOIN jecp.providers p ON p.id = c.provider_id
           JOIN jecp.manifests m ON m.capability_id = c.id
          WHERE c.full_id = $1
            AND c.status IN ('active', 'deprecated', 'sunset')
            AND p.status IN ('verified', 'active')
          ORDER BY c.version DESC
          LIMIT 1",
    )
    .bind(full_id)
    .persistent(false)
    .fetch_optional(pool)
    .await?;

    let Some(r) = row else { return Ok(None); };
    Ok(Some(ResolvedCapability {
        capability_id: r.try_get("capability_id")?,
        provider_id: r.try_get("provider_id")?,
        capability_name: r.try_get("capability_name")?,
        version: r.try_get("version")?,
        namespace: r.try_get("namespace")?,
        endpoint_url: r.try_get::<Option<String>, _>("endpoint_url")?
            .unwrap_or_default(),
        hmac_secret: r.try_get("hmac_secret")?,
        parsed_json: r.try_get("parsed_json")?,
        status: r.try_get::<Option<String>, _>("status")?.unwrap_or_else(|| "active".into()),
        sunset_at: r.try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("sunset_at")?,
    }))
}

// ────────────────────────────────────────────────────────────────────────────
// Sprint 12: Provider invocation billing
// ────────────────────────────────────────────────────────────────────────────

/// Atomic deduct + split via jecp.invoke_charge() function.
/// Returns Ok(Some(InvokeChargeResult)) on success, Ok(None) on insufficient balance.
#[derive(Debug, Clone)]
pub struct InvokeChargeResult {
    pub balance_after: f64,
    pub transaction_id: uuid::Uuid,
    pub provider_share_usdc: f64,
    pub hub_fee_usdc: f64,
    pub payment_fee_usdc: f64,
}

#[allow(clippy::too_many_arguments)]
pub async fn invoke_charge(
    pool: &PgPool,
    agent_id: &str,
    amount_usdc: f64,
    capability_name: &str,
    action_id: &str,
    request_id: &str,
    provider_id: &uuid::Uuid,
    capability_id: &uuid::Uuid,
) -> Result<Option<InvokeChargeResult>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT success, balance_after, transaction_id, provider_share, hub_fee, payment_fee
           FROM jecp.invoke_charge($1, $2::DECIMAL, $3, $4, $5, $6, $7)",
    )
    .bind(agent_id)
    .bind(amount_usdc)
    .bind(capability_name)
    .bind(action_id)
    .bind(request_id)
    .bind(provider_id)
    .bind(capability_id)
    .persistent(false)
    .fetch_one(pool)
    .await?;

    let success: bool = row.try_get("success")?;
    if !success {
        return Ok(None);
    }

    let balance_after: rust_decimal::Decimal = row.try_get("balance_after")?;
    let provider_share: rust_decimal::Decimal = row.try_get("provider_share")?;
    let hub_fee: rust_decimal::Decimal = row.try_get("hub_fee")?;
    let payment_fee: rust_decimal::Decimal = row.try_get("payment_fee")?;
    let transaction_id: uuid::Uuid = row.try_get("transaction_id")?;

    Ok(Some(InvokeChargeResult {
        balance_after: decimal_to_f64(balance_after),
        transaction_id,
        provider_share_usdc: decimal_to_f64(provider_share),
        hub_fee_usdc: decimal_to_f64(hub_fee),
        payment_fee_usdc: decimal_to_f64(payment_fee),
    }))
}

/// Legacy: kept for backwards-compat. Calls split_revenue separately (non-atomic).
/// Prefer invoke_charge() above.
pub async fn record_provider_invocation_charge(
    pool: &PgPool,
    transaction_id: &str,
    provider_id: &uuid::Uuid,
    capability_id: &uuid::Uuid,
    action_id: &str,
    gross_usdc: f64,
) -> Result<(), sqlx::Error> {
    // Parse transaction_id String → Uuid
    let tx_uuid = uuid::Uuid::parse_str(transaction_id)
        .map_err(|e| sqlx::Error::Decode(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid transaction_id uuid: {}", e),
        ))))?;

    // Update transaction with provider/capability/action references for audit
    sqlx::query(
        "UPDATE jecp.transactions
            SET provider_id = $1, capability_id = $2, action_id = $3
          WHERE id = $4",
    )
    .bind(provider_id)
    .bind(capability_id)
    .bind(action_id)
    .bind(&tx_uuid)
    .persistent(false)
    .execute(pool)
    .await?;

    // Call split_revenue function (creates jecp.revenue_splits row + updates stats)
    let _ = sqlx::query(
        "SELECT * FROM jecp.split_revenue($1, $2, $3, $4::DECIMAL, 85, 10, 5)",
    )
    .bind(&tx_uuid)
    .bind(provider_id)
    .bind(capability_id)
    .bind(gross_usdc)
    .persistent(false)
    .fetch_one(pool)
    .await?;

    Ok(())
}

/// Increment capability + provider total_calls counters.
/// Called async after a successful invocation.
pub async fn increment_capability_calls(
    pool: &PgPool,
    capability_id: &uuid::Uuid,
    provider_id: &uuid::Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE jecp.capabilities SET total_calls = total_calls + 1 WHERE id = $1",
    )
    .bind(capability_id)
    .persistent(false)
    .execute(pool)
    .await?;

    sqlx::query(
        "UPDATE jecp.providers SET total_calls = total_calls + 1 WHERE id = $1",
    )
    .bind(provider_id)
    .persistent(false)
    .execute(pool)
    .await?;

    Ok(())
}

// ────────────────────────────────────────────────────────────────────────────
// Manifest lifecycle ops (Sprint 10 / Stage 3)
// ────────────────────────────────────────────────────────────────────────────

/// Lookup capability owned by a Provider (security check before promote/sunset).
pub async fn get_capability_for_provider(
    pool: &PgPool,
    capability_id: &uuid::Uuid,
    provider_id: &uuid::Uuid,
) -> Result<Option<(String, String)>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT full_id, status
           FROM jecp.capabilities
          WHERE id = $1 AND provider_id = $2",
    )
    .bind(capability_id)
    .bind(provider_id)
    .persistent(false)
    .fetch_optional(pool)
    .await?;
    let Some(r) = row else { return Ok(None); };
    Ok(Some((r.try_get("full_id")?, r.try_get("status")?)))
}

/// Promote capability submitted → active (Provider owner only, requires verified status).
/// Returns Ok(true) if state changed, Ok(false) if no-op (already active).
pub async fn promote_capability(
    pool: &PgPool,
    capability_id: &uuid::Uuid,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE jecp.capabilities
            SET status = 'active', updated_at = NOW()
          WHERE id = $1 AND status = 'submitted'",
    )
    .bind(capability_id)
    .persistent(false)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Sunset capability: status='sunset' + sunset_at = NOW()
/// (deprecated → sunset is the natural lifecycle; Sprint 10 MVP では直接 sunset を許可)
pub async fn sunset_capability(
    pool: &PgPool,
    capability_id: &uuid::Uuid,
    provider_id: &uuid::Uuid,
) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;

    let result = sqlx::query(
        "UPDATE jecp.capabilities
            SET status = 'sunset', sunset_at = NOW(), updated_at = NOW()
          WHERE id = $1 AND status NOT IN ('sunset', 'deprecated')",
    )
    .bind(capability_id)
    .persistent(false)
    .execute(&mut *tx)
    .await?;

    if result.rows_affected() > 0 {
        // Audit log
        sqlx::query(
            "INSERT INTO jecp.manifest_history (
                capability_id, provider_id, action, yaml_content_sha256, actor_provider_id
             )
             VALUES ($1, $2, 'sunset', '', $2)",
        )
        .bind(capability_id)
        .bind(provider_id)
        .persistent(false)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;
    Ok(result.rows_affected() > 0)
}

// ────────────────────────────────────────────────────────────────────────────
// Manifest publish (Sprint 8 / Stage 3)
// ────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PublishedCapability {
    pub capability_id: uuid::Uuid,
    pub status: String,
}

/// Publish a manifest in a transaction:
///   1. INSERT INTO jecp.capabilities (returns capability_id)
///   2. INSERT INTO jecp.manifests (yaml_content + parsed_json)
///   3. INSERT INTO jecp.manifest_history (action='publish' audit)
/// Caller must validate before calling. UNIQUE(provider_id, capability, version)
/// violation surfaces as sqlx::Error::Database with code "23505".
///
/// Initial status:
///   - 'active'    if provider has BOTH dns_verified AND stripe_account_verified
///   - 'submitted' otherwise (Provider must complete verification, then call promotion API)
#[allow(clippy::too_many_arguments)]
pub async fn publish_manifest(
    pool: &PgPool,
    provider_id: &uuid::Uuid,
    capability_name: &str,
    version: &str,
    full_id: &str,
    description: &str,
    tags: &[String],
    parsed_json: &serde_json::Value,
    yaml_content: &str,
    yaml_sha256: &str,
    fully_verified: bool,
) -> Result<PublishedCapability, sqlx::Error> {
    let mut tx = pool.begin().await?;

    let initial_status = if fully_verified { "active" } else { "submitted" };

    let cap_row = sqlx::query(
        "INSERT INTO jecp.capabilities (
            provider_id, capability_name, version, full_id,
            description, tags, status
         )
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         RETURNING id, status",
    )
    .bind(provider_id)
    .bind(capability_name)
    .bind(version)
    .bind(full_id)
    .bind(description)
    .bind(tags)
    .bind(initial_status)
    .persistent(false)
    .fetch_one(&mut *tx)
    .await?;

    let capability_id: uuid::Uuid = cap_row.try_get("id")?;
    let status: String = cap_row.try_get("status")?;

    // Manifests
    sqlx::query(
        "INSERT INTO jecp.manifests (
            capability_id, yaml_content, parsed_json, validated_at
         )
         VALUES ($1, $2, $3, NOW())",
    )
    .bind(&capability_id)
    .bind(yaml_content)
    .bind(parsed_json)
    .persistent(false)
    .execute(&mut *tx)
    .await?;

    // Audit log
    sqlx::query(
        "INSERT INTO jecp.manifest_history (
            capability_id, provider_id, action,
            yaml_content_sha256, yaml_content_snapshot, actor_provider_id
         )
         VALUES ($1, $2, 'publish', $3, $4, $2)",
    )
    .bind(&capability_id)
    .bind(provider_id)
    .bind(yaml_sha256)
    .bind(yaml_content)
    .persistent(false)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(PublishedCapability { capability_id, status })
}

/// Look up the expected DNS verification token for a provider.
pub async fn get_dns_verification_data(
    pool: &PgPool,
    provider_id: &uuid::Uuid,
) -> Result<Option<(String, String)>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT namespace, dns_verification_token
           FROM jecp.providers
          WHERE id = $1
            AND status != 'deleted'",
    )
    .bind(provider_id)
    .persistent(false)
    .fetch_optional(pool)
    .await?;

    let Some(r) = row else { return Ok(None); };
    let ns: String = r.try_get("namespace")?;
    let token: Option<String> = r.try_get("dns_verification_token").ok();
    Ok(token.map(|t| (ns, t)))
}

// ════════════════════════════════════════════════════════════════════════════
// M2 — API key rotation (Phase B)
// ════════════════════════════════════════════════════════════════════════════

pub struct KeyRotationResult {
    /// None when revoke_old=true was used (no grace period — old key
    /// rejected immediately).
    pub previous_key_valid_until: Option<chrono::DateTime<chrono::Utc>>,
}

/// TIER A.4 — atomic agent rotation. Combines (a) 24h cap count, (b) UPDATE,
/// and (c) audit_log insert in one transaction with FOR UPDATE on the agent
/// row. Concurrent rotates serialise on the lock; audit failure rolls back
/// the rotation (no silent best-effort behaviour).
///
/// Returns `AtomicRotationResult` so the caller can branch on cap_exceeded
/// vs row mismatch.
#[derive(Debug, Clone)]
pub struct AtomicRotationResult {
    pub success: bool,
    pub cap_exceeded: bool,
    pub rotations_in_last_24h: i64,
    pub previous_key_valid_until: Option<chrono::DateTime<chrono::Utc>>,
}

#[allow(clippy::too_many_arguments)]
pub async fn rotate_agent_api_key_atomic(
    pool: &PgPool,
    agent_id: &str,
    current_api_key: &str,
    new_api_key: &str,
    grace_seconds: i32,
    revoke_old: bool,
    cap_per_24h: i32,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
    metadata: serde_json::Value,
) -> Result<AtomicRotationResult, sqlx::Error> {
    let row = sqlx::query(
        "SELECT success, cap_exceeded, rotations_in_last_24h, previous_key_valid_until
           FROM public.rotate_agent_api_key_atomic($1, $2, $3, $4, $5, $6, $7::INET, $8, $9::JSONB)",
    )
    .bind(agent_id)
    .bind(current_api_key)
    .bind(new_api_key)
    .bind(grace_seconds)
    .bind(revoke_old)
    .bind(cap_per_24h)
    .bind(ip_address)
    .bind(user_agent)
    .bind(metadata)
    .persistent(false)
    .fetch_one(pool)
    .await?;

    Ok(AtomicRotationResult {
        success: row.try_get("success")?,
        cap_exceeded: row.try_get("cap_exceeded")?,
        rotations_in_last_24h: row.try_get("rotations_in_last_24h")?,
        previous_key_valid_until: row.try_get("previous_key_valid_until").ok(),
    })
}

/// TIER A.5 — atomic agent rotation with bcrypt verification.
///
/// Caller pre-computes the bcrypt hash of the new key (Hub-side) so the
/// SQL function holds the row lock only during the cheap hash comparison
/// + UPDATE + audit insert. Replaces the v1 atomic function which
/// compared plaintext.
#[allow(clippy::too_many_arguments)]
pub async fn rotate_agent_api_key_atomic_v2(
    pool: &PgPool,
    agent_id: &str,
    current_api_key: &str,
    new_api_key_hash: &str,
    new_api_key_prefix: &str,
    grace_seconds: i32,
    revoke_old: bool,
    cap_per_24h: i32,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
    metadata: serde_json::Value,
) -> Result<AtomicRotationResult, sqlx::Error> {
    let row = sqlx::query(
        "SELECT success, cap_exceeded, rotations_in_last_24h, previous_key_valid_until
           FROM public.rotate_agent_api_key_atomic_v2($1, $2, $3, $4, $5, $6, $7, $8::INET, $9, $10::JSONB)",
    )
    .bind(agent_id)
    .bind(current_api_key)
    .bind(new_api_key_hash)
    .bind(new_api_key_prefix)
    .bind(grace_seconds)
    .bind(revoke_old)
    .bind(cap_per_24h)
    .bind(ip_address)
    .bind(user_agent)
    .bind(metadata)
    .persistent(false)
    .fetch_one(pool)
    .await?;

    Ok(AtomicRotationResult {
        success: row.try_get("success")?,
        cap_exceeded: row.try_get("cap_exceeded")?,
        rotations_in_last_24h: row.try_get("rotations_in_last_24h")?,
        previous_key_valid_until: row.try_get("previous_key_valid_until").ok(),
    })
}

#[allow(clippy::too_many_arguments)]
pub async fn rotate_provider_api_key_atomic(
    pool: &PgPool,
    provider_id: &uuid::Uuid,
    new_api_key_hash: &str,
    new_api_key_prefix: &str,
    grace_seconds: i32,
    revoke_old: bool,
    cap_per_24h: i32,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
    metadata: serde_json::Value,
) -> Result<AtomicRotationResult, sqlx::Error> {
    let row = sqlx::query(
        "SELECT success, cap_exceeded, rotations_in_last_24h, previous_key_valid_until
           FROM jecp.rotate_provider_api_key_atomic($1, $2, $3, $4, $5, $6, $7::INET, $8, $9::JSONB)",
    )
    .bind(provider_id)
    .bind(new_api_key_hash)
    .bind(new_api_key_prefix)
    .bind(grace_seconds)
    .bind(revoke_old)
    .bind(cap_per_24h)
    .bind(ip_address)
    .bind(user_agent)
    .bind(metadata)
    .persistent(false)
    .fetch_one(pool)
    .await?;

    Ok(AtomicRotationResult {
        success: row.try_get("success")?,
        cap_exceeded: row.try_get("cap_exceeded")?,
        rotations_in_last_24h: row.try_get("rotations_in_last_24h")?,
        previous_key_valid_until: row.try_get("previous_key_valid_until").ok(),
    })
}

/// Atomic agent key rotation. Caller has already verified the current key.
///
/// `revoke_old=true` drops the previous key entirely (no grace period) — use
/// when compromise is suspected. `revoke_old=false` (the normal path) keeps
/// the previous key valid for `grace_seconds` so deploys can stagger.
///
/// **DEPRECATED**: prefer `rotate_agent_api_key_atomic` (TIER A.4).
/// This 5-step variant has TOCTOU between the count and the update.
#[deprecated(note = "use rotate_agent_api_key_atomic — count + UPDATE + audit in one TX")]
pub async fn rotate_agent_api_key(
    pool: &PgPool,
    agent_id: &str,
    current_api_key: &str,
    new_api_key: &str,
    grace_seconds: i32,
    revoke_old: bool,
) -> Result<Option<KeyRotationResult>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT success, previous_key_valid_until
           FROM public.rotate_agent_api_key($1, $2, $3, $4, $5)",
    )
    .bind(agent_id)
    .bind(current_api_key)
    .bind(new_api_key)
    .bind(grace_seconds)
    .bind(revoke_old)
    .persistent(false)
    .fetch_one(pool)
    .await?;

    let success: bool = row.try_get("success")?;
    if !success {
        return Ok(None);
    }
    let valid_until: Option<chrono::DateTime<chrono::Utc>> =
        row.try_get("previous_key_valid_until").ok();
    Ok(Some(KeyRotationResult { previous_key_valid_until: valid_until }))
}

/// Atomic provider key rotation. Caller has already verified bcrypt of the
/// current key against the active hash.
///
/// `revoke_old=true` drops the previous key entirely (no grace period).
pub async fn rotate_provider_api_key(
    pool: &PgPool,
    provider_id: &uuid::Uuid,
    new_api_key_hash: &str,
    new_api_key_prefix: &str,
    grace_seconds: i32,
    revoke_old: bool,
) -> Result<Option<KeyRotationResult>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT success, previous_key_valid_until
           FROM jecp.rotate_provider_api_key($1, $2, $3, $4, $5)",
    )
    .bind(provider_id)
    .bind(new_api_key_hash)
    .bind(new_api_key_prefix)
    .bind(grace_seconds)
    .bind(revoke_old)
    .persistent(false)
    .fetch_one(pool)
    .await?;

    let success: bool = row.try_get("success")?;
    if !success {
        return Ok(None);
    }
    let valid_until: Option<chrono::DateTime<chrono::Utc>> =
        row.try_get("previous_key_valid_until").ok();
    Ok(Some(KeyRotationResult { previous_key_valid_until: valid_until }))
}
