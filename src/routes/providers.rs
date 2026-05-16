//! Provider lifecycle endpoints (Sprint 6 / Stage 3).
//!
//! - POST /v1/providers/register   — 新規 Provider 登録
//! - GET  /v1/providers/me         — 自分の Provider 情報(authenticated)
//! - POST /v1/providers/verify-dns — DNS TXT レコード検証
//!
//! Auth: `Authorization: Bearer <provider_api_key>`
//! API key format: `jdb_pk_<48 hex>`

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::services::database;
use crate::AppState;

// ---------------------------------------------------------------------------
// POST /v1/providers/register
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub namespace: String,
    pub display_name: String,
    pub owner_email: String,
    pub endpoint_url: String,
    /// ISO 3166-1 alpha-2 country code (e.g. "JP", "US", "DE").
    /// Stripe Connect 対応国に限る。Provider の登録国 = Stripe Account 作成国。
    pub country: String,
    pub website: Option<String>,
    /// v1.1.0 x402: optional Base mainnet USDC payout address
    /// (locked-design §5.8). Required for capabilities that declare
    /// `payment_methods: [x402]`; rejected at /v1/manifests/{id}/promote
    /// if missing. Format: `0x` + 40 hex chars.
    #[serde(default)]
    pub usdc_payout_address: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub provider_id: String,
    pub namespace: String,
    /// only shown once
    pub provider_api_key: String,
    /// only shown once
    pub hmac_secret: String,
    pub dns_verification_token: String,
    pub next_steps: Value,
}

pub async fn register_provider(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<(StatusCode, Json<RegisterResponse>), (StatusCode, Json<Value>)> {
    // K2.1 (v1.0.2): 415 on non-JSON Content-Type with JECP envelope.
    crate::protocol::http_guards::ensure_json_ct_tuple(&headers)?;

    let req: RegisterRequest = serde_json::from_slice(&body).map_err(|e| error(
        StatusCode::BAD_REQUEST, "INVALID_REQUEST",
        &format!("body is not valid JSON: {}", e)))?;

    // ---- validate input ----
    if !is_valid_namespace(&req.namespace) {
        return Err(error(StatusCode::BAD_REQUEST,
            "INVALID_NAMESPACE",
            "namespace must match ^[a-z][a-z0-9-]{2,31}$"));
    }
    // v1.1.0 c7: SSRF preflight — reject IP literals + non-https schemes
    // immediately. Full DNS-resolve check fires at deref time (invoke
    // forward + DNS verify) per spec §9.7.1.
    if let Err(e) = crate::protocol::url_guard::validate_outbound_url_preflight(&req.endpoint_url) {
        let safe_url = crate::protocol::url_guard::redact_url(&req.endpoint_url);
        let reason = e.reason().to_string();
        if let Some(pool) = state.provider_pool() {
            crate::protocol::url_guard::audit_log_rejection(
                pool, None, None, "endpoint_url", "register",
                &safe_url, &reason, None,
            ).await;
        }
        return Err(crate::protocol::url_guard::url_blocked_ssrf_tuple(
            "endpoint_url", &safe_url, &reason,
        ));
    }
    if !is_valid_email(&req.owner_email) {
        return Err(error(StatusCode::BAD_REQUEST,
            "INVALID_EMAIL",
            "owner_email is not a valid email address"));
    }
    if req.display_name.trim().is_empty() || req.display_name.len() > 120 {
        return Err(error(StatusCode::BAD_REQUEST,
            "INVALID_DISPLAY_NAME",
            "display_name must be 1-120 chars"));
    }
    // v1.1.0 x402: validate optional usdc_payout_address format.
    if let Some(ref addr) = req.usdc_payout_address {
        if !is_valid_eth_address(addr) {
            return Err(error(StatusCode::BAD_REQUEST,
                "INVALID_USDC_PAYOUT_ADDRESS",
                "usdc_payout_address must match ^0x[a-fA-F0-9]{40}$"));
        }
    }

    let country_normalized = req.country.trim().to_uppercase();
    if !is_stripe_connect_country(&country_normalized) {
        return Err(error(StatusCode::BAD_REQUEST,
            "UNSUPPORTED_COUNTRY",
            &format!(
                "country '{}' is not supported by Stripe Connect. \
                 See https://stripe.com/global for the list of supported countries.",
                req.country
            )));
    }

    let pool = state.provider_pool().ok_or_else(|| error(
        StatusCode::SERVICE_UNAVAILABLE,
        "DB_UNAVAILABLE",
        "Database not connected",
    ))?;

    // ---- generate secrets ----
    let api_key_secret = random_hex(48);                       // 48 hex chars
    let api_key = format!("jdb_pk_{}", api_key_secret);
    let api_key_prefix = api_key.chars().take(12).collect::<String>();
    let api_key_hash = bcrypt::hash(&api_key, 10).map_err(|e| error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "HASH_FAILED",
        &format!("bcrypt: {}", e),
    ))?;

    let hmac_secret_bytes = random_bytes(32);
    let hmac_secret = base64::engine::general_purpose::STANDARD.encode(&hmac_secret_bytes);

    let dns_nonce = random_hex(16);
    let dns_token = compute_dns_token(&req.namespace, &dns_nonce);

    // ---- DB insert ----
    let created = database::register_provider(
        pool,
        &req.namespace,
        &req.display_name,
        &req.owner_email,
        req.website.as_deref(),
        &req.endpoint_url,
        &country_normalized,
        &api_key_hash,
        &api_key_prefix,
        &hmac_secret,
        &dns_token,
        &dns_nonce,
    ).await.map_err(|e| {
        // unique violation -> 409
        if let sqlx::Error::Database(db_err) = &e {
            if db_err.code().as_deref() == Some("23505") {
                return error(
                    StatusCode::CONFLICT,
                    "NAMESPACE_TAKEN",
                    &format!("namespace '{}' is already registered", req.namespace),
                );
            }
        }
        tracing::error!("provider register DB error: {}", e);
        error(StatusCode::INTERNAL_SERVER_ERROR, "DB_ERROR", "registration failed")
    })?;

    // v1.1.0 x402: persist the optional usdc_payout_address. Done as a
    // follow-up UPDATE rather than threading through register_provider()
    // — keeps the existing DB helper signature stable (Provider register
    // happens at 100s of RPM peak; the extra UPDATE only fires when the
    // field is present, ~0.1% of calls in v1.1).
    if let Some(ref addr) = req.usdc_payout_address {
        if let Err(e) = sqlx::query(
            "UPDATE jecp.providers SET usdc_payout_address = $1 WHERE id = $2",
        )
        .bind(addr)
        .bind(created.id)
        .persistent(false)
        .execute(pool)
        .await
        {
            tracing::warn!("usdc_payout_address persist failed (non-fatal): {}", e);
        }
    }

    let txt_record_value = format!("jecp-verify={}", &created.dns_verification_token);

    let next_steps = json!({
        "1_dns": {
            "type": "TXT",
            "name": format!("_jecp.{}", domain_from_url(&req.endpoint_url).unwrap_or_else(|| "your-domain.com".into())),
            "value": txt_record_value,
            "verify_endpoint": "POST https://jecp.dev/v1/providers/verify-dns"
        },
        "2_stripe": {
            "endpoint": "POST https://jecp.dev/v1/providers/connect-stripe",
            "via": "Stripe Connect Express OAuth"
        },
        "3_publish": {
            "endpoint": "POST https://jecp.dev/v1/manifests",
            "format": "application/x-yaml",
            "auth": "Bearer <provider_api_key>"
        }
    });

    Ok((StatusCode::CREATED, Json(RegisterResponse {
        provider_id: created.id.to_string(),
        namespace: created.namespace,
        provider_api_key: api_key,
        hmac_secret,
        dns_verification_token: created.dns_verification_token,
        next_steps,
    })))
}

// ---------------------------------------------------------------------------
// GET /v1/providers/me
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct ProviderMeResponse {
    pub provider_id: String,
    pub namespace: String,
    pub display_name: String,
    pub status: String,
    pub dns_verified: bool,
    pub stripe_verified: bool,
    pub endpoint_url: Option<String>,
    pub total_calls: i64,
}

pub async fn get_me(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ProviderMeResponse>, (StatusCode, Json<Value>)> {
    let provider = authenticate(&state, &headers).await?;

    Ok(Json(ProviderMeResponse {
        provider_id: provider.id.to_string(),
        namespace: provider.namespace,
        display_name: provider.display_name,
        status: provider.status,
        dns_verified: provider.dns_verified_at.is_some(),
        stripe_verified: provider.stripe_account_verified,
        endpoint_url: provider.endpoint_url,
        total_calls: provider.total_calls,
    }))
}

// ---------------------------------------------------------------------------
// POST /v1/providers/verify-dns
// ---------------------------------------------------------------------------
//
// S1 / TIER A.1 fix (2026-05-09 critical audit):
// Previously this handler trusted `req.domain` to choose where to look up the
// TXT record. An attacker holding a Provider api_key could register
// `endpoint_url=https://victim.com/...` and then call verify-dns with
// `{ domain: "attacker.com" }` — passing because the verification *token*
// is bound to the Provider, not to the URL. That meant the Hub would
// happily mark a Provider as DNS-verified for a domain they don't control,
// enabling brand impersonation and Stripe Connect onboarding fraud.
//
// The fix: the domain is extracted SERVER-SIDE from `provider.endpoint_url`.
// `req.domain` is now optional and treated as an integrity check — if
// supplied it MUST equal the extracted host or the request fails 400. The
// Provider can never trick the Hub into looking up the wrong TXT name.

#[derive(Debug, Deserialize)]
pub struct VerifyDnsRequest {
    /// Optional. If supplied, MUST equal the host extracted from
    /// `provider.endpoint_url` or the request is rejected. Useful as a
    /// client-side sanity check; never used as authoritative source.
    #[serde(default)]
    pub domain: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct VerifyDnsResponse {
    pub verified: bool,
    pub status: String,
    pub message: String,
}

pub async fn verify_dns(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<VerifyDnsResponse>, (StatusCode, Json<Value>)> {
    // K2.1 (v1.0.2): 415 on non-JSON Content-Type with JECP envelope.
    crate::protocol::http_guards::ensure_json_ct_tuple(&headers)?;

    let req: VerifyDnsRequest = serde_json::from_slice(&body).map_err(|e| error(
        StatusCode::BAD_REQUEST, "INVALID_REQUEST",
        &format!("body is not valid JSON: {}", e)))?;

    let provider = authenticate(&state, &headers).await?;
    let pool = state.provider_pool().ok_or_else(|| error(
        StatusCode::SERVICE_UNAVAILABLE, "DB_UNAVAILABLE", "Database not connected"))?;

    // Get expected token
    let (_namespace, expected_token) = database::get_dns_verification_data(pool, &provider.id)
        .await
        .map_err(|e| {
            tracing::error!("get_dns_verification_data: {}", e);
            error(StatusCode::INTERNAL_SERVER_ERROR, "DB_ERROR", "lookup failed")
        })?
        .ok_or_else(|| error(
            StatusCode::NOT_FOUND, "NOT_FOUND", "provider has no verification token"))?;

    // Authoritative source: extract host from the Provider's registered endpoint_url.
    // Falls back to error if endpoint_url is missing or malformed (should never
    // happen — register validates `https://` prefix — but defend in depth).
    let endpoint = provider.endpoint_url.as_deref().ok_or_else(|| error(
        StatusCode::CONFLICT,
        "ENDPOINT_NOT_SET",
        "Provider has no endpoint_url. Re-run register with a valid endpoint."))?;

    let authoritative_host = domain_from_endpoint(endpoint).ok_or_else(|| error(
        StatusCode::CONFLICT,
        "ENDPOINT_INVALID",
        &format!("Could not extract host from endpoint_url '{}'", endpoint),
    ))?;

    // Sanity check: if client supplied a domain, it must match.
    if let Some(client_domain) = req.domain.as_deref() {
        let normalized = client_domain.trim().trim_end_matches('.').to_lowercase();
        if normalized != authoritative_host {
            return Err(error(
                StatusCode::BAD_REQUEST,
                "DOMAIN_MISMATCH",
                &format!(
                    "Provided domain '{}' does not match the domain in endpoint_url ('{}'). \
                     This field is optional — omit it to use the registered domain.",
                    normalized, authoritative_host
                ),
            ));
        }
    }

    let lookup_name = format!("_jecp.{}", authoritative_host);
    let expected_value = format!("jecp-verify={}", expected_token);

    let found_records = lookup_txt_records(&lookup_name).await
        .map_err(|e| {
            tracing::warn!("DNS lookup failed for {}: {}", lookup_name, e);
            error(
                StatusCode::BAD_REQUEST,
                "DNS_LOOKUP_FAILED",
                &format!("Could not resolve TXT records for {}", lookup_name),
            )
        })?;

    if found_records.iter().any(|r| r == &expected_value) {
        database::mark_dns_verified(pool, &provider.id).await.map_err(|e| {
            tracing::error!("mark_dns_verified: {}", e);
            error(StatusCode::INTERNAL_SERVER_ERROR, "DB_ERROR", "update failed")
        })?;

        return Ok(Json(VerifyDnsResponse {
            verified: true,
            status: "verified".into(),
            message: format!("DNS TXT record verified for {}", authoritative_host),
        }));
    }

    Ok(Json(VerifyDnsResponse {
        verified: false,
        status: provider.status,
        message: format!(
            "Expected TXT record at {} containing '{}'. DNS may take up to 24 hours to propagate.",
            lookup_name, expected_value
        ),
    }))
}

/// Extract the host portion of an `https://host[:port]/path` URL.
///
/// Returns lowercase host (DNS is case-insensitive) without port. Returns
/// None if the URL does not start with `https://` or the host is empty.
/// This is small enough to keep inline; pulling in the `url` crate just for
/// this would add ~200 KB to the binary.
fn domain_from_endpoint(endpoint: &str) -> Option<String> {
    let after_scheme = endpoint.strip_prefix("https://")?;
    let host_with_port = after_scheme.split('/').next()?;
    let host = host_with_port.split(':').next()?;
    if host.is_empty() { return None; }
    Some(host.to_lowercase())
}

// ---------------------------------------------------------------------------
// POST /v1/providers/connect-stripe
// ---------------------------------------------------------------------------
//
// Provider が Stripe Connect Express で銀行口座を紐付けるための onboarding URL を取得する。
// 実際の Stripe API 呼出は Next.js bridge が担当(JECP Rust に Stripe SDK を持ち込まないポリシー)。
// Provider 体験は 1-step: POST して URL が返る → ブラウザで開いて完了。
//
// 流れ:
//   1. Bearer auth で Provider 特定
//   2. Provider の country_code / owner_email / namespace を bridge に渡す
//   3. Next.js が Stripe Account 作成 + Account Link 生成 + jecp.providers.stripe_account_id 更新
//   4. onboarding_url を Provider に返す

#[derive(Debug, Serialize, Deserialize)]
pub struct ConnectStripeResponse {
    pub onboarding_url: String,
    pub expires_at: i64,
}

#[derive(Debug, Serialize)]
struct BridgeStripeConnectRequest<'a> {
    provider_id: String,
    namespace: &'a str,
    owner_email: &'a str,
    country: &'a str,
}

#[derive(Debug, Deserialize)]
struct BridgeStripeConnectResponse {
    onboarding_url: String,
    expires_at: i64,
}

pub async fn connect_stripe(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ConnectStripeResponse>, (StatusCode, Json<Value>)> {
    let provider = authenticate(&state, &headers).await?;

    let pool = state.provider_pool().ok_or_else(|| error(
        StatusCode::SERVICE_UNAVAILABLE, "DB_UNAVAILABLE", "Database not connected"))?;

    // Need country_code + owner_email — re-fetch to get full row
    let detail = database::get_provider_full(pool, &provider.id).await
        .map_err(|e| {
            tracing::error!("get_provider_full: {}", e);
            error(StatusCode::INTERNAL_SERVER_ERROR, "DB_ERROR", "lookup failed")
        })?
        .ok_or_else(|| error(
            StatusCode::NOT_FOUND, "NOT_FOUND", "provider record incomplete"))?;

    let country = detail.country_code.as_deref().ok_or_else(|| error(
        StatusCode::FAILED_DEPENDENCY,
        "COUNTRY_NOT_SET",
        "Provider has no country_code. Re-register with country field.",
    ))?;
    let email = detail.owner_email.as_deref().ok_or_else(|| error(
        StatusCode::FAILED_DEPENDENCY,
        "EMAIL_NOT_SET",
        "Provider has no owner_email.",
    ))?;

    // Bridge call to Next.js (Stripe SDK lives there)
    if state.config.jecp_bridge_secret.is_empty() {
        return Err(error(
            StatusCode::SERVICE_UNAVAILABLE,
            "BRIDGE_NOT_CONFIGURED",
            "JECP_BRIDGE_SECRET not configured",
        ));
    }

    let bridge_url = format!(
        "{}/api/jecp/providers/stripe-connect-bridge",
        state.config.nextjs_base_url.trim_end_matches('/')
    );

    let req_body = BridgeStripeConnectRequest {
        provider_id: detail.id.to_string(),
        namespace: &detail.namespace,
        owner_email: email,
        country,
    };

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| error(StatusCode::INTERNAL_SERVER_ERROR, "HTTP_CLIENT", &e.to_string()))?;

    let resp = client.post(&bridge_url)
        .header("Authorization", format!("Bearer {}", state.config.jecp_bridge_secret))
        .header("content-type", "application/json")
        .json(&req_body)
        .send()
        .await
        .map_err(|e| {
            tracing::error!("bridge stripe-connect call failed: {}", e);
            error(StatusCode::BAD_GATEWAY, "BRIDGE_UNREACHABLE",
                  &format!("Failed to reach Stripe bridge: {}", e))
        })?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        tracing::error!("bridge stripe-connect HTTP {}: {}", status, body);
        return Err(error(
            StatusCode::BAD_GATEWAY,
            "BRIDGE_ERROR",
            &format!("Stripe bridge returned {}", status),
        ));
    }

    let parsed: BridgeStripeConnectResponse = resp.json().await
        .map_err(|e| error(StatusCode::BAD_GATEWAY, "BRIDGE_PARSE_ERROR", &e.to_string()))?;

    Ok(Json(ConnectStripeResponse {
        onboarding_url: parsed.onboarding_url,
        expires_at: parsed.expires_at,
    }))
}

// ---------------------------------------------------------------------------
// Auth helper
// ---------------------------------------------------------------------------

/// Public re-export so other route modules (e.g. manifests) can authenticate Providers.
pub async fn authenticate_provider(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<database::ProviderRow, (StatusCode, Json<Value>)> {
    authenticate(state, headers).await
}

async fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<database::ProviderRow, (StatusCode, Json<Value>)> {
    let token = headers.get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.trim())
        .ok_or_else(|| error(
            StatusCode::UNAUTHORIZED, "AUTH_REQUIRED",
            "Missing Authorization: Bearer <provider_api_key>"))?;

    if !token.starts_with("jdb_pk_") {
        return Err(error(StatusCode::UNAUTHORIZED,
            "INVALID_API_KEY",
            "API key must start with jdb_pk_"));
    }
    let prefix = token.chars().take(12).collect::<String>();

    let pool = state.provider_pool().ok_or_else(|| error(
        StatusCode::SERVICE_UNAVAILABLE,
        "DB_UNAVAILABLE",
        "Database not connected",
    ))?;

    let auth_match = database::get_provider_for_auth(pool, &prefix).await
        .map_err(|e| {
            tracing::error!("get_provider_for_auth: {}", e);
            error(StatusCode::INTERNAL_SERVER_ERROR, "DB_ERROR", "lookup failed")
        })?
        .ok_or_else(|| error(
            StatusCode::UNAUTHORIZED, "INVALID_API_KEY", "API key not recognized"))?;

    let valid = bcrypt::verify(token, &auth_match.hash).unwrap_or(false);
    if !valid {
        return Err(error(StatusCode::UNAUTHORIZED, "INVALID_API_KEY", "API key not recognized"));
    }

    if auth_match.is_grace_match {
        tracing::info!(
            "provider authenticated with previous (rotation) key: provider_id={} namespace={}",
            auth_match.provider.id, auth_match.provider.namespace
        );
    }

    Ok(auth_match.provider)
}

// ---------------------------------------------------------------------------
// DNS lookup — multi-resolver consensus (S1 / P0-7 mitigation)
// ---------------------------------------------------------------------------
//
// Single-resolver lookups are vulnerable to DNS cache poisoning + transient
// resolver compromise: an attacker that briefly poisons one resolver could
// pass DNS verify and squat a namespace. We query 3 independent DoH
// resolvers (Cloudflare / Google / Quad9) in parallel and require ≥ 2
// agreeing answers. A single-resolver lie is rejected.
//
// Each resolver has its own 5 s timeout. Total wall-clock cap ~6 s.

const DOH_RESOLVERS: &[(&str, &str)] = &[
    ("cloudflare", "https://1.1.1.1/dns-query"),
    ("google",     "https://dns.google/resolve"),
    ("quad9",      "https://dns.quad9.net:5053/dns-query"),
];

async fn lookup_txt_records(name: &str) -> Result<Vec<String>, String> {
    let mut futures = Vec::with_capacity(DOH_RESOLVERS.len());
    for (label, base) in DOH_RESOLVERS {
        futures.push(async move {
            let result = lookup_one_resolver(base, name).await;
            (*label, result)
        });
    }

    let results = futures::future::join_all(futures).await;

    // Collect successful results.
    let mut successful: Vec<(&str, std::collections::HashSet<String>)> = Vec::new();
    let mut errors: Vec<(&str, String)> = Vec::new();
    for (label, r) in results {
        match r {
            Ok(records) => successful.push((label, records.into_iter().collect())),
            Err(e) => errors.push((label, e)),
        }
    }

    if successful.len() < 2 {
        return Err(format!(
            "DNS multi-resolver consensus failed: only {}/{} resolvers responded successfully ({}). At least 2 must agree.",
            successful.len(), DOH_RESOLVERS.len(),
            errors.iter().map(|(k, e)| format!("{}: {}", k, e)).collect::<Vec<_>>().join("; "),
        ));
    }

    // Majority intersection: a record must appear in at least 2 resolvers'
    // answers to be accepted. This rejects single-resolver poisoning.
    let mut record_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for (_, records) in &successful {
        for r in records {
            *record_counts.entry(r.clone()).or_insert(0) += 1;
        }
    }

    let consensus: Vec<String> = record_counts
        .into_iter()
        .filter(|(_, count)| *count >= 2)
        .map(|(r, _)| r)
        .collect();

    if consensus.is_empty() {
        // Resolvers responded but no record had ≥ 2 agreement. This may be
        // a propagation race or active poisoning — either way reject.
        return Err(format!(
            "DNS resolvers disagree: {}/{} responded but no TXT record reached 2-resolver consensus. Check propagation and retry in 60 s.",
            successful.len(), DOH_RESOLVERS.len(),
        ));
    }

    tracing::info!(
        name = name,
        resolvers_ok = successful.len(),
        consensus_records = consensus.len(),
        "DNS multi-resolver consensus achieved"
    );

    Ok(consensus)
}

async fn lookup_one_resolver(base: &str, name: &str) -> Result<Vec<String>, String> {
    let url = format!("{}?name={}&type=TXT", base, name);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| e.to_string())?;

    let resp = client
        .get(&url)
        .header("accept", "application/dns-json")
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if !resp.status().is_success() {
        return Err(format!("DoH HTTP {}", resp.status()));
    }
    let body: Value = resp.json().await.map_err(|e| e.to_string())?;
    let answers = body.get("Answer").and_then(|a| a.as_array()).cloned().unwrap_or_default();

    let mut records = Vec::new();
    for ans in answers {
        if let Some(data) = ans.get("data").and_then(|d| d.as_str()) {
            // TXT records may include surrounding quotes.
            let trimmed = data.trim_matches('"').to_string();
            records.push(trimmed);
        }
    }
    Ok(records)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn is_valid_namespace(ns: &str) -> bool {
    let bytes = ns.as_bytes();
    if bytes.len() < 3 || bytes.len() > 32 { return false; }
    if !bytes[0].is_ascii_lowercase() { return false; }
    bytes.iter().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
}

/// Stripe Connect Express 対応国 (ISO 3166-1 alpha-2)。
/// 出典: https://stripe.com/global (2026-05-08 時点 47 カ国)。
/// 国の追加は Stripe の対応拡大に応じて手動更新する。
fn is_stripe_connect_country(code: &str) -> bool {
    matches!(
        code,
        "AE" | "AT" | "AU" | "BE" | "BG" | "BR" | "CA" | "CH" | "CY" | "CZ" |
        "DE" | "DK" | "EE" | "ES" | "FI" | "FR" | "GB" | "GI" | "GR" | "HK" |
        "HR" | "HU" | "IE" | "IN" | "IS" | "IT" | "JP" | "LI" | "LT" | "LU" |
        "LV" | "MT" | "MX" | "MY" | "NL" | "NO" | "NZ" | "PL" | "PT" | "RO" |
        "SE" | "SG" | "SI" | "SK" | "TH" | "US"
    )
}

/// Validate Ethereum address: `0x` + 40 hex chars.
fn is_valid_eth_address(s: &str) -> bool {
    if s.len() != 42 || !s.starts_with("0x") {
        return false;
    }
    s[2..].chars().all(|c| c.is_ascii_hexdigit())
}

fn is_valid_email(email: &str) -> bool {
    let parts: Vec<&str> = email.split('@').collect();
    parts.len() == 2 && !parts[0].is_empty() && parts[1].contains('.') && email.len() <= 254
}

fn random_hex(byte_len: usize) -> String {
    let mut buf = vec![0u8; byte_len];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    hex::encode(&buf)
}

fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf
}

fn compute_dns_token(namespace: &str, nonce: &str) -> String {
    // base64url(SHA256(namespace || ":" || nonce || ":" || "jecp-v1-static-seed"))[:32]
    // 注: "jecp-v1-static-seed" は将来的に env から読む(現状は MVP 固定)。
    let mut hasher = Sha256::new();
    hasher.update(namespace.as_bytes());
    hasher.update(b":");
    hasher.update(nonce.as_bytes());
    hasher.update(b":");
    hasher.update(b"jecp-v1-static-seed");
    let digest = hasher.finalize();
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&digest);
    b64.chars().take(32).collect()
}

fn domain_from_url(url: &str) -> Option<String> {
    // https://api.example.com/path → api.example.com
    let stripped = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://"))?;
    let host = stripped.split('/').next()?;
    Some(host.split(':').next()?.to_string())
}

fn error(status: StatusCode, code: &str, message: &str) -> (StatusCode, Json<Value>) {
    (status, Json(json!({
        "jecp": "1.0",
        "status": "failed",
        "error": { "code": code, "message": message }
    })))
}

#[cfg(test)]
mod tests {
    use super::domain_from_endpoint;

    #[test]
    fn extracts_simple_host() {
        assert_eq!(domain_from_endpoint("https://example.com/path"),
                   Some("example.com".to_string()));
    }

    #[test]
    fn strips_port() {
        assert_eq!(domain_from_endpoint("https://example.com:8443/x"),
                   Some("example.com".to_string()));
    }

    #[test]
    fn lowercases_host() {
        assert_eq!(domain_from_endpoint("https://Example.COM/"),
                   Some("example.com".to_string()));
    }

    #[test]
    fn handles_no_path() {
        assert_eq!(domain_from_endpoint("https://example.com"),
                   Some("example.com".to_string()));
    }

    #[test]
    fn rejects_http() {
        assert_eq!(domain_from_endpoint("http://example.com/"), None);
    }

    #[test]
    fn rejects_empty_host() {
        assert_eq!(domain_from_endpoint("https:///path"), None);
    }

    #[test]
    fn rejects_no_scheme() {
        assert_eq!(domain_from_endpoint("example.com"), None);
    }

    #[test]
    fn handles_subdomain() {
        assert_eq!(domain_from_endpoint("https://a.b.example.com/"),
                   Some("a.b.example.com".to_string()));
    }
}
