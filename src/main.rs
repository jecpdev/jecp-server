mod auth;
mod capabilities;
mod config;
mod middleware;
mod protocol;
mod routes;
mod services;

use std::sync::Arc;

use axum::http::{header, HeaderName, HeaderValue};
use axum::{routing::get, routing::post, Router};
use sqlx::PgPool;
use std::time::Instant;
use tower_http::set_header::SetResponseHeaderLayer;

use crate::config::{Config, X402Config};
use crate::middleware::cors::build_cors;
use crate::middleware::feature_flag::FeatureFlagCache;
use crate::middleware::rate_limit::RateLimiter;
use crate::services::claude::ClaudeClient;
use crate::services::database::PartitionedPools;
use crate::services::sns_bridge::SnsBridge;
use crate::services::storage::TempStorage;
use crate::services::supervisor::{spawn_supervised, SupervisedTaskStats};

/// Shared application state
#[derive(Clone)]
pub struct AppState {
    /// Legacy single pool — kept for backward compatibility while existing
    /// handlers are progressively migrated to the partitioned pools below.
    /// Points at `pools.invoke` when partitioning is enabled.
    pub pool: Option<PgPool>,
    /// S0: 4-way partitioned pools for in-process bulkhead.
    pub pools: Option<PartitionedPools>,
    /// S0: feature flag cache (30 s TTL, fail-open).
    pub flags: Arc<FeatureFlagCache>,
    pub claude: ClaudeClient,
    pub storage: TempStorage,
    pub rate_limiter: RateLimiter,
    pub sns_bridge: Option<SnsBridge>,
    pub config: Config,
    pub started_at: Instant,
    /// S0: supervised background task counters, exposed via /health.
    pub task_stats: Arc<TaskStatsRegistry>,
    /// v1.0.1: Provenance v2 nonce replay-defense cache (spec §5.2 step 5).
    /// `Arc<dyn NonceStore>` so v1.1 can swap a `RedisReplayCache` without
    /// touching call sites.
    pub replay_cache: Arc<dyn crate::auth::replay_cache::NonceStore>,
    /// v1.0.2 K2.5: per-action `input_schema` validator cache. LRU keyed
    /// by `(capability_id, action_id)`. `Arc<dyn SchemaStore>` so v1.0.3
    /// can swap to Redis-cached precompiled schemas without touching
    /// invocation hot path.
    pub schema_cache: Arc<dyn crate::protocol::schema_validator::SchemaStore>,
    /// v1.1.0 x402 (locked-design §5.2): `None` when X402_FACILITATOR_URL
    /// unset — Hub runs in wallet-only mode. Branch on `state.x402.is_some()`
    /// at the X-Payment dispatch gate.
    pub x402: Option<X402Config>,
}

impl AppState {
    /// TIER A.7 — pool accessors for bulkhead. Each handler picks the pool
    /// matching its workload so a hot-path /v1/invoke surge cannot starve
    /// catalog GETs or webhook delivery.
    pub fn invoke_pool(&self) -> Option<&PgPool> {
        self.pools.as_ref().map(|p| &p.invoke)
    }
    pub fn provider_pool(&self) -> Option<&PgPool> {
        self.pools.as_ref().map(|p| &p.provider)
    }
    pub fn read_pool(&self) -> Option<&PgPool> {
        self.pools.as_ref().map(|p| &p.read)
    }
    pub fn background_pool(&self) -> Option<&PgPool> {
        self.pools.as_ref().map(|p| &p.background)
    }
}

/// Registry of per-task SupervisedTaskStats. Keyed by task name.
#[derive(Debug, Default)]
pub struct TaskStatsRegistry {
    inner: parking_lot::RwLock<std::collections::HashMap<&'static str, Arc<SupervisedTaskStats>>>,
}

impl TaskStatsRegistry {
    pub fn register(&self, name: &'static str, stats: Arc<SupervisedTaskStats>) {
        self.inner.write().insert(name, stats);
    }

    pub fn snapshot(&self) -> serde_json::Value {
        let map = self.inner.read();
        let entries: serde_json::Map<String, serde_json::Value> = map
            .iter()
            .map(|(k, v)| {
                let (count, last_ms) = v.snapshot();
                (
                    (*k).to_string(),
                    serde_json::json!({
                        "restart_count":         count,
                        "last_restart_unix_ms":  last_ms,
                    }),
                )
            })
            .collect();
        serde_json::Value::Object(entries)
    }
}

#[tokio::main]
async fn main() {
    // Load .env in development
    let _ = dotenvy::dotenv();

    // Load config
    let config = Config::from_env().expect("Failed to load configuration. Check DATABASE_URL and ANTHROPIC_API_KEY.");

    // Init tracing
    middleware::tracing_layer::init_tracing(config.is_production());

    tracing::info!("Starting JECP Server v{}", env!("CARGO_PKG_VERSION"));

    // S0: Connect partitioned pools (graceful — don't crash if DB unavailable).
    let pools = if config.database_url.is_empty() {
        tracing::warn!("DATABASE_URL not set. Server will start in degraded mode (no DB).");
        None
    } else {
        match PartitionedPools::create(&config).await {
            Ok(p) => {
                tracing::info!("S0 partitioned pools connected");
                Some(p)
            }
            Err(e) => {
                tracing::warn!("Database connection failed: {}. Server will start in degraded mode.", e);
                None
            }
        }
    };

    // Backward-compat: legacy `pool` field aliases the invoke pool. Existing
    // handlers continue working unchanged; new code reads `state.pools.X`.
    let pool = pools.as_ref().map(|p| p.invoke.clone());

    // Initialize SNS Bridge (only if secret is configured)
    let sns_bridge = if config.jecp_bridge_secret.is_empty() {
        tracing::warn!("JECP_BRIDGE_SECRET not set. SNS Engine will not be able to post.");
        None
    } else {
        tracing::info!("SNS Bridge configured → {}", config.nextjs_base_url);
        Some(SnsBridge::new(&config))
    };

    let task_stats = Arc::new(TaskStatsRegistry::default());

    // v1.0.1: Provenance v2 replay cache. Hub identifier = "jecp-hub" until a
    // multi-Hub deployment requires unique identity; the cache key prefix is
    // already in place to support that without a code change.
    let replay_cache: Arc<dyn crate::auth::replay_cache::NonceStore> =
        crate::auth::replay_cache::MemoryReplayCache::from_env("jecp-hub");

    // v1.0.2 K2.5: per-action input_schema validator cache.
    let schema_cache: Arc<dyn crate::protocol::schema_validator::SchemaStore> =
        crate::protocol::schema_validator::MemorySchemaCache::from_env();

    // v1.1.0 x402 (locked-design §5.2): graceful — if env is incomplete
    // we run in wallet-only mode. Hard-fail only on partial config
    // (X402_FACILITATOR_URL set but a required peer var missing).
    let x402 = match X402Config::from_env() {
        Ok(x) => {
            if x.is_some() {
                tracing::info!("x402 enabled at boot");
            } else {
                tracing::info!("x402 disabled at boot (X402_FACILITATOR_URL unset)");
            }
            x
        }
        Err(e) => {
            tracing::error!("x402 config error: {} — disabling x402", e);
            None
        }
    };

    // v1.1.1 H-3 (locked-design Am-5): if x402 is up AND a KMS key id is
    // configured, swap the StubRelayerSigner for the production
    // AwsKmsRelayerSigner. Failing to construct the KMS signer disables
    // on-chain register at runtime but does NOT crash the Hub — promote
    // continues falling back to "best-effort, log a warn" exactly as today.
    let x402 = if let Some(mut cfg) = x402 {
        if let Some(key_id) = cfg.relayer_kms_key_id.clone() {
            match build_aws_kms_relayer(
                &key_id,
                &cfg.base_rpc_url,
                cfg.relayer_chain_id,
                cfg.relayer_address,
            )
            .await
            {
                Ok(signer) => {
                    tracing::info!(
                        kms_key_id = %key_id,
                        chain_id = cfg.relayer_chain_id,
                        relayer_address = %cfg.relayer_address,
                        "x402 RELAYER signer = AWS KMS (production, Am-5)"
                    );
                    cfg.relayer = signer;
                }
                Err(e) => {
                    tracing::error!(
                        kms_key_id = %key_id,
                        error = %e,
                        "x402 RELAYER signer = AWS KMS init failed — falling back to Stub. \
                         On-chain register will return NotImplemented; promote continues."
                    );
                }
            }
        } else {
            tracing::info!(
                "x402 RELAYER signer = Stub (JECP_RELAYER_KMS_KEY_ID unset). \
                 On-chain Splitter.register() calls will return NotImplemented."
            );
        }
        Some(cfg)
    } else {
        None
    };

    // Build application state
    let state = AppState {
        pool: pool.clone(),
        pools: pools.clone(),
        flags: FeatureFlagCache::new(),
        claude: ClaudeClient::new(&config),
        storage: TempStorage::new(),
        rate_limiter: RateLimiter::new(10),
        sns_bridge,
        config: config.clone(),
        started_at: Instant::now(),
        task_stats: task_stats.clone(),
        replay_cache,
        schema_cache,
        x402: x402.clone(),
    };

    // S0: spawn supervised background tasks. Each one is panic-protected and
    // restarted with exponential backoff (1 s → 30 s cap). Restart counters
    // are exposed via /health.task_stats.
    if let Some(p) = pools.as_ref().map(|p| p.background.clone()) {
        let pool_for_webhooks = p.clone();
        let (_, stats) = spawn_supervised("webhooks_delivery", move || {
            let p = pool_for_webhooks.clone();
            async move {
                services::webhooks::delivery_loop(p).await;
            }
        });
        task_stats.register("webhooks_delivery", stats);

        let pool_for_refunds = p;
        let (_, stats) = spawn_supervised("refunds_auto_approve", move || {
            let p = pool_for_refunds.clone();
            async move {
                routes::refunds::auto_approve_loop(p).await;
            }
        });
        task_stats.register("refunds_auto_approve", stats);
    }

    // v1.1.0 x402 reconciler (locked-design §5.7). Only spawn when
    // x402 is configured; the loop itself checks the kill-switch flag
    // before doing real work each tick.
    if state.x402.is_some() {
        let state_arc = Arc::new(state.clone());
        let stats = services::x402_reconciler::spawn_reconciler(state_arc);
        task_stats.register("x402_reconciler", stats);
    }

    // Build router
    let app = Router::new()
        // JECP endpoints
        .route("/v1/jecp", post(routes::jecp::execute_jecp))
        .route("/v1/capabilities", get(routes::capabilities::list_capabilities))
        // Provider lifecycle (Sprint 6-7 / Stage 3)
        .route("/v1/providers/register",       post(routes::providers::register_provider))
        .route("/v1/providers/me",             get(routes::providers::get_me))
        .route("/v1/providers/verify-dns",     post(routes::providers::verify_dns))
        .route("/v1/providers/connect-stripe", post(routes::providers::connect_stripe))
        // Manifest lifecycle (Sprint 8-10 / Stage 3)
        .route("/v1/manifests",                          post(routes::manifests::publish_manifest))
        .route("/v1/manifests/{capability_id}/promote",  post(routes::manifests::promote_capability))
        .route("/v1/manifests/{capability_id}",          axum::routing::delete(routes::manifests::sunset_capability))
        // Third-party invocation routing (Sprint 11 / Stage 3)
        .route("/v1/invoke",                             post(routes::invoke::invoke_capability))
        // M2 — API key rotation (Phase B / 7-day grace period)
        .route("/v1/agents/me/rotate-key",               post(routes::keys::rotate_agent_key))
        .route("/v1/providers/me/rotate-key",            post(routes::keys::rotate_provider_key))
        // Refunds (W2)
        .route("/v1/refunds",                            post(routes::refunds::request_refund))
        .route("/v1/refunds",                            get(routes::refunds::list_refunds))
        .route("/v1/refunds/{refund_id}",                get(routes::refunds::get_refund))
        .route("/v1/refunds/{refund_id}/approve",        post(routes::refunds::approve_refund))
        .route("/v1/refunds/{refund_id}/deny",           post(routes::refunds::deny_refund))
        // Webhook subscriptions (W4)
        .route("/v1/subscriptions",                      post(routes::subscriptions::create_subscription))
        .route("/v1/subscriptions",                      get(routes::subscriptions::list_subscriptions))
        .route("/v1/subscriptions/{sub_id}",             axum::routing::patch(routes::subscriptions::update_subscription))
        .route("/v1/subscriptions/{sub_id}",             axum::routing::delete(routes::subscriptions::delete_subscription))
        .route("/v1/subscriptions/{sub_id}/test",        post(routes::subscriptions::test_subscription))
        // Discovery
        .route("/.well-known/agent.json", get(routes::agent_card::agent_card))
        // v1.0.2 K4.1 — JECP Hub Discovery Document (spec 05-discovery §4)
        .route("/.well-known/agent-guide.json", get(routes::agent_guide::agent_guide))
        // Health
        .route("/health", get(routes::health::health_check))
        // OpenAPI 3.1 spec + interactive docs (W7)
        .route("/openapi.yaml", get(routes::openapi::openapi_yaml))
        .route("/openapi.json", get(routes::openapi::openapi_json))
        .route("/docs",         get(routes::openapi::docs))
        .route("/redoc",        get(routes::openapi::redoc))
        // Middleware
        .layer(build_cors(&config))
        // v1.0.1 c3: Provenance v1 deprecation headers (RFC 8594).
        // Reads ProvenanceVersion::V1 marker on response extensions and
        // attaches Deprecation: true / Sunset: <date> / Link rel=deprecation
        // when JECP_DEPRECATION_HEADERS=on (default off until 2026-08-01).
        .layer(middleware::deprecation::DeprecationLayer::new())
        // S0 — panic boundary: panics in handlers become JECP-formatted 500s,
        // not connection resets. Other in-flight requests are unaffected.
        .layer(middleware::panic_boundary::build_layer())
        // Sprint 4.5 / C5: Security headers (OWASP A05)
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("strict-transport-security"),
            HeaderValue::from_static("max-age=63072000; includeSubDomains; preload"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::REFERRER_POLICY,
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("permissions-policy"),
            HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
        ))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state);

    let addr = format!("{}:{}", config.host, config.port);
    tracing::info!("Listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("Failed to bind address");

    axum::serve(listener, app)
        .await
        .expect("Server error");
}

// ────────────────────────────────────────────────────────────────────────────
// v1.1.1 H-3 — AWS KMS RELAYER bring-up helper (locked-design Am-5).
// Loads default AWS credentials, constructs the KMS client, and runs
// `AwsKmsRelayerSigner::new` (which performs a KMS GetPublicKey + address
// derivation + cross-check against `JECP_RELAYER_ADDRESS`).
// ────────────────────────────────────────────────────────────────────────────

async fn build_aws_kms_relayer(
    key_id: &str,
    base_rpc_url: &str,
    chain_id: u64,
    expected_address: alloy_primitives::Address,
) -> Result<Arc<dyn services::x402_relayer::RelayerSigner>, String> {
    let rpc_url = url::Url::parse(base_rpc_url).map_err(|e| format!("rpc url parse: {}", e))?;
    let aws_cfg = aws_config::defaults(aws_config::BehaviorVersion::latest()).load().await;
    let kms = aws_sdk_kms::Client::new(&aws_cfg);
    let signer = services::x402_relayer_aws_kms::AwsKmsRelayerSigner::new(
        kms,
        key_id.to_string(),
        rpc_url,
        chain_id,
        Some(expected_address),
    )
    .await
    .map_err(|e| e.to_string())?;
    Ok(Arc::new(signer) as Arc<dyn services::x402_relayer::RelayerSigner>)
}
