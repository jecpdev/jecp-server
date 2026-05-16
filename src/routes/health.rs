use axum::extract::State;
use axum::Json;
use serde_json::{json, Value};
use std::time::Instant;

use crate::AppState;

/// GET /health — System health check.
///
/// S0: surfaces the per-feature pool utilisation (size / idle) for each
/// of the 4 partitioned pools and the supervised-task restart counters.
/// Operators can see at a glance which pool is saturated or which
/// background task is panicking.
pub async fn health_check(State(state): State<AppState>) -> Json<Value> {
    let start = Instant::now();

    // LEGACY: /health uses `state.pool` as a generic connectivity probe, not
    // a workload pool. K3 keeps this on the legacy alias by design — health
    // must remain reachable even when ALL workload pools are saturated, and
    // the alias still resolves to invoke (the only pool guaranteed at boot).
    // Per locked routing table (phase0-locked-design.md §4 + L9).
    let db_ok = match &state.pool {
        Some(pool) => crate::services::database::health_check(pool).await.is_ok(),
        None => false,
    };
    let duration = start.elapsed().as_millis();

    let uptime = state.started_at.elapsed().as_secs();

    let pools_stats = state.pools.as_ref().map(|p| p.stats());
    let tasks_stats = state.task_stats.snapshot();

    // K3: static map of route → pool name. Operators read this to verify
    // the routing table matches the locked design without reading the source.
    // Spec: docs/jecp/phase0-locked-design.md §4 K3 routing table.
    let pool_assignments = json!({
        "POST /v1/invoke":                       "invoke",
        "POST /v1/jecp":                         "invoke",
        "POST /v1/refunds":                      "invoke",
        "POST /v1/agents/me/rotate-key":         "invoke",
        "GET  /v1/capabilities":                 "read",
        "GET  /v1/refunds":                      "read",
        "GET  /v1/refunds/{id}":                 "read",
        "GET  /v1/subscriptions":                "read",
        "POST /v1/manifests":                    "provider",
        "POST /v1/manifests/{id}/promote":       "provider",
        "DELETE /v1/manifests/{id}":             "provider",
        "POST /v1/providers/register":           "provider",
        "GET  /v1/providers/me":                 "provider",
        "POST /v1/providers/verify-dns":         "provider",
        "POST /v1/providers/connect-stripe":     "provider",
        "POST /v1/providers/me/rotate-key":      "provider",
        "POST /v1/refunds/{id}/approve":         "provider",
        "POST /v1/refunds/{id}/deny":            "provider",
        "POST /v1/subscriptions":                "provider",
        "PATCH  /v1/subscriptions/{id}":         "provider",
        "DELETE /v1/subscriptions/{id}":         "provider",
        "POST /v1/subscriptions/{id}/test":      "provider",
        "BACKGROUND webhooks_delivery":          "background",
        "BACKGROUND refunds_auto_approve":       "background",
        "GET /health":                           "legacy_alias",
        "GET /openapi.{json,yaml}":              "none_static",
        "GET /docs, /redoc":                     "none_static",
        "GET /.well-known/*":                    "none_static",
    });

    // v1.0.1: replay cache observability per devops design (§3.9, §6).
    let cache = state.replay_cache.stats();
    let replay_cache_stats = json!({
        "size":             cache.size,
        "capacity":         cache.capacity,
        "evictions_total":  cache.evictions_total,
        "hits_total":       cache.hits_total,
        "misses_total":     cache.misses_total,
    });

    Json(json!({
        "status": if db_ok { "ok" } else { "degraded" },
        "engine": "jecp-v1",
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_seconds": uptime,
        "checks": {
            "database": if db_ok { "ok" } else { "error" },
            "response_ms": duration
        },
        "pools": pools_stats,
        "pool_assignments": pool_assignments,
        "tasks": tasks_stats,
        "replay_cache": replay_cache_stats,
    }))
}
