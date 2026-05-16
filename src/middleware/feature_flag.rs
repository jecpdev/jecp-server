//! S0 Sprint — Feature flag middleware (kill switch).
//!
//! Reads `jecp.feature_flags` with a 30 s TTL cache. If a flag is
//! disabled, the corresponding endpoint returns HTTP 503 with code
//! `FEATURE_DISABLED` and a `next_action.type=wait` hint.
//!
//! **Fail-open**: if the table does not exist or the query fails, the
//! middleware treats the feature as enabled. This makes the migration
//! deploy order safe — code can ship before the migration is applied.
//!
//! Per-feature gating is wired in route definitions like:
//!
//! ```ignore
//! .route("/v1/refunds", post(handler).layer(require_feature("refunds")))
//! ```

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use sqlx::PgPool;
use tokio::sync::RwLock;

use crate::AppState;

const CACHE_TTL: Duration = Duration::from_secs(30);

/// Lazy-initialised cache of feature flag values keyed by name.
#[derive(Debug, Default)]
pub struct FeatureFlagCache {
    inner: RwLock<CacheState>,
}

#[derive(Debug, Default)]
struct CacheState {
    map: std::collections::HashMap<String, bool>,
    fetched_at: Option<Instant>,
}

impl FeatureFlagCache {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Returns true if the feature is enabled OR if we cannot decide
    /// (fail-open). Falls back to enabled when the DB is unavailable.
    pub async fn is_enabled(&self, pool: &Option<PgPool>, flag: &str) -> bool {
        let now = Instant::now();
        {
            let guard = self.inner.read().await;
            if let Some(fetched) = guard.fetched_at {
                if now.duration_since(fetched) < CACHE_TTL {
                    // Cache hit: missing key means "no row in DB" → fail-open.
                    return guard.map.get(flag).copied().unwrap_or(true);
                }
            }
        }

        // Cache stale or empty — refresh from DB. Single-flight is good-enough
        // here: a few concurrent refreshes are cheap and harmless.
        if let Some(p) = pool {
            match sqlx::query("SELECT flag_name, enabled FROM jecp.feature_flags")
                .persistent(false)
                .fetch_all(p)
                .await
            {
                Ok(rows) => {
                    let mut new_map = std::collections::HashMap::new();
                    for row in rows {
                        use sqlx::Row;
                        if let (Ok(name), Ok(enabled)) =
                            (row.try_get::<String, _>("flag_name"), row.try_get::<bool, _>("enabled"))
                        {
                            new_map.insert(name, enabled);
                        }
                    }
                    let result = new_map.get(flag).copied().unwrap_or(true);
                    let mut guard = self.inner.write().await;
                    guard.map = new_map;
                    guard.fetched_at = Some(now);
                    return result;
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "feature_flag cache refresh failed (fail-open: treating all flags as enabled)"
                    );
                    return true;
                }
            }
        }
        true
    }
}

/// Returns a response that gates a request behind a feature flag.
/// Use as `axum::middleware::from_fn_with_state` or check inside handlers.
pub async fn check_feature(
    State(state): State<AppState>,
    flag: &'static str,
) -> Result<(), Response> {
    if state.flags.is_enabled(&state.pool, flag).await {
        Ok(())
    } else {
        Err(disabled_response(flag))
    }
}

fn disabled_response(flag: &str) -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({
            "jecp": "1.0",
            "status": "failed",
            "error": {
                "code": "FEATURE_DISABLED",
                "message": format!("Feature '{}' is currently disabled by operator. Try again later.", flag),
            },
            "next_action": {
                "type": "wait",
                "hint": "An operator has temporarily disabled this feature. Check status.jecp.dev for the timeline.",
            },
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fail_open_when_no_pool() {
        let cache = FeatureFlagCache::new();
        let pool: Option<PgPool> = None;
        assert!(cache.is_enabled(&pool, "anything").await);
    }

    #[tokio::test]
    async fn unknown_flag_is_enabled_by_default() {
        let cache = FeatureFlagCache::new();
        // Manually seed the cache with a known map, but query an unknown flag.
        {
            let mut guard = cache.inner.write().await;
            guard.map.insert("known".to_string(), false);
            guard.fetched_at = Some(Instant::now());
        }
        let pool: Option<PgPool> = None;
        assert!(cache.is_enabled(&pool, "unknown_flag").await);
        assert!(!cache.is_enabled(&pool, "known").await);
    }
}
