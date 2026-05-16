use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Simple in-memory rate limiter (per agent_id, sliding window)
#[derive(Clone)]
pub struct RateLimiter {
    windows: Arc<RwLock<HashMap<String, Vec<std::time::Instant>>>>,
    default_rpm: u32,
}

impl RateLimiter {
    pub fn new(default_rpm: u32) -> Self {
        let limiter = Self {
            windows: Arc::new(RwLock::new(HashMap::new())),
            default_rpm,
        };

        // Cleanup old entries every 5 minutes
        let windows = limiter.windows.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
            loop {
                interval.tick().await;
                let mut store = windows.write().await;
                let now = std::time::Instant::now();
                for entries in store.values_mut() {
                    entries.retain(|t| now.duration_since(*t).as_secs() < 60);
                }
                store.retain(|_, v| !v.is_empty());
            }
        });

        limiter
    }

    /// Check if the agent is within rate limits. Returns Ok(remaining) or
    /// Err(RateLimitDecision { retry_after_secs }).
    ///
    /// v1.0.2 K2.4: when over-limit, computes how many seconds the caller
    /// must wait before the oldest entry ages out of the 60s sliding window
    /// — that's the value Hubs MUST emit in the `Retry-After` response
    /// header per RFC 9110 §10.2.3 (integer-seconds form, bounded to
    /// `[1, 600]` per spec 03-errors §3.5).
    pub async fn check(&self, agent_id: &str, limit_rpm: Option<u32>) -> Result<u32, RateLimitDecision> {
        let limit = limit_rpm.unwrap_or(self.default_rpm);
        let now = std::time::Instant::now();
        let mut windows = self.windows.write().await;
        let entries = windows.entry(agent_id.to_string()).or_insert_with(Vec::new);

        // Remove entries older than 1 minute
        entries.retain(|t| now.duration_since(*t).as_secs() < 60);

        if entries.len() >= limit as usize {
            // Compute time-until-slot-frees from the OLDEST entry. Once it
            // ages out of the 60s window, the caller can retry. Bound to
            // [1, 600] per spec; the upper bound is mostly defensive — for
            // a 60s sliding window the natural ceiling is 60s.
            let oldest = entries.iter().min().copied().unwrap_or(now);
            let elapsed = now.duration_since(oldest).as_secs();
            let raw = 60u64.saturating_sub(elapsed);
            let bounded = raw.max(1).min(600) as u32;
            Err(RateLimitDecision { retry_after_secs: bounded })
        } else {
            entries.push(now);
            Ok(limit - entries.len() as u32)
        }
    }
}

/// v1.0.2 K2.4 — rate-limit denial with the seconds the caller should wait
/// before retrying. Carried into `JecpErrorCode::RateLimited { retry_after_secs }`
/// and from there into the `Retry-After` response header by `IntoResponse`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitDecision {
    pub retry_after_secs: u32,
}

/// Axum middleware that extracts agent_id from X-Agent-ID header and rate-limits
pub async fn rate_limit_middleware(
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Rate limiting is handled at the route level since we need agent context
    // This middleware just passes through
    Ok(next.run(request).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn under_limit_returns_remaining() {
        let r = RateLimiter::new(10);
        // First request: 9 remaining (10 - 1 just consumed)
        let remaining = r.check("agent-a", None).await.unwrap();
        assert_eq!(remaining, 9);
    }

    #[tokio::test]
    async fn over_limit_returns_decision_with_bounded_retry_after() {
        let r = RateLimiter::new(2);
        // Fill the bucket
        r.check("agent-b", None).await.unwrap();
        r.check("agent-b", None).await.unwrap();
        // Third request → over limit
        let decision = r.check("agent-b", None).await.unwrap_err();
        assert!(decision.retry_after_secs >= 1, "must be at least 1 (spec lower bound)");
        assert!(decision.retry_after_secs <= 600, "must be at most 600 (spec upper bound)");
        // For a 60s sliding window with entries just inserted, the natural
        // value is ~60s. Allow generous slack for test timing.
        assert!(
            decision.retry_after_secs <= 60,
            "for 60s window, natural max is 60s; got {}",
            decision.retry_after_secs
        );
    }

    #[tokio::test]
    async fn separate_agents_have_independent_buckets() {
        let r = RateLimiter::new(1);
        r.check("alice", None).await.unwrap();
        // alice over limit:
        assert!(r.check("alice", None).await.is_err());
        // bob unaffected:
        assert!(r.check("bob", None).await.is_ok());
    }
}
