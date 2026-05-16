//! Provenance v2 nonce replay-defense cache.
//!
//! Implements spec v1.0 §5.2 step 5: maintain an LRU cache of `(agent_id,
//! nonce)` pairs for ≥600s; reject the second observation as
//! `PROVENANCE_MISMATCH` with subcause `nonce_replay`.
//!
//! ## Design choices (per docs/jecp/v1.0.1-design.md §3.1)
//!
//! - **Library**: `lru` crate over `moka`. Smaller dep tree, lock-and-go
//!   semantics, audit-friendly for the panel-flagged DoS surface.
//! - **Concurrency**: `parking_lot::Mutex<LruCache>` — invoke-path traffic
//!   is well below contention thresholds (≤500 RPM Platinum × ~33 ops/s).
//! - **Cache key**: `(hub_id, agent_id, nonce_lowercase)` triple. The
//!   `hub_id` prefix prepares for v1.1 cluster Redis migration and prevents
//!   cross-Hub collisions when multiple Hubs share storage.
//! - **TTL eviction**: lazy on lookup. Each entry stores its insertion
//!   `Instant`; on `check_and_insert` we drop entries where `elapsed() >
//!   ttl`. Avoids janitor task overhead and time-based attacks where the
//!   attacker pins entries via repeated lookups (LRU access-bumping is the
//!   wrong policy here).
//! - **Per-agent flood defense** (threat-modeler H5): handled outside the
//!   cache by the per-agent rate limiter (60 RPM by default). At 60 RPM ×
//!   600s TTL, a single agent caps at ~600 entries — well below the global
//!   100k cap and unable to evict other agents' state. Spec §5.2.1
//!   (informative) recommends Hubs enforce per-agent rate limits.
//! - **Atomic insert**: `check_and_insert` is one operation; eliminates
//!   the TOCTOU window an `if !contains() { insert() }` would have.

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

use lru::LruCache;
use parking_lot::Mutex;

/// Default TTL = 600s (spec v1.0 §5.2 step 5).
pub const DEFAULT_TTL_SECONDS: u64 = 600;

/// Default global cache capacity (entries). Configurable via
/// `JECP_REPLAY_CACHE_CAP` env var. 100k entries × ~70B = ~7MB worst case.
pub const DEFAULT_CAPACITY: usize = 100_000;

/// Result of `check_and_insert`. `First` means this `(agent_id, nonce)`
/// was not in the cache and has now been recorded — the caller should
/// proceed. `Replay` means the pair was already present within the TTL
/// window and the caller MUST reject with `PROVENANCE_MISMATCH(nonce_replay)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Replay {
    First,
    Replay,
}

/// Cache key — `(hub_id, agent_id, nonce_lowercase)`. The `hub_id` prefix
/// prepares for v1.1 cluster shared storage.
type Key = (String, String, String);

#[derive(Clone)]
struct Entry {
    inserted: Instant,
}

/// Trait abstraction so v1.1 can swap a `RedisNonceStore` in without
/// touching call sites. v1.0.1 ships only the in-memory `MemoryReplayCache`.
pub trait NonceStore: Send + Sync {
    /// Atomically check-and-insert. Returns `First` on first sighting,
    /// `Replay` on duplicate. Caller maps `Replay` → `PROVENANCE_MISMATCH`.
    fn check_and_insert(&self, agent_id: &str, nonce: &str) -> Replay;

    /// Snapshot for `/health`: (current_size, total_evictions_since_start).
    fn stats(&self) -> CacheStats;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CacheStats {
    pub size: usize,
    pub capacity: usize,
    pub evictions_total: u64,
    pub hits_total: u64,
    pub misses_total: u64,
}

/// In-memory single-instance replay cache (v1.0.1 default).
///
/// For multi-region Hub deployments swap to a `RedisReplayCache` in v1.1
/// (spec §5.9 plan). The `NonceStore` trait keeps the call sites stable.
pub struct MemoryReplayCache {
    hub_id: String,
    ttl: Duration,
    inner: Mutex<Inner>,
}

struct Inner {
    entries: LruCache<Key, Entry>,
    evictions: u64,
    hits: u64,
    misses: u64,
}

impl MemoryReplayCache {
    pub fn new(hub_id: impl Into<String>, capacity: usize, ttl: Duration) -> Arc<Self> {
        let cap = NonZeroUsize::new(capacity.max(1)).unwrap();
        Arc::new(Self {
            hub_id: hub_id.into(),
            ttl,
            inner: Mutex::new(Inner {
                entries: LruCache::new(cap),
                evictions: 0,
                hits: 0,
                misses: 0,
            }),
        })
    }

    /// Convenience constructor with defaults (capacity from env or
    /// `DEFAULT_CAPACITY`, ttl = 600s).
    pub fn from_env(hub_id: impl Into<String>) -> Arc<Self> {
        let cap = std::env::var("JECP_REPLAY_CACHE_CAP")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(DEFAULT_CAPACITY);
        Self::new(hub_id, cap, Duration::from_secs(DEFAULT_TTL_SECONDS))
    }
}

impl NonceStore for MemoryReplayCache {
    fn check_and_insert(&self, agent_id: &str, nonce: &str) -> Replay {
        let nonce_lc = nonce.to_ascii_lowercase();
        let key: Key = (self.hub_id.clone(), agent_id.to_string(), nonce_lc);

        let mut inner = self.inner.lock();

        // Lazy TTL: drop the entry if it's past its TTL even if LRU still has it.
        let stale = inner
            .entries
            .peek(&key)
            .map(|e| e.inserted.elapsed() > self.ttl)
            .unwrap_or(false);
        if stale {
            inner.entries.pop(&key);
        }

        // Atomic check-and-insert. `peek` does NOT bump LRU access ordering,
        // which is what we want (LRU-by-access lets attackers pin entries).
        if inner.entries.peek(&key).is_some() {
            inner.hits += 1;
            return Replay::Replay;
        }
        inner.misses += 1;

        // Track eviction count: if cache was full before put, exactly one
        // entry was just evicted by lru's natural overflow handling.
        let was_full = inner.entries.len() >= inner.entries.cap().get();
        inner.entries.put(key, Entry { inserted: Instant::now() });
        if was_full {
            inner.evictions += 1;
        }

        Replay::First
    }

    fn stats(&self) -> CacheStats {
        let inner = self.inner.lock();
        CacheStats {
            size: inner.entries.len(),
            capacity: inner.entries.cap().get(),
            evictions_total: inner.evictions,
            hits_total: inner.hits,
            misses_total: inner.misses,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cache(cap: usize, ttl_secs: u64) -> Arc<MemoryReplayCache> {
        MemoryReplayCache::new("test-hub", cap, Duration::from_secs(ttl_secs))
    }

    #[test]
    fn first_observation_is_first() {
        let c = cache(100, 600);
        assert_eq!(c.check_and_insert("agent-a", "nonce-1"), Replay::First);
    }

    #[test]
    fn second_observation_is_replay() {
        let c = cache(100, 600);
        assert_eq!(c.check_and_insert("agent-a", "nonce-1"), Replay::First);
        assert_eq!(c.check_and_insert("agent-a", "nonce-1"), Replay::Replay);
    }

    #[test]
    fn different_agents_same_nonce_are_independent() {
        let c = cache(100, 600);
        assert_eq!(c.check_and_insert("agent-a", "nonce-x"), Replay::First);
        assert_eq!(c.check_and_insert("agent-b", "nonce-x"), Replay::First);
        assert_eq!(c.check_and_insert("agent-a", "nonce-x"), Replay::Replay);
        assert_eq!(c.check_and_insert("agent-b", "nonce-x"), Replay::Replay);
    }

    #[test]
    fn nonce_lowercase_normalized() {
        let c = cache(100, 600);
        assert_eq!(c.check_and_insert("agent-a", "ABCDEF12"), Replay::First);
        assert_eq!(c.check_and_insert("agent-a", "abcdef12"), Replay::Replay);
        assert_eq!(c.check_and_insert("agent-a", "AbCdEf12"), Replay::Replay);
    }

    #[test]
    fn ttl_eviction_allows_reinsertion() {
        let c = cache(100, 0); // ttl=0s → every lookup is stale
        assert_eq!(c.check_and_insert("agent-a", "nonce-1"), Replay::First);
        // After 1ms the previous entry's elapsed > 0s → stale → re-insert OK.
        std::thread::sleep(Duration::from_millis(2));
        assert_eq!(c.check_and_insert("agent-a", "nonce-1"), Replay::First);
    }

    #[test]
    fn stats_reflect_activity() {
        let c = cache(100, 600);
        c.check_and_insert("a", "n1"); // miss → insert
        c.check_and_insert("a", "n1"); // hit → replay
        c.check_and_insert("a", "n2"); // miss → insert
        let s = c.stats();
        assert_eq!(s.size, 2);
        assert_eq!(s.misses_total, 2);
        assert_eq!(s.hits_total, 1);
    }

    #[test]
    fn other_agents_unaffected_by_high_volume_neighbor() {
        // Confirm (loosely) that one agent's heavy nonce volume doesn't break
        // the cache for another agent — flood defense against H5 is enforced
        // by the per-agent rate limiter (60 RPM) at the route layer, not by
        // the cache itself; this test just exercises a normal coexistence
        // pattern.
        let c = cache(50_000, 600);
        for i in 0..1000 {
            c.check_and_insert("agent-a", &format!("nonce-{}", i));
        }
        assert_eq!(c.check_and_insert("agent-b", "honest-nonce"), Replay::First);
        assert_eq!(c.check_and_insert("agent-b", "honest-nonce"), Replay::Replay);
    }

    #[test]
    fn global_cap_evicts_lru() {
        let c = cache(3, 600);
        c.check_and_insert("a", "n1");
        c.check_and_insert("a", "n2");
        c.check_and_insert("a", "n3");
        // Inserting n4 evicts n1 (oldest LRU).
        c.check_and_insert("a", "n4");
        let s = c.stats();
        assert_eq!(s.size, 3);
        assert_eq!(s.evictions_total, 1);
        // n1 was evicted, so re-inserting it now is `First`, not `Replay`.
        // This insertion ALSO evicts the next LRU (n2), bringing eviction
        // count to 2 — that's expected lru-crate semantics.
        assert_eq!(c.check_and_insert("a", "n1"), Replay::First);
        let s = c.stats();
        assert_eq!(s.size, 3);
        assert_eq!(s.evictions_total, 2);
        // n3 is still in cache (was MRU after the n4 insert).
        assert_eq!(c.check_and_insert("a", "n3"), Replay::Replay);
    }
}
