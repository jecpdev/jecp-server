//! S0 Sprint — Background task supervisor.
//!
//! Wraps `tokio::spawn` so a background task that panics or returns
//! does not silently die. The supervisor logs the failure and restarts
//! the task after an exponential backoff (1 s → 30 s cap, factor 2).
//!
//! Used by main.rs to wrap webhook delivery loop and refund auto-approve
//! cron. Without this, a single panic in those loops would silently
//! disable that feature with no signal.

use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures::FutureExt;
use tokio::task::JoinHandle;

/// Per-task counters exposed via /health for visibility.
#[derive(Debug, Default)]
pub struct SupervisedTaskStats {
    pub restart_count: AtomicU64,
    pub last_restart_unix_ms: AtomicU64,
}

impl SupervisedTaskStats {
    pub fn snapshot(&self) -> (u64, u64) {
        (
            self.restart_count.load(Ordering::Relaxed),
            self.last_restart_unix_ms.load(Ordering::Relaxed),
        )
    }
}

/// Spawn a supervised task. The factory is called every time the inner
/// task ends or panics, with exponential backoff between attempts.
///
/// `name` is included in tracing events and is the key under which the
/// returned `Arc<SupervisedTaskStats>` should be registered.
pub fn spawn_supervised<F, Fut>(name: &'static str, factory: F) -> (JoinHandle<()>, Arc<SupervisedTaskStats>)
where
    F: Fn() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let stats = Arc::new(SupervisedTaskStats::default());
    let stats_for_task = stats.clone();
    let handle = tokio::spawn(async move {
        let mut backoff = Duration::from_secs(1);
        let cap = Duration::from_secs(30);

        loop {
            // AssertUnwindSafe is safe here because the task body owns its state and we
            // do not re-use any of it after a panic — we always discard and call factory()
            // again to build a fresh future.
            let result = AssertUnwindSafe(factory()).catch_unwind().await;

            match result {
                Ok(()) => {
                    tracing::warn!(
                        task = name,
                        backoff_secs = backoff.as_secs(),
                        "supervised task returned normally — treating as exit, restarting after backoff"
                    );
                }
                Err(panic_payload) => {
                    let msg = panic_message(&panic_payload);
                    tracing::error!(
                        task = name,
                        backoff_secs = backoff.as_secs(),
                        panic = %msg,
                        "supervised task panicked, restarting after backoff"
                    );
                }
            }

            stats_for_task.restart_count.fetch_add(1, Ordering::Relaxed);
            stats_for_task.last_restart_unix_ms.store(now_unix_ms(), Ordering::Relaxed);

            tokio::time::sleep(backoff).await;
            backoff = std::cmp::min(backoff.saturating_mul(2), cap);
        }
    });

    (handle, stats)
}

fn panic_message(payload: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        return (*s).to_string();
    }
    if let Some(s) = payload.downcast_ref::<String>() {
        return s.clone();
    }
    "unknown panic payload".to_string()
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[tokio::test]
    async fn restarts_on_normal_exit() {
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();

        let (handle, stats) = spawn_supervised("test_normal_exit", move || {
            let c = counter_clone.clone();
            async move {
                c.fetch_add(1, Ordering::Relaxed);
                // Return immediately — supervisor should treat as exit and restart
            }
        });

        // Wait long enough for ~3 restarts (1s + 2s = 3s, plus the first immediate run)
        tokio::time::sleep(Duration::from_millis(3500)).await;
        handle.abort();

        let runs = counter.load(Ordering::Relaxed);
        assert!(runs >= 2, "expected at least 2 runs, got {}", runs);
        let (restarts, _) = stats.snapshot();
        assert!(restarts >= 1, "expected at least 1 restart, got {}", restarts);
    }

    #[tokio::test]
    async fn restarts_on_panic() {
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();

        let (handle, stats) = spawn_supervised("test_panic", move || {
            let c = counter_clone.clone();
            async move {
                c.fetch_add(1, Ordering::Relaxed);
                panic!("boom");
            }
        });

        tokio::time::sleep(Duration::from_millis(3500)).await;
        handle.abort();

        let runs = counter.load(Ordering::Relaxed);
        assert!(runs >= 2, "expected at least 2 runs after panic, got {}", runs);
        let (restarts, last_ms) = stats.snapshot();
        assert!(restarts >= 1);
        assert!(last_ms > 0);
    }
}
