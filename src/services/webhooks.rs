//! W4 — Webhook delivery worker.
//!
//! Outbox pattern:
//!   1. State changes insert into jecp.webhook_outbox in the same TX
//!   2. Background worker (this module) polls and delivers
//!   3. HMAC-SHA256 signed (matches @jecpdev/sdk verifyWebhook)
//!   4. Exponential backoff: 1m, 2m, 4m, 8m, 16m, 32m, 1h × 6 → 12 attempts ~6h
//!   5. After 12 failures → abandoned (Dead Letter Queue equivalent)

use base64::Engine as _;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use sqlx::{PgPool, Row};
use tokio::time::{sleep, Duration};

type HmacSha256 = Hmac<Sha256>;

const POLL_INTERVAL_SECS: u64 = 2;
const BATCH_SIZE: i64 = 50;
const MAX_ATTEMPTS: i32 = 12;

/// Enqueue a webhook event for delivery to a subscriber (agent or provider).
/// Calls the SQL `jecp.enqueue_webhook(subscriber_id, kind, event_type, payload)` function.
/// Returns the number of subscriptions that received this event (0 if none subscribed).
///
/// Non-fatal — logs and continues on error to avoid breaking the calling handler.
pub async fn enqueue(
    pool: &PgPool,
    subscriber_id: &str,
    kind: &str, // "agent" or "provider"
    event_type: &str,
    payload: serde_json::Value,
) -> i32 {
    let result = sqlx::query_scalar::<_, i32>(
        "SELECT jecp.enqueue_webhook($1, $2, $3, $4)",
    )
    .bind(subscriber_id)
    .bind(kind)
    .bind(event_type)
    .bind(&payload)
    .fetch_one(pool)
    .await;

    match result {
        Ok(n) => {
            if n > 0 {
                tracing::debug!("enqueued {} '{}' event(s) for {}={}", n, event_type, kind, subscriber_id);
            }
            n
        }
        Err(e) => {
            tracing::warn!("enqueue_webhook failed (non-fatal): {} kind={} type={}", e, kind, event_type);
            0
        }
    }
}

pub async fn delivery_loop(pool: PgPool) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .expect("reqwest client");

    tracing::info!("webhook delivery worker started");
    loop {
        if let Err(e) = process_batch(&pool, &client).await {
            tracing::warn!("webhook delivery batch error: {}", e);
        }
        sleep(Duration::from_secs(POLL_INTERVAL_SECS)).await;
    }
}

async fn process_batch(pool: &PgPool, client: &reqwest::Client) -> Result<(), sqlx::Error> {
    // S2 / TIER A.3 fix: atomically claim rows so concurrent delivery workers
    // (multi-machine Fly deployment) do not double-deliver. The CTE selects
    // claimable rows with FOR UPDATE SKIP LOCKED and stamps claimed_at in a
    // single statement. Stale claims (> 5 min) are reclaimable in case a
    // worker died mid-process.
    let rows = sqlx::query(
        "WITH claimable AS (
           SELECT o.id
             FROM jecp.webhook_outbox o
             JOIN jecp.webhook_subscriptions s ON s.id = o.subscription_id
            WHERE o.delivered_at IS NULL
              AND o.abandoned_at IS NULL
              AND o.next_attempt_at <= NOW()
              AND s.status = 'active'
              AND (o.claimed_at IS NULL OR o.claimed_at < NOW() - INTERVAL '5 minutes')
            ORDER BY o.next_attempt_at
            LIMIT $1
            FOR UPDATE OF o SKIP LOCKED
         )
         UPDATE jecp.webhook_outbox o
            SET claimed_at = NOW()
           FROM claimable c
          WHERE o.id = c.id
         RETURNING o.id, o.subscription_id, o.event_id, o.event_type, o.payload, o.attempt_count,
                   (SELECT s.endpoint_url FROM jecp.webhook_subscriptions s WHERE s.id = o.subscription_id) AS endpoint_url,
                   (SELECT s.hmac_secret  FROM jecp.webhook_subscriptions s WHERE s.id = o.subscription_id) AS hmac_secret,
                   (SELECT s.failures_consecutive FROM jecp.webhook_subscriptions s WHERE s.id = o.subscription_id) AS failures_consecutive",
    )
    .bind(BATCH_SIZE)
    .fetch_all(pool)
    .await?;

    for r in rows {
        let id: uuid::Uuid = r.try_get("id")?;
        let subscription_id: uuid::Uuid = r.try_get("subscription_id")?;
        let _event_id: String = r.try_get("event_id")?;
        let endpoint_url: String = r.try_get("endpoint_url")?;
        let hmac_secret: String = r.try_get("hmac_secret")?;
        let payload: serde_json::Value = r.try_get("payload")?;
        let attempt_count: i32 = r.try_get("attempt_count")?;

        let body = serde_json::to_string(&payload).unwrap_or_default();
        let ts = chrono::Utc::now().timestamp();
        let sig = sign(&hmac_secret, ts, &body);

        // v1.1.0 c7 — SSRF defense at deliver time. DNS rebinding between
        // subscribe and deliver is the primary attack here; preflight at
        // subscribe alone is insufficient. Spec §9.7.1.1 step 6.
        let validated = match crate::protocol::url_guard::validate_outbound_url(&endpoint_url).await {
            Ok(v) => v,
            Err(e) => {
                let safe_url = crate::protocol::url_guard::redact_url(&endpoint_url);
                let reason = e.reason().to_string();
                crate::protocol::url_guard::audit_log_rejection(
                    pool, None, None,
                    "webhook_destination_url", "webhook_deliver",
                    &safe_url, &reason, None,
                ).await;
                // Mark abandoned (no retry) — DNS-rebound destination is not
                // recoverable by sleep+retry. Spec §9.7.1.3 deliver-path note.
                let _ = sqlx::query(
                    "UPDATE jecp.webhook_outbox
                        SET delivered_at = NOW(), claimed_at = NULL,
                            last_error   = CONCAT('SSRF_DENIED: ', $2::TEXT)
                      WHERE id = $1")
                    .bind(id).bind(&reason).execute(pool).await;
                continue;
            }
        };
        let pinned_client = crate::protocol::url_guard::guarded_client(
            &validated.host, validated.pinned_addr,
        ).unwrap_or_else(|_| client.clone());

        let res = pinned_client
            .post(&endpoint_url)
            .header("X-JECP-Webhook-Signature", format!("v1={}", sig))
            .header("X-JECP-Webhook-Timestamp", ts.to_string())
            .header("Content-Type", "application/json")
            .body(body.clone())
            .send()
            .await;

        match res {
            Ok(r) if r.status().is_success() => {
                // Clear claimed_at on success so a re-run of this row (which
                // shouldn't happen because delivered_at is set) would still be
                // observable. We set delivered_at + claimed_at = NULL together.
                let _ = sqlx::query(
                    "UPDATE jecp.webhook_outbox
                        SET delivered_at = NOW(), claimed_at = NULL
                      WHERE id = $1")
                    .bind(id).execute(pool).await;
                let _ = sqlx::query(
                    "UPDATE jecp.webhook_subscriptions
                       SET failures_consecutive = 0, last_success_at = NOW(), last_error = NULL
                       WHERE id = $1")
                    .bind(subscription_id).execute(pool).await;
            }
            Ok(r) => {
                let status = r.status();
                let err_msg = format!("HTTP {}", status);
                schedule_retry(pool, id, subscription_id, attempt_count, &err_msg).await;
            }
            Err(e) => {
                let err_msg = format!("network: {}", e);
                schedule_retry(pool, id, subscription_id, attempt_count, &err_msg).await;
            }
        }
    }
    Ok(())
}

async fn schedule_retry(pool: &PgPool, id: uuid::Uuid, subscription_id: uuid::Uuid, attempt_count: i32, err: &str) {
    let next_attempt = attempt_count + 1;
    if next_attempt >= MAX_ATTEMPTS {
        let _ = sqlx::query(
            "UPDATE jecp.webhook_outbox
               SET abandoned_at = NOW(), attempt_count = $2, last_error = $3,
                   claimed_at = NULL
               WHERE id = $1")
            .bind(id).bind(next_attempt).bind(err)
            .execute(pool).await;
        let _ = sqlx::query(
            "UPDATE jecp.webhook_subscriptions
               SET failures_consecutive = failures_consecutive + 1, last_error = $2
               WHERE id = $1")
            .bind(subscription_id).bind(err)
            .execute(pool).await;
        tracing::warn!("webhook abandoned after {} attempts: {}", next_attempt, err);
        return;
    }
    // Backoff: 60s × 2^attempt, capped 1h
    let delay_secs = (60_i64 * 2_i64.pow(next_attempt as u32)).min(3600);
    // Clear claimed_at so the row becomes claimable again at next_attempt_at.
    let _ = sqlx::query(
        "UPDATE jecp.webhook_outbox
           SET attempt_count = $2,
               next_attempt_at = NOW() + ($3 || ' seconds')::INTERVAL,
               last_error = $4,
               claimed_at = NULL
           WHERE id = $1")
        .bind(id).bind(next_attempt).bind(delay_secs.to_string()).bind(err)
        .execute(pool).await;
}

fn sign(secret_b64: &str, ts: i64, body: &str) -> String {
    let secret = base64::engine::general_purpose::STANDARD.decode(secret_b64).unwrap_or_default();
    let mut mac = HmacSha256::new_from_slice(&secret).expect("HMAC key");
    mac.update(ts.to_string().as_bytes());
    mac.update(b".");
    mac.update(body.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
}
