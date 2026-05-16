//! v1.1.0 x402 — `jecp.x402_settlements` repo (locked-design §5.8).
//!
//! CRUD wrappers over the settlements table. Insertion enforces both
//! UNIQUE constraints (tx_hash, (payer, eip3009_nonce)) — Postgres
//! 23505 maps to `X402_SETTLEMENT_REUSED`.
//!
//! Note: some helpers are exercised only via the reconciler (which wires
//! them up via `services::x402_reconciler::reconcile_once`); they may
//! appear unused to dead-code analysis on a build that omits the
//! reconciler. The `#[allow(dead_code)]` attribute records this
//! intentional decoupling.
#![allow(dead_code)]

use serde_json::Value;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::protocol::x402_types::{X402Error, X402Settlement, X402SettlementStatus};

/// Compact summary of an existing settlement row used to enrich
/// `X402_SETTLEMENT_REUSED` error envelopes (Audit A-M1, spec §3.5).
#[derive(Debug, Clone)]
pub struct ExistingSettlementInfo {
    pub tx_hash: String,
    pub original_request_id: String,
    pub original_settled_at: chrono::DateTime<chrono::Utc>,
}

pub struct NewSettlement<'a> {
    pub tx_hash: &'a str,
    pub payer: &'a str,
    pub eip3009_nonce: &'a str,
    pub agent_id: &'a str,
    pub capability_id: &'a str,
    pub request_id: &'a str,
    pub splitter_capability_id: &'a str,
    pub amount_usdc_micro: i64,
    pub provider_share_micro: i64,
    pub hub_share_micro: i64,
    pub network_share_micro: i64,
    pub facilitator_response: &'a Value,
}

/// Insert a freshly-attested settlement. Returns the new row's UUID.
///
/// Maps Postgres 23505 (unique violation on tx_hash OR (payer, nonce))
/// to `X402_SETTLEMENT_REUSED` with the appropriate subcause.
pub async fn insert(
    pool: &PgPool,
    s: &NewSettlement<'_>,
) -> Result<Uuid, X402Error> {
    let row = sqlx::query(
        "INSERT INTO jecp.x402_settlements (
            tx_hash, payer, eip3009_nonce,
            agent_id, capability_id, request_id, splitter_capability_id,
            amount_usdc_micro, provider_share_micro, hub_share_micro, network_share_micro,
            facilitator_response_jsonb, status
         )
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'facilitator_attested')
         RETURNING id",
    )
    .bind(s.tx_hash)
    .bind(s.payer)
    .bind(s.eip3009_nonce)
    .bind(s.agent_id)
    .bind(s.capability_id)
    .bind(s.request_id)
    .bind(s.splitter_capability_id)
    .bind(s.amount_usdc_micro)
    .bind(s.provider_share_micro)
    .bind(s.hub_share_micro)
    .bind(s.network_share_micro)
    .bind(s.facilitator_response)
    .persistent(false)
    .fetch_one(pool)
    .await
    .map_err(|e| map_insert_error(e, s.tx_hash, s.payer, s.eip3009_nonce))?;

    row.try_get::<Uuid, _>("id")
        .map_err(|e| X402Error::PaymentInvalid {
            subcause: "db_row_decode",
            message: e.to_string(),
        })
}

fn map_insert_error(e: sqlx::Error, tx_hash: &str, payer: &str, nonce: &str) -> X402Error {
    if let sqlx::Error::Database(db_err) = &e {
        if db_err.code().as_deref() == Some("23505") {
            // Inspect constraint name to choose the subcause precisely.
            let constraint = db_err.constraint().unwrap_or("");
            let (subcause, message) = if constraint.contains("tx_hash") {
                (
                    "tx_hash_seen",
                    format!("tx_hash {} already recorded", tx_hash),
                )
            } else {
                (
                    "nonce_reused",
                    format!(
                        "EIP-3009 nonce {} for payer {} already settled",
                        nonce, payer
                    ),
                )
            };
            return X402Error::SettlementReused { subcause, message, replay_info: None };
        }
    }
    X402Error::PaymentInvalid {
        subcause: "db_insert",
        message: e.to_string(),
    }
}

/// Check whether a (payer, nonce) pair has been seen before. Used as a
/// pre-flight to short-circuit obvious replays without the INSERT cost
/// (defense in depth; the UNIQUE constraint is still authoritative).
pub async fn exists_by_nonce(
    pool: &PgPool,
    payer: &str,
    nonce: &str,
) -> Result<bool, X402Error> {
    let row = sqlx::query(
        "SELECT 1 FROM jecp.x402_settlements
          WHERE payer = $1 AND eip3009_nonce = $2
          LIMIT 1",
    )
    .bind(payer)
    .bind(nonce)
    .persistent(false)
    .fetch_optional(pool)
    .await
    .map_err(|e| X402Error::PaymentInvalid {
        subcause: "db_lookup",
        message: e.to_string(),
    })?;
    Ok(row.is_some())
}

/// Lookup the original settlement row that conflicted with a replay attempt.
/// Used to surface `details.{tx_hash, original_request_id, original_settled_at}`
/// on `X402_SETTLEMENT_REUSED` envelopes (Audit A-M1, spec §3.5).
///
/// Looks up by `(payer, eip3009_nonce)` first (covers the nonce_reused case);
/// falls back to `tx_hash` if provided (covers the tx_hash_seen case).
pub async fn find_existing_for_replay(
    pool: &PgPool,
    payer: &str,
    nonce: &str,
    tx_hash: Option<&str>,
) -> Option<ExistingSettlementInfo> {
    // Prefer (payer, nonce) — UNIQUE → at most one row.
    if let Ok(Some(row)) = sqlx::query(
        "SELECT tx_hash, request_id, settled_at
           FROM jecp.x402_settlements
          WHERE payer = $1 AND eip3009_nonce = $2
          LIMIT 1",
    )
    .bind(payer)
    .bind(nonce)
    .persistent(false)
    .fetch_optional(pool)
    .await
    {
        return Some(ExistingSettlementInfo {
            tx_hash: row.try_get("tx_hash").unwrap_or_default(),
            original_request_id: row.try_get("request_id").unwrap_or_default(),
            original_settled_at: row.try_get("settled_at").ok()?,
        });
    }

    // Fallback: (tx_hash) — also UNIQUE.
    if let Some(tx) = tx_hash {
        if let Ok(Some(row)) = sqlx::query(
            "SELECT tx_hash, request_id, settled_at
               FROM jecp.x402_settlements
              WHERE tx_hash = $1
              LIMIT 1",
        )
        .bind(tx)
        .persistent(false)
        .fetch_optional(pool)
        .await
        {
            return Some(ExistingSettlementInfo {
                tx_hash: row.try_get("tx_hash").unwrap_or_default(),
                original_request_id: row.try_get("request_id").unwrap_or_default(),
                original_settled_at: row.try_get("settled_at").ok()?,
            });
        }
    }

    None
}

/// Fetch all settlements stuck in `facilitator_attested` for the
/// reconciler. Returns up to `limit` rows ordered by oldest first.
pub async fn list_facilitator_attested_older_than(
    pool: &PgPool,
    older_than_secs: i64,
    limit: i64,
) -> Result<Vec<X402Settlement>, X402Error> {
    let rows = sqlx::query(
        "SELECT id, tx_hash, payer, eip3009_nonce, agent_id, capability_id,
                request_id, splitter_capability_id,
                amount_usdc_micro, provider_share_micro, hub_share_micro, network_share_micro,
                status, reconcile_attempts, last_reconcile_at,
                on_chain_amount_micro, on_chain_recipient,
                facilitator_response_jsonb, settled_at, chain_confirmed_at
           FROM jecp.x402_settlements
          WHERE status = 'facilitator_attested'
            AND settled_at < NOW() - ($1 || ' seconds')::INTERVAL
          ORDER BY settled_at ASC
          LIMIT $2",
    )
    .bind(older_than_secs.to_string())
    .bind(limit)
    .persistent(false)
    .fetch_all(pool)
    .await
    .map_err(|e| X402Error::PaymentInvalid {
        subcause: "db_list",
        message: e.to_string(),
    })?;

    rows.into_iter().map(row_to_settlement).collect()
}

/// Transition a settlement to `chain_confirmed`. Idempotent.
pub async fn mark_chain_confirmed(pool: &PgPool, id: Uuid) -> Result<(), X402Error> {
    sqlx::query(
        "UPDATE jecp.x402_settlements
            SET status='chain_confirmed',
                chain_confirmed_at=NOW(),
                last_reconcile_at=NOW(),
                reconcile_attempts=reconcile_attempts+1
          WHERE id=$1 AND status='facilitator_attested'",
    )
    .bind(id)
    .persistent(false)
    .execute(pool)
    .await
    .map_err(|e| X402Error::PaymentInvalid {
        subcause: "db_update",
        message: e.to_string(),
    })?;
    Ok(())
}

pub async fn mark_failed(pool: &PgPool, id: Uuid) -> Result<(), X402Error> {
    sqlx::query(
        "UPDATE jecp.x402_settlements
            SET status='failed',
                last_reconcile_at=NOW(),
                reconcile_attempts=reconcile_attempts+1
          WHERE id=$1",
    )
    .bind(id)
    .persistent(false)
    .execute(pool)
    .await
    .map_err(|e| X402Error::PaymentInvalid {
        subcause: "db_update",
        message: e.to_string(),
    })?;
    Ok(())
}

pub async fn mark_orphaned(pool: &PgPool, id: Uuid) -> Result<(), X402Error> {
    sqlx::query(
        "UPDATE jecp.x402_settlements
            SET status='orphaned',
                last_reconcile_at=NOW(),
                reconcile_attempts=reconcile_attempts+1
          WHERE id=$1",
    )
    .bind(id)
    .persistent(false)
    .execute(pool)
    .await
    .map_err(|e| X402Error::PaymentInvalid {
        subcause: "db_update",
        message: e.to_string(),
    })?;
    Ok(())
}

pub async fn mark_mismatched(
    pool: &PgPool,
    id: Uuid,
    on_chain_amount_micro: i64,
    on_chain_recipient: &str,
) -> Result<(), X402Error> {
    sqlx::query(
        "UPDATE jecp.x402_settlements
            SET status='mismatched',
                on_chain_amount_micro=$2,
                on_chain_recipient=$3,
                last_reconcile_at=NOW(),
                reconcile_attempts=reconcile_attempts+1
          WHERE id=$1",
    )
    .bind(id)
    .bind(on_chain_amount_micro)
    .bind(on_chain_recipient)
    .persistent(false)
    .execute(pool)
    .await
    .map_err(|e| X402Error::PaymentInvalid {
        subcause: "db_update",
        message: e.to_string(),
    })?;
    Ok(())
}

fn parse_status(s: &str) -> X402SettlementStatus {
    match s {
        "facilitator_attested" => X402SettlementStatus::FacilitatorAttested,
        "chain_confirmed" => X402SettlementStatus::ChainConfirmed,
        "mismatched" => X402SettlementStatus::Mismatched,
        "failed" => X402SettlementStatus::Failed,
        "orphaned" => X402SettlementStatus::Orphaned,
        // Defensive default for any future state added in DB before code.
        _ => X402SettlementStatus::FacilitatorAttested,
    }
}

fn row_to_settlement(r: sqlx::postgres::PgRow) -> Result<X402Settlement, X402Error> {
    let status_s: String = r.try_get("status").map_err(|e| X402Error::PaymentInvalid {
        subcause: "db_row_decode",
        message: e.to_string(),
    })?;
    Ok(X402Settlement {
        id: r.try_get("id").map_err(map_decode)?,
        tx_hash: r.try_get("tx_hash").map_err(map_decode)?,
        payer: r.try_get("payer").map_err(map_decode)?,
        eip3009_nonce: r.try_get("eip3009_nonce").map_err(map_decode)?,
        agent_id: r.try_get("agent_id").map_err(map_decode)?,
        capability_id: r.try_get("capability_id").map_err(map_decode)?,
        request_id: r.try_get("request_id").map_err(map_decode)?,
        splitter_capability_id: r.try_get("splitter_capability_id").map_err(map_decode)?,
        amount_usdc_micro: r.try_get("amount_usdc_micro").map_err(map_decode)?,
        provider_share_micro: r.try_get("provider_share_micro").map_err(map_decode)?,
        hub_share_micro: r.try_get("hub_share_micro").map_err(map_decode)?,
        network_share_micro: r.try_get("network_share_micro").map_err(map_decode)?,
        status: parse_status(&status_s),
        reconcile_attempts: r.try_get("reconcile_attempts").unwrap_or(0),
        last_reconcile_at: r.try_get("last_reconcile_at").ok(),
        on_chain_amount_micro: r.try_get("on_chain_amount_micro").ok(),
        on_chain_recipient: r.try_get("on_chain_recipient").ok(),
        facilitator_response_jsonb: r
            .try_get("facilitator_response_jsonb")
            .unwrap_or(Value::Null),
        settled_at: r.try_get("settled_at").map_err(map_decode)?,
        chain_confirmed_at: r.try_get("chain_confirmed_at").ok(),
    })
}

fn map_decode(e: sqlx::Error) -> X402Error {
    X402Error::PaymentInvalid {
        subcause: "db_row_decode",
        message: e.to_string(),
    }
}
