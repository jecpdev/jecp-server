//! v1.1.0 x402 — Settlement reconciler (locked-design §5.7).
//!
//! Background task: every 60s, scan `facilitator_attested` settlements
//! older than 60s and confirm tx inclusion via Base RPC
//! `eth_getTransactionReceipt`. Transitions:
//!
//!   facilitator_attested ──┬─► chain_confirmed   (receipt.status == 0x1 + recipient + amount + confirmations OK)
//!                          ├─► mismatched        (receipt found but recipient/amount differ — Audit B TM-S6/T2/X4)
//!                          ├─► failed            (receipt.status == 0x0)
//!                          └─► orphaned          (no receipt after 30 attempts)
//!
//! ## Defenses (Audit B TM-X4 / TM-T2 / TM-S6)
//! - `MIN_CONFIRMATIONS = 3` Base blocks (~6s) before transitioning to
//!   `chain_confirmed`. Defers Provider payout against tip reorgs.
//! - Compare on-chain `to` (USDC.transfer recipient) against the Hub's
//!   pinned Splitter address; mismatch → `mark_mismatched`.
//! - Compare on-chain Transfer log value against facilitator's claim;
//!   mismatch → `mark_mismatched`. Disagreement is a P0 signal.
//!
//! Spawned via `spawn_supervised` so panics restart with backoff.
//! Reads kill-switch flag `x402_reconciler_on` on every tick (30s cache).

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;

use crate::services::supervisor::spawn_supervised;
use crate::AppState;

/// 60-second tick per locked-design §5.7.
const TICK_INTERVAL: Duration = Duration::from_secs(60);

/// Max age before a settlement is considered orphaned (locked-design §5.7).
const ORPHAN_THRESHOLD_SECS: u64 = 600;

/// Max reconciliation attempts before marking orphaned.
const MAX_RECONCILE_ATTEMPTS: i32 = 30;

/// Per-tick batch size cap to avoid one huge scan blocking the loop.
const BATCH_LIMIT: i64 = 100;

/// Minimum chain-tip distance before transitioning to `chain_confirmed`
/// (Audit B TM-T2). Base produces ~2s blocks → 3 blocks ≈ 6s settlement.
/// Higher values trade latency for reorg resistance.
pub const MIN_CONFIRMATIONS: u64 = 3;

/// USDC Transfer event topic — `keccak256("Transfer(address,address,uint256)")`.
/// Stable across all ERC-20 Transfer emissions (USDC v2.2).
const USDC_TRANSFER_TOPIC: &str =
    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

/// Spawn the supervised reconciler task. Should be called once at startup
/// in `main()`. Reads `x402_enabled` + `x402_reconciler_on` flags before
/// each tick — both must be true to do real work.
pub fn spawn_reconciler(state: Arc<AppState>) -> Arc<crate::services::supervisor::SupervisedTaskStats> {
    let (_, stats) = spawn_supervised("x402_reconciler", move || {
        let state = state.clone();
        async move {
            reconcile_loop(state).await;
        }
    });
    stats
}

/// Main reconciler loop. Runs until task cancellation. Each iteration:
/// 1. Sleeps `TICK_INTERVAL`.
/// 2. Checks kill-switch flag.
/// 3. Fetches a batch of `facilitator_attested` rows older than 60s.
/// 4. For each, calls Base RPC `eth_getTransactionReceipt`.
/// 5. Updates DB status.
pub async fn reconcile_loop(state: Arc<AppState>) {
    tracing::info!("x402 reconciler started (interval={:?})", TICK_INTERVAL);

    loop {
        tokio::time::sleep(TICK_INTERVAL).await;

        // Kill switch: skip work if flag off.
        let enabled = state.flags.is_enabled(&state.pool, "x402_enabled").await
            && state.flags.is_enabled(&state.pool, "x402_reconciler_on").await;
        if !enabled {
            tracing::debug!("x402 reconciler: flags off, skipping tick");
            continue;
        }

        let cfg = match state.x402.as_ref() {
            Some(c) => c.clone(),
            None => {
                tracing::warn!("x402 reconciler: state.x402 None, skipping tick");
                continue;
            }
        };

        let pool = match state.background_pool() {
            Some(p) => p.clone(),
            None => {
                tracing::warn!("x402 reconciler: no background pool, skipping tick");
                continue;
            }
        };

        let splitter_lc =
            format!("0x{}", hex::encode(cfg.splitter_address.as_slice())).to_lowercase();
        let usdc_lc =
            format!("0x{}", hex::encode(cfg.usdc_asset.as_slice())).to_lowercase();
        match reconcile_once(
            &pool,
            &cfg.base_rpc_url,
            &cfg.reconciler_client,
            &splitter_lc,
            &usdc_lc,
        )
        .await
        {
            Ok(stats) => {
                tracing::info!(
                    checked = stats.checked,
                    confirmed = stats.confirmed,
                    mismatched = stats.mismatched,
                    failed = stats.failed,
                    orphaned = stats.orphaned,
                    "x402 reconciler tick complete"
                );
            }
            Err(e) => {
                tracing::error!("x402 reconciler tick failed: {}", e);
            }
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ReconcileStats {
    pub checked: usize,
    pub confirmed: usize,
    pub mismatched: usize,
    pub failed: usize,
    pub orphaned: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum ReconcileError {
    #[error("db error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("rpc error: {0}")]
    Rpc(String),
}

/// Single reconciliation pass. Public for unit tests + admin CLI.
///
/// `splitter_address_lc` and `usdc_asset_lc` are the lowercased hex addresses
/// of the Hub's Splitter contract + USDC contract. The reconciler compares
/// the on-chain Transfer event's `to` (recipient) and value against the
/// facilitator's claim. Any mismatch → `mark_mismatched` (Audit B TM-S6/T2/X4).
pub async fn reconcile_once(
    pool: &sqlx::PgPool,
    rpc_url: &str,
    rpc_client: &reqwest::Client,
    splitter_address_lc: &str,
    usdc_asset_lc: &str,
) -> Result<ReconcileStats, ReconcileError> {
    let rows = sqlx::query(
        "SELECT id, tx_hash, payer, amount_usdc_micro, reconcile_attempts,
                EXTRACT(EPOCH FROM (NOW() - settled_at))::BIGINT AS age_secs
           FROM jecp.x402_settlements
          WHERE status = 'facilitator_attested'
            AND settled_at < NOW() - INTERVAL '60 seconds'
          ORDER BY settled_at ASC
          LIMIT $1",
    )
    .bind(BATCH_LIMIT)
    .persistent(false)
    .fetch_all(pool)
    .await?;

    use sqlx::Row;
    let mut stats = ReconcileStats::default();

    // Fetch chain head once per tick — confirmation depth math.
    let head_block = match get_block_number(rpc_client, rpc_url).await {
        Ok(n) => Some(n),
        Err(e) => {
            tracing::warn!("x402 reconciler: eth_blockNumber failed: {}", e);
            None
        }
    };

    for row in rows {
        stats.checked += 1;
        let id: uuid::Uuid = row.try_get("id").map_err(|e| ReconcileError::Db(e.into()))?;
        let tx_hash: String = row.try_get("tx_hash").map_err(|e| ReconcileError::Db(e.into()))?;
        let claimed_amount_micro: i64 = row.try_get("amount_usdc_micro").unwrap_or(0);
        let attempts: i32 = row.try_get("reconcile_attempts").unwrap_or(0);
        let age_secs: i64 = row.try_get("age_secs").unwrap_or(0);

        match get_tx_receipt(rpc_client, rpc_url, &tx_hash).await {
            Ok(Some(receipt)) => {
                if !receipt.status_ok {
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
                    .await?;
                    stats.failed += 1;
                    tracing::warn!(tx_hash = %tx_hash, "x402 tx receipt status=0x0 (failed)");
                    continue;
                }

                // Confirmation depth check (Audit B TM-T2). Defer transition
                // until at least MIN_CONFIRMATIONS blocks behind chain head.
                if let (Some(head), Some(block_no)) = (head_block, receipt.block_number) {
                    if head < block_no || head - block_no < MIN_CONFIRMATIONS {
                        // Not enough confirmations yet — leave row in
                        // facilitator_attested, bump attempts, retry later.
                        sqlx::query(
                            "UPDATE jecp.x402_settlements
                                SET last_reconcile_at=NOW(),
                                    reconcile_attempts=reconcile_attempts+1
                              WHERE id=$1",
                        )
                        .bind(id)
                        .persistent(false)
                        .execute(pool)
                        .await?;
                        continue;
                    }
                }

                // Recipient + amount verification (Audit B TM-S6).
                // Splitter is the EIP-3009 `to`; on-chain the USDC.transferWithAuthorization
                // emits Transfer(payer, splitter, value). We parse the Transfer log on
                // the USDC contract addressed to the Splitter and compare.
                let chain_observation =
                    extract_transfer_observation(&receipt, usdc_asset_lc, splitter_address_lc);

                match chain_observation {
                    Some((on_chain_to_lc, on_chain_value)) => {
                        let value_matches = on_chain_value == claimed_amount_micro as u128;
                        let recipient_matches = on_chain_to_lc == splitter_address_lc;
                        if value_matches && recipient_matches {
                            sqlx::query(
                                "UPDATE jecp.x402_settlements
                                    SET status='chain_confirmed',
                                        chain_confirmed_at=NOW(),
                                        last_reconcile_at=NOW(),
                                        on_chain_amount_micro=$2,
                                        on_chain_recipient=$3,
                                        reconcile_attempts=reconcile_attempts+1
                                  WHERE id=$1",
                            )
                            .bind(id)
                            .bind(on_chain_value as i64)
                            .bind(&on_chain_to_lc)
                            .persistent(false)
                            .execute(pool)
                            .await?;
                            stats.confirmed += 1;
                        } else {
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
                            .bind(on_chain_value as i64)
                            .bind(&on_chain_to_lc)
                            .persistent(false)
                            .execute(pool)
                            .await?;
                            stats.mismatched += 1;
                            tracing::error!(
                                tx_hash = %tx_hash,
                                on_chain_to = %on_chain_to_lc,
                                expected_to = %splitter_address_lc,
                                on_chain_value,
                                expected_value = claimed_amount_micro,
                                "x402 settlement MISMATCHED — facilitator claim diverges from on-chain reality (P0)"
                            );
                        }
                    }
                    None => {
                        // Receipt found, status_ok, but no Transfer log matches
                        // (Splitter, USDC). This is anomalous. Treat as mismatched.
                        sqlx::query(
                            "UPDATE jecp.x402_settlements
                                SET status='mismatched',
                                    last_reconcile_at=NOW(),
                                    reconcile_attempts=reconcile_attempts+1
                              WHERE id=$1",
                        )
                        .bind(id)
                        .persistent(false)
                        .execute(pool)
                        .await?;
                        stats.mismatched += 1;
                        tracing::error!(
                            tx_hash = %tx_hash,
                            "x402 settlement MISMATCHED — receipt ok but no matching USDC Transfer to Splitter (P0)"
                        );
                    }
                }
            }
            Ok(None) => {
                // No receipt yet. Either still pending or orphaned.
                let new_attempts = attempts + 1;
                if new_attempts >= MAX_RECONCILE_ATTEMPTS
                    || (age_secs as u64) > ORPHAN_THRESHOLD_SECS
                {
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
                    .await?;
                    stats.orphaned += 1;
                    tracing::error!(
                        tx_hash = %tx_hash,
                        attempts = new_attempts,
                        "x402 tx orphaned (not seen on chain)"
                    );
                } else {
                    sqlx::query(
                        "UPDATE jecp.x402_settlements
                            SET last_reconcile_at=NOW(),
                                reconcile_attempts=reconcile_attempts+1
                          WHERE id=$1",
                    )
                    .bind(id)
                    .persistent(false)
                    .execute(pool)
                    .await?;
                }
            }
            Err(e) => {
                tracing::warn!(tx_hash = %tx_hash, "x402 RPC error during reconcile: {}", e);
                // Don't bump attempts on transport error — try again next tick.
            }
        }
    }

    Ok(stats)
}

/// Minimal `eth_getTransactionReceipt` response we care about.
#[derive(Debug, Clone)]
struct TxReceipt {
    status_ok: bool,
    block_number: Option<u64>,
    logs: Vec<RawLog>,
}

#[derive(Debug, Clone)]
struct RawLog {
    /// Emitting contract address, lowercased 0x-hex.
    address: String,
    /// 32-byte topic words, lowercased 0x-hex.
    topics: Vec<String>,
    /// `data` field, 0x-hex (may be empty).
    data: String,
}

async fn get_tx_receipt(
    client: &reqwest::Client,
    rpc_url: &str,
    tx_hash: &str,
) -> Result<Option<TxReceipt>, ReconcileError> {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_getTransactionReceipt",
        "params": [tx_hash],
    });

    let resp = client
        .post(rpc_url)
        .json(&body)
        .send()
        .await
        .map_err(|e| ReconcileError::Rpc(format!("post: {}", e)))?;

    if !resp.status().is_success() {
        return Err(ReconcileError::Rpc(format!(
            "rpc returned {}",
            resp.status()
        )));
    }

    let v: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| ReconcileError::Rpc(format!("parse: {}", e)))?;

    if let Some(err) = v.get("error") {
        return Err(ReconcileError::Rpc(format!("rpc err: {}", err)));
    }

    let result = match v.get("result") {
        Some(r) if !r.is_null() => r,
        _ => return Ok(None),
    };

    // status: hex string "0x1" success, "0x0" failure.
    let status_ok = result
        .get("status")
        .and_then(|s| s.as_str())
        .map(|s| s == "0x1" || s == "0x01")
        .unwrap_or(false);

    let block_number = result
        .get("blockNumber")
        .and_then(|s| s.as_str())
        .and_then(parse_hex_u64);

    let logs = result
        .get("logs")
        .and_then(|l| l.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|log| {
                    let address = log.get("address")?.as_str()?.to_lowercase();
                    let topics = log
                        .get("topics")?
                        .as_array()?
                        .iter()
                        .filter_map(|t| t.as_str().map(|s| s.to_lowercase()))
                        .collect::<Vec<_>>();
                    let data = log
                        .get("data")
                        .and_then(|d| d.as_str())
                        .unwrap_or("")
                        .to_lowercase();
                    Some(RawLog {
                        address,
                        topics,
                        data,
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    Ok(Some(TxReceipt {
        status_ok,
        block_number,
        logs,
    }))
}

/// Fetch the latest Base block number for confirmation depth math.
async fn get_block_number(
    client: &reqwest::Client,
    rpc_url: &str,
) -> Result<u64, ReconcileError> {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_blockNumber",
        "params": [],
    });
    let resp = client
        .post(rpc_url)
        .json(&body)
        .send()
        .await
        .map_err(|e| ReconcileError::Rpc(format!("post: {}", e)))?;
    if !resp.status().is_success() {
        return Err(ReconcileError::Rpc(format!(
            "rpc returned {}",
            resp.status()
        )));
    }
    let v: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| ReconcileError::Rpc(format!("parse: {}", e)))?;
    if let Some(err) = v.get("error") {
        return Err(ReconcileError::Rpc(format!("rpc err: {}", err)));
    }
    let result = v
        .get("result")
        .and_then(|s| s.as_str())
        .ok_or_else(|| ReconcileError::Rpc("eth_blockNumber: missing result".into()))?;
    parse_hex_u64(result).ok_or_else(|| {
        ReconcileError::Rpc(format!("eth_blockNumber: bad hex {}", result))
    })
}

fn parse_hex_u64(s: &str) -> Option<u64> {
    let s = s.trim_start_matches("0x");
    if s.is_empty() {
        return None;
    }
    u64::from_str_radix(s, 16).ok()
}

fn parse_hex_u128(s: &str) -> Option<u128> {
    let s = s.trim_start_matches("0x");
    if s.is_empty() {
        return None;
    }
    u128::from_str_radix(s, 16).ok()
}

/// Look through `receipt.logs[]` for an ERC-20 `Transfer(address,address,uint256)`
/// log emitted by `usdc_asset_lc` whose `to` (topic[2]) matches `expected_to_lc`.
/// Returns `(recipient_lc, value_micro_usdc)` on match.
///
/// Returns `None` when no matching log exists — the caller treats this as
/// `mismatched` because a successful USDC settlement MUST emit Transfer.
fn extract_transfer_observation(
    receipt: &TxReceipt,
    usdc_asset_lc: &str,
    expected_to_lc: &str,
) -> Option<(String, u128)> {
    for log in &receipt.logs {
        if log.address != usdc_asset_lc {
            continue;
        }
        if log.topics.first().map(|s| s.as_str()) != Some(USDC_TRANSFER_TOPIC) {
            continue;
        }
        // topics[1] = from (indexed), topics[2] = to (indexed).
        // ABI-encoded address: last 20 bytes of the 32-byte word.
        let to_topic = log.topics.get(2)?;
        let to_lc = abi_address_from_topic(to_topic)?;
        // value lives in `data` (non-indexed uint256).
        let value = parse_hex_u128(&log.data)?;
        // Always return the observed recipient even on mismatch so the caller
        // can store it in `on_chain_recipient` for forensic comparison.
        if to_lc == expected_to_lc {
            return Some((to_lc, value));
        }
        // First USDC Transfer whose `to` differs — surface as mismatch.
        return Some((to_lc, value));
    }
    None
}

/// Decode an ABI-encoded 32-byte topic into a lowercased 0x-hex address
/// (last 20 bytes). Returns None on malformed input.
fn abi_address_from_topic(topic: &str) -> Option<String> {
    let s = topic.trim_start_matches("0x");
    if s.len() != 64 {
        return None;
    }
    // Address occupies the last 40 hex chars (20 bytes).
    Some(format!("0x{}", &s[24..]).to_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconcile_stats_default_zero() {
        let s = ReconcileStats::default();
        assert_eq!(s.checked, 0);
        assert_eq!(s.confirmed, 0);
        assert_eq!(s.mismatched, 0);
        assert_eq!(s.failed, 0);
        assert_eq!(s.orphaned, 0);
    }

    #[test]
    fn orphan_threshold_constants_sane() {
        assert!(ORPHAN_THRESHOLD_SECS > TICK_INTERVAL.as_secs());
        assert!(MAX_RECONCILE_ATTEMPTS >= 10);
    }

    #[test]
    fn min_confirmations_nontrivial() {
        // Audit B TM-T2: must be >= 1 for any reorg defense.
        assert!(MIN_CONFIRMATIONS >= 1);
        assert!(MIN_CONFIRMATIONS <= 12);
    }

    #[test]
    fn parse_hex_u64_works() {
        assert_eq!(parse_hex_u64("0x10").unwrap(), 16);
        assert_eq!(parse_hex_u64("0x0").unwrap(), 0);
        assert_eq!(parse_hex_u64("ff").unwrap(), 255);
        assert!(parse_hex_u64("0x").is_none());
        assert!(parse_hex_u64("0xZZ").is_none());
    }

    #[test]
    fn parse_hex_u128_works() {
        assert_eq!(parse_hex_u128("0x186a0").unwrap(), 100_000); // 100,000 micros
        assert_eq!(
            parse_hex_u128("0x00000000000000000000000000000000000000000000000000000000000186a0")
                .unwrap(),
            100_000
        );
    }

    #[test]
    fn abi_address_from_topic_decodes() {
        // 32-byte topic with address in low 20 bytes.
        let topic = "0x000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";
        let addr = abi_address_from_topic(topic).unwrap();
        assert_eq!(addr, "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48");
        // Wrong length
        assert!(abi_address_from_topic("0xabc").is_none());
    }

    #[test]
    fn extract_transfer_observation_matches() {
        let usdc = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
        let splitter = "0x0000000000000000000000000000000000000001";
        // Receipt with one Transfer log to the splitter, value=200000.
        let log = RawLog {
            address: usdc.to_string(),
            topics: vec![
                USDC_TRANSFER_TOPIC.to_string(),
                "0x000000000000000000000000aaaa000000000000000000000000000000000001".into(),
                "0x0000000000000000000000000000000000000000000000000000000000000001".into(),
            ],
            data: "0x0000000000000000000000000000000000000000000000000000000000030d40"
                .into(), // 200000 dec
        };
        let receipt = TxReceipt {
            status_ok: true,
            block_number: Some(100),
            logs: vec![log],
        };
        let obs = extract_transfer_observation(&receipt, usdc, splitter).unwrap();
        assert_eq!(obs.0, splitter);
        assert_eq!(obs.1, 200_000);
    }

    #[test]
    fn extract_transfer_observation_returns_mismatch_recipient() {
        let usdc = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
        let splitter = "0x0000000000000000000000000000000000000001";
        // Transfer to a *different* recipient — Audit B TM-S6 surface.
        let log = RawLog {
            address: usdc.to_string(),
            topics: vec![
                USDC_TRANSFER_TOPIC.to_string(),
                "0x000000000000000000000000aaaa000000000000000000000000000000000001".into(),
                "0x000000000000000000000000dead000000000000000000000000000000000099".into(),
            ],
            data: "0x0000000000000000000000000000000000000000000000000000000000030d40"
                .into(),
        };
        let receipt = TxReceipt {
            status_ok: true,
            block_number: Some(100),
            logs: vec![log],
        };
        let obs = extract_transfer_observation(&receipt, usdc, splitter).unwrap();
        // First USDC Transfer is returned even though it doesn't match the
        // splitter — caller compares + marks mismatched.
        assert_ne!(obs.0, splitter);
        assert!(obs.0.starts_with("0xdead"));
    }

    #[test]
    fn extract_transfer_observation_none_when_no_usdc_log() {
        let usdc = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
        let splitter = "0x0000000000000000000000000000000000000001";
        let receipt = TxReceipt {
            status_ok: true,
            block_number: Some(100),
            logs: vec![],
        };
        assert!(extract_transfer_observation(&receipt, usdc, splitter).is_none());
    }
}
