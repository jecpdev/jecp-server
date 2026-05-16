//! v1.1.0 x402 — x402 payment branch for `POST /v1/invoke`
//! (locked-design §5.6).
//!
//! Called from `routes::invoke::invoke_capability_json` immediately
//! before the wallet pre-flight check, after auth + idempotency + capability
//! resolution. Returns a finalized billing summary if it took over the payment;
//! returns `None` if the request should fall through to the wallet path.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::HeaderMap;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::protocol::x402_types::{
    PaymentRequirements, ReplayInfo, X402Error, X402SettlementStatus,
};
use crate::protocol::x402_verify::{decode_x_payment_header, validate_payment_payload};
use crate::services::splitter_registry::derive_capability_id;
use crate::services::x402_settlements;
use crate::AppState;

/// Outcome of the x402 dispatch.
pub enum X402Outcome {
    /// Settlement succeeded; downstream Provider-forward proceeds and the
    /// returned billing summary replaces the wallet billing.
    Settled(X402Billing),
    /// X-Payment was present but the capability doesn't accept x402 or
    /// some other non-fatal condition; caller falls through to wallet.
    FallthroughToWallet,
    /// X-Payment was not present at all.
    NoXPayment,
    /// Hard error — the caller should propagate this back as a JECP envelope.
    Error(X402Error),
}

pub struct X402Billing {
    pub settlement_id: Uuid,
    pub tx_hash: String,
    pub payer: String,
    /// Network name (e.g. "base") from facilitator settle response.
    pub network: String,
    /// Trusted facilitator URL (echoed into billing.x402.facilitator per spec §5.1).
    pub facilitator_url: String,
    pub amount_usdc: f64,
    pub provider_share_usdc: f64,
    pub hub_share_usdc: f64,
    pub network_share_usdc: f64,
    /// Base64-encoded JSON for the `X-Payment-Response` header (locked-design §3.4).
    pub payment_response_b64: String,
    /// Settlement status at write time (always `facilitator_attested` for now).
    #[allow(dead_code)]
    pub status: X402SettlementStatus,
}

impl X402Billing {
    /// Convert to the JSON `billing` field of the invoke response envelope.
    ///
    /// Spec §5.1: the `billing.x402` nested object MUST carry
    /// `{settlement_tx, network, payer, facilitator}` as canonical keys
    /// (Audit A-C4). Hub-internal extras (share breakdowns, audit URL)
    /// live alongside but never replace those.
    pub fn to_billing_summary(&self) -> Value {
        json!({
            "charged": true,
            "method": "x402",
            "amount_usdc": self.amount_usdc,
            "settlement_id": self.settlement_id,
            "confirmation": "facilitator_attested",
            "x402": {
                "settlement_tx": self.tx_hash,
                "network": self.network,
                "payer": self.payer,
                "facilitator": self.facilitator_url,
            },
            "extensions": {
                "jdb-share-breakdown": {
                    "provider_share_usdc": self.provider_share_usdc,
                    "hub_share_usdc": self.hub_share_usdc,
                    "network_share_usdc": self.network_share_usdc,
                },
                "jdb-audit-url": format!("https://basescan.org/tx/{}", self.tx_hash),
            }
        })
    }
}

/// Dispatcher used by routes/invoke.rs. Idempotent: re-invocation with
/// same (payer, nonce) returns `X402_SETTLEMENT_REUSED`.
#[allow(clippy::too_many_arguments)]
pub async fn dispatch_x402(
    state: &AppState,
    headers: &HeaderMap,
    namespace: &str,
    capability_id_str: &str,
    action_id: &str,
    version: &str,
    agent_id: &str,
    request_id: &str,
    price_usdc: f64,
    manifest: &Value,
) -> X402Outcome {
    // 1. Reject duplicate X-Payment headers (Audit B TM-S5, spec §3.3).
    //    Reverse-proxy normalization differences can let an attacker submit two
    //    `X-Payment` headers — without this check, only the first reaches the
    //    facilitator and the second could be replayed on a different path.
    let x_payment_count = headers.get_all("x-payment").iter().count();
    if x_payment_count > 1 {
        return X402Outcome::Error(X402Error::PaymentInvalid {
            subcause: "duplicate_payment_header",
            message: format!(
                "{} X-Payment headers presented; exactly one required",
                x_payment_count
            ),
        });
    }

    // 2. Header present?
    let x_payment_raw = match headers.get("x-payment").and_then(|v| v.to_str().ok()) {
        Some(s) if !s.is_empty() => s,
        _ => return X402Outcome::NoXPayment,
    };

    // 3. x402 must be configured at boot. If the operator never configured
    //    x402 (kill switch at boot) but the agent presents X-Payment, the
    //    spec mandates an explicit `X402_NOT_ACCEPTED` with
    //    `subcause = "x402_disabled"` (Audit A-C7, spec §6.3) — NOT silent
    //    fallthrough to wallet. The agent must learn x402 was rejected.
    let cfg = match state.x402.as_ref() {
        Some(c) => c,
        None => {
            return X402Outcome::Error(X402Error::NotAccepted {
                subcause: "x402_disabled",
                message: "x402 is disabled on this Hub (operator kill switch at boot)".into(),
            });
        }
    };

    // 4. Feature flag check (30s TTL cache, fail-open). Same explicit rejection
    //    when the runtime kill switch is off (Audit A-C7).
    let pool_for_flag = state.pool.clone();
    let enabled = state
        .flags
        .is_enabled(&pool_for_flag, "x402_enabled")
        .await;
    if !enabled {
        return X402Outcome::Error(X402Error::NotAccepted {
            subcause: "x402_disabled",
            message: "x402 is currently disabled on this Hub (runtime kill switch)".into(),
        });
    }

    // 5. Capability manifest must declare x402 in payment_methods for this action.
    if !action_accepts_x402(manifest, action_id) {
        return X402Outcome::Error(X402Error::NotAccepted {
            subcause: "capability_wallet_only",
            message: format!(
                "action '{}' does not declare 'x402' in payment_methods",
                action_id
            ),
        });
    }

    // 5. Decode the X-Payment header.
    let payload = match decode_x_payment_header(x_payment_raw) {
        Ok(p) => p,
        Err(e) => return X402Outcome::Error(e),
    };

    // 6. Build PaymentRequirements for this invoke and validate.
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let amount_micro = (price_usdc * 1_000_000.0).round() as u128;
    let splitter_cap_id = derive_capability_id(namespace, action_id, version);
    let splitter_cap_id_hex = format!("0x{}", hex::encode(splitter_cap_id.as_slice()));

    let requirements = PaymentRequirements {
        scheme: "exact".into(),
        network: cfg.network.clone(),
        max_amount_required: amount_micro.to_string(),
        asset: cfg.usdc_asset,
        pay_to: cfg.splitter_address,
        resource: "https://jecp.dev/v1/invoke".into(),
        description: format!("Payment for capability {}", capability_id_str),
        mime_type: "application/json".into(),
        max_timeout_seconds: 60,
        extra: json!({
            "splitter_capability_id": splitter_cap_id_hex,
        }),
    };

    if let Err(e) = validate_payment_payload(&payload, &requirements, now_unix) {
        return X402Outcome::Error(e);
    }

    // 7. Pre-flight nonce replay check (DB).
    let payer_hex = format!("0x{}", hex::encode(payload.payload.authorization.from.as_slice()));
    let nonce_hex = format!("0x{}", hex::encode(payload.payload.authorization.nonce.as_slice()));
    let invoke_pool = match state.invoke_pool() {
        Some(p) => p,
        None => {
            return X402Outcome::Error(X402Error::PaymentInvalid {
                subcause: "db_unavailable",
                message: "Hub DB unavailable".into(),
            });
        }
    };

    match x402_settlements::exists_by_nonce(invoke_pool, &payer_hex, &nonce_hex).await {
        Ok(true) => {
            // Audit A-M1: enrich the error envelope with the conflicting row's
            // tx_hash + original_request_id + original_settled_at so SDKs can
            // fingerprint the replay and not retry blindly. Best-effort —
            // a missing row (race) still surfaces the bare envelope.
            let info = x402_settlements::find_existing_for_replay(
                invoke_pool,
                &payer_hex,
                &nonce_hex,
                None,
            )
            .await;
            if let Some(i) = info {
                return X402Outcome::Error(X402Error::SettlementReused {
                    subcause: "nonce_reused",
                    message: format!(
                        "EIP-3009 nonce {} already settled for payer {} (tx={}, original_request_id={})",
                        nonce_hex,
                        payer_hex,
                        i.tx_hash,
                        i.original_request_id,
                    ),
                    replay_info: Some(ReplayInfo {
                        tx_hash: i.tx_hash,
                        original_request_id: i.original_request_id,
                        original_settled_at: i.original_settled_at,
                    }),
                });
            }
            return X402Outcome::Error(X402Error::SettlementReused {
                subcause: "nonce_reused",
                message: format!(
                    "EIP-3009 nonce {} already settled for payer {}",
                    nonce_hex, payer_hex
                ),
                replay_info: None,
            });
        }
        Ok(false) => {}
        Err(e) => return X402Outcome::Error(e),
    }

    // 8. Facilitator verify (cheap).
    let verify_resp = match cfg.facilitator.verify(&payload, &requirements).await {
        Ok(r) => r,
        Err(e) => return X402Outcome::Error(e),
    };
    if !verify_resp.is_valid {
        return X402Outcome::Error(X402Error::PaymentInvalid {
            subcause: "facilitator_rejected",
            message: verify_resp.invalid_reason.unwrap_or_else(|| {
                "facilitator returned is_valid=false".to_string()
            }),
        });
    }

    // 9. Facilitator settle (on-chain commit).
    let settle_resp = match cfg.facilitator.settle(&payload, &requirements).await {
        Ok(r) => r,
        Err(e) => return X402Outcome::Error(e),
    };
    if !settle_resp.success || settle_resp.tx_hash.is_none() {
        return X402Outcome::Error(X402Error::PaymentInvalid {
            subcause: "settle_failed",
            message: settle_resp
                .error
                .unwrap_or_else(|| "facilitator /settle returned success=false".into()),
        });
    }
    let tx_hash = settle_resp.tx_hash.unwrap();
    let tx_hash_hex = format!("0x{}", hex::encode(tx_hash.as_slice()));

    // 10. Compute split (85/10/5) in micro.
    let amount_i64 = amount_micro as i64;
    let provider_micro = (amount_i64 * 8500) / 10_000;
    let hub_micro = (amount_i64 * 1000) / 10_000;
    let network_micro = amount_i64 - provider_micro - hub_micro;

    // 11. Persist the settlement.
    let facilitator_jsonb = serde_json::to_value(&serde_json::json!({
        "verify": { "is_valid": verify_resp.is_valid },
        "settle": {
            "success": settle_resp.success,
            "tx_hash": tx_hash_hex,
            "network_id": settle_resp.network_id,
        }
    }))
    .unwrap_or(Value::Null);

    let new = x402_settlements::NewSettlement {
        tx_hash: &tx_hash_hex,
        payer: &payer_hex,
        eip3009_nonce: &nonce_hex,
        agent_id,
        capability_id: capability_id_str,
        request_id,
        splitter_capability_id: &splitter_cap_id_hex,
        amount_usdc_micro: amount_i64,
        provider_share_micro: provider_micro,
        hub_share_micro: hub_micro,
        network_share_micro: network_micro,
        facilitator_response: &facilitator_jsonb,
    };
    let settlement_id = match x402_settlements::insert(invoke_pool, &new).await {
        Ok(id) => id,
        Err(X402Error::SettlementReused { subcause, message, .. }) => {
            // Audit A-M1: enrich the late-detected unique-constraint error
            // (race between exists_by_nonce and INSERT, OR tx_hash collision).
            let info = x402_settlements::find_existing_for_replay(
                invoke_pool,
                &payer_hex,
                &nonce_hex,
                Some(&tx_hash_hex),
            )
            .await;
            return X402Outcome::Error(X402Error::SettlementReused {
                subcause,
                message,
                replay_info: info.map(|i| ReplayInfo {
                    tx_hash: i.tx_hash,
                    original_request_id: i.original_request_id,
                    original_settled_at: i.original_settled_at,
                }),
            });
        }
        Err(e) => return X402Outcome::Error(e),
    };

    // 12. Build the X-Payment-Response header (base64 JSON per §3.4).
    // Spec §5: canonical keys are `transaction`, `network`, `payer` (Audit A-C2).
    let network_name = settle_resp.network_id.unwrap_or_else(|| cfg.network.clone());
    let payer_for_receipt = settle_resp
        .payer
        .map(|a| format!("0x{}", hex::encode(a.as_slice())))
        .unwrap_or_else(|| payer_hex.clone());
    let response_obj = json!({
        "success": true,
        "transaction": tx_hash_hex,
        "network": network_name,
        "payer": payer_for_receipt,
    });
    use base64::Engine;
    let payment_response_b64 = base64::engine::general_purpose::STANDARD
        .encode(serde_json::to_vec(&response_obj).unwrap_or_default());

    let facilitator_url = cfg.facilitator.base_url_str();

    X402Outcome::Settled(X402Billing {
        settlement_id,
        tx_hash: tx_hash_hex,
        payer: payer_for_receipt,
        network: network_name,
        facilitator_url,
        amount_usdc: price_usdc,
        provider_share_usdc: (provider_micro as f64) / 1_000_000.0,
        hub_share_usdc: (hub_micro as f64) / 1_000_000.0,
        network_share_usdc: (network_micro as f64) / 1_000_000.0,
        payment_response_b64,
        status: X402SettlementStatus::FacilitatorAttested,
    })
}

/// Read `actions[].payment_methods[]` from the manifest. Returns true
/// when the array contains "x402" (case-sensitive per spec).
fn action_accepts_x402(manifest: &Value, action_id: &str) -> bool {
    manifest
        .get("actions")
        .and_then(|a| a.as_array())
        .and_then(|arr| {
            arr.iter().find(|x| {
                x.get("id").and_then(|i| i.as_str()) == Some(action_id)
            })
        })
        .and_then(|a| a.get("pricing"))
        .and_then(|p| p.get("payment_methods"))
        .and_then(|m| m.as_array())
        .map(|arr| arr.iter().any(|v| v.as_str() == Some("x402")))
        .unwrap_or(false)
}

/// SHA-256 of the X-Payment header for the idempotency input hash
/// (Panel 2 TM-D2 + ADR-0004 — locked-design §4.1).
///
/// Currently inlined into `routes::invoke::compute_input_hash`; this
/// public form is retained so the SDK conformance harness + downstream
/// consumers can reproduce the same hash deterministically.
#[allow(dead_code)]
pub fn x_payment_sha256(header: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(header.as_bytes());
    hex::encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_accepts_x402_yes() {
        let m = json!({
            "actions": [
                {
                    "id": "translate",
                    "pricing": {
                        "base": 0.005,
                        "payment_methods": ["wallet", "x402"]
                    }
                }
            ]
        });
        assert!(action_accepts_x402(&m, "translate"));
    }

    #[test]
    fn action_accepts_x402_no_when_missing() {
        let m = json!({
            "actions": [
                { "id": "translate", "pricing": { "base": 0.005 } }
            ]
        });
        assert!(!action_accepts_x402(&m, "translate"));
    }

    #[test]
    fn action_accepts_x402_no_when_only_wallet() {
        let m = json!({
            "actions": [
                {
                    "id": "translate",
                    "pricing": {
                        "base": 0.005,
                        "payment_methods": ["wallet"]
                    }
                }
            ]
        });
        assert!(!action_accepts_x402(&m, "translate"));
    }

    #[test]
    fn x_payment_sha_stable() {
        let h1 = x_payment_sha256("abc");
        let h2 = x_payment_sha256("abc");
        assert_eq!(h1, h2);
        let h3 = x_payment_sha256("abd");
        assert_ne!(h1, h3);
    }
}
