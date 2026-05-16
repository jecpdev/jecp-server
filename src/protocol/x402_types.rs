//! v1.1.0 x402 — wire-format DTOs (locked-design §3).
//!
//! Pure types: no I/O, no DB, no HTTP. Easy to fuzz / property-test.
//!
//! Reference: docs/jecp/x402-integration-locked-design.md §3 (Wire Format)
//! and docs/jecp/x402-design/panel-3-architecture.md §1.4.

// Many fields are public API for SDK consumers / future modules; suppress
// dead-code warnings on this module specifically.
#![allow(dead_code)]

use alloy_primitives::{Address, B256, U256};
use serde::{Deserialize, Serialize};

// ────────────────────────────────────────────────────────────────────────────
// X-Payment header (agent → Hub retry, base64-encoded JSON; locked-design §3.2)
// ────────────────────────────────────────────────────────────────────────────

/// Decoded form of the `X-Payment` header per x402 spec §4.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PaymentPayload {
    #[serde(rename = "x402Version", alias = "x402_version")]
    pub x402_version: u8,
    /// "exact" for EIP-3009 transferWithAuthorization (locked).
    pub scheme: String,
    /// "base" for Base mainnet, "base-sepolia" for testnet.
    pub network: String,
    pub payload: ExactPayload,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExactPayload {
    /// EIP-712 signature, 0x-prefixed 65-byte hex (r || s || v).
    pub signature: String,
    pub authorization: Eip3009Authorization,
}

/// EIP-3009 `transferWithAuthorization` parameters. USDC supports this
/// natively per EIP-3009. All numeric values use string encoding per
/// the x402 spec to avoid JS BigInt loss.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Eip3009Authorization {
    /// Payer's address (0x...40 hex).
    pub from: Address,
    /// Recipient — MUST equal the Hub's Splitter contract address.
    pub to: Address,
    /// Amount in micro-USDC (1e6 = $1), decimal string.
    pub value: U256,
    /// Earliest valid unix timestamp (decimal string).
    #[serde(rename = "validAfter", alias = "valid_after")]
    pub valid_after: u64,
    /// Latest valid unix timestamp (decimal string).
    #[serde(rename = "validBefore", alias = "valid_before")]
    pub valid_before: u64,
    /// 32-byte random nonce (EIP-3009 replay defense at chain layer).
    pub nonce: B256,
}

// ────────────────────────────────────────────────────────────────────────────
// PaymentRequirements (Hub → agent on 402; locked-design §3.1)
// ────────────────────────────────────────────────────────────────────────────

/// PaymentRequirements wire-format (Hub → facilitator + Hub → agent).
///
/// Audit A-L1: JECP spec §2.2 and §4.2 use snake_case throughout
/// (`max_amount_required`, `pay_to`, `mime_type`, `max_timeout_seconds`).
/// We emit snake_case as canonical and accept camelCase via `#[serde(alias)]`
/// so we interoperate with x402.org-reference facilitators that historically
/// used camelCase. Symmetry: the on-the-wire 402 `accepts[]` array (built in
/// `routes/invoke::build_payment_accepts_inner`) also emits snake_case.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentRequirements {
    pub scheme: String,
    pub network: String,
    /// Maximum amount the Hub will accept (micro-USDC, decimal string).
    #[serde(rename = "max_amount_required", alias = "maxAmountRequired")]
    pub max_amount_required: String,
    /// USDC contract address on Base.
    pub asset: Address,
    /// Recipient — Splitter contract address.
    #[serde(rename = "pay_to", alias = "payTo")]
    pub pay_to: Address,
    /// The protected endpoint URL.
    pub resource: String,
    pub description: String,
    #[serde(rename = "mime_type", alias = "mimeType")]
    pub mime_type: String,
    #[serde(rename = "max_timeout_seconds", alias = "maxTimeoutSeconds")]
    pub max_timeout_seconds: u32,
    /// Hub-extension fields: splitter_capability_id, facilitator_url.
    pub extra: serde_json::Value,
}

// ────────────────────────────────────────────────────────────────────────────
// Facilitator request/response (locked-design §3.3)
// ────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct VerifyRequest<'a> {
    #[serde(rename = "x402Version")]
    pub x402_version: u8,
    #[serde(rename = "paymentPayload")]
    pub payment_payload: &'a PaymentPayload,
    #[serde(rename = "paymentRequirements")]
    pub payment_requirements: &'a PaymentRequirements,
}

#[derive(Debug, Clone, Deserialize)]
pub struct VerifyResponse {
    #[serde(rename = "isValid", alias = "is_valid")]
    pub is_valid: bool,
    #[serde(
        rename = "invalidReason",
        alias = "invalid_reason",
        alias = "errorReason",
        default
    )]
    pub invalid_reason: Option<String>,
    #[serde(default)]
    pub payer: Option<Address>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SettleRequest<'a> {
    #[serde(rename = "x402Version")]
    pub x402_version: u8,
    #[serde(rename = "paymentPayload")]
    pub payment_payload: &'a PaymentPayload,
    #[serde(rename = "paymentRequirements")]
    pub payment_requirements: &'a PaymentRequirements,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SettleResponse {
    pub success: bool,
    /// x402.org spec returns `errorReason`; accept legacy `error` too (Audit A-M5).
    #[serde(default, alias = "errorReason")]
    pub error: Option<String>,
    /// x402.org spec returns `transaction` (canonical). Accept `txHash` / `tx_hash`
    /// as legacy aliases for interop with non-conformant facilitators (Audit A-H7).
    #[serde(
        rename = "transaction",
        alias = "txHash",
        alias = "tx_hash",
        default
    )]
    pub tx_hash: Option<B256>,
    /// x402.org spec returns `network`. Accept `networkId` / `network_id` as legacy aliases.
    #[serde(
        rename = "network",
        alias = "networkId",
        alias = "network_id",
        default
    )]
    pub network_id: Option<String>,
    #[serde(default)]
    pub payer: Option<Address>,
}

// ────────────────────────────────────────────────────────────────────────────
// X402Settlement (DB audit row, locked-design §5.8)
// ────────────────────────────────────────────────────────────────────────────

/// Status state machine per locked-design §5.7.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum X402SettlementStatus {
    /// Facilitator returned tx_hash; reconciler has not yet confirmed.
    FacilitatorAttested,
    /// Reconciler verified inclusion + recipient + amount on Base.
    ChainConfirmed,
    /// Reconciler saw the tx but recipient or amount differs from facilitator claim.
    Mismatched,
    /// Facilitator returned failure / tx_hash invalid.
    Failed,
    /// Reconciler retried 30+ times (~30 min) and tx never appeared.
    Orphaned,
}

impl X402SettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            X402SettlementStatus::FacilitatorAttested => "facilitator_attested",
            X402SettlementStatus::ChainConfirmed => "chain_confirmed",
            X402SettlementStatus::Mismatched => "mismatched",
            X402SettlementStatus::Failed => "failed",
            X402SettlementStatus::Orphaned => "orphaned",
        }
    }
}

#[derive(Debug, Clone)]
pub struct X402Settlement {
    pub id: uuid::Uuid,
    pub tx_hash: String,
    pub payer: String,
    pub eip3009_nonce: String,
    pub agent_id: String,
    pub capability_id: String,
    pub request_id: String,
    pub splitter_capability_id: String,
    pub amount_usdc_micro: i64,
    pub provider_share_micro: i64,
    pub hub_share_micro: i64,
    pub network_share_micro: i64,
    pub status: X402SettlementStatus,
    pub reconcile_attempts: i32,
    pub last_reconcile_at: Option<chrono::DateTime<chrono::Utc>>,
    pub on_chain_amount_micro: Option<i64>,
    pub on_chain_recipient: Option<String>,
    pub facilitator_response_jsonb: serde_json::Value,
    pub settled_at: chrono::DateTime<chrono::Utc>,
    pub chain_confirmed_at: Option<chrono::DateTime<chrono::Utc>>,
}

// ────────────────────────────────────────────────────────────────────────────
// CapabilitySplit (on-chain JecpSplitter mapping read; locked-design §7.2)
// ────────────────────────────────────────────────────────────────────────────

/// Mirror of Solidity `struct CapabilitySplit` in JecpSplitter.sol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilitySplit {
    pub provider: Address,
    pub provider_bps: u16,
    pub hub_bps: u16,
    pub reserve_bps: u16,
    pub active: bool,
}

// ────────────────────────────────────────────────────────────────────────────
// X402Error (locked-design §3.5 new error codes)
// ────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, thiserror::Error)]
pub enum X402Error {
    /// X-Payment header missing, malformed, base64 invalid, or JSON parse fail.
    #[error("X402_PAYMENT_INVALID ({subcause}): {message}")]
    PaymentInvalid {
        subcause: &'static str,
        message: String,
    },

    /// Capability does not accept x402 (manifest payment_methods doesn't include "x402").
    #[error("X402_NOT_ACCEPTED ({subcause}): {message}")]
    NotAccepted {
        subcause: &'static str,
        message: String,
    },

    /// Facilitator timed out beyond max_timeout_seconds.
    ///
    /// `elapsed_ms` (Audit A-M2) is the wall-clock duration of the facilitator
    /// HTTP call as measured by the Hub. Surfaced into `details.elapsed_ms`.
    #[error("X402_SETTLEMENT_TIMEOUT ({subcause}): {message}")]
    SettlementTimeout {
        subcause: &'static str,
        message: String,
        elapsed_ms: Option<u64>,
    },

    /// Hub could not reach facilitator (DNS, TLS, cert pin, sig pin).
    #[error("X402_FACILITATOR_UNREACHABLE ({subcause}): {message}")]
    FacilitatorUnreachable {
        subcause: &'static str,
        message: String,
    },

    /// Same X-Payment / nonce / tx_hash submitted twice.
    ///
    /// `replay_info` (Audit A-M1) carries the original settlement metadata
    /// when known (lookup is best-effort). When `None`, the envelope omits
    /// the per-row `details.{tx_hash, original_request_id, original_settled_at}`
    /// triplet — only `subcause` is guaranteed.
    #[error("X402_SETTLEMENT_REUSED ({subcause}): {message}")]
    SettlementReused {
        subcause: &'static str,
        message: String,
        replay_info: Option<ReplayInfo>,
    },
}

/// Original-row metadata surfaced on `X402_SETTLEMENT_REUSED` envelopes
/// per spec §3.5 (Audit A-M1). RFC3339 timestamp serialization happens at
/// envelope-build time.
#[derive(Debug, Clone)]
pub struct ReplayInfo {
    pub tx_hash: String,
    pub original_request_id: String,
    pub original_settled_at: chrono::DateTime<chrono::Utc>,
}

impl X402Error {
    /// Map to the JECP wire-format `code` per §3.5.
    pub fn code(&self) -> &'static str {
        match self {
            X402Error::PaymentInvalid { .. } => "X402_PAYMENT_INVALID",
            X402Error::NotAccepted { .. } => "X402_NOT_ACCEPTED",
            X402Error::SettlementTimeout { .. } => "X402_SETTLEMENT_TIMEOUT",
            X402Error::FacilitatorUnreachable { .. } => "X402_FACILITATOR_UNREACHABLE",
            X402Error::SettlementReused { .. } => "X402_SETTLEMENT_REUSED",
        }
    }

    pub fn subcause(&self) -> &'static str {
        match self {
            X402Error::PaymentInvalid { subcause, .. }
            | X402Error::NotAccepted { subcause, .. }
            | X402Error::SettlementTimeout { subcause, .. }
            | X402Error::FacilitatorUnreachable { subcause, .. }
            | X402Error::SettlementReused { subcause, .. } => subcause,
        }
    }

    /// HTTP status code per §3.5.
    pub fn http_status(&self) -> u16 {
        match self {
            X402Error::PaymentInvalid { .. } => 422,
            X402Error::NotAccepted { .. } => 422,
            X402Error::SettlementTimeout { .. } => 504,
            X402Error::FacilitatorUnreachable { .. } => 502,
            X402Error::SettlementReused { .. } => 409,
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────────────

/// Convert U256 micro-USDC to f64 dollar amount (lossy at extreme values).
/// Safe within agent invoice range ($0–$1B).
pub fn micro_to_usd_f64(micro: u128) -> f64 {
    (micro as f64) / 1_000_000.0
}

/// Convert f64 USD to integer micro-USDC. Rounds.
pub fn usd_f64_to_micro(usd: f64) -> i64 {
    (usd * 1_000_000.0).round() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settlement_status_strings_stable() {
        // String form is wire-stable — must match DB CHECK constraints.
        assert_eq!(
            X402SettlementStatus::FacilitatorAttested.as_str(),
            "facilitator_attested"
        );
        assert_eq!(
            X402SettlementStatus::ChainConfirmed.as_str(),
            "chain_confirmed"
        );
        assert_eq!(X402SettlementStatus::Mismatched.as_str(), "mismatched");
        assert_eq!(X402SettlementStatus::Failed.as_str(), "failed");
        assert_eq!(X402SettlementStatus::Orphaned.as_str(), "orphaned");
    }

    #[test]
    fn micro_usd_roundtrip() {
        assert_eq!(usd_f64_to_micro(0.20), 200_000);
        assert_eq!(usd_f64_to_micro(1.0), 1_000_000);
        assert!((micro_to_usd_f64(200_000) - 0.20).abs() < f64::EPSILON);
    }

    #[test]
    fn error_codes_match_spec() {
        let e = X402Error::PaymentInvalid {
            subcause: "amount_mismatch",
            message: "x".into(),
        };
        assert_eq!(e.code(), "X402_PAYMENT_INVALID");
        assert_eq!(e.subcause(), "amount_mismatch");
        assert_eq!(e.http_status(), 422);

        let e = X402Error::SettlementReused {
            subcause: "nonce_reused",
            message: "x".into(),
            replay_info: None,
        };
        assert_eq!(e.http_status(), 409);
    }
}
