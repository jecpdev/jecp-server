//! v1.1.0 x402 — RELAYER: submits Provider-signed register() txs (Am-1, Am-5).
//!
//! Stub helpers are intentionally unused in v1.1.0 ship — they're wired in
//! when AwsKmsRelayerSigner replaces StubRelayerSigner.
//!
//! ## Design
//!
//! The locked-design v1.1.1 (Am-1) inverts the original Hub-controlled
//! REGISTRAR model: the Provider signs `register()` via EIP-712, and the
//! Hub merely RELAYS the tx (pays gas, orders nonces). If the Hub
//! RELAYER key is compromised, the attacker can DoS new registrations
//! but cannot reassign capabilities — because the Provider's EIP-712
//! signature is required and binds to a specific provider address.
//!
//! Per locked-design Am-5, the RELAYER key MUST live in AWS KMS
//! (`alloy-signer-aws`); never plaintext in env vars or memory.
//!
//! ## Status of this module
//!
//! Two impls live behind the `RelayerSigner` trait. Selection is governed by
//! [`select_relayer_signer`] at boot:
//!
//! - **`StubRelayerSigner`** (this file) — returns `NotImplemented`. Used
//!   when `JECP_RELAYER_KMS_KEY_ID` is unset, preserving v1.1.0 behavior.
//! - **`AwsKmsRelayerSigner`** (`x402_relayer_aws_kms`) — production v1.1.1
//!   H-3 impl. KMS holds the secp256k1 private key; this Hub binary holds
//!   no key material at any point. Wired in `main.rs` AppState construction
//!   when the KMS key id env var is non-empty.
//!
//! `routes/manifests.rs::register_x402_capabilities_best_effort` is the
//! single call site and is unchanged across both impls — the only
//! difference is whether `send_register_tx()` returns `Ok(receipt)` or
//! `Err(NotImplemented)` (in which case the promote continues without
//! on-chain registration; the locked-design lazy-on-promote path).

#![allow(dead_code)]

use alloy_primitives::{Address, B256};

/// Errors a RelayerSigner can produce.
#[derive(Debug, thiserror::Error)]
pub enum RelayerError {
    #[error("relayer not implemented (DEFERRED — AWS KMS impl pending Am-5 follow-up)")]
    NotImplemented,
    #[error("provider signature invalid: {0}")]
    InvalidProviderSig(String),
    #[error("rpc error: {0}")]
    Rpc(String),
    #[error("tx submission timeout")]
    Timeout,
    #[error("revert: {0}")]
    Revert(String),
}

/// EIP-712 typed data the Provider signs to authorize a `register()` call.
/// Mirrors `JecpSplitter.Register` typehash (locked-design §7.2).
#[derive(Debug, Clone)]
pub struct RegisterAuthorization {
    pub capability_id: B256,
    pub provider: Address,
    pub provider_bps: u16,
    pub hub_bps: u16,
    pub reserve_bps: u16,
    pub nonce: B256,
    pub deadline: u64,
}

/// Result of a successful submission.
#[derive(Debug, Clone)]
pub struct RegisterTxReceipt {
    /// Submitted tx hash.
    pub tx_hash: B256,
    /// Block in which the tx was included (None until reconciled).
    pub block_number: Option<u64>,
}

/// Trait abstraction for the AWS KMS RELAYER signer.
///
/// Production impl (deferred):
///   1. Use `aws-sdk-kms` to sign the EIP-1559 tx hash with the KMS key.
///   2. Assemble the raw signed tx (no in-process private key material).
///   3. `eth_sendRawTransaction` to Base RPC.
///   4. Poll receipt with 60s timeout.
///   5. Return tx_hash + block_number.
#[async_trait::async_trait]
pub trait RelayerSigner: Send + Sync {
    /// Submit `Splitter.register(...)` with the Provider's EIP-712 signature.
    /// Returns the tx hash on success.
    async fn send_register_tx(
        &self,
        splitter_address: Address,
        auth: &RegisterAuthorization,
        provider_sig: &[u8; 65],
    ) -> Result<RegisterTxReceipt, RelayerError>;

    /// Address of the RELAYER key (the EOA paying gas).
    fn relayer_address(&self) -> Address;
}

// ────────────────────────────────────────────────────────────────────────────
// StubRelayerSigner — DEFERRED. Returns NotImplemented but compiles.
// ────────────────────────────────────────────────────────────────────────────

/// Stub impl used in v1.1.0 ship. Returns `NotImplemented` from every call so
/// the manifests promote flow surfaces the missing infra cleanly rather than
/// silently registering nothing on-chain.
///
/// Replaced by `AwsKmsRelayerSigner` once OQ-1 (AUTHORIZED_SETTLER) is
/// resolved and aws-sdk-kms is wired into Cargo.toml.
#[derive(Debug, Clone)]
pub struct StubRelayerSigner {
    relayer_address: Address,
}

impl StubRelayerSigner {
    pub fn new(relayer_address: Address) -> Self {
        Self { relayer_address }
    }
}

#[async_trait::async_trait]
impl RelayerSigner for StubRelayerSigner {
    async fn send_register_tx(
        &self,
        _splitter_address: Address,
        _auth: &RegisterAuthorization,
        _provider_sig: &[u8; 65],
    ) -> Result<RegisterTxReceipt, RelayerError> {
        Err(RelayerError::NotImplemented)
    }

    fn relayer_address(&self) -> Address {
        self.relayer_address
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Helper: parse the 65-byte (r || s || v) provider signature
// ────────────────────────────────────────────────────────────────────────────

/// Decode a 0x-prefixed hex signature into the canonical [u8; 65] form.
pub fn parse_provider_sig(hex_str: &str) -> Result<[u8; 65], RelayerError> {
    let stripped = hex_str.trim().trim_start_matches("0x");
    let bytes =
        hex::decode(stripped).map_err(|e| RelayerError::InvalidProviderSig(e.to_string()))?;
    if bytes.len() != 65 {
        return Err(RelayerError::InvalidProviderSig(format!(
            "expected 65 bytes (r||s||v), got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 65];
    out.copy_from_slice(&bytes);
    Ok(out)
}

// ────────────────────────────────────────────────────────────────────────────
// v1.1.1 H-3 — runtime signer selection
// ────────────────────────────────────────────────────────────────────────────

/// Identifies which `RelayerSigner` impl is active at boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayerSignerKind {
    /// `StubRelayerSigner` — returns `NotImplemented` (preserves v1.1.0
    /// behavior; safe when on-chain registration is intentionally skipped).
    Stub,
    /// `AwsKmsRelayerSigner` — production impl, signs via AWS KMS, never
    /// holds key material in process memory.
    AwsKms,
}

/// Choose the signer kind based on env. Pure helper — actual construction
/// of `AwsKmsRelayerSigner` lives in `main.rs` (it requires async + an
/// `aws_sdk_kms::Client`).
pub fn select_relayer_signer_kind(kms_key_id_env: Option<&str>) -> RelayerSignerKind {
    match kms_key_id_env {
        Some(id) if !id.trim().is_empty() => RelayerSignerKind::AwsKms,
        _ => RelayerSignerKind::Stub,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selector_picks_stub_when_unset() {
        assert_eq!(select_relayer_signer_kind(None), RelayerSignerKind::Stub);
        assert_eq!(select_relayer_signer_kind(Some("")), RelayerSignerKind::Stub);
        assert_eq!(select_relayer_signer_kind(Some("   ")), RelayerSignerKind::Stub);
    }

    #[test]
    fn selector_picks_kms_when_set() {
        let id = "arn:aws:kms:us-east-1:123:key/abc";
        assert_eq!(select_relayer_signer_kind(Some(id)), RelayerSignerKind::AwsKms);
    }

    #[tokio::test]
    async fn stub_returns_not_implemented() {
        let signer = StubRelayerSigner::new(Address::ZERO);
        let auth = RegisterAuthorization {
            capability_id: B256::ZERO,
            provider: Address::ZERO,
            provider_bps: 8500,
            hub_bps: 1000,
            reserve_bps: 500,
            nonce: B256::ZERO,
            deadline: 0,
        };
        let res = signer
            .send_register_tx(Address::ZERO, &auth, &[0u8; 65])
            .await;
        assert!(matches!(res, Err(RelayerError::NotImplemented)));
    }

    #[test]
    fn parses_valid_sig() {
        let hex_str = format!("0x{}", "ab".repeat(65));
        let sig = parse_provider_sig(&hex_str).unwrap();
        assert_eq!(sig.len(), 65);
        assert!(sig.iter().all(|b| *b == 0xab));
    }

    #[test]
    fn rejects_short_sig() {
        let err = parse_provider_sig("0xabcd").unwrap_err();
        assert!(matches!(err, RelayerError::InvalidProviderSig(_)));
    }
}
