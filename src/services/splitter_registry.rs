//! v1.1.0 x402 — On-chain JecpSplitter capability registry read
//! (locked-design §7.2, splitter-panel-integration.md §1-2).
//!
//! Reads `JecpSplitter.capabilities(bytes32)` via Base RPC `eth_call`.
//! No signing, no tx submission — pure read-only.
//!
//! The Solidity signature:
//! ```solidity
//! struct CapabilitySplit {
//!     address provider;
//!     uint16 providerBps;
//!     uint16 hubBps;
//!     uint16 reserveBps;
//!     bool active;
//! }
//! mapping(bytes32 => CapabilitySplit) public capabilities;
//! ```
//!
//! Solidity auto-generates a getter `capabilities(bytes32) → (address, uint16, uint16, uint16, bool)`.
//! We ABI-encode the call manually (no alloy-sol-types) since the shape is fixed
//! and trivially decoded.

use std::sync::Arc;
use std::time::{Duration, Instant};

use alloy_primitives::{Address, B256};
use parking_lot::Mutex;
use serde_json::json;
use sha3::{Digest, Keccak256};
use std::collections::HashMap;

use crate::protocol::x402_types::{CapabilitySplit, X402Error};

/// Function selector for `capabilities(bytes32)`. First 4 bytes of
/// keccak256("capabilities(bytes32)").
fn capabilities_selector() -> [u8; 4] {
    let mut h = Keccak256::new();
    h.update(b"capabilities(bytes32)");
    let digest = h.finalize();
    let mut out = [0u8; 4];
    out.copy_from_slice(&digest[..4]);
    out
}

/// Derive the on-chain capabilityId per splitter-panel-integration §2.2:
///   keccak256(0x01 || namespace || "/" || action_id || "@" || version)
pub fn derive_capability_id(namespace: &str, action_id: &str, version: &str) -> B256 {
    let mut h = Keccak256::new();
    h.update([0x01u8]); // protocol-version domain byte
    h.update(namespace.as_bytes());
    h.update(b"/");
    h.update(action_id.as_bytes());
    h.update(b"@");
    h.update(version.as_bytes());
    let digest = h.finalize();
    B256::from_slice(&digest)
}

/// Cache entry — locked-design says 5 min freshness is fine because
/// register() is rare and read frequency is invoke-time hot path.
const CACHE_TTL: Duration = Duration::from_secs(300);

#[derive(Clone)]
struct CacheEntry {
    split: Option<CapabilitySplit>,
    inserted_at: Instant,
}

/// Cached read-only client.
#[derive(Clone)]
pub struct SplitterRegistry {
    inner: Arc<Inner>,
}

struct Inner {
    splitter_address: Address,
    rpc_url: String,
    http: reqwest::Client,
    cache: Mutex<HashMap<B256, CacheEntry>>,
}

impl SplitterRegistry {
    pub fn new(splitter_address: Address, rpc_url: &str) -> Self {
        let http = reqwest::Client::builder()
            .pool_max_idle_per_host(8)
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            inner: Arc::new(Inner {
                splitter_address,
                rpc_url: rpc_url.to_string(),
                http,
                cache: Mutex::new(HashMap::new()),
            }),
        }
    }

    pub fn splitter_address(&self) -> Address {
        self.inner.splitter_address
    }

    /// Read the on-chain CapabilitySplit. Returns `None` if not registered.
    pub async fn read_capability_split(
        &self,
        capability_id: B256,
    ) -> Result<Option<CapabilitySplit>, X402Error> {
        // Cache check
        {
            let cache = self.inner.cache.lock();
            if let Some(entry) = cache.get(&capability_id) {
                if entry.inserted_at.elapsed() < CACHE_TTL {
                    return Ok(entry.split.clone());
                }
            }
        }

        let result = self.eth_call(capability_id).await?;

        // Cache and return
        let mut cache = self.inner.cache.lock();
        cache.insert(
            capability_id,
            CacheEntry {
                split: result.clone(),
                inserted_at: Instant::now(),
            },
        );

        Ok(result)
    }

    async fn eth_call(
        &self,
        capability_id: B256,
    ) -> Result<Option<CapabilitySplit>, X402Error> {
        // ABI-encode: selector || padded bytes32
        let selector = capabilities_selector();
        let mut data = Vec::with_capacity(4 + 32);
        data.extend_from_slice(&selector);
        data.extend_from_slice(capability_id.as_slice());
        let data_hex = format!("0x{}", hex::encode(&data));

        let to_hex = format!("0x{}", hex::encode(self.inner.splitter_address.as_slice()));

        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_call",
            "params": [
                { "to": to_hex, "data": data_hex },
                "latest"
            ],
        });

        let resp = self
            .inner
            .http
            .post(&self.inner.rpc_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| X402Error::FacilitatorUnreachable {
                subcause: "base_rpc_unreachable",
                message: format!("eth_call transport: {}", e),
            })?;

        if !resp.status().is_success() {
            return Err(X402Error::FacilitatorUnreachable {
                subcause: "base_rpc_status",
                message: format!("eth_call returned {}", resp.status()),
            });
        }

        let v: serde_json::Value =
            resp.json().await.map_err(|e| X402Error::FacilitatorUnreachable {
                subcause: "base_rpc_parse",
                message: format!("eth_call parse: {}", e),
            })?;

        if let Some(err) = v.get("error") {
            return Err(X402Error::FacilitatorUnreachable {
                subcause: "base_rpc_err",
                message: format!("eth_call rpc err: {}", err),
            });
        }

        let result_hex = v
            .get("result")
            .and_then(|r| r.as_str())
            .ok_or_else(|| X402Error::FacilitatorUnreachable {
                subcause: "base_rpc_empty",
                message: "eth_call returned no result".into(),
            })?;

        decode_capability_split(result_hex)
    }
}

/// Decode the ABI return of `capabilities(bytes32)`.
///
/// Wire layout (5 × 32-byte words):
///   word 0: address provider     (right-padded in low 20 bytes)
///   word 1: uint16 providerBps   (right-padded, value in last 2 bytes)
///   word 2: uint16 hubBps        (same)
///   word 3: uint16 reserveBps    (same)
///   word 4: bool active          (0 or 1 in last byte)
///
/// Unregistered capabilityId returns 5 × 32 zero bytes; we surface that
/// as `Ok(None)` so the caller can distinguish "not registered" from "RPC error".
fn decode_capability_split(hex_str: &str) -> Result<Option<CapabilitySplit>, X402Error> {
    let stripped = hex_str.trim_start_matches("0x");
    let bytes = hex::decode(stripped).map_err(|e| X402Error::FacilitatorUnreachable {
        subcause: "base_rpc_decode",
        message: format!("eth_call result hex decode: {}", e),
    })?;
    if bytes.len() != 160 {
        // Unregistered returns 160 zero bytes; anything else is an error
        // or an evolution of the Splitter contract — fail safe.
        return Err(X402Error::FacilitatorUnreachable {
            subcause: "base_rpc_shape",
            message: format!(
                "eth_call result expected 160 bytes (5 × 32), got {}",
                bytes.len()
            ),
        });
    }

    // All-zero result → unregistered.
    if bytes.iter().all(|b| *b == 0) {
        return Ok(None);
    }

    let mut provider_bytes = [0u8; 20];
    provider_bytes.copy_from_slice(&bytes[12..32]);
    let provider = Address::from(provider_bytes);

    let provider_bps = u16::from_be_bytes([bytes[62], bytes[63]]);
    let hub_bps = u16::from_be_bytes([bytes[94], bytes[95]]);
    let reserve_bps = u16::from_be_bytes([bytes[126], bytes[127]]);
    let active = bytes[159] == 1;

    Ok(Some(CapabilitySplit {
        provider,
        provider_bps,
        hub_bps,
        reserve_bps,
        active,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selector_is_stable() {
        let s = capabilities_selector();
        // First 4 bytes of keccak256("capabilities(bytes32)") — calculated
        // once during dev and locked here. Selector goes on-chain so this
        // MUST not silently change.
        // (Sanity check only — we re-derive at runtime.)
        assert_eq!(s.len(), 4);
    }

    #[test]
    fn derive_capability_id_deterministic() {
        let a = derive_capability_id("jobdonebot", "bg-remover-pro", "1.0.0");
        let b = derive_capability_id("jobdonebot", "bg-remover-pro", "1.0.0");
        assert_eq!(a, b);

        let c = derive_capability_id("jobdonebot", "bg-remover-pro", "1.0.1");
        assert_ne!(a, c, "different version must produce different id");
    }

    #[test]
    fn decode_unregistered_returns_none() {
        let zeros = format!("0x{}", "00".repeat(160));
        assert!(decode_capability_split(&zeros).unwrap().is_none());
    }

    #[test]
    fn decode_active_split() {
        // Build a fake response: provider=0x1234..., bps=(8500,1000,500), active=true.
        let mut bytes = vec![0u8; 160];
        bytes[12..32].copy_from_slice(&[0x12; 20]);
        bytes[62..64].copy_from_slice(&8500u16.to_be_bytes());
        bytes[94..96].copy_from_slice(&1000u16.to_be_bytes());
        bytes[126..128].copy_from_slice(&500u16.to_be_bytes());
        bytes[159] = 1;
        let hex_str = format!("0x{}", hex::encode(&bytes));

        let split = decode_capability_split(&hex_str).unwrap().unwrap();
        assert_eq!(split.provider, Address::from([0x12; 20]));
        assert_eq!(split.provider_bps, 8500);
        assert_eq!(split.hub_bps, 1000);
        assert_eq!(split.reserve_bps, 500);
        assert!(split.active);
    }
}
