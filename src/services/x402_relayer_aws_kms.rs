//! v1.1.1 H-3 — Production AWS KMS RelayerSigner (locked-design Am-5).
//!
//! ## Why this exists
//!
//! Per locked-design v1.1.1 §2 Tension B + Am-1 + Am-5: the JECP Hub holds
//! NO authorization keys for the Splitter contract. It holds only a RELAYER
//! key (gas-payer + nonce sequencer) used to call `JecpSplitter.register()`
//! on behalf of Provider EIP-712 signatures. Per Am-5 the RELAYER key MUST
//! live in AWS KMS — never plaintext anywhere in the process.
//!
//! Task#3 shipped `StubRelayerSigner` returning `RelayerError::NotImplemented`
//! so the wire plumbing could compile and tests run without an AWS dep
//! footprint. H-3 is the production replacement: a `RelayerSigner` impl
//! backed by AWS KMS that signs Ethereum EIP-1559 transactions and submits
//! them to Base RPC.
//!
//! ## Architecture
//!
//! ```text
//!     manifests::promote → relayer.send_register_tx(...)
//!                                      │
//!                                      ▼
//!         AwsKmsRelayerSigner::send_register_tx
//!           1. eth_getTransactionCount  (Base RPC) → nonce
//!           2. eth_gasPrice + EIP-1559 priority    → fees
//!           3. encode_register_calldata(...)        → 4-byte selector + args
//!           4. encode EIP-1559 unsigned tx (RLP)   → digest
//!           5. KMS Sign (ECDSA_SHA_256)            → DER sig
//!           6. parse DER → (r, s)
//!           7. low-s normalize
//!           8. y-parity recovery (try v=0/v=1; pubkey must match self.address)
//!           9. encode signed tx envelope (0x02 || rlp([...]))
//!          10. eth_sendRawTransaction              → tx hash
//! ```
//!
//! ## Backward compatibility
//!
//! This signer is opt-in via `JECP_RELAYER_KMS_KEY_ID`. When unset,
//! `AppState` falls back to `StubRelayerSigner` exactly as before. Existing
//! deploys see zero behavior change.
//!
//! ## Deferred
//!
//! - Nonce manager: this impl uses `eth_getTransactionCount` per call (simple,
//!   correct under low submit volume <100/day expected). In-memory counter
//!   with reorg recovery is deferred to v1.2 when daily register volume
//!   exceeds 100.
//! - Receipt polling: returns the tx hash on submit; reconciler service
//!   polls receipts (already wired in `x402_reconciler.rs`).
//! - Ledger / hardware backup signer: deferred until quarterly RELAYER key
//!   rotation playbook is drafted (locked-design §7.5).

#![allow(dead_code)]

use std::sync::Arc;
use std::time::Duration;

use alloy_primitives::{Address, B256, U256};
use alloy_rlp::Header;
use sha3::{Digest, Keccak256};
use tokio::sync::Mutex;

use crate::services::x402_relayer::{
    RegisterAuthorization, RegisterTxReceipt, RelayerError, RelayerSigner,
};

// ────────────────────────────────────────────────────────────────────────────
// Errors specific to AWS KMS bring-up. Public surface stays
// `RelayerError` (the trait).
// ────────────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum AwsKmsRelayerError {
    #[error("kms describe key failed: {0}")]
    KmsDescribe(String),
    #[error("kms get_public_key failed: {0}")]
    KmsGetPublicKey(String),
    #[error("kms returned no public key bytes")]
    KmsNoPublicKey,
    #[error("invalid SubjectPublicKeyInfo from KMS: {0}")]
    InvalidSpki(String),
    #[error("kms key derived address {derived:?} != configured RELAYER_ADDRESS {expected:?}")]
    AddressMismatch { derived: Address, expected: Address },
    #[error("invalid rpc url: {0}")]
    InvalidRpcUrl(String),
    #[error("http client init failed: {0}")]
    HttpClient(String),
}

impl From<AwsKmsRelayerError> for RelayerError {
    fn from(e: AwsKmsRelayerError) -> Self {
        RelayerError::Rpc(e.to_string())
    }
}

// ────────────────────────────────────────────────────────────────────────────
// secp256k1 group order N (used for low-s normalization).
// ────────────────────────────────────────────────────────────────────────────

/// secp256k1 curve order (N).
const SECP256K1_N: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

/// N / 2 (rounded down). Used to enforce low-s on ECDSA sigs (EIP-2 / BIP-62).
const SECP256K1_N_HALF: [u8; 32] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0,
];

/// Returns true if `s` (32 BE bytes) is greater than N/2.
fn is_high_s(s: &[u8; 32]) -> bool {
    for i in 0..32 {
        match s[i].cmp(&SECP256K1_N_HALF[i]) {
            std::cmp::Ordering::Greater => return true,
            std::cmp::Ordering::Less => return false,
            std::cmp::Ordering::Equal => continue,
        }
    }
    false
}

/// Normalize s to the low-s form (s' = N - s if s > N/2). Returns whether
/// the value was flipped — caller flips y-parity guess accordingly.
fn normalize_s(s_in: &[u8; 32]) -> ([u8; 32], bool) {
    if !is_high_s(s_in) {
        return (*s_in, false);
    }
    // s' = N - s
    let mut out = [0u8; 32];
    let mut borrow: i16 = 0;
    for i in (0..32).rev() {
        let n_i = SECP256K1_N[i] as i16;
        let s_i = s_in[i] as i16;
        let diff = n_i - s_i - borrow;
        if diff < 0 {
            out[i] = (diff + 256) as u8;
            borrow = 1;
        } else {
            out[i] = diff as u8;
            borrow = 0;
        }
    }
    (out, true)
}

// ────────────────────────────────────────────────────────────────────────────
// DER ECDSA signature parsing
//
// AWS KMS Sign returns raw DER:
//   SEQUENCE {
//     INTEGER r,
//     INTEGER s,
//   }
// Both r and s are positive ASN.1 INTEGERs which means a leading 0x00
// byte may be present to disambiguate the sign bit. We strip it.
// ────────────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DerError {
    #[error("der: short input")]
    Short,
    #[error("der: expected SEQUENCE tag 0x30, got {0:#x}")]
    BadSeqTag(u8),
    #[error("der: expected INTEGER tag 0x02, got {0:#x}")]
    BadIntTag(u8),
    #[error("der: integer length {0} too large (max 33 with sign byte)")]
    IntTooLarge(usize),
    #[error("der: trailing bytes after sequence")]
    Trailing,
}

/// Parse a DER ECDSA signature into (r, s) as big-endian 32-byte arrays.
pub fn parse_der_signature(der: &[u8]) -> Result<([u8; 32], [u8; 32]), DerError> {
    if der.len() < 8 {
        return Err(DerError::Short);
    }
    let mut p = 0;
    if der[p] != 0x30 {
        return Err(DerError::BadSeqTag(der[p]));
    }
    p += 1;
    // Length encoding: short-form only (KMS returns < 128 length).
    let seq_len = der[p] as usize;
    p += 1;
    if p + seq_len > der.len() {
        return Err(DerError::Short);
    }
    let seq_end = p + seq_len;

    let r = read_der_int(&der[p..seq_end])?;
    p += 2 + r.raw_len;
    let s = read_der_int(&der[p..seq_end])?;
    p += 2 + s.raw_len;

    if p != seq_end {
        return Err(DerError::Trailing);
    }

    Ok((r.value_be32, s.value_be32))
}

struct DerInt {
    value_be32: [u8; 32],
    raw_len: usize,
}

fn read_der_int(buf: &[u8]) -> Result<DerInt, DerError> {
    if buf.len() < 2 {
        return Err(DerError::Short);
    }
    if buf[0] != 0x02 {
        return Err(DerError::BadIntTag(buf[0]));
    }
    let len = buf[1] as usize;
    if len == 0 || len > 33 {
        return Err(DerError::IntTooLarge(len));
    }
    if buf.len() < 2 + len {
        return Err(DerError::Short);
    }
    let raw = &buf[2..2 + len];
    // Strip leading 0x00 sign byte if present.
    let stripped: &[u8] = if raw.len() == 33 && raw[0] == 0x00 {
        &raw[1..]
    } else {
        raw
    };
    if stripped.len() > 32 {
        return Err(DerError::IntTooLarge(stripped.len()));
    }
    let mut out = [0u8; 32];
    let off = 32 - stripped.len();
    out[off..].copy_from_slice(stripped);
    Ok(DerInt {
        value_be32: out,
        raw_len: len,
    })
}

// ────────────────────────────────────────────────────────────────────────────
// SubjectPublicKeyInfo parser (KMS GetPublicKey response).
//
// KMS returns:
//   SEQUENCE {
//     SEQUENCE {
//       OBJECT IDENTIFIER ecPublicKey,
//       OBJECT IDENTIFIER secp256k1,
//     },
//     BIT STRING uncompressed_pubkey  (0x04 || X || Y, 65 bytes)
//   }
//
// We don't validate the OIDs strictly — we just extract the BIT STRING
// payload and verify it's the uncompressed-secp256k1 form (1 + 64 bytes,
// leading 0x04). The KMS key spec is constrained at create time
// (`ECC_SECG_P256K1`); a wrong key would fail address-derivation match
// against `JECP_RELAYER_ADDRESS` at boot.
// ────────────────────────────────────────────────────────────────────────────

/// Extract the 64-byte uncompressed public key (X || Y) from a KMS-returned
/// SubjectPublicKeyInfo DER blob.
///
/// Walk: outer SEQUENCE { alg SEQUENCE {OIDs}, BIT STRING { 0x00, 0x04, X, Y } }
/// We skip the algorithm SEQUENCE and inspect only the BIT STRING contents.
pub fn extract_uncompressed_pubkey(spki: &[u8]) -> Result<[u8; 64], AwsKmsRelayerError> {
    let mut p = 0usize;

    // Outer SEQUENCE
    if spki.len() < 2 || spki[p] != 0x30 {
        return Err(AwsKmsRelayerError::InvalidSpki("missing outer SEQUENCE".into()));
    }
    p += 1;
    let outer_len = der_len_skip(spki, &mut p)?;
    let outer_end = p + outer_len;
    if outer_end > spki.len() {
        return Err(AwsKmsRelayerError::InvalidSpki("outer SEQUENCE runs past buffer".into()));
    }

    // Inner: algorithm SEQUENCE — read header and skip its payload entirely.
    if p >= outer_end || spki[p] != 0x30 {
        return Err(AwsKmsRelayerError::InvalidSpki("missing alg SEQUENCE".into()));
    }
    p += 1;
    let alg_payload_len = der_len_skip(spki, &mut p)?;
    p = p
        .checked_add(alg_payload_len)
        .ok_or_else(|| AwsKmsRelayerError::InvalidSpki("alg overflow".into()))?;
    if p > outer_end {
        return Err(AwsKmsRelayerError::InvalidSpki("alg SEQUENCE overruns".into()));
    }

    // BIT STRING
    if p >= outer_end || spki[p] != 0x03 {
        return Err(AwsKmsRelayerError::InvalidSpki("missing BIT STRING".into()));
    }
    p += 1;
    let bit_len = der_len_skip(spki, &mut p)?;
    if p
        .checked_add(bit_len)
        .map(|end| end > spki.len() || end > outer_end)
        .unwrap_or(true)
    {
        return Err(AwsKmsRelayerError::InvalidSpki("BIT STRING runs past buffer".into()));
    }
    let body = &spki[p..p + bit_len];

    // BIT STRING body: first byte = unused bits (must be 0).
    if body.len() != 66 {
        return Err(AwsKmsRelayerError::InvalidSpki(format!(
            "expected 66-byte BIT STRING content (1 unused-bits + 1 prefix + 64 X||Y), got {}",
            body.len()
        )));
    }
    if body[0] != 0x00 {
        return Err(AwsKmsRelayerError::InvalidSpki("non-zero unused-bits".into()));
    }
    if body[1] != 0x04 {
        return Err(AwsKmsRelayerError::InvalidSpki(
            "pubkey is not in uncompressed form (expected 0x04 prefix)".into(),
        ));
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&body[2..66]);
    Ok(out)
}

/// DER length parser. Returns the payload length and advances `p` past the length bytes.
fn der_len_skip(buf: &[u8], p: &mut usize) -> Result<usize, AwsKmsRelayerError> {
    if *p >= buf.len() {
        return Err(AwsKmsRelayerError::InvalidSpki("DER length truncated".into()));
    }
    let b = buf[*p];
    *p += 1;
    if b < 0x80 {
        Ok(b as usize)
    } else {
        let nbytes = (b & 0x7F) as usize;
        if nbytes == 0 || nbytes > 4 {
            return Err(AwsKmsRelayerError::InvalidSpki(format!(
                "unsupported DER long-form length {}",
                nbytes
            )));
        }
        if *p + nbytes > buf.len() {
            return Err(AwsKmsRelayerError::InvalidSpki("DER length truncated".into()));
        }
        let mut v = 0usize;
        for _ in 0..nbytes {
            v = (v << 8) | buf[*p] as usize;
            *p += 1;
        }
        Ok(v)
    }
}

/// keccak256(uncompressed_pubkey) → take last 20 bytes → Ethereum address.
pub fn address_from_uncompressed_pubkey(xy: &[u8; 64]) -> Address {
    let mut h = Keccak256::new();
    h.update(xy);
    let digest = h.finalize();
    let mut out = [0u8; 20];
    out.copy_from_slice(&digest[12..]);
    Address::from(out)
}

// ────────────────────────────────────────────────────────────────────────────
// y-parity recovery via k256.
//
// Given (msg_hash, r, s, expected_address), try v=0 and v=1; recover
// the public key, derive the address; pick the v that matches.
// ────────────────────────────────────────────────────────────────────────────

fn recover_y_parity(
    msg_hash: &[u8; 32],
    r: &[u8; 32],
    s: &[u8; 32],
    expected: Address,
) -> Result<u8, RelayerError> {
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(r);
    sig_bytes[32..].copy_from_slice(s);
    let sig = Signature::from_slice(&sig_bytes)
        .map_err(|e| RelayerError::Rpc(format!("k256 sig decode: {}", e)))?;

    for v in 0u8..=1u8 {
        let rid = RecoveryId::from_byte(v).ok_or_else(|| RelayerError::Rpc("bad recid".into()))?;
        if let Ok(vk) = VerifyingKey::recover_from_prehash(msg_hash, &sig, rid) {
            let enc = vk.to_encoded_point(false);
            let bytes = enc.as_bytes();
            if bytes.len() != 65 || bytes[0] != 0x04 {
                continue;
            }
            let mut xy = [0u8; 64];
            xy.copy_from_slice(&bytes[1..]);
            let addr = address_from_uncompressed_pubkey(&xy);
            if addr == expected {
                return Ok(v);
            }
        }
    }
    Err(RelayerError::Rpc(
        "y-parity recovery failed: neither v=0 nor v=1 matches RELAYER address".into(),
    ))
}

// ────────────────────────────────────────────────────────────────────────────
// EIP-1559 transaction RLP encoding (type 0x02).
//
// Payload list:
//   [chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas,
//    gas_limit, to, value, data, access_list,
//    /* signed: */ y_parity, r, s]
//
// All numerics are minimal-leading-zero big-endian RLP integers.
// `to` is the 20-byte destination address (or empty for contract creation).
// `access_list` is an empty RLP list when no access list (typical).
// ────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Eip1559Tx {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: u128,
    pub max_fee_per_gas: u128,
    pub gas_limit: u64,
    pub to: Address,
    pub value: U256,
    pub data: Vec<u8>,
    // access_list: omitted (always empty for our register() call)
}

impl Eip1559Tx {
    /// RLP-encode the unsigned tx body and prepend the 0x02 type byte.
    pub fn encode_for_signing(&self) -> Vec<u8> {
        let mut out = vec![0x02u8];
        let mut payload = Vec::with_capacity(256);
        self.encode_payload(&mut payload, /* with_sig= */ None);
        out.extend_from_slice(&payload);
        out
    }

    /// Compute the keccak256 digest of `encode_for_signing()`.
    pub fn signing_digest(&self) -> [u8; 32] {
        let body = self.encode_for_signing();
        let mut h = Keccak256::new();
        h.update(&body);
        let d = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&d);
        out
    }

    /// RLP-encode the signed tx envelope: 0x02 || rlp([...payload..., y_parity, r, s]).
    pub fn encode_signed(&self, y_parity: u8, r: &[u8; 32], s: &[u8; 32]) -> Vec<u8> {
        let mut out = vec![0x02u8];
        let mut payload = Vec::with_capacity(256);
        self.encode_payload(&mut payload, Some((y_parity, r, s)));
        out.extend_from_slice(&payload);
        out
    }

    /// Encode the RLP list payload (with or without signature elements).
    fn encode_payload(&self, out: &mut Vec<u8>, sig: Option<(u8, &[u8; 32], &[u8; 32])>) {
        // Compute payload length first.
        let mut body = Vec::with_capacity(192);
        u64_to_rlp(self.chain_id, &mut body);
        u64_to_rlp(self.nonce, &mut body);
        u128_to_rlp(self.max_priority_fee_per_gas, &mut body);
        u128_to_rlp(self.max_fee_per_gas, &mut body);
        u64_to_rlp(self.gas_limit, &mut body);
        // to: 20-byte address as RLP string
        bytes_to_rlp(self.to.as_slice(), &mut body);
        // value: U256 BE, minimal-leading-zero
        u256_to_rlp(&self.value, &mut body);
        // data
        bytes_to_rlp(&self.data, &mut body);
        // access_list: empty list 0xc0
        body.push(0xc0);
        // Signature (if signed envelope)
        if let Some((y, r, s)) = sig {
            u64_to_rlp(y as u64, &mut body);
            // r and s as integers (minimal-leading-zero).
            int32_to_rlp(r, &mut body);
            int32_to_rlp(s, &mut body);
        }
        // Wrap in an RLP list header.
        let h = Header {
            list: true,
            payload_length: body.len(),
        };
        h.encode(out);
        out.extend_from_slice(&body);
    }
}

fn u64_to_rlp(v: u64, out: &mut Vec<u8>) {
    let be = v.to_be_bytes();
    let stripped = strip_leading_zeros(&be);
    bytes_to_rlp(stripped, out);
}

fn u128_to_rlp(v: u128, out: &mut Vec<u8>) {
    let be = v.to_be_bytes();
    let stripped = strip_leading_zeros(&be);
    bytes_to_rlp(stripped, out);
}

fn u256_to_rlp(v: &U256, out: &mut Vec<u8>) {
    let be = v.to_be_bytes::<32>();
    let stripped = strip_leading_zeros(&be);
    bytes_to_rlp(stripped, out);
}

fn int32_to_rlp(v: &[u8; 32], out: &mut Vec<u8>) {
    let stripped = strip_leading_zeros(v);
    bytes_to_rlp(stripped, out);
}

fn strip_leading_zeros(buf: &[u8]) -> &[u8] {
    let mut i = 0;
    while i < buf.len() && buf[i] == 0 {
        i += 1;
    }
    &buf[i..]
}

fn bytes_to_rlp(buf: &[u8], out: &mut Vec<u8>) {
    if buf.len() == 1 && buf[0] < 0x80 {
        out.push(buf[0]);
        return;
    }
    let h = Header {
        list: false,
        payload_length: buf.len(),
    };
    h.encode(out);
    out.extend_from_slice(buf);
}

// ────────────────────────────────────────────────────────────────────────────
// register() calldata encoding.
//
// Solidity:
//   function register(
//       bytes32 capabilityId,
//       address provider,
//       uint16 providerBps,
//       uint16 hubBps,
//       uint16 reserveBps,
//       bytes32 nonce,
//       uint256 deadline,
//       bytes calldata providerSig
//   ) external;
//
// ABI: 4-byte selector + head (8 args × 32 bytes) + tail (bytes data).
// ────────────────────────────────────────────────────────────────────────────

fn register_selector() -> [u8; 4] {
    let mut h = Keccak256::new();
    h.update(b"register(bytes32,address,uint16,uint16,uint16,bytes32,uint256,bytes)");
    let d = h.finalize();
    let mut out = [0u8; 4];
    out.copy_from_slice(&d[..4]);
    out
}

/// Build calldata for `JecpSplitter.register(...)`.
pub fn encode_register_calldata(
    auth: &RegisterAuthorization,
    provider_sig: &[u8; 65],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 32 * 9 + 96);
    out.extend_from_slice(&register_selector());

    // head: 8 fixed-size args (bytes is dynamic, so we put an offset there)
    // word 0: capabilityId
    out.extend_from_slice(auth.capability_id.as_slice());
    // word 1: provider (left-padded)
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(auth.provider.as_slice());
    out.extend_from_slice(&w);
    // word 2: providerBps
    out.extend_from_slice(&u16_word(auth.provider_bps));
    // word 3: hubBps
    out.extend_from_slice(&u16_word(auth.hub_bps));
    // word 4: reserveBps
    out.extend_from_slice(&u16_word(auth.reserve_bps));
    // word 5: nonce
    out.extend_from_slice(auth.nonce.as_slice());
    // word 6: deadline
    out.extend_from_slice(&u256_word_from_u64(auth.deadline));
    // word 7: offset to providerSig bytes data = 8 * 32 = 256
    out.extend_from_slice(&u256_word_from_u64(8 * 32));

    // tail: bytes providerSig
    // length word
    out.extend_from_slice(&u256_word_from_u64(provider_sig.len() as u64));
    // data, padded to 32 bytes
    out.extend_from_slice(provider_sig);
    let pad = (32 - (provider_sig.len() % 32)) % 32;
    out.extend(std::iter::repeat(0u8).take(pad));

    out
}

fn u16_word(v: u16) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[30..].copy_from_slice(&v.to_be_bytes());
    w
}

fn u256_word_from_u64(v: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&v.to_be_bytes());
    w
}

// ────────────────────────────────────────────────────────────────────────────
// AwsKmsRelayerSigner — production impl.
// ────────────────────────────────────────────────────────────────────────────

pub struct AwsKmsRelayerSigner {
    kms_client: aws_sdk_kms::Client,
    key_id: String,
    address: Address,
    rpc_url: url::Url,
    chain_id: u64,
    http: reqwest::Client,
    /// Coarse mutex serialising tx submission so two concurrent register()
    /// calls cannot fetch the same nonce. v1.2 will replace with an
    /// in-memory nonce manager + reorg recovery.
    nonce_lock: Arc<Mutex<()>>,
}

impl AwsKmsRelayerSigner {
    /// Construct + verify KMS access. Performs one KMS GetPublicKey call to
    /// derive the relayer Ethereum address; if `expected_address` is supplied
    /// (typical: from `JECP_RELAYER_ADDRESS` env), the derived address MUST
    /// match — otherwise we fail-closed at boot rather than burn gas
    /// accidentally signing for a different EOA.
    pub async fn new(
        kms_client: aws_sdk_kms::Client,
        key_id: String,
        rpc_url: url::Url,
        chain_id: u64,
        expected_address: Option<Address>,
    ) -> Result<Self, AwsKmsRelayerError> {
        // Fetch + decode KMS public key.
        let resp = kms_client
            .get_public_key()
            .key_id(&key_id)
            .send()
            .await
            .map_err(|e| AwsKmsRelayerError::KmsGetPublicKey(format!("{}", e)))?;
        let spki = resp
            .public_key()
            .ok_or(AwsKmsRelayerError::KmsNoPublicKey)?;
        let xy = extract_uncompressed_pubkey(spki.as_ref())?;
        let derived = address_from_uncompressed_pubkey(&xy);

        if let Some(exp) = expected_address {
            if derived != exp {
                return Err(AwsKmsRelayerError::AddressMismatch {
                    derived,
                    expected: exp,
                });
            }
        }

        let http = reqwest::Client::builder()
            .pool_max_idle_per_host(4)
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| AwsKmsRelayerError::HttpClient(e.to_string()))?;

        Ok(Self {
            kms_client,
            key_id,
            address: derived,
            rpc_url,
            chain_id,
            http,
            nonce_lock: Arc::new(Mutex::new(())),
        })
    }

    /// Returns the Ethereum address derived from the KMS public key.
    pub fn address(&self) -> Address {
        self.address
    }

    async fn rpc(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value, RelayerError> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id":      1,
            "method":  method,
            "params":  params,
        });
        let resp = self
            .http
            .post(self.rpc_url.as_str())
            .json(&body)
            .send()
            .await
            .map_err(|e| RelayerError::Rpc(format!("{} transport: {}", method, e)))?;
        if !resp.status().is_success() {
            return Err(RelayerError::Rpc(format!("{} status {}", method, resp.status())));
        }
        let v: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| RelayerError::Rpc(format!("{} parse: {}", method, e)))?;
        if let Some(err) = v.get("error") {
            return Err(RelayerError::Rpc(format!("{} rpc-err: {}", method, err)));
        }
        v.get("result")
            .cloned()
            .ok_or_else(|| RelayerError::Rpc(format!("{} no result", method)))
    }

    async fn get_nonce(&self) -> Result<u64, RelayerError> {
        let to_hex = format!("0x{}", hex::encode(self.address.as_slice()));
        let r = self
            .rpc("eth_getTransactionCount", serde_json::json!([to_hex, "pending"]))
            .await?;
        let s = r.as_str().ok_or_else(|| RelayerError::Rpc("nonce: not string".into()))?;
        u64::from_str_radix(s.trim_start_matches("0x"), 16)
            .map_err(|e| RelayerError::Rpc(format!("nonce parse: {}", e)))
    }

    async fn get_gas_price(&self) -> Result<u128, RelayerError> {
        let r = self.rpc("eth_gasPrice", serde_json::json!([])).await?;
        let s = r.as_str().ok_or_else(|| RelayerError::Rpc("gas: not string".into()))?;
        u128::from_str_radix(s.trim_start_matches("0x"), 16)
            .map_err(|e| RelayerError::Rpc(format!("gas parse: {}", e)))
    }

    async fn estimate_gas(&self, to: Address, data: &[u8]) -> Result<u64, RelayerError> {
        let from_hex = format!("0x{}", hex::encode(self.address.as_slice()));
        let to_hex = format!("0x{}", hex::encode(to.as_slice()));
        let data_hex = format!("0x{}", hex::encode(data));
        let r = self
            .rpc(
                "eth_estimateGas",
                serde_json::json!([{
                    "from": from_hex, "to": to_hex, "data": data_hex,
                }]),
            )
            .await?;
        let s = r.as_str().ok_or_else(|| RelayerError::Rpc("gas est: not string".into()))?;
        u64::from_str_radix(s.trim_start_matches("0x"), 16)
            .map_err(|e| RelayerError::Rpc(format!("gas est parse: {}", e)))
    }

    async fn send_raw(&self, raw: &[u8]) -> Result<B256, RelayerError> {
        let raw_hex = format!("0x{}", hex::encode(raw));
        let r = self
            .rpc("eth_sendRawTransaction", serde_json::json!([raw_hex]))
            .await?;
        let s = r.as_str().ok_or_else(|| RelayerError::Rpc("send: not string".into()))?;
        let stripped = s.trim_start_matches("0x");
        let bytes = hex::decode(stripped).map_err(|e| RelayerError::Rpc(format!("hash hex: {}", e)))?;
        if bytes.len() != 32 {
            return Err(RelayerError::Rpc(format!("hash bad len {}", bytes.len())));
        }
        Ok(B256::from_slice(&bytes))
    }

    async fn kms_sign(&self, digest: &[u8; 32]) -> Result<([u8; 32], [u8; 32]), RelayerError> {
        use aws_sdk_kms::primitives::Blob;
        use aws_sdk_kms::types::{MessageType, SigningAlgorithmSpec};

        let resp = self
            .kms_client
            .sign()
            .key_id(&self.key_id)
            .message(Blob::new(digest.to_vec()))
            .message_type(MessageType::Digest)
            .signing_algorithm(SigningAlgorithmSpec::EcdsaSha256)
            .send()
            .await
            .map_err(|e| RelayerError::Rpc(format!("kms sign: {}", e)))?;
        let der = resp
            .signature()
            .ok_or_else(|| RelayerError::Rpc("kms sign: no signature".into()))?
            .as_ref()
            .to_vec();
        let (r, s_raw) = parse_der_signature(&der)
            .map_err(|e| RelayerError::Rpc(format!("kms der: {:?}", e)))?;
        let (s, _flipped) = normalize_s(&s_raw);
        Ok((r, s))
    }
}

#[async_trait::async_trait]
impl RelayerSigner for AwsKmsRelayerSigner {
    async fn send_register_tx(
        &self,
        splitter_address: Address,
        auth: &RegisterAuthorization,
        provider_sig: &[u8; 65],
    ) -> Result<RegisterTxReceipt, RelayerError> {
        // Serialize submission: nonce ordering safety for v1.1.x.
        let _guard = self.nonce_lock.lock().await;

        let calldata = encode_register_calldata(auth, provider_sig);

        let nonce = self.get_nonce().await?;
        let base_gas_price = self.get_gas_price().await?;
        // EIP-1559 fee shape: priority 2 gwei, max fee = 2*base + tip.
        let priority_fee: u128 = 2_000_000_000;
        let max_fee: u128 = base_gas_price.saturating_mul(2).saturating_add(priority_fee);
        let est = self.estimate_gas(splitter_address, &calldata).await?;
        let gas_limit = est.saturating_add(est / 5); // 20% buffer

        let tx = Eip1559Tx {
            chain_id: self.chain_id,
            nonce,
            max_priority_fee_per_gas: priority_fee,
            max_fee_per_gas: max_fee,
            gas_limit,
            to: splitter_address,
            value: U256::ZERO,
            data: calldata,
        };

        let digest = tx.signing_digest();
        let (r, s) = self.kms_sign(&digest).await?;
        let y_parity = recover_y_parity(&digest, &r, &s, self.address)?;
        let raw = tx.encode_signed(y_parity, &r, &s);

        let tx_hash = self.send_raw(&raw).await?;
        Ok(RegisterTxReceipt {
            tx_hash,
            block_number: None,
        })
    }

    fn relayer_address(&self) -> Address {
        self.address
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ---------- Low-s normalisation ----------

    #[test]
    fn low_s_unchanged() {
        let mut s = [0u8; 32];
        s[31] = 0x01;
        assert!(!is_high_s(&s));
        let (out, flipped) = normalize_s(&s);
        assert_eq!(out, s);
        assert!(!flipped);
    }

    #[test]
    fn high_s_normalized() {
        // s = N - 1 → high. After normalize: s' = 1.
        let mut s = SECP256K1_N;
        s[31] -= 1;
        assert!(is_high_s(&s));
        let (out, flipped) = normalize_s(&s);
        let mut expected = [0u8; 32];
        expected[31] = 1;
        assert_eq!(out, expected, "N - (N-1) should be 1");
        assert!(flipped);
    }

    #[test]
    fn n_half_boundary_not_high() {
        // Exactly N/2 must be considered low-s (not high).
        let half = SECP256K1_N_HALF;
        assert!(!is_high_s(&half));
    }

    // ---------- DER parse ----------

    #[test]
    fn der_parses_simple_sig() {
        // SEQUENCE (len=8) { INTEGER (len=2) 0x0102, INTEGER (len=2) 0x0304 }
        let der = [0x30, 0x08, 0x02, 0x02, 0x01, 0x02, 0x02, 0x02, 0x03, 0x04];
        let (r, s) = parse_der_signature(&der).unwrap();
        let mut want_r = [0u8; 32];
        want_r[30..].copy_from_slice(&[0x01, 0x02]);
        let mut want_s = [0u8; 32];
        want_s[30..].copy_from_slice(&[0x03, 0x04]);
        assert_eq!(r, want_r);
        assert_eq!(s, want_s);
    }

    #[test]
    fn der_strips_sign_byte() {
        // INTEGER (len=33, leading 0x00 sign byte) 0x00 || 0xFF * 32
        let mut der = vec![0x30, 0x46, 0x02, 0x21, 0x00];
        der.extend_from_slice(&[0xFF; 32]);
        der.extend_from_slice(&[0x02, 0x21, 0x00]);
        der.extend_from_slice(&[0xEE; 32]);
        let (r, s) = parse_der_signature(&der).unwrap();
        assert_eq!(r, [0xFF; 32]);
        assert_eq!(s, [0xEE; 32]);
    }

    #[test]
    fn der_rejects_bad_seq() {
        let der = [0x31u8, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
        assert!(matches!(parse_der_signature(&der), Err(DerError::BadSeqTag(0x31))));
    }

    #[test]
    fn der_rejects_short() {
        let der = [0x30u8, 0x00];
        assert!(matches!(parse_der_signature(&der), Err(DerError::Short)));
    }

    // ---------- SubjectPublicKeyInfo / address derivation ----------

    /// Build a synthetic SPKI blob around an X||Y point and return it.
    fn make_spki(xy: &[u8; 64]) -> Vec<u8> {
        // alg SEQUENCE { OID ecPublicKey (1.2.840.10045.2.1), OID secp256k1 (1.3.132.0.10) }
        // Hex literal taken from RFC 5480 / SEC1 — we only need the byte
        // pattern, the parser does not validate the OIDs.
        let alg_seq: Vec<u8> = vec![
            0x30, 0x10, // SEQUENCE, len=16
            0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, // OID ecPublicKey
            0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A,             // OID secp256k1
        ];
        // BIT STRING { 0x00 unused-bits, 0x04 || X || Y }
        let mut bit = vec![0x03, 0x42, 0x00, 0x04];
        bit.extend_from_slice(xy);
        let mut inner = Vec::new();
        inner.extend_from_slice(&alg_seq);
        inner.extend_from_slice(&bit);
        let mut spki = vec![0x30, inner.len() as u8];
        spki.extend_from_slice(&inner);
        spki
    }

    #[test]
    fn address_derivation_known_vector() {
        // Public test vector (SEC1 / commonly used Ethereum example):
        // privkey = 0x...01 → pubkey x = 79be...98, y = 483a...8;
        // address = 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf
        let mut xy = [0u8; 64];
        let x = hex::decode("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798").unwrap();
        let y = hex::decode("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8").unwrap();
        xy[..32].copy_from_slice(&x);
        xy[32..].copy_from_slice(&y);
        let addr = address_from_uncompressed_pubkey(&xy);
        assert_eq!(
            format!("{:?}", addr).to_lowercase(),
            "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
        );
    }

    #[test]
    fn spki_extracts_pubkey() {
        let mut xy = [0u8; 64];
        for i in 0..64 {
            xy[i] = i as u8;
        }
        let spki = make_spki(&xy);
        let out = extract_uncompressed_pubkey(&spki).unwrap();
        assert_eq!(out, xy);
    }

    #[test]
    fn spki_rejects_wrong_prefix() {
        // Replace the 0x04 uncompressed prefix with 0x02 (compressed).
        let xy = [0u8; 64];
        let mut spki = make_spki(&xy);
        let pos = spki
            .windows(4)
            .position(|w| w == [0x03, 0x42, 0x00, 0x04])
            .expect("BIT STRING header must exist");
        spki[pos + 3] = 0x02;
        let err = extract_uncompressed_pubkey(&spki).unwrap_err();
        assert!(matches!(err, AwsKmsRelayerError::InvalidSpki(_)));
    }

    // ---------- y-parity recovery ----------

    #[test]
    fn y_parity_recovery_roundtrip() {
        use k256::ecdsa::signature::hazmat::PrehashSigner;
        use k256::ecdsa::{Signature, SigningKey};

        // Generate a deterministic key.
        let sk_bytes = [0x42u8; 32];
        let sk = SigningKey::from_bytes(&sk_bytes.into()).unwrap();
        let vk = sk.verifying_key();
        let enc = vk.to_encoded_point(false);
        let mut xy = [0u8; 64];
        xy.copy_from_slice(&enc.as_bytes()[1..]);
        let addr = address_from_uncompressed_pubkey(&xy);

        // Sign a digest.
        let digest = [0xAAu8; 32];
        let sig: Signature = sk.sign_prehash(&digest).unwrap();
        let bytes = sig.to_bytes();
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&bytes[..32]);
        s.copy_from_slice(&bytes[32..]);
        let (s_norm, _) = normalize_s(&s);

        // Recover y parity.
        let v = recover_y_parity(&digest, &r, &s_norm, addr).unwrap();
        assert!(v == 0 || v == 1);
    }

    // ---------- EIP-1559 RLP ----------

    #[test]
    fn rlp_unsigned_starts_with_type_byte() {
        let tx = Eip1559Tx {
            chain_id: 8453,
            nonce: 0,
            max_priority_fee_per_gas: 2_000_000_000,
            max_fee_per_gas: 4_000_000_000,
            gas_limit: 100_000,
            to: Address::ZERO,
            value: U256::ZERO,
            data: vec![],
        };
        let body = tx.encode_for_signing();
        assert_eq!(body[0], 0x02, "EIP-1559 type byte");
        // The next byte must be an RLP list header (>= 0xc0).
        assert!(body[1] >= 0xc0, "RLP list header byte");
    }

    #[test]
    fn rlp_signed_includes_y_parity_and_rs() {
        let tx = Eip1559Tx {
            chain_id: 8453,
            nonce: 1,
            max_priority_fee_per_gas: 1,
            max_fee_per_gas: 1_000_000_000,
            gas_limit: 21_000,
            to: Address::ZERO,
            value: U256::ZERO,
            data: vec![],
        };
        let r = [0xAAu8; 32];
        let s = [0xBBu8; 32];
        let signed = tx.encode_signed(0, &r, &s);
        // The signed envelope must be longer than the unsigned one.
        assert!(signed.len() > tx.encode_for_signing().len());
    }

    #[test]
    fn strip_leading_zeros_works() {
        assert_eq!(strip_leading_zeros(&[0, 0, 0]), &[] as &[u8]);
        assert_eq!(strip_leading_zeros(&[0, 0, 1]), &[1u8]);
        assert_eq!(strip_leading_zeros(&[1, 2, 3]), &[1u8, 2, 3]);
    }

    // ---------- register() calldata ----------

    #[test]
    fn register_selector_is_4_bytes() {
        let sel = register_selector();
        assert_eq!(sel.len(), 4);
    }

    #[test]
    fn register_calldata_layout() {
        let auth = RegisterAuthorization {
            capability_id: B256::from([0x11u8; 32]),
            provider: Address::from([0x22u8; 20]),
            provider_bps: 8500,
            hub_bps: 1000,
            reserve_bps: 500,
            nonce: B256::from([0x33u8; 32]),
            deadline: 0xDEADBEEF,
        };
        let sig = [0x44u8; 65];
        let calldata = encode_register_calldata(&auth, &sig);
        // 4 selector + 8 head words + 1 length word + 65 bytes + 31 padding = 4 + 256 + 32 + 65 + 31
        assert_eq!(calldata.len(), 4 + 8 * 32 + 32 + 65 + 31);
        // Selector then capability_id at offset 4.
        assert_eq!(&calldata[4..36], &[0x11u8; 32]);
        // provider (left-padded) at offset 36+12.
        assert_eq!(&calldata[36 + 12..36 + 32], &[0x22u8; 20]);
        // bps words: low byte of the u16 sits at offset+31, high byte at +30.
        assert_eq!(calldata[68 + 30], (8500u16 >> 8) as u8);
        assert_eq!(calldata[68 + 31], (8500u16 & 0xFF) as u8);
    }

    // ---------- RelayerError surface ----------

    #[test]
    fn aws_err_converts_to_relayer_err() {
        let aws_err = AwsKmsRelayerError::AddressMismatch {
            derived: Address::ZERO,
            expected: Address::from([0x99u8; 20]),
        };
        let r: RelayerError = aws_err.into();
        match r {
            RelayerError::Rpc(msg) => assert!(msg.contains("RELAYER_ADDRESS")),
            _ => panic!("wrong variant"),
        }
    }
}
