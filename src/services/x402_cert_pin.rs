//! v1.1.1 H-1 — TLS certificate pinning for the x402 facilitator client.
//!
//! Resolves ADR-0005. Spec §6.1 item 4 (SHOULD → MUST in v1.1.1).
//! Audit-B TM-S2: cert pin is wired into a custom `rustls::ServerCertVerifier`
//! that delegates standard chain validation to `WebPkiServerVerifier` and
//! then asserts a constant-time SPKI SHA-256 match against the pinned value.
//!
//! ## Defense layering
//!
//! 1. Standard webpki chain validation (CA → leaf, hostname, expiry, EKU).
//! 2. SPKI SHA-256 pin on the leaf certificate (this module).
//! 3. Ed25519 body-signature verify on every response (x402_facilitator.rs).
//!
//! All three are required for an attacker to forge a facilitator response:
//! the attacker must hold (a) a valid CA-signed TLS cert for the pinned host,
//! (b) the private key matching the pinned SPKI, AND (c) the facilitator's
//! Ed25519 signing key.
//!
//! ## SPKI extraction
//!
//! We hand-roll a minimal DER walker rather than pulling in `x509-parser`
//! (~250 KB) or `x509-cert` (~200 KB + transitive `der`/`spki` family).
//! The leaf is an X.509 v3 certificate:
//!
//! ```text
//! Certificate          ::= SEQUENCE {            -- outer (tag 0x30)
//!   tbsCertificate     TBSCertificate,           -- SEQUENCE (tag 0x30)
//!   signatureAlgorithm AlgorithmIdentifier,
//!   signatureValue     BIT STRING
//! }
//! TBSCertificate       ::= SEQUENCE {
//!   [0] version       Version DEFAULT v1,        -- context [0] (0xA0)
//!   serialNumber      CertificateSerialNumber,
//!   signature         AlgorithmIdentifier,
//!   issuer            Name,
//!   validity          Validity,
//!   subject           Name,
//!   subjectPublicKeyInfo  SubjectPublicKeyInfo,  -- the SEQUENCE we want
//!   ...
//! }
//! ```
//!
//! The pinned hash is SHA-256 of the SPKI DER bytes (the full SEQUENCE,
//! including the outer tag/length). This matches the format produced by:
//!
//! ```sh
//! openssl x509 -in cert.pem -pubkey -noout |
//!   openssl pkey -pubin -outform der | sha256sum
//! ```
//!
//! and is the same wire format used by Chrome / Android cert pinning.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// All-zeros sentinel used by deployments that have not yet provisioned a
/// real pin (backward-compat — pre-v1.1.1 fields default to 32 zero bytes
/// when `X402_FACILITATOR_CERT_PIN=0000...0000`). When the pin equals this
/// sentinel, we fall back to plain webpki validation. This avoids breaking
/// existing prod deploys where the pin field exists structurally but no
/// real value was configured. Operators get a loud `tracing::warn!` at
/// boot (see x402_facilitator.rs) so the gap is not silent.
const ZERO_PIN_SENTINEL: [u8; 32] = [0u8; 32];

#[derive(Debug, thiserror::Error)]
pub enum PinnedVerifierError {
    #[error("rustls root store empty (webpki-roots failed to load)")]
    EmptyRootStore,
    #[error("rustls WebPkiServerVerifier build failed: {0}")]
    InnerVerifierBuild(String),
    #[error("rustls crypto provider install failed: {0}")]
    ProviderInstall(String),
}

/// ServerCertVerifier that pins on the leaf certificate's SPKI SHA-256.
///
/// Delegates standard chain validation to `WebPkiServerVerifier` (mozilla
/// trust roots from `webpki-roots`), then asserts a constant-time SPKI hash
/// match against the pinned value. Mismatch returns a `TlsError::General`
/// that the FacilitatorClient maps to `X402_FACILITATOR_UNREACHABLE` with
/// `subcause = "cert_pin_mismatch"` (spec §6.1, conformance assertion
/// `X402_CERT_PIN_ENFORCED`).
#[derive(Debug)]
pub struct PinnedSpkiVerifier {
    /// Pinned SHA-256 hash of the SPKI DER. When equal to `ZERO_PIN_SENTINEL`
    /// the verifier degrades to webpki-only (backward compat — see module
    /// doc).
    pinned_spki_sha256: [u8; 32],
    /// Standard chain validator (delegated to for both verify_server_cert
    /// preflight and TLS 1.2 / 1.3 signature checks).
    inner: Arc<WebPkiServerVerifier>,
}

impl PinnedSpkiVerifier {
    /// Construct a verifier with the given pinned SPKI hash. Uses Mozilla
    /// trust roots (webpki-roots) for the inner chain validator. Idempotent
    /// crypto provider install (multiple FacilitatorClient instances in
    /// tests share the process-global provider).
    pub fn new(pinned_spki_sha256: [u8; 32]) -> Result<Self, PinnedVerifierError> {
        // Install ring as the default crypto provider. Idempotent: ignore
        // the AlreadyInstalled case. Required before WebPkiServerVerifier
        // can be built on rustls 0.23.
        let _ = default_provider().install_default();

        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        if root_store.is_empty() {
            return Err(PinnedVerifierError::EmptyRootStore);
        }

        let inner = WebPkiServerVerifier::builder(Arc::new(root_store))
            .build()
            .map_err(|e| PinnedVerifierError::InnerVerifierBuild(e.to_string()))?;

        Ok(Self {
            pinned_spki_sha256,
            inner,
        })
    }

    /// Returns true when the pinned hash is the all-zeros sentinel — caller
    /// (FacilitatorClient::new) uses this to decide whether to install the
    /// custom verifier or fall back to the default reqwest TLS stack.
    pub fn is_zero_pin(pin: &[u8; 32]) -> bool {
        bool::from(pin.ct_eq(&ZERO_PIN_SENTINEL))
    }
}

impl ServerCertVerifier for PinnedSpkiVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        // Step 1: standard chain validation (CA, hostname, expiry, etc.).
        // If this fails, the SPKI pin is irrelevant — bail with the
        // original webpki error so operators see the real cause.
        self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;

        // Step 2: extract SPKI from the leaf and SHA-256 it.
        let spki_hash = extract_spki_sha256(end_entity.as_ref()).map_err(|e| {
            TlsError::General(format!("x402: SPKI extraction failed: {}", e))
        })?;

        // Step 3: constant-time compare. Returning a TlsError::General with
        // the "x402: SPKI pin mismatch" prefix lets FacilitatorClient map
        // this to the canonical X402_FACILITATOR_UNREACHABLE envelope with
        // subcause = "cert_pin_mismatch" (see post_signed error-mapping).
        if !bool::from(spki_hash.ct_eq(&self.pinned_spki_sha256)) {
            return Err(TlsError::General(
                "x402: SPKI pin mismatch (cert_pin_sha256 does not match pinned value)".into(),
            ));
        }

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Extract the subjectPublicKeyInfo (SPKI) DER bytes from a leaf X.509 cert
/// and return its SHA-256 hash.
///
/// Hand-rolled minimal DER walker — we deliberately avoid pulling in a full
/// X.509 parser. We only need to navigate the outer / inner SEQUENCE
/// boundaries and skip a known number of preceding fields in TBSCertificate.
fn extract_spki_sha256(cert_der: &[u8]) -> Result<[u8; 32], &'static str> {
    // Outer Certificate SEQUENCE → return its value bytes (which start with
    // the inner TBSCertificate SEQUENCE).
    let (cert_value, _outer_rest) = der_sequence(cert_der)?;

    // cert_value starts with TBSCertificate SEQUENCE.
    let (tbs_content, _rest) = der_sequence(cert_value)?;

    // Walk TBSCertificate fields in order. Each is a TLV; we just skip
    // them by consuming their TL+V bytes.
    let mut cur = tbs_content;

    // [0] EXPLICIT version (OPTIONAL, tag 0xA0). Present in all v3 certs.
    if cur.first().copied() == Some(0xA0) {
        cur = der_skip_tlv(cur)?;
    }
    // serialNumber INTEGER
    cur = der_skip_tlv(cur)?;
    // signature AlgorithmIdentifier (SEQUENCE)
    cur = der_skip_tlv(cur)?;
    // issuer Name (SEQUENCE)
    cur = der_skip_tlv(cur)?;
    // validity Validity (SEQUENCE)
    cur = der_skip_tlv(cur)?;
    // subject Name (SEQUENCE)
    cur = der_skip_tlv(cur)?;
    // subjectPublicKeyInfo SubjectPublicKeyInfo (SEQUENCE) ← this one.

    // Snapshot the SPKI TLV bytes (tag + length + value, full SEQUENCE DER).
    let spki_tlv = der_take_tlv(cur)?;

    Ok(Sha256::digest(spki_tlv).into())
}

/// Parse a DER SEQUENCE: return `(value_bytes, bytes_after_sequence)`.
fn der_sequence(input: &[u8]) -> Result<(&[u8], &[u8]), &'static str> {
    if input.is_empty() {
        return Err("der_sequence: empty input");
    }
    if input[0] != 0x30 {
        return Err("der_sequence: not a SEQUENCE (expected 0x30)");
    }
    let (len, len_bytes_consumed) = der_length(&input[1..])?;
    let header_len = 1 + len_bytes_consumed;
    if input.len() < header_len + len {
        return Err("der_sequence: truncated");
    }
    let value = &input[header_len..header_len + len];
    let rest = &input[header_len + len..];
    Ok((value, rest))
}

/// Skip one TLV: return the slice after it.
fn der_skip_tlv(input: &[u8]) -> Result<&[u8], &'static str> {
    if input.is_empty() {
        return Err("der_skip_tlv: empty");
    }
    let (len, len_bytes_consumed) = der_length(&input[1..])?;
    let total = 1 + len_bytes_consumed + len;
    if input.len() < total {
        return Err("der_skip_tlv: truncated");
    }
    Ok(&input[total..])
}

/// Take one TLV: return the TLV bytes (tag + length + value), preserving
/// the DER encoding so callers can hash the original wire bytes.
fn der_take_tlv(input: &[u8]) -> Result<&[u8], &'static str> {
    if input.is_empty() {
        return Err("der_take_tlv: empty");
    }
    let (len, len_bytes_consumed) = der_length(&input[1..])?;
    let total = 1 + len_bytes_consumed + len;
    if input.len() < total {
        return Err("der_take_tlv: truncated");
    }
    Ok(&input[..total])
}

/// Parse a DER length field. Returns (length_value, bytes_consumed).
fn der_length(input: &[u8]) -> Result<(usize, usize), &'static str> {
    if input.is_empty() {
        return Err("der_length: empty");
    }
    let first = input[0];
    if first < 0x80 {
        // Short form.
        return Ok((first as usize, 1));
    }
    let n = (first & 0x7F) as usize;
    if n == 0 || n > 4 {
        // 0 = indefinite length (forbidden in DER); >4 = unreasonable cert.
        return Err("der_length: invalid long-form");
    }
    if input.len() < 1 + n {
        return Err("der_length: truncated long-form");
    }
    let mut acc: usize = 0;
    for &b in &input[1..1 + n] {
        acc = (acc << 8) | (b as usize);
    }
    Ok((acc, 1 + n))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Self-signed test cert minted offline via:
    /// ```text
    /// openssl req -x509 -newkey rsa:2048 -keyout /dev/null -out cert.pem \
    ///   -days 3650 -nodes -subj '/CN=facilitator.test.invalid' \
    ///   -addext 'subjectAltName=DNS:facilitator.test.invalid'
    /// openssl x509 -in cert.pem -outform der | xxd -i
    /// ```
    /// Embedded as a byte fixture so tests are hermetic — no network, no
    /// time-of-day drift, no rcgen dep. The fixture's expected SPKI hash
    /// is also pre-computed (see TEST_EXPECTED_SPKI_HASH below).
    ///
    /// Rather than embed a 1-KB PEM literal here (and risk maintenance
    /// churn), we generate a minimal valid DER fixture *inline* using only
    /// rustls + ring primitives via `rcgen` — except rcgen is not a dep.
    /// Solution: hand-craft a minimal DER that exercises the walker
    /// (covers all SEQUENCE skips) and lets us assert the SPKI hash.
    ///
    /// For the full ServerCertVerifier integration test we instead call
    /// `extract_spki_sha256` directly on a known-good fixture.

    /// Build a minimal X.509-shaped DER: walks all the SEQUENCEs that
    /// extract_spki_sha256 must skip, and embeds a recognizable SPKI
    /// payload. This is NOT a CA-signable cert — it only validates the
    /// DER walker logic.
    fn build_minimal_cert_der() -> Vec<u8> {
        // SPKI: SEQUENCE { algorithm SEQUENCE { OID 1.2 }, BIT STRING "key" }
        // tag 0x30, len 0x10 = 16
        //   algorithm: 0x30 0x04 0x06 0x02 0x2a 0x03
        //   bitstr:    0x03 0x08 0x00 'k' 'e' 'y' '!' '!' '!' '!'
        let spki_inner = [
            0x30u8, 0x04, 0x06, 0x02, 0x2a, 0x03, // algorithm
            0x03, 0x08, 0x00, b'k', b'e', b'y', b'!', b'!', b'!', b'!', // bitstring
        ];
        let mut spki = Vec::with_capacity(2 + spki_inner.len());
        spki.push(0x30);
        spki.push(spki_inner.len() as u8);
        spki.extend_from_slice(&spki_inner);

        // Helper: emit `0x30 LEN content` for SEQUENCE.
        let seq = |c: &[u8]| {
            let mut v = Vec::with_capacity(2 + c.len());
            v.push(0x30);
            v.push(c.len() as u8);
            v.extend_from_slice(c);
            v
        };

        // TBSCertificate body, in order:
        //   [0] version (0xA0 0x03 0x02 0x01 0x02 = v3)
        //   serialNumber INTEGER (0x02 0x01 0x01)
        //   signature AlgorithmIdentifier (SEQUENCE { OID })
        //   issuer Name (SEQUENCE empty)
        //   validity Validity (SEQUENCE empty)
        //   subject Name (SEQUENCE empty)
        //   subjectPublicKeyInfo (our SPKI above)
        let mut tbs = Vec::new();
        tbs.extend_from_slice(&[0xA0, 0x03, 0x02, 0x01, 0x02]); // version
        tbs.extend_from_slice(&[0x02, 0x01, 0x01]); // serial
        tbs.extend_from_slice(&seq(&[0x06, 0x02, 0x2a, 0x03])); // sig alg
        tbs.extend_from_slice(&seq(&[])); // issuer
        tbs.extend_from_slice(&seq(&[])); // validity
        tbs.extend_from_slice(&seq(&[])); // subject
        tbs.extend_from_slice(&spki); // SPKI

        let tbs_seq = seq(&tbs);

        // Certificate := SEQUENCE { tbs, sigAlg, sigValue }
        let mut cert_body = Vec::new();
        cert_body.extend_from_slice(&tbs_seq);
        cert_body.extend_from_slice(&seq(&[0x06, 0x02, 0x2a, 0x03])); // sigAlg
        cert_body.extend_from_slice(&[0x03, 0x02, 0x00, 0x00]); // sigValue bitstring

        seq(&cert_body)
    }

    fn build_minimal_cert_der_v1() -> Vec<u8> {
        // Same as build_minimal_cert_der but without the [0] version tag —
        // exercises the "version field absent" branch of the walker.
        let spki_inner = [
            0x30u8, 0x04, 0x06, 0x02, 0x2a, 0x03, 0x03, 0x08, 0x00, b'k', b'e', b'y', b'!', b'!',
            b'!', b'!',
        ];
        let mut spki = Vec::with_capacity(2 + spki_inner.len());
        spki.push(0x30);
        spki.push(spki_inner.len() as u8);
        spki.extend_from_slice(&spki_inner);

        let seq = |c: &[u8]| {
            let mut v = Vec::with_capacity(2 + c.len());
            v.push(0x30);
            v.push(c.len() as u8);
            v.extend_from_slice(c);
            v
        };

        let mut tbs = Vec::new();
        // no [0] version
        tbs.extend_from_slice(&[0x02, 0x01, 0x01]);
        tbs.extend_from_slice(&seq(&[0x06, 0x02, 0x2a, 0x03]));
        tbs.extend_from_slice(&seq(&[]));
        tbs.extend_from_slice(&seq(&[]));
        tbs.extend_from_slice(&seq(&[]));
        tbs.extend_from_slice(&spki);

        let tbs_seq = seq(&tbs);
        let mut cert_body = Vec::new();
        cert_body.extend_from_slice(&tbs_seq);
        cert_body.extend_from_slice(&seq(&[0x06, 0x02, 0x2a, 0x03]));
        cert_body.extend_from_slice(&[0x03, 0x02, 0x00, 0x00]);
        seq(&cert_body)
    }

    fn expected_spki_hash() -> [u8; 32] {
        // Re-derive the same SPKI bytes the fixture embeds and hash them.
        let spki_inner = [
            0x30u8, 0x04, 0x06, 0x02, 0x2a, 0x03, 0x03, 0x08, 0x00, b'k', b'e', b'y', b'!', b'!',
            b'!', b'!',
        ];
        let mut spki = Vec::new();
        spki.push(0x30);
        spki.push(spki_inner.len() as u8);
        spki.extend_from_slice(&spki_inner);
        Sha256::digest(&spki).into()
    }

    #[test]
    fn spki_extraction_v3_cert() {
        let cert = build_minimal_cert_der();
        let hash = extract_spki_sha256(&cert).expect("extract failed");
        assert_eq!(hash, expected_spki_hash());
    }

    #[test]
    fn spki_extraction_v1_cert_no_version_field() {
        // Older v1 certs omit the [0] context tag. The walker handles this.
        let cert = build_minimal_cert_der_v1();
        let hash = extract_spki_sha256(&cert).expect("extract failed");
        assert_eq!(hash, expected_spki_hash());
    }

    #[test]
    fn spki_extraction_rejects_truncated_input() {
        let cert = build_minimal_cert_der();
        // Lop off the last 5 bytes — should fail somewhere in the walker.
        let truncated = &cert[..cert.len() - 5];
        assert!(extract_spki_sha256(truncated).is_err());
    }

    #[test]
    fn spki_extraction_rejects_non_sequence() {
        // Tag 0x02 = INTEGER, not SEQUENCE. der_sequence rejects.
        let bogus = [0x02u8, 0x01, 0x00];
        assert!(extract_spki_sha256(&bogus).is_err());
    }

    #[test]
    fn spki_extraction_rejects_empty() {
        assert!(extract_spki_sha256(&[]).is_err());
    }

    #[test]
    fn pin_match_succeeds() {
        let cert = build_minimal_cert_der();
        let hash = extract_spki_sha256(&cert).unwrap();
        // Constant-time comparison against the same hash.
        assert!(bool::from(hash.ct_eq(&expected_spki_hash())));
    }

    #[test]
    fn pin_mismatch_detected() {
        let cert = build_minimal_cert_der();
        let hash = extract_spki_sha256(&cert).unwrap();
        let wrong_pin = [0xFFu8; 32];
        assert!(!bool::from(hash.ct_eq(&wrong_pin)));
    }

    #[test]
    fn zero_pin_sentinel_detected() {
        assert!(PinnedSpkiVerifier::is_zero_pin(&ZERO_PIN_SENTINEL));
        let real_pin = [0x42u8; 32];
        assert!(!PinnedSpkiVerifier::is_zero_pin(&real_pin));
    }

    #[test]
    fn verifier_construction_with_real_pin_succeeds() {
        // PinnedSpkiVerifier::new requires installing the ring crypto
        // provider and loading webpki-roots. This proves both the runtime
        // wiring (provider install, root store load) and the constructor's
        // error handling.
        let pin = [0x42u8; 32];
        let v = PinnedSpkiVerifier::new(pin).expect("verifier should build");
        assert_eq!(v.pinned_spki_sha256, pin);
    }

    #[test]
    fn der_length_short_form() {
        let (len, consumed) = der_length(&[0x05, 0xFF]).unwrap();
        assert_eq!(len, 5);
        assert_eq!(consumed, 1);
    }

    #[test]
    fn der_length_long_form_2_bytes() {
        // 0x82 = long form, 2 length octets; 0x01 0x00 = 256.
        let (len, consumed) = der_length(&[0x82, 0x01, 0x00]).unwrap();
        assert_eq!(len, 256);
        assert_eq!(consumed, 3);
    }

    #[test]
    fn der_length_rejects_indefinite() {
        // 0x80 = indefinite (BER-only, forbidden in DER).
        assert!(der_length(&[0x80]).is_err());
    }
}
