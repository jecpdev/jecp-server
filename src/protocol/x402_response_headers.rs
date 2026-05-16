//! v1.1.0 H-2 — x402 response header policy (audit-A H3/H4/H5).
//!
//! Centralizes the three HTTP-header MUSTs that every x402 surface emits:
//!
//! 1. `Cache-Control: no-store` on every `/v1/invoke` response (sync + stream,
//!    402 challenges, 422/402 errors, and 200 x402-settled bodies). Replayable
//!    paid-call leak via CDN is the threat (spec §2.1 / §5.2 / audit A-H3).
//! 2. `Access-Control-Expose-Headers: X-Payment-Response, X-Request-Id,
//!    Retry-After, WWW-Authenticate` — browser fetch() strips non-default
//!    response headers from JS by default (spec §5 / audit A-H4).
//! 3. `WWW-Authenticate` on 402 responses, in two shapes (spec §2.1 / §2.2 /
//!    audit A-H5):
//!    - x402-only: `x402, scheme="exact", network="base"`
//!    - both methods accepted: `x402, Bearer`
//!
//! All call sites (sync invoke 200/402/422/502/504, streaming 402, x402
//! dispatch helper) MUST call into this module instead of inserting the
//! headers directly. This is the single point of policy enforcement.

use axum::http::{header, HeaderMap, HeaderValue};

/// Headers exposed across the CORS boundary for x402 surfaces.
/// Browsers strip non-default response headers from JS access; we make the
/// receipt + correlation + retry hints first-class for browser agents.
const CORS_EXPOSE_VALUE: &str =
    "X-Payment-Response, X-Request-Id, Retry-After, WWW-Authenticate";

/// `Cache-Control: no-store` — applied to every /v1/invoke response.
fn insert_no_store(headers: &mut HeaderMap) {
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
}

/// `Access-Control-Expose-Headers: ...` — applied to every /v1/invoke response.
fn insert_expose_headers(headers: &mut HeaderMap) {
    headers.insert(
        header::ACCESS_CONTROL_EXPOSE_HEADERS,
        HeaderValue::from_static(CORS_EXPOSE_VALUE),
    );
}

/// Insert `WWW-Authenticate` per spec §2.1 + audit A-H5. The challenge value
/// depends on which payment schemes the Hub accepts for the current capability:
///
/// - `["x402"]` only → `x402, scheme="exact", network="base"`
/// - both `["stripe", "x402"]` or `["stripe"]` (legacy) → `x402, Bearer`
///
/// `accepted_schemes` is the list of payment-method tokens the Hub will accept
/// for this capability (from manifest `pricing.payment_methods`); empty means
/// stripe-only (legacy default).
fn insert_www_authenticate(headers: &mut HeaderMap, accepted_schemes: &[&str]) {
    let has_stripe = accepted_schemes.iter().any(|s| *s == "stripe") || accepted_schemes.is_empty();
    let has_x402 = accepted_schemes.iter().any(|s| *s == "x402");
    let val = match (has_stripe, has_x402) {
        (false, true) => HeaderValue::from_static(r#"x402, scheme="exact", network="base""#),
        (true, true) => HeaderValue::from_static("x402, Bearer"),
        // Stripe-only or unknown: still emit Bearer per RFC 7235 (so RFC-7235-
        // aware proxies have a scheme hint). x402 is not advertised.
        _ => HeaderValue::from_static("Bearer"),
    };
    headers.insert(header::WWW_AUTHENTICATE, val);
}

/// Apply the always-on x402 response header policy (Cache-Control + CORS
/// expose). Called on EVERY /v1/invoke response (sync + streaming, success +
/// error, 402 + 200 + 422 + 502 + 504).
pub fn apply_invoke_headers(headers: &mut HeaderMap) {
    insert_no_store(headers);
    insert_expose_headers(headers);
}

/// Apply headers specific to a 402 PAYMENT_REQUIRED response: the always-on
/// policy PLUS `WWW-Authenticate` per spec §2.1 / audit A-H5.
pub fn apply_402_headers(headers: &mut HeaderMap, accepted_schemes: &[&str]) {
    apply_invoke_headers(headers);
    insert_www_authenticate(headers, accepted_schemes);
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    #[test]
    fn apply_invoke_headers_sets_cache_control_no_store() {
        let mut h = HeaderMap::new();
        apply_invoke_headers(&mut h);
        assert_eq!(h.get(header::CACHE_CONTROL).unwrap(), "no-store");
    }

    #[test]
    fn apply_invoke_headers_sets_expose_with_all_four_names() {
        let mut h = HeaderMap::new();
        apply_invoke_headers(&mut h);
        let v = h.get(header::ACCESS_CONTROL_EXPOSE_HEADERS).unwrap().to_str().unwrap();
        assert!(v.contains("X-Payment-Response"));
        assert!(v.contains("X-Request-Id"));
        assert!(v.contains("Retry-After"));
        assert!(v.contains("WWW-Authenticate"));
    }

    #[test]
    fn www_authenticate_x402_only() {
        let mut h = HeaderMap::new();
        apply_402_headers(&mut h, &["x402"]);
        let v = h.get(header::WWW_AUTHENTICATE).unwrap().to_str().unwrap();
        assert!(v.starts_with("x402"));
        assert!(v.contains(r#"scheme="exact""#));
        assert!(v.contains(r#"network="base""#));
    }

    #[test]
    fn www_authenticate_x402_plus_bearer() {
        let mut h = HeaderMap::new();
        apply_402_headers(&mut h, &["stripe", "x402"]);
        let v = h.get(header::WWW_AUTHENTICATE).unwrap().to_str().unwrap();
        assert!(v.contains("x402"));
        assert!(v.contains("Bearer"));
    }

    #[test]
    fn www_authenticate_stripe_only_no_x402() {
        let mut h = HeaderMap::new();
        apply_402_headers(&mut h, &["stripe"]);
        let v = h.get(header::WWW_AUTHENTICATE).unwrap().to_str().unwrap();
        // Stripe-only: no x402 advertisement, but still a Bearer hint for RFC 7235.
        assert!(!v.contains("x402"));
        assert!(v.contains("Bearer"));
    }

    #[test]
    fn apply_402_headers_includes_no_store_and_expose() {
        let mut h = HeaderMap::new();
        apply_402_headers(&mut h, &["stripe", "x402"]);
        assert_eq!(h.get(header::CACHE_CONTROL).unwrap(), "no-store");
        assert!(h.get(header::ACCESS_CONTROL_EXPOSE_HEADERS).is_some());
        assert!(h.get(header::WWW_AUTHENTICATE).is_some());
    }
}
