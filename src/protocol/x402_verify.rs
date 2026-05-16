//! v1.1.0 x402 — X-Payment header decode + payment validation
//! (locked-design §3, §3.5).
//!
//! Pure functions over `X402PaymentHeader` and `PaymentRequirements`.
//! No I/O: facilitator communication lives in `services::x402_facilitator`.

use base64::Engine;

use crate::protocol::x402_types::{
    Eip3009Authorization, PaymentPayload, PaymentRequirements, X402Error,
};

/// Maximum allowed length of the X-Payment header value (base64 form).
///
/// Spec §3.2 / locked-design §3.2: when the header exceeds this, the Hub
/// MUST reject with HTTP **422** `X402_PAYMENT_INVALID` and
/// `details.subcause = "header_too_large"`. (Earlier doc revisions said
/// "413" — that was wrong. The wire returns the JECP error envelope at
/// 422, not a bare HTTP 413. Audit A-L5.)
pub const MAX_X_PAYMENT_HEADER_BYTES: usize = 8 * 1024;

/// Decode the base64 X-Payment header into a typed `PaymentPayload`.
///
/// Validates per locked-design §3.5:
/// - Length ≤ 8 KiB
/// - Valid base64
/// - Valid JSON conforming to the x402 payment wire schema
pub fn decode_x_payment_header(header: &str) -> Result<PaymentPayload, X402Error> {
    if header.len() > MAX_X_PAYMENT_HEADER_BYTES {
        return Err(X402Error::PaymentInvalid {
            subcause: "header_too_large",
            message: format!(
                "X-Payment header is {} bytes; max {} per x402 spec",
                header.len(),
                MAX_X_PAYMENT_HEADER_BYTES
            ),
        });
    }

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(header.trim())
        .map_err(|e| X402Error::PaymentInvalid {
            subcause: "base64_decode",
            message: format!("X-Payment is not valid base64: {}", e),
        })?;

    let parsed: PaymentPayload =
        serde_json::from_slice(&decoded).map_err(|e| X402Error::PaymentInvalid {
            subcause: "json_parse",
            message: format!("X-Payment body is not valid JSON: {}", e),
        })?;

    // Cheap shape validations before any network call.
    if parsed.scheme != "exact" {
        return Err(X402Error::PaymentInvalid {
            subcause: "scheme_unsupported",
            message: format!(
                "Only scheme='exact' supported in v1.1; got '{}'",
                parsed.scheme
            ),
        });
    }
    if parsed.x402_version != 1 {
        return Err(X402Error::PaymentInvalid {
            subcause: "version_unsupported",
            message: format!(
                "Only x402Version=1 supported in v1.1; got {}",
                parsed.x402_version
            ),
        });
    }
    Ok(parsed)
}

/// Validate the decoded `PaymentPayload` against the `PaymentRequirements`
/// the Hub constructed for this capability + agent (locked-design §3.5).
///
/// This is the Hub-side check before calling facilitator `/verify`. The
/// facilitator does its own crypto verification; this is the pre-flight
/// that rejects obvious mismatches without burning a facilitator round-trip.
pub fn validate_payment_payload(
    payload: &PaymentPayload,
    requirements: &PaymentRequirements,
    now_unix: u64,
) -> Result<(), X402Error> {
    // 1. Scheme + network must match exactly.
    if payload.scheme != requirements.scheme {
        return Err(X402Error::PaymentInvalid {
            subcause: "scheme_mismatch",
            message: format!(
                "scheme '{}' does not match requirements '{}'",
                payload.scheme, requirements.scheme
            ),
        });
    }
    if payload.network != requirements.network {
        return Err(X402Error::PaymentInvalid {
            subcause: "network_mismatch",
            message: format!(
                "network '{}' does not match requirements '{}'",
                payload.network, requirements.network
            ),
        });
    }

    let auth: &Eip3009Authorization = &payload.payload.authorization;

    // 2. Recipient (Splitter / pay_to) must match exactly. Locked-design §2 (B).
    if auth.to != requirements.pay_to {
        return Err(X402Error::PaymentInvalid {
            subcause: "recipient_mismatch",
            message: format!(
                "authorization.to={} does not match required pay_to={}",
                auth.to, requirements.pay_to
            ),
        });
    }

    // 3. Validity window. valid_after ≤ now < valid_before.
    if auth.valid_after > now_unix {
        return Err(X402Error::PaymentInvalid {
            subcause: "not_yet_valid",
            message: format!(
                "authorization.validAfter={} is in the future (now={})",
                auth.valid_after, now_unix
            ),
        });
    }
    if now_unix >= auth.valid_before {
        return Err(X402Error::PaymentInvalid {
            subcause: "expired",
            message: format!(
                "authorization.validBefore={} has passed (now={})",
                auth.valid_before, now_unix
            ),
        });
    }

    // 4. Amount must satisfy max_amount_required (string-encoded big int).
    let required: u128 = requirements
        .max_amount_required
        .parse()
        .map_err(|e| X402Error::PaymentInvalid {
            subcause: "amount_parse_error",
            message: format!(
                "payment_requirements.max_amount_required '{}' is not parseable: {}",
                requirements.max_amount_required, e
            ),
        })?;

    // alloy-primitives U256 → u128 conversion: x402 invoice amounts fit comfortably.
    let value_u128: u128 = auth.value.try_into().map_err(|_| X402Error::PaymentInvalid {
        subcause: "amount_overflow",
        message: format!(
            "authorization.value={} exceeds u128 range",
            auth.value
        ),
    })?;

    if value_u128 != required {
        // Strict equality per locked-design §3.5 (amount_mismatch). Future v1.2
        // may relax to value ≥ required if facilitator returns change.
        return Err(X402Error::PaymentInvalid {
            subcause: "amount_mismatch",
            message: format!(
                "authorization.value={} does not match required={}",
                value_u128, required
            ),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::x402_types::{Eip3009Authorization, ExactPayload};
    use alloy_primitives::{Address, U256};

    fn sample_payload(value_micro: u128, to: Address) -> PaymentPayload {
        PaymentPayload {
            x402_version: 1,
            scheme: "exact".into(),
            network: "base".into(),
            payload: ExactPayload {
                signature: "0x00".into(),
                authorization: Eip3009Authorization {
                    from: Address::ZERO,
                    to,
                    value: U256::from(value_micro),
                    valid_after: 0,
                    valid_before: 9_999_999_999,
                    nonce: alloy_primitives::B256::ZERO,
                },
            },
        }
    }

    fn sample_requirements(amount: u128, pay_to: Address) -> PaymentRequirements {
        PaymentRequirements {
            scheme: "exact".into(),
            network: "base".into(),
            max_amount_required: amount.to_string(),
            asset: Address::ZERO,
            pay_to,
            resource: "https://jecp.dev/v1/invoke".into(),
            description: "test".into(),
            mime_type: "application/json".into(),
            max_timeout_seconds: 60,
            extra: serde_json::Value::Null,
        }
    }

    #[test]
    fn decode_rejects_large_header() {
        let big = "A".repeat(MAX_X_PAYMENT_HEADER_BYTES + 1);
        let err = decode_x_payment_header(&big).unwrap_err();
        assert_eq!(err.code(), "X402_PAYMENT_INVALID");
        assert_eq!(err.subcause(), "header_too_large");
    }

    #[test]
    fn decode_rejects_invalid_base64() {
        let err = decode_x_payment_header("not!!base64").unwrap_err();
        assert_eq!(err.subcause(), "base64_decode");
    }

    #[test]
    fn decode_rejects_invalid_json() {
        let b64 = base64::engine::general_purpose::STANDARD.encode(b"not-json");
        let err = decode_x_payment_header(&b64).unwrap_err();
        assert_eq!(err.subcause(), "json_parse");
    }

    #[test]
    fn validate_rejects_recipient_mismatch() {
        let splitter = Address::from([0xAB; 20]);
        let attacker = Address::from([0xCD; 20]);
        let p = sample_payload(200_000, attacker);
        let r = sample_requirements(200_000, splitter);
        let err = validate_payment_payload(&p, &r, 100).unwrap_err();
        assert_eq!(err.subcause(), "recipient_mismatch");
    }

    #[test]
    fn validate_rejects_amount_mismatch() {
        let splitter = Address::from([0xAB; 20]);
        let p = sample_payload(100_000, splitter);
        let r = sample_requirements(200_000, splitter);
        let err = validate_payment_payload(&p, &r, 100).unwrap_err();
        assert_eq!(err.subcause(), "amount_mismatch");
    }

    #[test]
    fn validate_rejects_expired() {
        let splitter = Address::from([0xAB; 20]);
        let p = sample_payload(200_000, splitter);
        let mut r = sample_requirements(200_000, splitter);
        r.scheme = "exact".into();
        let err = validate_payment_payload(&p, &r, 10_000_000_000).unwrap_err();
        assert_eq!(err.subcause(), "expired");
    }

    #[test]
    fn validate_accepts_happy_path() {
        let splitter = Address::from([0xAB; 20]);
        let p = sample_payload(200_000, splitter);
        let r = sample_requirements(200_000, splitter);
        assert!(validate_payment_payload(&p, &r, 100).is_ok());
    }
}
