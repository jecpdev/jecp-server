//! HTTP-layer guards applied at handler entry.
//!
//! Centralises the `Content-Type` validation that every body-accepting POST
//! endpoint must perform per spec v1.0.2 §3.1 + §2 (K2.1 errata). Each
//! handler calls `ensure_json_ct(&headers)?` before parsing the body — on
//! failure the helper returns `JecpErrorCode::UnsupportedMediaType(...)`,
//! which `IntoResponse` renders as HTTP 415 with a structured envelope.
//!
//! ## Admiral decision D1 (2026-05-10): tolerate empty Content-Type.
//!
//! Per `phase0-locked-design.md` §11 D1 = "tolerate". Some HTTP clients
//! (including curl when called without `-H 'Content-Type:'` and some
//! testcontainer integrations) omit `Content-Type` on POST with body.
//! Spec §3 reads "Content-Type ≠ application/json MUST return 415" which
//! is technically silent on missing CT. We tolerate empty CT to preserve
//! existing e2e backward compat; non-JSON CT is rejected.
//!
//! ## What this rejects
//!
//! - `Content-Type: text/plain`
//! - `Content-Type: application/x-www-form-urlencoded`
//! - `Content-Type: application/xml`
//! - `Content-Type: multipart/form-data; boundary=...`
//! - Any value whose media type (left of the first `;`) does not equal
//!   the literal string `application/json` (case-insensitive).
//!
//! ## What this tolerates
//!
//! - `Content-Type: application/json`
//! - `Content-Type: application/json; charset=utf-8`  (parameter is allowed)
//! - `Content-Type: application/JSON`                 (case-insensitive)
//! - Missing `Content-Type` header (per D1)
//!
//! Streaming response negotiation (`Accept: text/event-stream`) is independent
//! of request `Content-Type`; this helper does not touch `Accept`.

use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::json;

use crate::protocol::errors::JecpErrorCode;

/// Validate that the request's `Content-Type` header is `application/json`
/// (with optional `;charset=...` parameter), or absent.
///
/// Returns `Ok(())` on accept; `Err(UnsupportedMediaType(received))` on reject.
pub fn ensure_json_ct(headers: &HeaderMap) -> Result<(), JecpErrorCode> {
    let raw = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok());

    let value = match raw {
        // No Content-Type header at all — tolerate (D1).
        None => return Ok(()),
        Some(s) => s,
    };

    // Parse out the media type (strip parameters). RFC 7231 §3.1.1.1:
    //   media-type = type "/" subtype *( OWS ";" OWS parameter )
    let media = value.split(';').next().unwrap_or("").trim();

    // Empty CT value (e.g. "Content-Type:" with no value) — tolerate.
    if media.is_empty() {
        return Ok(());
    }

    // Case-insensitive comparison against the canonical media type.
    if media.eq_ignore_ascii_case("application/json") {
        Ok(())
    } else {
        Err(JecpErrorCode::UnsupportedMediaType(value.to_string()))
    }
}

/// Tuple-form 415 response used by handlers whose return type is
/// `Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)>` rather
/// than `axum::response::Response`. Produces the same JECP envelope as
/// `JecpErrorCode::UnsupportedMediaType.into_response()`.
///
/// Use via `ensure_json_ct_tuple(&headers)?` at the top of these handlers.
fn unsupported_media_type_tuple(received: String) -> (StatusCode, Json<serde_json::Value>) {
    let body = json!({
        "jecp": "1.0",
        "status": "failed",
        "error": {
            "code": "UNSUPPORTED_MEDIA_TYPE",
            "message": format!("Unsupported media type: expected application/json, got {}", received),
            "details": {
                "received": received,
                "expected": "application/json",
                "documentation_url": "https://jecp.dev/errors/unsupported_media_type"
            }
        }
    });
    (StatusCode::UNSUPPORTED_MEDIA_TYPE, Json(body))
}

/// Convenience wrapper for handlers that return
/// `Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)>` —
/// converts the JecpErrorCode into the tuple form expected by `?`.
///
/// Defensive: if `ensure_json_ct` ever returns a different variant in the
/// future (e.g. a header parsing error), we fall back to the canonical 415
/// shape with `received="<unknown>"` rather than panicking in prod. The
/// `debug_assert!` makes the violation loud in CI/tests but harmless live.
pub fn ensure_json_ct_tuple(
    headers: &HeaderMap,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    ensure_json_ct(headers).map_err(|e| match e {
        JecpErrorCode::UnsupportedMediaType(received) => unsupported_media_type_tuple(received),
        other => {
            debug_assert!(
                false,
                "ensure_json_ct returned unexpected variant: {:?} — only UnsupportedMediaType is expected",
                other
            );
            unsupported_media_type_tuple(format!("<unknown: {}>", other.code()))
        }
    })
}

/// Convenience wrapper for handlers that return `axum::response::Response`.
/// Mirrors `ensure_json_ct_tuple` for handlers using the IntoResponse pattern.
pub fn ensure_json_ct_response(
    headers: &HeaderMap,
) -> Result<(), axum::response::Response> {
    use axum::response::IntoResponse;
    ensure_json_ct(headers).map_err(|e| e.into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn hm(ct: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Some(v) = ct {
            h.insert(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn accepts_application_json() {
        assert!(ensure_json_ct(&hm(Some("application/json"))).is_ok());
    }

    #[test]
    fn accepts_application_json_with_charset() {
        assert!(ensure_json_ct(&hm(Some("application/json; charset=utf-8"))).is_ok());
        assert!(ensure_json_ct(&hm(Some("application/json;charset=utf-8"))).is_ok());
    }

    #[test]
    fn accepts_case_variants() {
        assert!(ensure_json_ct(&hm(Some("Application/JSON"))).is_ok());
        assert!(ensure_json_ct(&hm(Some("APPLICATION/JSON"))).is_ok());
    }

    #[test]
    fn tolerates_missing_content_type() {
        // D1 = tolerate empty CT for backward compat.
        assert!(ensure_json_ct(&hm(None)).is_ok());
    }

    #[test]
    fn tolerates_blank_content_type() {
        // Some clients send "Content-Type:" with no value.
        assert!(ensure_json_ct(&hm(Some(""))).is_ok());
        assert!(ensure_json_ct(&hm(Some("  "))).is_ok());
        assert!(ensure_json_ct(&hm(Some("; charset=utf-8"))).is_ok());
    }

    #[test]
    fn rejects_text_plain() {
        let err = ensure_json_ct(&hm(Some("text/plain"))).unwrap_err();
        match err {
            JecpErrorCode::UnsupportedMediaType(received) => {
                assert_eq!(received, "text/plain");
            }
            other => panic!("expected UnsupportedMediaType, got {:?}", other),
        }
    }

    #[test]
    fn rejects_form_urlencoded() {
        let err = ensure_json_ct(&hm(Some("application/x-www-form-urlencoded"))).unwrap_err();
        assert!(matches!(err, JecpErrorCode::UnsupportedMediaType(_)));
    }

    #[test]
    fn rejects_application_xml() {
        let err = ensure_json_ct(&hm(Some("application/xml"))).unwrap_err();
        assert!(matches!(err, JecpErrorCode::UnsupportedMediaType(_)));
    }

    #[test]
    fn rejects_multipart_form_data() {
        let err = ensure_json_ct(&hm(Some("multipart/form-data; boundary=---abc"))).unwrap_err();
        match err {
            JecpErrorCode::UnsupportedMediaType(received) => {
                // Full value retained for diagnostics, not just the media type.
                assert!(received.contains("multipart/form-data"));
            }
            other => panic!("expected UnsupportedMediaType, got {:?}", other),
        }
    }

    #[test]
    fn rejects_application_jsonl() {
        // application/jsonl is NOT application/json.
        let err = ensure_json_ct(&hm(Some("application/jsonl"))).unwrap_err();
        assert!(matches!(err, JecpErrorCode::UnsupportedMediaType(_)));
    }

    #[test]
    fn unsupported_media_type_carries_correct_status_and_code() {
        let err = JecpErrorCode::UnsupportedMediaType("text/plain".into());
        assert_eq!(err.code(), "UNSUPPORTED_MEDIA_TYPE");
        assert_eq!(err.status_code(), axum::http::StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
}
