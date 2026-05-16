//! S0 Sprint — panic boundary middleware.
//!
//! Wraps the entire router with `tower-http::catch_panic` so a panic in
//! any handler is converted to HTTP 500 with a JECP-formatted error
//! envelope, NOT a hung connection or terminated process. Other
//! requests in flight continue normally.
//!
//! Without this, a panic in handler code would propagate up the stack
//! and reset the connection without a body — clients see a hard
//! disconnect, not a structured error.

use axum::http::{HeaderMap, HeaderValue, Response, StatusCode};
use http_body_util::Full;
use serde_json::json;
use std::any::Any;
use tower_http::catch_panic::CatchPanicLayer;

/// Build the panic boundary layer used by `Router::layer(...)`.
pub fn build_layer() -> CatchPanicLayer<fn(Box<dyn Any + Send + 'static>) -> Response<Full<axum::body::Bytes>>> {
    CatchPanicLayer::custom(panic_to_response as fn(_) -> _)
}

fn panic_to_response(panic_payload: Box<dyn Any + Send + 'static>) -> Response<Full<axum::body::Bytes>> {
    let message = downcast_panic(&panic_payload);
    tracing::error!(panic = %message, "panic boundary caught panic in handler");

    let body = json!({
        "jecp": "1.0",
        "status": "failed",
        "error": {
            "code": "INTERNAL_PANIC",
            "message": "An internal error occurred. The request was rejected; other requests are unaffected.",
        },
        "next_action": {
            "type": "retry_with_backoff",
            "hint": "Transient internal error. Retry once with exponential backoff. If it persists, contact hello@jecp.dev with the X-Request-Id header.",
        },
    });
    let bytes = axum::body::Bytes::from(body.to_string());

    let mut headers = HeaderMap::new();
    headers.insert("content-type", HeaderValue::from_static("application/json"));

    let mut resp = Response::new(Full::new(bytes));
    *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    *resp.headers_mut() = headers;
    resp
}

fn downcast_panic(payload: &Box<dyn Any + Send + 'static>) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        return (*s).to_string();
    }
    if let Some(s) = payload.downcast_ref::<String>() {
        return s.clone();
    }
    "unknown panic payload".to_string()
}
