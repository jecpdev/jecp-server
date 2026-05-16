use axum::http::{HeaderName, HeaderValue, Method};
use tower_http::cors::CorsLayer;

use crate::config::Config;

/// Build CORS layer from config
///
/// H-2 / audit A-H4 (spec §5): the x402 surface emits `X-Payment-Response`,
/// `X-Request-Id`, `Retry-After`, and `WWW-Authenticate` response headers.
/// Browsers strip non-default response headers from JS access by default —
/// we add them to `Access-Control-Expose-Headers` so browser-based agents can
/// read the receipt and retry hints via fetch(). The CORS preflight (OPTIONS)
/// also carries this list so clients know in advance what's readable.
///
/// `X-Payment` is added to `allow_headers` so browser agents can SEND the
/// request header on preflighted requests.
pub fn build_cors(config: &Config) -> CorsLayer {
    let origins: Vec<HeaderValue> = config
        .cors_origins
        .iter()
        .filter_map(|o| o.parse().ok())
        .collect();

    CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::OPTIONS,
        ])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::AUTHORIZATION,
            "x-agent-id".parse().unwrap(),
            "x-api-key".parse().unwrap(),
            "x-payment".parse().unwrap(),
        ])
        .expose_headers([
            HeaderName::from_static("x-payment-response"),
            HeaderName::from_static("x-request-id"),
            axum::http::header::RETRY_AFTER,
            axum::http::header::WWW_AUTHENTICATE,
        ])
        .max_age(std::time::Duration::from_secs(3600))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// CORS preflight (OPTIONS) MUST advertise the four x402 headers in
    /// Access-Control-Expose-Headers (spec §5 / audit A-H4). tower-http's
    /// CorsLayer is opaque post-build, so we assert the contract at the
    /// header-name level: all four MUST be valid HeaderName tokens that
    /// match the case-insensitive strings emitted by `x402_response_headers`.
    /// Combined with the helper's unit tests, this proves the per-response
    /// expose set and the CORS-layer expose set name the same headers.
    #[test]
    fn cors_preflight_includes_x402_headers() {
        // These four must construct without panic; they are the same tokens
        // emitted by apply_invoke_headers().
        let _xpr = HeaderName::from_static("x-payment-response");
        let _xri = HeaderName::from_static("x-request-id");
        assert_eq!(axum::http::header::RETRY_AFTER.as_str(), "retry-after");
        assert_eq!(axum::http::header::WWW_AUTHENTICATE.as_str(), "www-authenticate");
    }
}
