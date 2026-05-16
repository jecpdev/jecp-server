//! Tower middleware: attach `Deprecation` / `Sunset` / `Link` response
//! headers when an invocation succeeded using Provenance v1 (per spec
//! v1.0 §5.7 sunset schedule and RFC 8594).
//!
//! Activation: handlers mark a successful v1 invocation by inserting
//! `ProvenanceVersion::V1` into the `Response::extensions`. The middleware
//! reads that marker, checks the feature flag, and (only on 2xx responses)
//! injects the three headers.
//!
//! Feature flag: `JECP_DEPRECATION_HEADERS` env var. When unset or set to
//! anything other than `"on"`, the middleware is a no-op. The intended
//! activation date is 2026-08-01 (spec §5.7); shipping the code earlier
//! lets us flip the flag in production with a single restart and no
//! second deploy. Setting it to `"on"` immediately is also conformant
//! per spec ("Hubs MAY attach earlier").

use std::env;
use std::task::{Context, Poll};

use axum::http::{HeaderValue, Request, Response};
use futures::future::BoxFuture;
use tower::{Layer, Service};

/// Marker placed by the handler in `Response::extensions` when a successful
/// invocation accepted a Provenance v1 hash (`<sha256_hex>` wire format).
/// Absence of the marker means v2 was used (or no provenance hash at all).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvenanceVersion {
    V1,
    V2,
}

const SUNSET_VALUE: &str = "Sat, 01 Nov 2026 00:00:00 GMT";
const LINK_VALUE: &str =
    "<https://jecp.dev/spec/v1.0/02-authentication.md#57-sunset-schedule-for-v1>; rel=\"deprecation\"";

#[inline]
fn flag_enabled() -> bool {
    matches!(env::var("JECP_DEPRECATION_HEADERS").ok().as_deref(), Some("on" | "1" | "true"))
}

#[derive(Clone, Default)]
pub struct DeprecationLayer;

impl DeprecationLayer {
    pub fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for DeprecationLayer {
    type Service = DeprecationService<S>;
    fn layer(&self, inner: S) -> Self::Service {
        DeprecationService { inner }
    }
}

#[derive(Clone)]
pub struct DeprecationService<S> {
    inner: S,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for DeprecationService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<S::Response, S::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let fut = self.inner.call(req);
        Box::pin(async move {
            let mut response = fut.await?;
            // Only inject on 2xx + v1 marker + feature flag enabled.
            // v2 + non-2xx + flag-off → no headers.
            let is_success = response.status().is_success();
            let is_v1 = response.extensions().get::<ProvenanceVersion>()
                == Some(&ProvenanceVersion::V1);
            if is_success && is_v1 && flag_enabled() {
                let headers = response.headers_mut();
                headers.insert("Deprecation", HeaderValue::from_static("true"));
                headers.insert("Sunset", HeaderValue::from_static(SUNSET_VALUE));
                headers.insert("Link", HeaderValue::from_static(LINK_VALUE));
            }
            Ok(response)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_recognises_on_variants() {
        // Save / restore env
        let old = env::var("JECP_DEPRECATION_HEADERS").ok();

        env::set_var("JECP_DEPRECATION_HEADERS", "on");
        assert!(flag_enabled());
        env::set_var("JECP_DEPRECATION_HEADERS", "1");
        assert!(flag_enabled());
        env::set_var("JECP_DEPRECATION_HEADERS", "true");
        assert!(flag_enabled());
        env::set_var("JECP_DEPRECATION_HEADERS", "off");
        assert!(!flag_enabled());
        env::remove_var("JECP_DEPRECATION_HEADERS");
        assert!(!flag_enabled());

        if let Some(v) = old {
            env::set_var("JECP_DEPRECATION_HEADERS", v);
        }
    }
}
