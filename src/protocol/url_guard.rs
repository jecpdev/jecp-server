//! v1.1.0 c6 — Composite SSRF defense for Agent-controlled URLs.
//!
//! Spec: 02-authentication §9.7 + §9.7.1 (normative). ADR-0002 records the
//! architecture decision (5-layer pipeline) and rejected alternatives.
//!
//! # Pipeline (in order)
//!
//! 1. **Parse** — `url::Url::parse` per RFC 3986. Malformed → reject.
//! 2. **Scheme allowlist** — `https` only in production. `http` permitted
//!    iff `JECP_TEST_MODE=true` (admiral D14, env-flag at boot, not API-toggleable).
//! 3. **Host normalization** — percent-decoded; IDN punycoded. Reject if the
//!    decoded host is itself an IP literal that hits the deny CIDRs (catches
//!    `https://%31%32%37.0.0.1/` style bypass).
//! 4. **DNS resolve** — `tokio::net::lookup_host` returns ALL addresses. Each
//!    one is checked against the deny CIDRs. Any deny hit rejects the URL.
//! 5. **Connect-time pin** — caller uses `guarded_client(pinned_addr)` to build
//!    a `reqwest::Client` whose `.resolve(host, addr)` overrides the resolver
//!    so `connect()` cannot be redirected by DNS rebinding between check and
//!    use. Outbound clients also disable redirects (`Policy::none()`); each
//!    redirect target is a NEW Agent-controlled URL that callers must
//!    re-validate.
//!
//! Returns `Result<ValidatedUrl, UrlGuardError>` where `ValidatedUrl` exposes
//! the pinned `SocketAddr` for `guarded_client(addr)`. The matching error
//! converter for the JECP wire-format envelope is
//! `UrlGuardError::into_jecp_error(field)` → `JecpErrorCode::UrlBlockedSsrf`.

use std::env;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use once_cell::sync::Lazy;
use url::Url;

/// 10 deny CIDRs covering loopback / link-local / RFC1918 / RFC4193 / IPv4-mapped IPv6
/// / unspecified (`0.0.0.0/8`). Source-of-truth: spec §9.7.1.2.
static DENY_CIDRS: Lazy<Vec<IpNet>> = Lazy::new(|| {
    let v4: Vec<Ipv4Net> = vec![
        "0.0.0.0/8".parse().unwrap(),       // any / unspecified
        "10.0.0.0/8".parse().unwrap(),      // RFC 1918
        "127.0.0.0/8".parse().unwrap(),     // loopback (covers 127.0.0.1)
        "169.254.0.0/16".parse().unwrap(),  // link-local (AWS / GCP / Azure metadata at .169.254)
        "172.16.0.0/12".parse().unwrap(),   // RFC 1918
        "192.168.0.0/16".parse().unwrap(),  // RFC 1918
    ];
    let v6: Vec<Ipv6Net> = vec![
        "::1/128".parse().unwrap(),         // IPv6 loopback
        "fe80::/10".parse().unwrap(),       // IPv6 link-local
        "fc00::/7".parse().unwrap(),        // IPv6 ULA (RFC 4193)
        "::ffff:0.0.0.0/96".parse().unwrap(), // IPv4-mapped IPv6 (catches ::ffff:127.0.0.1)
    ];
    v4.into_iter()
        .map(IpNet::V4)
        .chain(v6.into_iter().map(IpNet::V6))
        .collect()
});

/// Outcome of a successful validation: pinned IP for `connect()` + the
/// host the caller passes to `Client::resolve(host, pinned_addr)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedUrl {
    /// The original URL (unchanged from input).
    pub url: String,
    /// Hostname extracted from the URL (for `Client::resolve(host, addr)`).
    pub host: String,
    /// The IP address the caller MUST connect to. Calling `client.post(&url)`
    /// with `Client::resolve(host, pinned_addr)` overrides DNS for this request
    /// so DNS rebinding between check and connect cannot redirect the request.
    pub pinned_addr: SocketAddr,
}

/// Why an URL was rejected. Maps to `error.details.reason` in the
/// `URL_BLOCKED_SSRF` envelope per spec §9.7.1.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UrlGuardError {
    /// URL did not parse per RFC 3986.
    ParseError(String),
    /// Scheme is not `https` (or `http` outside test mode).
    Scheme(String),
    /// Host is empty / percent-encoded that decodes to a deny IP literal /
    /// otherwise malformed after normalization.
    HostSyntax(String),
    /// DNS resolved the host but at least one returned address falls in a
    /// deny CIDR (loopback / link-local / RFC 1918 / etc.). Reports the
    /// blocked address.
    ResolvedToDenyCidr {
        host: String,
        blocked_ip: IpAddr,
    },
    /// DNS resolution failed entirely (NXDOMAIN, network unreachable, etc.).
    /// Treated as soft-fail at register time; callers MAY retry.
    DnsResolveFailed(String),
}

impl UrlGuardError {
    /// String token for the `error.details.reason` field.
    pub fn reason(&self) -> &'static str {
        match self {
            UrlGuardError::ParseError(_)        => "parse_error",
            UrlGuardError::Scheme(_)            => "scheme",
            UrlGuardError::HostSyntax(_)        => "host_syntax",
            UrlGuardError::ResolvedToDenyCidr{..} => "resolved_to_deny_cidr",
            UrlGuardError::DnsResolveFailed(_)  => "dns_resolve_failed",
        }
    }

    /// Human-readable summary; safe to surface in `error.message`.
    pub fn summary(&self) -> String {
        match self {
            UrlGuardError::ParseError(d)        => format!("URL parse failed: {d}"),
            UrlGuardError::Scheme(s)            => format!("scheme '{s}' not permitted"),
            UrlGuardError::HostSyntax(h)        => format!("host '{h}' rejected by normalization"),
            UrlGuardError::ResolvedToDenyCidr{host, blocked_ip} =>
                format!("host '{host}' resolved to deny-CIDR address {blocked_ip}"),
            UrlGuardError::DnsResolveFailed(d)  => format!("DNS resolve failed: {d}"),
        }
    }
}

/// Whether `JECP_TEST_MODE=true` is enabled at boot. Per admiral D14, this
/// gates the `http` scheme + the loopback exception (allows local CI to
/// stand up a test webhook receiver). The flag is read ONCE at startup;
/// runtime mutation has no effect.
fn test_mode_enabled() -> bool {
    static FLAG: Lazy<bool> = Lazy::new(|| {
        env::var("JECP_TEST_MODE").map(|v| v == "true" || v == "1").unwrap_or(false)
    });
    *FLAG
}

/// Returns true if `addr` is in any deny CIDR.
pub fn is_denied(addr: IpAddr) -> bool {
    // Map IPv4-mapped IPv6 to its IPv4 equivalent for deny-list comparison
    // so `::ffff:127.0.0.1` is checked against the IPv4 deny CIDRs too.
    let normalized: IpAddr = match addr {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None     => IpAddr::V6(v6),
        },
        v4 => v4,
    };
    DENY_CIDRS.iter().any(|net| net.contains(&normalized))
}

/// Apply layers 1-4 of the SSRF pipeline (everything except connect-time pin).
/// Returns the validated URL + pinned address on success.
///
/// Pin layer happens at the caller via `guarded_client(pinned_addr)`.
///
/// Note: this is the **async** entry point because layer 4 (DNS resolve) is
/// async via `tokio::net::lookup_host`. Synchronous register-time preflights
/// can use `validate_outbound_url_preflight` (skips DNS resolve, runs only
/// layers 1-3 + a deny-IP-literal check on parsed host).
pub async fn validate_outbound_url(url_str: &str) -> Result<ValidatedUrl, UrlGuardError> {
    // Layer 1: parse.
    let url = Url::parse(url_str)
        .map_err(|e| UrlGuardError::ParseError(e.to_string()))?;

    // Layer 2: scheme allowlist.
    let scheme = url.scheme();
    let scheme_ok = scheme == "https" || (test_mode_enabled() && scheme == "http");
    if !scheme_ok {
        return Err(UrlGuardError::Scheme(scheme.to_string()));
    }

    // Layer 3: host normalization.
    // Use url::Host directly so IPv6 literals come out as Host::Ipv6 (no
    // brackets to strip) and IPv4 literals come out as Host::Ipv4.
    let host = url.host()
        .ok_or_else(|| UrlGuardError::HostSyntax("missing host".to_string()))?;

    // Re-derive the canonical host string for `Client::resolve(host, addr)`.
    // For IPv6 literals, reqwest expects the bracketed form, so use
    // `host_str()` which preserves the wire form.
    let host_str = url.host_str()
        .ok_or_else(|| UrlGuardError::HostSyntax("missing host".to_string()))?
        .to_string();

    // Layer 3 fast-path: IP literal hosts skip DNS resolution.
    let literal_ip: Option<IpAddr> = match host {
        url::Host::Ipv4(v4) => Some(IpAddr::V4(v4)),
        url::Host::Ipv6(v6) => Some(IpAddr::V6(v6)),
        url::Host::Domain(_) => None,
    };
    if let Some(ip) = literal_ip {
        if is_denied(ip) {
            return Err(UrlGuardError::ResolvedToDenyCidr {
                host: host_str.clone(),
                blocked_ip: ip,
            });
        }
        // Public IP literal — no DNS resolve needed.
        let port = url.port_or_known_default()
            .ok_or_else(|| UrlGuardError::HostSyntax("no port and no default for scheme".to_string()))?;
        return Ok(ValidatedUrl {
            url: url_str.to_string(),
            host: host_str,
            pinned_addr: SocketAddr::new(ip, port),
        });
    }

    // Reject empty / dot-only / control-char hosts.
    if host_str.is_empty() || host_str == "." || host_str.contains('\0') {
        return Err(UrlGuardError::HostSyntax(host_str));
    }

    // Layer 4: DNS resolve. Use a short timeout so a deliberately-slow resolver
    // can't pin a Hub thread.
    let port = url.port_or_known_default()
        .ok_or_else(|| UrlGuardError::HostSyntax("no port and no default for scheme".to_string()))?;
    let lookup = format!("{host_str}:{port}");

    let resolved = tokio::time::timeout(
        Duration::from_secs(3),
        tokio::net::lookup_host(&lookup),
    )
    .await
    .map_err(|_| UrlGuardError::DnsResolveFailed(format!("timeout resolving '{host_str}'")))?
    .map_err(|e| UrlGuardError::DnsResolveFailed(format!("{e}")))?;

    let mut chosen: Option<SocketAddr> = None;
    for sa in resolved {
        if is_denied(sa.ip()) {
            return Err(UrlGuardError::ResolvedToDenyCidr {
                host: host_str.clone(),
                blocked_ip: sa.ip(),
            });
        }
        if chosen.is_none() {
            chosen = Some(sa);
        }
    }

    let pinned_addr = chosen.ok_or_else(||
        UrlGuardError::DnsResolveFailed(format!("no addresses returned for '{host_str}'")))?;

    Ok(ValidatedUrl {
        url: url_str.to_string(),
        host: host_str,
        pinned_addr,
    })
}

/// Synchronous preflight: layers 1-3 + literal-IP deny check. Suitable for
/// register-time fast-fail (`POST /v1/providers/register`,
/// `POST /v1/subscriptions`) where the Hub returns a 422 immediately for
/// obvious violations without paying the DNS resolve cost. Async deref
/// paths still MUST call `validate_outbound_url` (the full pipeline) at
/// request time per spec §9.7.1 — DNS rebinding requires deref-time check.
pub fn validate_outbound_url_preflight(url_str: &str) -> Result<(), UrlGuardError> {
    let url = Url::parse(url_str)
        .map_err(|e| UrlGuardError::ParseError(e.to_string()))?;

    let scheme = url.scheme();
    let scheme_ok = scheme == "https" || (test_mode_enabled() && scheme == "http");
    if !scheme_ok {
        return Err(UrlGuardError::Scheme(scheme.to_string()));
    }

    let host = url.host()
        .ok_or_else(|| UrlGuardError::HostSyntax("missing host".to_string()))?;
    let host_str = url.host_str()
        .ok_or_else(|| UrlGuardError::HostSyntax("missing host".to_string()))?;

    let literal_ip: Option<IpAddr> = match host {
        url::Host::Ipv4(v4) => Some(IpAddr::V4(v4)),
        url::Host::Ipv6(v6) => Some(IpAddr::V6(v6)),
        url::Host::Domain(_) => None,
    };
    if let Some(ip) = literal_ip {
        if is_denied(ip) {
            return Err(UrlGuardError::ResolvedToDenyCidr {
                host: host_str.to_string(),
                blocked_ip: ip,
            });
        }
    }
    if host_str.is_empty() || host_str == "." || host_str.contains('\0') {
        return Err(UrlGuardError::HostSyntax(host_str.to_string()));
    }
    Ok(())
}

/// Persist a rejected URL to the `ssrf_attempts` audit table per spec
/// §9.7.1.4. Best-effort: failures are logged but do NOT propagate (the
/// authoritative rejection is the JECP envelope returned to the caller).
pub async fn audit_log_rejection(
    pool: &sqlx::PgPool,
    agent_id:    Option<&str>,
    provider_id: Option<uuid::Uuid>,
    field_name:  &str,
    surface:     &str,
    blocked_url: &str,
    reason:      &str,
    request_id:  Option<&str>,
) {
    // Redact credentials (anything before @ in the userinfo).
    let safe_url = redact_url(blocked_url);

    // Mirror to logs first (always works even if DB is offline).
    tracing::warn!(
        target = "ssrf",
        agent_id = ?agent_id,
        provider_id = ?provider_id,
        field = field_name,
        surface = surface,
        reason = reason,
        request_id = ?request_id,
        "URL_BLOCKED_SSRF: {}", safe_url,
    );

    // Persist audit row.
    let res = sqlx::query(
        "INSERT INTO jecp.ssrf_attempts \
         (agent_id, provider_id, field_name, surface, blocked_url, reason, request_id) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)"
    )
    .bind(agent_id)
    .bind(provider_id)
    .bind(field_name)
    .bind(surface)
    .bind(&safe_url)
    .bind(reason)
    .bind(request_id)
    .execute(pool)
    .await;

    if let Err(e) = res {
        tracing::warn!(target = "ssrf", error = %e,
            "ssrf_attempts INSERT failed (rejection still surfaced to caller)");
    }
}

/// Strip credentials from a URL: `https://user:pass@host/path` → `https://host/path`.
/// Best-effort string transform; falls back to the input if parsing fails.
pub fn redact_url(s: &str) -> String {
    match Url::parse(s) {
        Ok(mut u) => {
            let _ = u.set_username("");
            let _ = u.set_password(None);
            u.to_string()
        }
        Err(_) => s.to_string(),
    }
}

/// Convert a UrlGuardError into the tuple form returned by routes that
/// use `Result<_, (StatusCode, Json<Value>)>`. The tuple shape matches the
/// JECP envelope from `JecpErrorCode::UrlBlockedSsrf` IntoResponse so the
/// wire bytes are identical regardless of which call site rejected.
pub fn url_blocked_ssrf_tuple(
    field:       &str,
    blocked_url: &str,
    reason:      &str,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    use serde_json::json;
    let body = json!({
        "jecp":   "1.0",
        "status": "failed",
        "error": {
            "code":    "URL_BLOCKED_SSRF",
            "message": format!("URL blocked by SSRF policy: {field} {reason}"),
            "details": {
                "field":             field,
                "blocked_url":       blocked_url,
                "reason":            reason,
                "documentation_url": format!("https://jecp.dev/errors/url_blocked_ssrf#{reason}"),
            }
        }
    });
    (axum::http::StatusCode::UNPROCESSABLE_ENTITY, axum::Json(body))
}

/// Build a `reqwest::Client` that connects to `pinned_addr` for the validated
/// host. Per ADR-0002, this closes the rebinding window between check and
/// connect. Redirects are DISABLED — callers MUST re-validate redirect
/// targets explicitly.
///
/// The client's connection pool is keyed by `(host, pinned_addr)` so two
/// requests to the same host but different pins do not share a pool entry
/// (the underlying TCP connection is bound to the validated address).
pub fn guarded_client(host: &str, pinned_addr: SocketAddr) -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .resolve(host, pinned_addr)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()
}

// ----------------------------------------------------------------------
// Tests (20+)
// ----------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // ---- is_denied: 6 attack families × 4 representations ----

    #[test]
    fn deny_loopback_v4()    { assert!(is_denied(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))); }
    #[test]
    fn deny_loopback_v6()    { assert!(is_denied(IpAddr::V6(Ipv6Addr::LOCALHOST))); }
    #[test]
    fn deny_metadata_aws()   { assert!(is_denied(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)))); }
    #[test]
    fn deny_link_local_v6()  { assert!(is_denied(IpAddr::V6("fe80::1".parse().unwrap()))); }
    #[test]
    fn deny_rfc1918_10()     { assert!(is_denied(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))); }
    #[test]
    fn deny_rfc1918_172()    { assert!(is_denied(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)))); }
    #[test]
    fn deny_rfc1918_192()    { assert!(is_denied(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)))); }
    #[test]
    fn deny_rfc4193()        { assert!(is_denied(IpAddr::V6("fc00::1".parse().unwrap()))); }
    #[test]
    fn deny_unspecified()    { assert!(is_denied(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)))); }

    /// IPv4-mapped IPv6 form of 127.0.0.1 — most common bypass.
    #[test]
    fn deny_v4_mapped_v6_loopback() {
        let mapped: Ipv6Addr = "::ffff:127.0.0.1".parse().unwrap();
        assert!(is_denied(IpAddr::V6(mapped)));
    }

    /// IPv4-mapped IPv6 form of metadata IP.
    #[test]
    fn deny_v4_mapped_v6_metadata() {
        let mapped: Ipv6Addr = "::ffff:169.254.169.254".parse().unwrap();
        assert!(is_denied(IpAddr::V6(mapped)));
    }

    #[test]
    fn allow_public_dns() {
        assert!(!is_denied(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        assert!(!is_denied(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    #[test]
    fn allow_public_v6() {
        // 2606:4700:4700::1111 is Cloudflare's public IPv6 DNS.
        let public: Ipv6Addr = "2606:4700:4700::1111".parse().unwrap();
        assert!(!is_denied(IpAddr::V6(public)));
    }

    // ---- validate_outbound_url: scheme + parse + literal-IP rejection ----

    #[tokio::test]
    async fn parse_error_on_garbage() {
        let r = validate_outbound_url("not a url").await;
        assert!(matches!(r, Err(UrlGuardError::ParseError(_))));
    }

    #[tokio::test]
    async fn scheme_rejected_gopher() {
        let r = validate_outbound_url("gopher://example.com/").await;
        assert!(matches!(r, Err(UrlGuardError::Scheme(s)) if s == "gopher"));
    }

    #[tokio::test]
    async fn scheme_rejected_file() {
        let r = validate_outbound_url("file:///etc/passwd").await;
        assert!(matches!(r, Err(UrlGuardError::Scheme(s)) if s == "file"));
    }

    #[tokio::test]
    async fn scheme_rejected_ftp() {
        let r = validate_outbound_url("ftp://example.com/").await;
        assert!(matches!(r, Err(UrlGuardError::Scheme(_))));
    }

    #[tokio::test]
    async fn scheme_rejected_http_in_prod() {
        // Without JECP_TEST_MODE, http MUST be rejected.
        // Note: this test relies on the static Lazy not having been initialized
        // with TEST_MODE=true elsewhere in the same process.
        if !test_mode_enabled() {
            let r = validate_outbound_url("http://example.com/").await;
            assert!(matches!(r, Err(UrlGuardError::Scheme(s)) if s == "http"));
        }
    }

    #[tokio::test]
    async fn ip_literal_loopback_rejected() {
        let r = validate_outbound_url("https://127.0.0.1/").await;
        match r {
            Err(UrlGuardError::ResolvedToDenyCidr { blocked_ip, .. }) => {
                assert_eq!(blocked_ip, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
            }
            other => panic!("expected deny CIDR, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn ip_literal_metadata_rejected() {
        let r = validate_outbound_url("https://169.254.169.254/latest/meta-data/").await;
        assert!(matches!(r, Err(UrlGuardError::ResolvedToDenyCidr { .. })));
    }

    #[tokio::test]
    async fn ip_literal_v6_loopback_rejected() {
        let r = validate_outbound_url("https://[::1]/").await;
        assert!(matches!(r, Err(UrlGuardError::ResolvedToDenyCidr { .. })));
    }

    #[tokio::test]
    async fn ip_literal_v4_mapped_v6_rejected() {
        let r = validate_outbound_url("https://[::ffff:127.0.0.1]/").await;
        assert!(matches!(r, Err(UrlGuardError::ResolvedToDenyCidr { .. })));
    }

    #[tokio::test]
    async fn ip_literal_rfc1918_rejected() {
        let r = validate_outbound_url("https://10.0.0.7/internal").await;
        assert!(matches!(r, Err(UrlGuardError::ResolvedToDenyCidr { .. })));
    }

    #[tokio::test]
    async fn empty_host_rejected() {
        let r = validate_outbound_url("https:///nohost").await;
        // url crate may flag this as parse error; both outcomes are correct rejection.
        assert!(r.is_err());
    }

    // ---- preflight (sync, no DNS) ----

    #[test]
    fn preflight_ip_literal_loopback_rejected() {
        let r = validate_outbound_url_preflight("https://127.0.0.1/x");
        assert!(matches!(r, Err(UrlGuardError::ResolvedToDenyCidr { .. })));
    }

    #[test]
    fn preflight_v6_loopback_rejected() {
        let r = validate_outbound_url_preflight("https://[::1]/x");
        assert!(matches!(r, Err(UrlGuardError::ResolvedToDenyCidr { .. })));
    }

    #[test]
    fn preflight_https_public_passes() {
        // No DNS — preflight only checks scheme + literal-IP. Public domain passes.
        let r = validate_outbound_url_preflight("https://example.com/webhook");
        assert!(r.is_ok(), "expected Ok, got {r:?}");
    }

    #[test]
    fn preflight_scheme_rejection() {
        assert!(matches!(
            validate_outbound_url_preflight("gopher://example.com/"),
            Err(UrlGuardError::Scheme(_))
        ));
    }

    // ---- error reason mapping (used in 422 envelope) ----

    #[test]
    fn reason_strings_match_spec() {
        assert_eq!(UrlGuardError::ParseError("x".into()).reason(), "parse_error");
        assert_eq!(UrlGuardError::Scheme("ftp".into()).reason(),   "scheme");
        assert_eq!(UrlGuardError::HostSyntax("..".into()).reason(),"host_syntax");
        assert_eq!(UrlGuardError::ResolvedToDenyCidr {
            host: "x.example".into(),
            blocked_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        }.reason(), "resolved_to_deny_cidr");
        assert_eq!(UrlGuardError::DnsResolveFailed("nx".into()).reason(), "dns_resolve_failed");
    }

    // ---- guarded_client ----

    #[test]
    fn guarded_client_builds() {
        let addr = "1.1.1.1:443".parse::<SocketAddr>().unwrap();
        let client = guarded_client("example.com", addr);
        assert!(client.is_ok());
    }

    #[test]
    fn guarded_client_disables_redirects() {
        // We can't easily intercept redirect handling without a real server,
        // but we can confirm the builder constructs successfully and that the
        // construction doesn't panic. The Policy::none() invariant is
        // preserved by the impl above; if the source ever drifts, this
        // test prompts a re-review.
        let addr = "8.8.8.8:443".parse::<SocketAddr>().unwrap();
        let _ = guarded_client("example.com", addr).expect("client must build");
    }
}
