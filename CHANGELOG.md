# Changelog

All notable changes to the JECP reference Hub.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
The Hub follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html);
**v1.x wire compatibility is frozen** per
[RELEASE_NOTES_v1.0.0.md](./RELEASE_NOTES_v1.0.0.md).

Spec version that each Hub release implements is recorded at
[`github.com/jecpdev/jecp-spec`](https://github.com/jecpdev/jecp-spec).

---

## [1.1.1] — 2026-05-15

### Added — x402 native settlement (locked-design v1.1.1, Panel 3)
- **Hub Rust x402 integration** — `/v1/invoke` can settle directly on the
  x402 facilitator network as an alternative to Stripe Connect.
- **AWS KMS Ethereum signer** — production signer for x402 settlement.
  Keys never leave KMS; the Hub signs request envelopes via the KMS API.

### Security — H-series hardening (HIGH severity, audit-A)
- **H-1: Cert pin TLS enforcement** — facilitator outbound HTTPS now
  uses a custom `ServerCertVerifier` (rustls) with SPKI pinning on top of
  WebPKI chain validation. Constant-time SPKI compare via `subtle`.
  Documented as ADR-0005.
- **H-2: HIGH-severity response headers wired across all endpoints**
  (HSTS / X-Content-Type-Options / X-Frame-Options / Referrer-Policy /
  Permissions-Policy / Cross-Origin-Resource-Policy).
- **H-3: AWS KMS Ethereum signer production implementation** (closure of
  the security audit's `Am-5` finding).

### Security — Composite SSRF defense (Phase 1)
- New `protocol/url_guard.rs` performs DNS resolution + IP allowlist +
  port allowlist + scheme allowlist + redirect chase guard.
- Wired into 4 outbound HTTP sinks (manifest fetch, webhook delivery,
  Provider forward, subscription target).
- New `ssrf_attempts` audit table records denied destinations.
- Wire format: `422 UrlBlockedSsrf` per spec error envelope.

### Fixed — audit-A residual sweep
- 2 HIGH + 6 MEDIUM + 4 LOW security findings closed
  (post-implementation audit pass).

### Dependencies
- **Dependabot triage:** 29 advisories → 5 residual (24 closed) across the
  workspace, including `xlsx` CDN migration.

---

## [1.1.0] — 2026-05-14

### Changed
- **`wee_alloc` removed** — the project no longer depends on `wee_alloc`
  (deprecated and unmaintained). The default system allocator is now used
  across the Hub binary.

### Documentation
- B-3 **Hub Fly deploy runbook** added (operator-facing).

---

## [1.0.2] — 2026-05-10 (wire errata)

This is a wire-compatibility errata release. No breaking changes to v1.0.x.

### Added — error envelope completeness
- **HTTP 415 `UNSUPPORTED_MEDIA_TYPE`** — explicit error for non-JSON
  request bodies on JSON endpoints; wired across all 9 sites with a safe
  fallback path.
- **HTTP 409 `DUPLICATE_REQUEST`** — idempotency cache hit with
  diverging body now responds 409 instead of silently overwriting.
- **HTTP 410 `CAPABILITY_DEPRECATED`** — replaces 404 for capabilities
  that exist but are past their `sunset` date. Includes RFC 8594
  `Deprecation` and `Sunset` response headers.
- **HTTP 400 `INPUT_SCHEMA_VIOLATION`** — distinct from 422 for
  structural input mismatches (missing required fields, wrong types).
- **`Retry-After` header on HTTP 429 `RATE_LIMITED`** responses.

### Added — discovery & deployment posture
- **`/.well-known/agent-guide.json`** — discovery route for AI agents
  visiting the Hub directly (K4.1).
- **In-process bulkhead pools** wired per the locked routing table:
  4 partitioned pools (auth / hot path / cold path / admin) with
  supervised tasks and panic boundary.

### Fixed
- `Link rel=deprecation` anchor now points to the canonical
  spec §5.7 form.

---

## [1.0.1] — 2026-05-10 (wire-compatible)

### Added
- **Replay cache** wired into `/v1/invoke` (nonce window enforcement
  for Provenance v2). Closes findings R1, H1, H2.
- **RFC 8594 `Deprecation` and `Sunset` response headers** for
  Provenance v1 sunset path. Emission starts 2026-08-01.
- **Cross-stack fixture loader** + tag-length pre-check (T4).

### Fixed
- `PROVENANCE_MISMATCH` subcause registry closed (enumerated values:
  `drift_too_large`, `nonce_replay`, `tampered`, `unknown_format`).
- Provenance E2E test matrix expanded from 4 to 12 cases.

---

## [1.0.0] — 2026-05-10

First stable release. **Wire compatibility is frozen for the v1.x line.**

See [RELEASE_NOTES_v1.0.0.md](./RELEASE_NOTES_v1.0.0.md) for the full
inventory: TIER A 8/8 security pass, Provenance v2 (HMAC-SHA256
dual-path), 5 live capabilities (`content-factory`, `sns-engine`,
`document-pipeline`, `data-insight`, `file-chain`), Stripe Connect
Express onboarding across 47 countries, manifest lifecycle, programmatic
refund flow, async event subscriptions, OpenAPI 3.1 spec, atomic
85/10/5 billing split.

---

## Pre-1.0.0 highlights

For historical context only — these were development sprints leading to
the v1.0.0 stable release. The wire surface they introduced is now
stabilized in v1.0.0.

| Date | Highlight |
|------|-----------|
| 2026-05-09 | Bulkhead in-process pools + supervisor + panic boundary |
| 2026-05-09 | Audit `S1 P0`: rotate-key `revoke_old` for compromise scenarios, 24h rotation cap, DNS verify multi-resolver consensus |
| 2026-05-09 | W2 Refund API + W4 Webhook delivery (2 migrations) |
| 2026-05-09 | W5 SSE streaming on `/v1/invoke` |
| 2026-05-09 | W3 catalog pagination + W7 OpenAPI 3.1 spec + interactive `/docs` |
| 2026-05-08 | Mandate + Trust Gate enforcement on `/v1/invoke` |
| 2026-05-08 | Invocation billing (atomic wallet debit + 85/10/5 revenue split) |
| 2026-05-08 | Provider invocation routing (HMAC-SHA256 forwarding) |
| 2026-05-08 | Manifest publish + lifecycle (promote / sunset) |
| 2026-05-08 | Capability discovery with status auto-promotion |
| 2026-05-08 | Provider Stripe Connect Express onboarding |
| 2026-05-08 | Provider lifecycle (register / me / verify-dns) |

---

— Tufe Company Inc., operator of [jecp.dev](https://jecp.dev)
