# JECP Hub — v1.0.0 Release Notes

**Release date**: 2026-05-10
**Reference Hub**: `https://setsuna-jobdonebot.fly.dev` (Fly v53)
**Spec compliance**: `github.com/jecpdev/jecp-spec` `v1.0.0-stable`
**TS SDK**: `@jecpdev/sdk` `v0.6.0`

---

## What ships in v1.0.0

The first stable release of the JECP reference Hub. Wire compatibility is
frozen for the v1.x line; everything below is either a launch-included
feature or a launch-included security fix.

### Capabilities (live)

| Capability | Status | Notes |
|------------|--------|-------|
| `content-factory` | ✅ live | Bronze tier, free 100 calls/agent |
| `sns-engine` | ✅ live | Bronze tier, dogfeeded by JobDoneBot |
| `document-pipeline` | ✅ live | Silver tier |
| `data-insight` | ✅ live | Silver tier |
| `file-chain` | ✅ live | Gold tier |
| `workflow` (composite) | spec only | M3 reference impl ships in v1.1 |

### Endpoints (live)

| Path | Method | Notes |
|------|--------|-------|
| `/v1/jecp` | POST | Legacy execution route (kept for backward compat) |
| `/v1/invoke` | POST | Primary execution route, supports SSE streaming via `Accept: text/event-stream` |
| `/v1/capabilities` | GET | Cursor-pagination (W3) |
| `/v1/agents/register` | POST | (served via Next.js at `https://jecp.dev/api/agents/register`) |
| `/v1/agents/me/rotate-key` | POST | Atomic rotation, 3/24h cap, optional `revoke_old` |
| `/v1/providers/me/rotate-key` | POST | Same semantics for Provider keys |
| `/v1/providers/register`, `/me`, `/verify-dns` | various | Provider onboarding (Stripe Connect Express, 47 countries) |
| `/v1/manifests`, `/<id>/promote`, DELETE | various | Manifest publish + lifecycle |
| `/v1/refunds`, `/<id>/deny` | POST | Programmatic refund flow (W2) |
| `/v1/subscriptions` | various | Async event subscription (W4) |
| `/openapi.json`, `/docs` | GET | OpenAPI 3.1 spec + Swagger UI |
| `/health` | GET | Pool / task / DB status |

---

## Security posture (TIER A 8/8 + Provenance v2)

This release is the result of a multi-agent security audit (the "TIER A" pass)
that ran 2026-05-09 → 2026-05-10. All eight launch-blocker findings shipped:

| # | Fix | Spec / Hub area |
|---|-----|-----------------|
| A.1 | DNS spoof — multi-resolver consensus | Provider DNS verification |
| A.2 | bcrypt DoS — Provider prefix lookup | Auth |
| A.3 | Outbox redelivery — `FOR UPDATE SKIP LOCKED` + `claimed_at` | Webhooks |
| A.4 | Rotation atomic + 3/24h cap | Key rotation |
| A.5 | Agent api_key plaintext → bcrypt | Auth (storage) |
| A.6 | Pool floor (`MIN_TOTAL_POOL_BUDGET=14`) | Bulkhead |
| A.7 | Bulkhead — 4-pool partition + supervised tasks | Reliability |
| A.8 | Provenance v2 (HMAC-SHA256 dual-path) | Auth (replay) |

### Provenance v2 (headline)

The Hub now verifies two Provenance wire formats:

- **v2 (RECOMMENDED)** — `"v2:<unix_seconds>:<nonce_hex>:<hmac_hex>"`
  HMAC-SHA256 over `agent_id:timestamp:nonce`. Clock-skew window ±300s,
  nonce-replay cache 600s. Works after key rotation (uses `mandate.api_key`
  plaintext directly, not the stored bcrypt hash).
- **v1 (DEPRECATED)** — 64-hex SHA-256 of `agent_id:total_calls:api_key[..8]`.
  Retained for backward compat. Sunset 2026-11-01.

The reference Hub dispatches automatically by `"v2:"` prefix detection.

E2E verified in production (`scripts/jecp-provenance-v2-e2e.sh`):

```
✓ v1 hash       → HTTP 200
✓ v2 hash       → HTTP 200
✓ Tampered v1   → HTTP 403 PROVENANCE_MISMATCH
✓ Stale v2 (1h) → HTTP 403 PROVENANCE_MISMATCH (drift=3603s)
```

---

## Wire-format guarantees

| Stability | Surface |
|-----------|---------|
| **Frozen** in v1.x | `/v1/jecp`, `/v1/invoke`, `/v1/capabilities`, error envelope, idempotency window (24h), Mandate schema, Provenance v1 + v2 wire formats |
| **Additive** in v1.x | New capabilities, new actions, new error codes, new manifest fields with defaults |
| **Deprecation policy** | At least 90 days notice via `Deprecation` + `Sunset` headers before removal. Provenance v1 follows this exact path: deprecated 2026-05-10 → headers from 2026-08-01 → removal 2026-11-01 |

---

## Operational baseline

| Metric | Target | Actual |
|--------|--------|--------|
| `/health` p95 | < 500ms | ~50ms |
| `/v1/invoke` p95 (cached) | < 100ms | ~80ms |
| `/v1/invoke` p95 (Claude pass-through) | < 5s | ~2.5s |
| Bulkhead pool floor | 14 connections | 14 (4+4+4+2) |
| GitHub Actions auto-deploy | < 10 min | 5m54s − 6m9s typical |
| Supabase migration count | n/a | 51 (all in `supabase/migrations/`) |

---

## What does NOT ship in v1.0.0

- **M3 Workflow (composite execution)** — spec only. v1.1 ships the Hub workflow engine.
- **W6 Mandate budget cumulative tracking** — v1.0 enforces per-call only; v1.1 adds `budget_total_usdc`.
- **Provenance v3** — no concrete plan; v2 is expected to last the v1.x line.
- **Multi-region active-active** — Fly.io single primary (nrt) only.

---

## Upgrading from `1.0.0-draft`

There are no wire-breaking changes from `1.0.0-draft`:

- v1 `provenance_hash` (64-hex SHA-256) values continue to validate.
- `agent_id` / `api_key` with `jdb_` prefix continue to validate (the regex was widened to a strict superset).
- `Pricing.currency = "USD"` and `"USDC"` continue to validate; `"both"` continues until 2026-11-01.
- All `1.0.0-draft` Agents and Providers remain conformant.

Recommended actions:

1. Bump `@jecpdev/sdk` to `0.6.0` and switch to `computeProvenanceV2` for any
   call that issues a `provenance_hash`. `computeProvenanceV1` is retained
   but `@deprecated`.
2. Plan the v1 → v2 cutover before 2026-11-01.
3. Watch for `Deprecation: true` and `Sunset: Sat, 01 Nov 2026 00:00:00 GMT`
   response headers starting 2026-08-01 — if you see them, you are still
   sending v1.

---

## References

- Spec: `https://github.com/jecpdev/jecp-spec` (`v1.0.0-stable`)
- LP: `https://jecp.dev`
- npm: `https://www.npmjs.com/package/@jecpdev/sdk`
- npm CLI: `https://www.npmjs.com/package/@jecpdev/cli` (`v0.6.2`)
- TS SDK source: `https://github.com/jecpdev/jecp-sdk-typescript`
- Hub source: this repository, `jecp/`

— Tufe Company Inc. (operator of `jecp.dev`)
