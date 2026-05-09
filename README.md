# jecp-server

> Reference Hub implementation of the **Joint Execution & Commerce Protocol** (JECP).

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-production-green.svg)](https://jecp.dev)
[![Built with](https://img.shields.io/badge/built%20with-Rust-orange.svg)](https://www.rust-lang.org/)
[![Spec](https://img.shields.io/badge/spec-v1.0--draft-blue.svg)](https://github.com/jecpdev/jecp-spec)

A Rust + Axum Hub implementation. Powers https://jecp.dev in production.

---

## What this Hub does

- **Agent registration & wallets** — `/api/agents/*` (top-up via Stripe Checkout, atomic per-call debit)
- **Provider onboarding** — `/v1/providers/*` (DNS verify, Stripe Connect Express in 47 countries)
- **Manifest publishing** — `/v1/manifests` (YAML manifests, validation, lifecycle promote/sunset)
- **Capability invocation** — `/v1/invoke` (Mandate enforcement, Trust Gate, idempotency, atomic billing 85/10/5)
- **Discovery** — `/v1/capabilities` (live catalog, includes both built-in and third-party)
- **Forwarding** — HMAC-SHA256 signed requests to Provider endpoints with replay window

## Quick start (developers)

### Prerequisites

- Rust 1.75+
- PostgreSQL 15+ (Supabase or self-hosted)
- Stripe account (test mode is fine for dev)

### Local development

```bash
git clone https://github.com/jecpdev/jecp-server.git
cd jecp-server
cp .env.example .env
# Edit .env with your DB URL and Stripe test keys
cargo run
```

Server starts on `localhost:8080`.

### Health check

```bash
curl http://localhost:8080/health
curl http://localhost:8080/v1/capabilities | jq
```

### Production deployment

```bash
flyctl deploy
```

The production Hub at jecp.dev runs on Fly.io (Tokyo region, NRT).

## Architecture

```
src/
├── main.rs               # Axum router, middleware stack, Sentry
├── routes/
│   ├── invoke.rs         # POST /v1/invoke — Mandate, Trust Gate, atomic billing, HMAC forward
│   ├── providers.rs      # /v1/providers/{register,me,verify-dns,connect-stripe}
│   ├── manifests.rs      # /v1/manifests publish + lifecycle (promote/sunset)
│   ├── capabilities.rs   # /v1/capabilities (DB-driven catalog, core + third-party)
│   ├── agents.rs         # /api/agents/{register,topup,share-kit}
│   └── health.rs
├── auth/                 # API key bcrypt + Mandate + Trust Tier resolution
├── billing/              # invoke_charge() (atomic deduct + 85/10/5 split)
├── middleware/           # CORS, rate limit (60 RPM/agent), tracing
├── protocol/             # Wire format, error catalog with next_action
└── services/             # Postgres pool, Stripe API, signing
```

## Specification

This server implements [JECP Spec v1.0-draft](https://github.com/jecpdev/jecp-spec).
RFC 2119 compliant, JSON Schema 2020-12.

## Performance (production, May 2026)

| Metric | Target | Current |
|--------|-------:|--------:|
| `/v1/invoke` p50 | < 200ms | ~127ms |
| `/v1/invoke` p95 | < 500ms | ~340ms |
| Wallet debit consistency | 100% | 100% (atomic SQL function) |
| Idempotency window | 24h | 24h on `(agent_id, request_id)` |
| Concurrent RPS | 100+ | tested 200 |

## Client SDKs

- **TypeScript:** [@jecpdev/sdk](https://www.npmjs.com/package/@jecpdev/sdk) — `npm install @jecpdev/sdk`
- **Python:** planned (v0.2)
- **Go:** planned (v0.3)

The protocol is plain HTTP+JSON, so any language can implement directly. See [spec §3](https://github.com/jecpdev/jecp-spec/blob/main/spec/03-api.md).

## Running your own Hub

You don't need to use jecp.dev. Run your own Hub:

1. Fork this repo
2. Configure your DB + Stripe accounts
3. Deploy (Fly.io / Railway / your-cloud-of-choice)
4. Optionally federate with jecp.dev (federation registry is on Q4 roadmap)

The protocol is multi-vendor and federation-ready.

## License

[Apache License 2.0](LICENSE)

Copyright 2026 Tufe Company Inc. and JECP contributors.
