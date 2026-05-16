# jecp-server

> Reference Hub implementation of the **Joint Execution & Commerce Protocol** (JECP).

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-alpha-orange.svg)](https://jecp.dev)
[![Built with](https://img.shields.io/badge/built%20with-Rust-orange.svg)](https://www.rust-lang.org/)
[![Spec](https://img.shields.io/badge/spec-v1.1.1-blue.svg)](https://github.com/jecpdev/jecp-spec)

A Rust + Axum Hub. Reference implementation of the JECP spec; the production Hub at https://jecp.dev runs on this exact source.

**Indie operators**: see the **alpha readiness notice** below before attempting `cargo run`.

---

## What this Hub does

- **Agent registration & wallets** — `/api/agents/*` (top-up via Stripe Checkout, atomic per-call debit)
- **Provider onboarding** — `/v1/providers/*` (DNS verify, Stripe Connect Express in 47 countries)
- **Manifest publishing** — `/v1/manifests` (YAML manifests, validation, lifecycle promote/sunset)
- **Capability invocation** — `/v1/invoke` (Mandate enforcement, Trust Gate, idempotency, atomic billing 85/10/5)
- **Discovery** — `/v1/capabilities` (live catalog, includes both built-in and third-party)
- **Forwarding** — HMAC-SHA256 signed requests to Provider endpoints with replay window

## ⚠️ Alpha readiness notice (2026-05-16)

The production Hub at jecp.dev runs on this exact source, but `cargo run` from a fresh clone is **not yet supported**. The binary boots only with all of:

- a Supabase-schema Postgres (51 migrations applied)
- Stripe Connect platform account + test mode
- Anthropic API key
- AWS KMS asymmetric key (ECDSA secp256k1) for the keeper
- Sentry + Better Stack credentials
- Cloudflare DNS zone for Provider DNS verification

We have **not yet** packaged this into a one-shot `docker-compose`; that's the v0.2 priority. See [ROADMAP.md](./ROADMAP.md).

**Until then, this repo is best used as a specification-conforming reference**:

- Read the Rust to see how the spec is implemented (`src/routes/`, `src/auth/`, `src/protocol/`).
- Point a JECP SDK / CLI at the live Hub at `https://jecp.dev` instead of running your own.
- Use [@jecpdev/sdk](https://www.npmjs.com/package/@jecpdev/sdk) or [@jecpdev/cli](https://www.npmjs.com/package/@jecpdev/cli) for the agent / Provider integration path.

## Architecture (for readers, not runners)

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
└── services/             # Postgres pool, Stripe API, signing, KMS-backed keeper
```

## Specification

This server implements [JECP Spec v1.1.1](https://github.com/jecpdev/jecp-spec).
RFC 2119 compliant, JSON Schema 2020-12.

## Performance

Production numbers (p50 ~127ms on `/v1/invoke` cached path) hold on the Tufe-operated Hub at jecp.dev under live load.

**These are not reproducible from a fresh clone** — they depend on the Postgres schema, Stripe Connect accounts, and KMS keeper key that the Hub is provisioned against. A reproducible benchmark methodology + a self-hosted-friendly profile ship in v0.2 — see [ROADMAP.md](./ROADMAP.md).

## Client SDKs

- **TypeScript:** [@jecpdev/sdk](https://www.npmjs.com/package/@jecpdev/sdk) — `npm install @jecpdev/sdk`
- **Python:** planned (v0.2)
- **Go:** planned (v0.3)

The protocol is plain HTTP+JSON, so any language can implement directly. See [the JECP spec](https://github.com/jecpdev/jecp-spec).

## Running your own Hub (today's reality)

For now, the realistic path is to **use the hosted Hub at jecp.dev** (it's the only fully-provisioned deployment of this reference).

If you already have all 6 dependencies in the Alpha readiness notice above and want to self-host today, your starting points are:

1. `fly.toml` — current production Fly.io config (retarget the app name + secrets)
2. `Dockerfile` — current production container build
3. `spec/openapi.yaml` — OpenAPI 3.1 schema if you want to start fresh in another language

The protocol is multi-vendor and federation-ready by design; the federation registry itself ships in Q4 ([ROADMAP.md](./ROADMAP.md)).

## License

[Apache License 2.0](LICENSE)

Copyright 2026 Tufe Company Inc. and JECP contributors.
