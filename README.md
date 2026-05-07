# jecp-server

> Reference implementation of the **Joint Execution Capability Protocol** (JECP).

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-production-green.svg)](https://jecp.dev)
[![Built with](https://img.shields.io/badge/built%20with-Rust-orange.svg)](https://www.rust-lang.org/)

A Rust + Axum implementation of the JECP Hub. Powers https://jecp.dev with 25+ days of production uptime.

---

## What runs on this server

- 6 native capabilities (document-pipeline, file-chain, content-factory, data-insight, workflow, sns-engine)
- 25+ actions
- Mandate verification, Trust Gate, Provenance check
- A2A-compatible agent card discovery
- Stripe Connect routing (Stage 3)

## Quick start

### Prerequisites

- Rust 1.75+
- PostgreSQL 15+ (or Supabase)
- Stripe account (for billing, optional in dev)

### Local development

```bash
git clone https://github.com/jecpdev/jecp-server.git
cd jecp-server
cp .env.example .env
# Edit .env with your DB URL

cargo run
```

Server starts on `localhost:8080`.

### Try it

```bash
curl http://localhost:8080/health

curl http://localhost:8080/v1/capabilities | jq
```

### Production deployment

```bash
flyctl deploy
```

See [docs/deployment.md](docs/deployment.md) for full guide.

## Architecture

```
src/
├── main.rs               # Axum router
├── routes/               # HTTP handlers
├── auth/                 # Mandate, API key, Trust Gate
├── capabilities/         # Built-in capability implementations
│   ├── document_pipeline.rs
│   ├── file_chain.rs
│   ├── content_factory.rs
│   ├── data_insight.rs
│   ├── workflow.rs
│   └── sns_engine/
├── middleware/           # CORS, rate limit, tracing
├── protocol/             # Wire format, types, errors
└── services/             # DB, Stripe, Anthropic
```

## Specification

This server implements [JECP Spec v1.0-draft](https://github.com/jecpdev/jecp-spec).

## Performance

| Metric | Target | Current |
|--------|-------:|--------:|
| `/v1/jecp` p50 | < 200ms | ~127ms |
| `/v1/jecp` p95 | < 500ms | ~340ms |
| Concurrent rps | 100+ | tested 200 |
| Uptime (May 2026) | 99%+ | 99.8% |

## Building your own JECP server

You don't need to use this implementation. Implement the [spec](https://github.com/jecpdev/jecp-spec) in any language. We provide:

- TypeScript SDK: [`@jecp/server`](https://github.com/jecpdev/server-sdk-node)
- Python SDK (Stage 2): coming soon

## License

[Apache License 2.0](LICENSE)

Copyright 2026 JobDoneBot Inc. and JECP Working Group contributors.
