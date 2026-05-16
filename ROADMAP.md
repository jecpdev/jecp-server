# ROADMAP

Public roadmap for the `jecp-server` reference Hub. Tracks what's runnable from a fresh clone — not the production Hub's roadmap at jecp.dev (which is operated separately).

---

## v0.1 (2026-05-16, current) — specification-conforming reference

- ✅ Full Rust + Axum source matching the production Hub at jecp.dev
- ✅ Spec conformance: v1.1.1, wire-frozen
- ✅ OpenAPI 3.1 schema + Spectral lint config
- ✅ Apache 2.0 + standard OSS scaffolding (CoC, Contributing, Security, PR / Issue templates, CI)
- ⚠️ `cargo run` from a fresh clone is **not yet supported** — see [README "Alpha readiness notice"](./README.md#-alpha-readiness-notice-2026-05-16)

## v0.2 (2026 Q3) — self-hostable alpha

- [ ] `docker-compose.dev.yaml` profile: Postgres + Mailpit + LocalStack KMS + Stripe CLI test mode
- [ ] **Demo mode** feature flag — mocks Anthropic + Stripe so end-to-end test runs without external keys
- [ ] Benchmark methodology doc — so cloners can reproduce p50 / p95 claims on their own hardware
- [ ] Self-hosted Fly.io quickstart guide (managed-Postgres variant)

## v0.3 (2026 Q4)

- [ ] `examples/minimal-hub/` — 8-endpoint Minimum Viable Hub profile (indie-dev path, no Trust Gate, no x402)
- [ ] Federation registry alpha (Hub-to-Hub trust discovery)

## After B-4 audit clean (TBD)

- [ ] x402 mainnet settlement path (gated on the 3-scope `B4-audit-rfp-MASTER.md` engagement clean)
- [ ] Threshold-signing keeper (FROST or Lit, replacing single-key KMS)
- [ ] Python SDK
- [ ] Go SDK

## Deliberately out of scope for v1.x

- Multi-chain support (Base only for v1.x; other chains in v2.x)
- Composable revenue split beyond fixed 85 / 10 / 5
- Single-block atomicity guarantee — v1.x is **invariant-level atomic** (split-or-revert), not **block-level**. See `RELEASE_NOTES_v1.0.0.md`.

---

This roadmap is informative, not binding. The protocol spec (wire-format) is binding; see [jecp-spec](https://github.com/jecpdev/jecp-spec).
