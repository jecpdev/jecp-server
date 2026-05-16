# Security Policy

## Coordinated disclosure

Please **do not open public GitHub issues** for security vulnerabilities in the JECP reference Hub.

Email **security@jecp.dev** instead — see [`https://jecp.dev/.well-known/security.txt`](https://jecp.dev/.well-known/security.txt) (RFC 9116) for the canonical contact and PGP key.

We aim to acknowledge reports within **2 business days** (Tokyo time, JST/UTC+9).

## Scope

In scope for this repository (the JECP reference Hub):

| Area | In scope? |
|------|----------|
| `/v1/invoke` request handling, billing, forwarding | ✅ |
| `/v1/providers/*` registration / DNS verify / Stripe Connect | ✅ |
| `/v1/manifests` publish + lifecycle | ✅ |
| Wallet ledger atomicity | ✅ |
| Provenance v1/v2 verification | ✅ |
| API key auth (bcrypt + rotation) | ✅ |
| Mandate / Trust Gate enforcement | ✅ |
| Cert-pin TLS to facilitator | ✅ |
| SSRF guards on outbound HTTP | ✅ |
| Wire-format parsers | ✅ |

Out of scope for **this** repository (report separately):

| Area | Where to report |
|------|----------------|
| Spec ambiguity that enables attack | [`jecpdev/jecp-spec`](https://github.com/jecpdev/jecp-spec/security) |
| TypeScript SDK / CLI vuln | [`jecpdev/jecp-sdk-typescript`](https://github.com/jecpdev/jecp-sdk-typescript/security) |
| Vulnerability in `jecp.dev` LP | Same channel (`security@jecp.dev`) |
| Vulnerability in JobDoneBot (first Provider) | `security@jobdonebot.com` |

## What we do not consider a vulnerability

- Missing rate-limit headers on endpoints not in the documented surface
- Information leakage from `/openapi.json` (it is intentionally public)
- DNS-poisoning attacks on Provider DNS verification when **resolver multi-consensus** is already configured (the operator can adjust the resolver set)
- 3rd-party transitive dependency CVE that does not have a reachable exploit path through the Hub (please still mention, but P3 by default)

## Supported versions

We only patch security issues on:

- The latest published `v1.x.y` tag on this repo
- The currently-deployed Hub at `jecp.dev` (matches the latest tag)

Older versions are unsupported. Pre-1.0 staging snapshots are not supported.

## Bug bounty

We do not currently run a paid bounty. If you would value attribution in the next release's CHANGELOG.md, say so in your report and we'll do that by default.

## Audit reports

External audits are published under [`jecpdev/jecp-contracts`](https://github.com/jecpdev/jecp-contracts) and (for Hub Rust scope) on this repo as they complete. See `B-4` engagement plan in our handoff docs.
