---
name: Bug report
about: A bug in the JECP reference Hub (this repo).
title: 'bug: '
labels: bug
---

## What happened

<!-- One paragraph. Concrete behavior, not "it doesn't work." -->

## What you expected

<!-- One paragraph. -->

## Reproduction

<!--
Smallest possible curl / SDK snippet that reproduces the issue.
Redact any API keys or Mandate signatures.
-->

```bash
# curl ...
```

## Environment

- Hub commit / tag: <!-- e.g., v1.1.1 -->
- Deployment: <!-- jecp.dev hosted / self-hosted / local cargo run -->
- Client SDK: <!-- @jecpdev/sdk vX.Y / curl / your own impl -->

## Logs

<!--
Paste relevant log lines. The Hub emits structured JSON logs; you can
include them as a fenced ```json block. Redact API keys, signatures, and
agent_id values you do not want public.
-->

```json
```

## Security implication

- [ ] This bug has **no** security implication.
- [ ] This bug **may** have security implications — I should email `security@jecp.dev` instead. *(If you check this, close the issue and email — do not paste exploit details in a public issue.)*
