---
name: Feature request
about: Propose a new feature for the JECP reference Hub.
title: 'feat: '
labels: enhancement
---

## Problem

<!--
What problem does this solve? One paragraph, user-focused, no jargon.
"It would be nice if X" is not a problem — say what fails today.
-->

## Proposed solution

<!-- High-level shape of the solution. Not the full design. -->

## Wire-format impact

> The v1.x Hub is wire-frozen. New features can land if they are additive
> (new fields with defaults, new error codes, new actions). Breaking
> changes go to a v2.x track.

- [ ] Additive — no breaking change to existing clients
- [ ] Breaking — requires v2.x (state why)

## Spec change required?

- [ ] No — Hub-only change (e.g., internal performance, observability)
- [ ] Yes — open a parallel issue on `jecpdev/jecp-spec` first: <!-- URL -->

## Alternatives considered

<!-- Optional, but helps reviewers see you weighed options. -->

## Are you willing to implement it?

- [ ] Yes, with guidance
- [ ] No, requesting that someone else picks it up
