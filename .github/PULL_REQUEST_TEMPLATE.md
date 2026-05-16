<!--
Thanks for contributing to the JECP reference Hub.

Please complete the sections below. Items marked with [REQUIRED] block merge.
-->

## Summary

<!-- One-paragraph description of what this PR changes and why. -->

## Type of change

- [ ] Bug fix (non-breaking)
- [ ] New feature (non-breaking)
- [ ] Breaking change (wire-format or API change)
- [ ] Documentation only
- [ ] CI / tooling only

## Wire compatibility [REQUIRED]

> The v1.x line is **wire-frozen** per `RELEASE_NOTES_v1.0.0.md`. Breaking changes are deferred to v2.x.

- [ ] This PR does not change the wire format of `/v1/invoke`, `/v1/capabilities`, the error envelope, the Mandate schema, or the Provenance v1/v2 wire formats.
- [ ] If checked above is false: this PR is targeting a future v2.x branch (state which).

## Spec alignment [REQUIRED]

- [ ] No spec changes required.
- [ ] Spec change PR opened at `jecpdev/jecp-spec` — link: <!-- URL -->

## Testing

- [ ] `cargo test` passes locally
- [ ] `cargo clippy --all-targets -- -D warnings` passes
- [ ] `cargo fmt --check` passes
- [ ] New tests added where appropriate

## Security implications

<!--
If this PR touches auth, the wallet ledger, the manifest verifier, signing,
or any wire-format parser: describe the security model change. If unsure,
say "unsure — please review" and a maintainer will help.
-->

## Coordinated disclosure

If this PR addresses a security finding, **do not include exploit details**
in the public PR description. Use `security@jecp.dev` for disclosure (see
`SECURITY.md`).

## Checklist

- [ ] I have read [`CONTRIBUTING.md`](../CONTRIBUTING.md)
- [ ] My commit messages follow Conventional Commits (`type(scope): subject`)
- [ ] I have added entries to `CHANGELOG.md` under `[Unreleased]` if user-visible
