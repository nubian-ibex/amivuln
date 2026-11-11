# Security policies

## Dependency policy (SCA)

`cargo deny`, `cargo audit` and `cargo vet` run on every pull request and in
the release pipeline (`just ci`). The threshold is zero undeclared findings:
an advisory, license or provenance finding blocks the change unless it is
declared with a reason in `deny.toml` (advisories, licenses) or
`supply-chain/config.toml` (vet exemptions). Declared exemptions are
re-reviewed at every release.

A dependency advisory that does not affect amivuln is recorded in `deny.toml`
with the advisory id and the reason it is not exploitable here; that record
is the VEX statement of record for the project. No release ships with an
undeclared SCA finding: the checks fail closed.

## Static analysis policy (SAST)

The threshold is zero findings. `cargo clippy --workspace --all-targets
--all-features -- -D warnings` and `cargo fmt --check` block every change in
`just ci`. A suppression needs an inline `#[allow]` whose comment names why
the finding does not apply; the lint set is never lowered to make code pass.

## Secrets policy

- No credential belongs in the repository or the issue tracker.
- CI credentials (the release minisign key, `MINISIGN_SECRET_KEY` and
  `MINISIGN_PASSWORD`, cosign and crates.io tokens) are GitHub Actions
  secrets scoped to the workflows and the `release` environment that need
  them, and are never echoed to logs.
- Secrets are rotated when a workflow, machine or person with access changes,
  and immediately on suspicion of a leak; after a leak the audit logs are
  reviewed for use of the exposed value.
- Local development needs no credentials: tests are network-free.

## Access and review policy

Only the maintainer account holds write access, tag rights and the release
environment approval. A new collaborator is reviewed before any escalated
permission is granted: contribution history on the project, security
practices (signed commits, dependency discipline) and a public identity. The
rulesets on `main` and on `v*` tags enforce signed commits and block
force-pushes and deletions regardless of who holds the permission.

## Test policy

Every major change adds or updates tests in the automated suite; a bug fix
adds the regression test before the fix. Tests must not touch the network:
HTTP behavior is covered by recorded fixtures and `wiremock`. Run `just ci`
before opening a pull request; CI runs the full suite on every pull request
and the merge is blocked while it fails.
