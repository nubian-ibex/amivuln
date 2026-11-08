# AGENTS.md

amivuln answers: which CVEs apply to this binary, service or package on this host, taking distro backports into account?

## Commands

- `just ci`: fmt check, clippy, tests, docs, deny, audit, vet, typos, reuse, actionlint, zizmor.
- `just fmt`, `just lint`, `just test`: individual steps.

## Architecture

- Cargo workspace under `crates/`; the `amivuln` binary only orchestrates.
- `amivuln-core`: domain types, traits (`Resolver`, `Source`, `Clock`, `Cache`, `ProcessRunner`, `FileSystem`), policy.
- `amivuln-resolve`: target to package reference (rpm, pacman, dpkg, apk, systemd, /proc).
- `amivuln-version`: version comparators per ecosystem.
- `amivuln-sources`: advisory and enrichment clients.
- `amivuln-cache`: SQLite cache and offline DB.
- `amivuln-report`: output formatters.
- Domain logic performs no direct I/O; edge crates implement the traits.
- The internal crates are published to crates.io because `amivuln` depends on them; they carry no API stability promise before 1.0.

## Code rules

- No `unsafe`; no `unwrap`, `expect` or `panic!` outside tests.
- stdout carries only the result; logs go to stderr via `tracing`.
- Output is deterministic: sorted findings, stable JSON field order, no `HashMap` in output.
- Every file read, HTTP response and subprocess has a size or time limit.
- External text is sanitized before reaching a terminal, CSV, Markdown or SARIF.
- Subprocesses: allowlisted system binaries, absolute path, no shell, clean env with `LC_ALL=C`, fixed args, timeout.
- Every source file starts with an SPDX header. Public items have doc comments.
- Comments explain why, not what.

## Invariants

- Distro patch status overrides upstream version comparison.
- Unknown status is reported separately and never silently counted as affected.
- Never degrade silently: output states every source's status; a failed required source means an incomplete result.
- No host-identifying data leaves the host or appears in output.

## Tests

No network in tests: recorded fixtures plus `wiremock`. Snapshot outputs with `insta`; property-test comparators with `proptest`.

## Commits

Conventional Commits, English, imperative, subject up to 50 characters, signed off (`-s`). Never commit to `main` directly, never force-push.

## Never

Add telemetry, execute the target binary outside the sandboxed probe, commit secrets, or disable lints and checks to make them pass.
