# ADR-0013: Version metadata embedded in binaries

- Status: Accepted
- Date: 2026-11-10

## Context

A binary no package database owns (copied into a container, vendored, built from source) has no distribution package to look up. Three formats say what is inside it without executing it: the systemd `.note.package` ELF note, the Go build information block and the cargo-auditable `.dep-v0` section.

## Decision

- Resolution order for a path target: the owning package, then its `.note.package`, then the Go modules or Rust crates it declares.
- A note names a distribution package, so it is judged by the distribution data like any package, with the provenance `embedded_note`. A note for another packaging system than the host's is refused, not guessed.
- Go modules and crates are judged by OSV (`Go`, `crates.io`), which matches the exact version server side, with the provenance `embedded_buildinfo`. They are used **only** for files nothing owns. A distribution backports fixes into vendored code without changing the module version, so judging an owned binary's modules by version would report false positives; the principle of precision before coverage wins over coverage here.
- The readers are bounded (file size, record counts, offsets validated with checked arithmetic), handle ELF64 little-endian only, and a malformed file is a miss, never an error that stops the run.
- `[sources.osv]` configures the endpoint and whether a failure makes the result incomplete (required by default); on OSV distributions the language packages share the distro pass.

## Consequences

- Unowned Go and Rust programs get real findings with a fix version; static linking is stated in the update hint, since no package manager can update it.
- Severity for language advisories comes from the advisory's textual severity when stated (GitHub advisories); RUSTSEC entries carry none and report `unknown`.
- Not covered: ELF32 and big-endian files, stripped Go binaries without build info, C libraries linked statically (the string-signature heuristic of phase 6 is a separate decision).
