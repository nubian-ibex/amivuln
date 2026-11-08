# Architecture

amivuln is a Cargo workspace. The `amivuln` binary only orchestrates; the
domain rules perform no I/O.

## Pipeline

1. **Target.** What the user asked about: a package name, a file path, a
   `.service` unit, `name@version` or a purl (`amivuln-resolve`).
2. **Identity.** The installed package, read from the package manager
   (`rpm`, `pacman`) through an allowlisted, bounded subprocess runner.
3. **Distro data.** The distribution's own advisory data, fetched through a
   cache-aware HTTP client (`amivuln-sources`, `amivuln-cache`).
4. **Matching.** The distribution status decides, never an upstream version
   range. `Fixed(v)` with an installed version at or above `v` is patched; an
   older one is affected and names the version that fixes it (`amivuln-core`).
5. **Enrichment.** CISA KEV and FIRST EPSS.
6. **Policy.** `--fail-on`, `--fail-on-epss`, `--strict`, and the exit code
   precedence 70, 64, 2, 3, 1, 0.
7. **Report.** `summary`, `detail` and JSON (`amivuln-report`).

## Crates

- `amivuln`: command line, configuration and orchestration.
- `amivuln-core`: domain types, matching rules, policy, exit codes and the
  traits for the outside world.
- `amivuln-resolve`: target resolution and the system process runner.
- `amivuln-version`: RPM and pacman version comparison, verified against
  `rpm` and `vercmp` on thousands of generated pairs.
- `amivuln-sources`: parsers for the Arch Security Tracker, Fedora
  `updateinfo`, CISA KEV and FIRST EPSS, and the bounded HTTP client.
- `amivuln-cache`: SQLite HTTP cache with ETag revalidation and
  fresh/stale/expired classification.
- `amivuln-report`: output formatters.

All crates are published to crates.io because the binary depends on them. The
library crates carry no API stability promise before 1.0.

## Invariants

- The distribution status overrides upstream version comparison.
- A finding without a distribution statement is *unverified*, listed apart,
  and never counted as affected.
- A failed required source makes the result incomplete (exit code 2). Stale
  cached data within `stale_max_age` is used and reported as `stale`.
- Every file read, HTTP response and subprocess output is size-bounded, every
  subprocess has a timeout and an allowlisted absolute path, and no shell is
  involved.
- Text from outside the process is sanitised before it reaches a terminal.
- No field that identifies the host exists in the output or the requests.
