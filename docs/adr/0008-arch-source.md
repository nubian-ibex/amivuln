# ADR-0008: Source of truth for Arch Linux

- Status: Accepted
- Date: 2026-11-07

## Context

Evidence gathered on 2026-11-07 (preliminary spike S2):

- OSV has **no Arch Linux** ecosystem.
- Arch Security Tracker serves JSON at `https://security.archlinux.org/issues/all.json` (HTTP 200, `application/json`) and per group at `https://security.archlinux.org/AVG-NNNN/json`. The path `/<package>.json` returned 404.
- Each entry (an AVG group) has: `name`, `packages[]`, `status` (observed values: Fixed, Not affected, Vulnerable, Unknown), `severity`, `type`, `affected` (version), `fixed` (version or null), `ticket`, `issues[]` (CVE IDs) and `advisories[]`. The full file had 2444 entries on that date.

## Options

- Arch Security Tracker `all.json`: one file, full map of AVG, package, CVE, affected and fixed versions. Cons: whole-file download (cache with ETag), package match by name only (pacman package names, check split packages).
- Upstream data: ignores Arch status; false positives on rolling releases are rare but fixed versions still differ.

## Decision

Accepted by the maintainer on 2026-11-07. Arch Security Tracker as the required distro source, with `all.json` cached locally and queried by package name; `fixed` compared with the pacman `vercmp` algorithm.

## Consequences

- `Unknown` and `Vulnerable` without a `fixed` version map to `unknown` and `affected` respectively; `Not affected` suppresses the CVE with the tracker as justification.
- TODO(verify): conditional request support (ETag, Last-Modified), file size growth, and an official statement on API stability.

## Measurement (2026-11-08)

`tests/integration/arch-vs-arch-audit.sh` compares amivuln with `arch-audit` in an archlinux container (295 packages). arch-audit lists 11 packages as affected; amivuln lists 0 as affected and 12 as unverified. The difference is deliberate: the tracker keeps "Vulnerable" groups with no fixed version for years (for example CVE-2022-2068 recorded against openssl 1.1.1.o, still "Vulnerable" while Arch ships openssl 3.6), and arch-audit reports every installed version as affected by them. amivuln reports a Vulnerable group as affected only for the same upstream version as the recorded build, and as unverified for newer ones, so the findings stay visible without being asserted. `--strict` makes them count for `--fail-on`.

The corpus `tests/ground-truth/arch-boundaries.toml` (92 cases from 31 real tracker groups) probes each Fixed group one build before the fix, at the fix, after it and before the range, and the stale-Vulnerable rule.
