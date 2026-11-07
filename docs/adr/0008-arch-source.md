# ADR-0008: Source of truth for Arch Linux

- Status: Proposed
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

Pending. Recommendation: Arch Security Tracker as the required distro source, with `all.json` cached locally and queried by package name; `fixed` compared with the pacman `vercmp` algorithm.

## Consequences

- `Unknown` and `Vulnerable` without a `fixed` version map to `unknown` and `affected` respectively; `Not affected` suppresses the CVE with the tracker as justification.
- TODO(verify): conditional request support (ETag, Last-Modified), file size growth, and an official statement on API stability.
