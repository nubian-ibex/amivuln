# ADR-0012: Red Hat Enterprise Linux data source

- Status: Accepted, amended 2026-11-12 (the unfixed CVEs: see ADR-0014)
- Date: 2026-11-09

## Context

Rocky Linux and AlmaLinux are covered through OSV (ecosystems `Rocky Linux:N`, `AlmaLinux:N`). OSV has no Red Hat Enterprise Linux ecosystem (`Red Hat Enterprise Linux 9` is rejected as an invalid ecosystem, checked 2026-11-09), so RHEL itself needs Red Hat's own data. The roadmap names CSAF.

## What the data looks like (checked 2026-11-09)

- CSAF VEX, one document per CVE at `security.access.redhat.com/data/csaf/v2/vex/YYYY/cve-YYYY-NNNN.json`, with `changes.csv` and `index.txt` listings. `product_status` ids carry the stream and the package NEVRA, for example `AppStream-9.4.0.GA:openssl-1:3.0.7-27.el9.x86_64`. The same CVE lists fixes per minor stream (GA, EUS, E4S, ELS), so one CVE has several fixed versions for one major release.
- Security Data API (`access.redhat.com/hydra/rest/securitydata`): `cve/CVE-ID.json` has `affected_release` (product, advisory, fixed `package` NEVRA) and `package_state` (`Affected`, `Will not fix`, `Fix deferred`, `Out of support scope`, `Not affected`) per package. It is easier to read than CSAF.
- Both are CVE-first. The package filter of `cve.json?package=openssl` returned 546 entries, many of them unrelated to the package, so it cannot be trusted as a package index.

## Options

1. Per-package fan-out: list CVEs for a package, then fetch each CVE document. Hundreds of requests per package; too slow for `--all`.
2. Bulk mirror: download the CSAF VEX archive (or `changes.csv` deltas), build a local package-to-CVE index in the cache and query it. One large first download, then cheap. Fits the offline database planned for phase 4.
3. Do not support RHEL; document Rocky/Alma as the RHEL-compatible path.

## Decision

Proposed: option 2, after the offline database format exists, and option 3 until then. The merge rule would be the Fedora one: among the fixed versions for the installed major release, installed at or above any published fix is patched; a `package_state` of `Affected` or `Fix deferred` with no fix is affected without a fix; `Will not fix` and `Out of support scope` are reported as such, never silently counted as clean; `Not affected` is not-affected.

## Open questions for the maintainer

- Is a first download in the hundreds of MB acceptable, or must the index be a published, signed artifact of this project (the phase 4 offline database)?
- How are minor streams (EUS, E4S) handled when the host does not declare its subscription? Proposal: compare against the lowest fix of the GA stream and report the stream in the evidence.
- Red Hat data licensing for redistribution of a derived index.

## Consequences

- No false confidence: until this is implemented, `--distro rhel:N` stays unsupported and says so.
- The ground-truth corpus needs RHEL cases with recorded fixtures before any implementation lands.

## Amendment (2026-11-12)

OSV now has a `Red Hat` ecosystem. Its advisories are RHSA and RHBA records filed under `Red Hat:enterprise_linux:N::baseos|appstream|crb|...` with the fixed NEVRA per package, a `upstream` list of CVEs and a link to the severity classification. The `Red Hat Enterprise Linux N` spelling from the Context section is still rejected, but this one is not.

Decision: RHEL is implemented through OSV, the same path as Rocky and AlmaLinux, with option 2 (the CSAF bulk index) deferred. amivuln asks the `baseos`, `appstream` and `crb` ecosystems, merges the advisories, and applies the Fedora merge rule per package name. Advisories only exist for fixed issues, so the `package_state` cases (`Affected`, `Fix deferred`, `Will not fix`, `Out of support scope`) are **not visible**. The documentation says RHEL results are a lower bound.

Still open: the CSAF index for those cases, EUS and E4S stream handling beyond comparing against the lowest fix, and licensing of a derived Red Hat index.
