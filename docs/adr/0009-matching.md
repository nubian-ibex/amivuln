# ADR-0009: Matching algorithm and precedence of conflicting sources

- Status: Proposed
- Date: 2026-11-08

## Context

One CVE may be described by several sources with different statements: the distribution tracker says fixed at version X, OSV says fixed at Y, upstream ranges say vulnerable below Z. The result must be one verdict, and a false positive must be impossible when any source says fixed.

## Options

- One source of truth per distro, others only enrich.
- Merge statements: affected beats unverified beats patched, and the highest fixed version wins among affected statements.

## Decision

Recommended and implemented (`amivuln_core::matching::merge`):

- The **distribution statement decides**. Upstream ranges are never used to call a package affected; they only exist as a future complement.
- Per CVE and per package, statements merge as: affected > unverified > patched/not-affected. When several statements say affected, the fix that closes all of them is the **highest** fixed version.
- A statement whose version kind cannot be compared with the installed one (for example a Debian fix against an rpm install) is unverified, never assumed.
- No statement at all is not a statement: the result is unverified, listed apart.
- Enrichment (KEV, EPSS) never changes the verdict.

## Consequences

- A backported fix always wins over an upstream range: no false positives from backports.
- An unverified result is loud in the output but does not fail a build unless `--strict`.
- Merging is deterministic and pure, so two runs on the same data agree.

## Evidence (2026-11-08)

Debian via OSV: in a `debian:stable` (Debian 13) container, 95 installed packages, the OSV oracle (`querybatch` for every installed package/version, advisory bodies required to carry a fixed event for `Debian:13`) and amivuln agree exactly: 0 packages with a pending fix on both sides, no divergence (`tests/integration/debian-vs-osv.sh`). OSV's Debian ecosystem has thousands of advisories with **no** fixed event; those are "known but not fixable" and are not reported as findings, or every Debian host would show hundreds of unverified findings. `amivuln cve` answers them explicitly through `knows()`.
