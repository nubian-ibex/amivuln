# ADR-0007: Source of truth for Fedora

- Status: Proposed
- Date: 2026-11-07

## Context

Fedora packages must be matched against advisories that account for Fedora's own updates. Evidence gathered on 2026-11-07 (preliminary spike S1, no false-positive measurement yet):

- The OSV ecosystem list (`https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt`) contains AlmaLinux, Alpine, Debian, Red Hat, Rocky Linux, SUSE, Ubuntu, openSUSE and others, but **no Fedora** entry. OSV cannot be the distro source for Fedora.
- The Bodhi API (`https://bodhi.fedoraproject.org/updates/?type=security&releases=F42&rows_per_page=N`) returns paginated JSON. Each update has `builds[]` (with `nvr` and `epoch`), `release`, `status`, `severity` and `bugs[]`. CVE IDs appear in the bug titles (for example "CVE-2026-22020 libpng: ..."), not in a dedicated field. The update `status` includes `obsolete`, so superseded updates need handling.

## Options

- Bodhi security updates: map bug-title CVE IDs to builds and fixed NVRs. Pros: authoritative for what Fedora shipped. Cons: CVE extraction from free text; updates marked obsolete; only covers CVEs that produced an update.
- Repository `updateinfo` metadata: structured, per-repo, includes CVE references. Cons: needs repo metadata download and parsing; verify availability for Fedora repos.
- Upstream data (OSV by upstream ecosystem, NVD): ignores Fedora patch status and produces false positives from backports.

## Decision

Pending. Recommendation: Bodhi (with updateinfo evaluated as a cross-check) as the primary status source, upstream data only as a complement flagged as lower confidence. Requires the S1 measurement on 50 real packages before acceptance.

## Consequences

- A package with no Bodhi record cannot be proven fixed, so its CVEs from upstream sources must be reported as `unknown` (unverified), never `affected`.
- TODO(verify): updateinfo URL layout and CVE reference fields; Bodhi rate limits.
