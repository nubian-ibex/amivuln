# ADR-0007: Source of truth for Fedora

- Status: Proposed
- Date: 2026-11-07

## Context

Fedora packages must be matched against advisories that account for Fedora's own updates. Evidence gathered on 2026-11-07 (preliminary spike S1, no false-positive measurement yet):

- The OSV ecosystem list (`https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt`) contains AlmaLinux, Alpine, Debian, Red Hat, Rocky Linux, SUSE, Ubuntu, openSUSE and others, but **no Fedora** entry. OSV cannot be the distro source for Fedora.
- The Bodhi API (`https://bodhi.fedoraproject.org/updates/?type=security&releases=F42&rows_per_page=N`) returns paginated JSON. Each update has `builds[]` (with `nvr` and `epoch`), `release`, `status`, `severity` and `bugs[]`. CVE IDs appear in the bug titles (for example "CVE-2026-22020 libpng: ..."), not in a dedicated field. The update `status` includes `obsolete`, so superseded updates need handling.

- `updateinfo` evidence (2026-11-07, Fedora 43 `updates` repo, found through `repomd.xml` from the metalink `https://mirrors.fedoraproject.org/metalink?repo=updates-released-f43&arch=x86_64`): one `updateinfo.xml.zst` of about 2.9 MB (4513 updates, checksum listed in `repomd.xml`). Each `<update>` has `id`, `severity`, `issued`, and a `pkglist` with `name`, `epoch`, `version`, `release`, `arch` per package, so fixed EVRs are structured. There is **no** `type="cve"` reference: CVE IDs appear only in the free-text `description` and in the `title` of `bugzilla` references (for example "CVE-2026-28356 python-multipart: ..."). Most updates are `type="unspecified"`, so security relevance cannot be taken from `type` alone.

## Options

- Bodhi security updates: map bug-title CVE IDs to builds and fixed NVRs. Pros: authoritative for what Fedora shipped. Cons: CVE extraction from free text; updates marked obsolete; only covers CVEs that produced an update.
- Repository `updateinfo` metadata: one bulk file per release and repo, structured package EVRs, checksum chain through `repomd.xml`, no per-request API load. Cons: CVE IDs only in free text, needs mirror selection and zstd plus XML parsing (two new dependencies to vet), and the file holds all updates, not only security ones.
- Upstream data (OSV by upstream ecosystem, NVD): ignores Fedora patch status and produces false positives from backports.

## Decision

Pending. Recommendation: Bodhi (with updateinfo evaluated as a cross-check) as the primary status source, upstream data only as a complement flagged as lower confidence. Requires the S1 measurement on 50 real packages before acceptance.

## Consequences

- A package with no Bodhi record cannot be proven fixed, so its CVEs from upstream sources must be reported as `unknown` (unverified), never `affected`.
- Both Fedora sources carry CVE IDs only in free text, so extraction must be a strict regex over bugzilla titles and descriptions, covered by fixtures.
- Offline and cache design favors `updateinfo` (bulk, verifiable); Bodhi is better for freshness. A combination remains open.
- TODO(verify): Bodhi rate limits; whether the `updates-testing` repo must be excluded (it is by using `updates-released`).

## Implementation notes (2026-11-07)

The parser in `amivuln_sources::fedora` implements the `updateinfo` option:

- Only bugzilla reference titles that **start** with CVE ids count as "this update fixes this CVE". CVE ids found in free-text descriptions are ignored: a description such as "regression introduced by the fix for CVE-X" would otherwise mark CVE-X as fixed and hide a vulnerability.
- When several updates fix the same CVE for the same package, the **lowest** fixed EVR wins, so an installed version at or above any published fix is patched.
- An empty answer means "no statement", not "not affected": callers report the CVE as unverified.
- Measured on the real F43 `updates` file (62 MB decompressed, 2.9 MB zstd): 63415 fix records parsed in 0.31 s (release build). Decompressed size is capped at 256 MiB.
- Dependencies: quick-xml and ruzstd (pure Rust, so static musl builds stay simple).

Still open before acceptance: the false-positive measurement on 50 real packages (spike S1) and the Bodhi cross-check.
