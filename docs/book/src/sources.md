# Data sources

- **Arch Security Tracker**: CVE status and fixed version on Arch (`https://security.archlinux.org/issues/all.json`)
- **Fedora `updateinfo`**: security updates and the CVEs they fix on Fedora (`https://dl.fedoraproject.org/pub/fedora/linux/updates/<release>/Everything/<arch>/repodata/`)
- **OSV**: Debian, Ubuntu, Rocky Linux, `AlmaLinux`, Go modules and `crates.io` (`https://api.osv.dev/v1/querybatch`, one advisory document per id). Advisories that also exist in the distro trackers carry the same meaning; for Go and crates exact versions are what decide.
- **CISA KEV**: actively exploited CVEs (`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`)
- **FIRST EPSS**: probability of exploitation (`https://api.first.org/data/v1/epss`)

The distribution source is required by default. KEV and EPSS enrich the
result and are optional: if they fail the output says so, but the result is
still complete.

## Why not OSV for Fedora and Arch

The OSV ecosystem list (checked 2026-11-07) contains Debian, Ubuntu, Alpine,
Red Hat, Rocky, AlmaLinux, SUSE and others, but not Fedora or Arch Linux. For
these two, the distribution's own data is the source of truth.

## Fedora specifics

`updateinfo` states which CVEs an update fixed. amivuln reports a CVE as
affecting an installed package when Fedora has published a fix in a newer
version. Only CVE ids that open a bugzilla bug title are trusted; ids that
appear only in free-text descriptions are ignored, because "regression from
the fix for CVE-X" would otherwise mark CVE-X as fixed. A security update that
names no CVE is reported under its update id. A CVE without a published fix is
not visible in this data.

## Where the data lives offline

`amivuln db build` packs everything consulted into a `tar.zst` that another
host verifies, `amivuln db pull`, and queries with `--offline` (see the guide). VEX
input comes from documents you supply with `--vex`.

## Planned

The Fedora Bodhi API as a cross-check, NVD by CPE as a fallback, and
endoflife.date. RHEL itself stays out until its data licensing is settled
(ADR-0012).

## Arch specifics

The tracker marks a group *Vulnerable* with no fixed version for the build
that was current when the entry was written, and some entries stay that way
for years. amivuln reports an installed package as affected only when it has
the same upstream version as the recorded build (a rebuild of it is still
affected). A newer upstream version is reported as *unverified*, because the
entry cannot say whether it still applies. An install older than the recorded
build is outside the entry and is not reported.
