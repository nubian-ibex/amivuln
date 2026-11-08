# Data sources

- **Arch Security Tracker**: CVE status and fixed version on Arch (`https://security.archlinux.org/issues/all.json`)
- **Fedora `updateinfo`**: security updates and the CVEs they fix on Fedora (`https://dl.fedoraproject.org/pub/fedora/linux/updates/<release>/Everything/<arch>/repodata/`)
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

## Planned

OSV for Debian, Ubuntu, Alpine and RHEL-family distributions, the Fedora Bodhi
API as a cross-check, NVD by CPE as a fallback, and endoflife.date.
