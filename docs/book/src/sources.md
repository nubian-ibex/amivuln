# Data sources

- **Arch Security Tracker**: CVE status and fixed version on Arch (`https://security.archlinux.org/issues/all.json`)
- **Fedora `updateinfo`**: security updates and the CVEs they fix on Fedora (`https://dl.fedoraproject.org/pub/fedora/linux/updates/<release>/Everything/<arch>/repodata/`)
- **OSV**: Debian, Ubuntu, Alpine, openSUSE, Red Hat Enterprise Linux, Rocky Linux, `AlmaLinux`, Go modules and `crates.io` (`https://api.osv.dev/v1/querybatch`, one advisory document per id). Advisories that also exist in the distro trackers carry the same meaning; for Go and crates exact versions are what decide.
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

## Red Hat Enterprise Linux

RHEL is judged from OSV's `Red Hat` ecosystem, which republishes Red Hat
security advisories (RHSA and RHBA). OSV files a package under the repository
it ships in (`Red Hat:enterprise_linux:9::baseos`, `::appstream`, `::crb`) and
the rpm database does not record which, so amivuln asks all three and merges
the answers. One CVE usually has several fixes, one per minor stream (GA, EUS,
E4S). amivuln follows the Fedora rule: an installed version at or above any
published fix is patched, and an older one is reported against the lowest fix.
A host that is not on the lowest stream can therefore see a fix it cannot
install; the finding names the version so the stream can be checked.

**Blind spot.** OSV carries advisories that shipped a fix. A CVE that Red Hat
has not fixed (`Affected`, `Fix deferred`, `Will not fix`, `Out of support
scope`) has no advisory and is **not visible** in this data, so a RHEL result
is a lower bound. Red Hat's CSAF VEX data would close the gap; see ADR-0012.
Severity comes from the rating Red Hat links in each advisory (Important maps
to high).

## Where the data lives offline

`amivuln db build` packs everything consulted into a `tar.zst` that another
host verifies, `amivuln db pull`, and queries with `--offline` (see the guide). VEX
input comes from documents you supply with `--vex`.

## Supported distributions

How a target is identified, and what the data can and cannot show:

- **Fedora.** The host is read through `rpm`. Data: `updateinfo`. A CVE with no published fix is not visible.
- **Arch Linux.** The host is read through `pacman`. Data: the Arch Security Tracker, which also lists vulnerable packages with no fix.
- **Red Hat Enterprise Linux 8, 9 and 10.** The host is read through `rpm`; UBI containers work. Data: OSV's Red Hat ecosystem, a lower bound (see below).
- **Rocky Linux and AlmaLinux 8 and 9.** The host is read through `rpm`. Data: OSV; only CVEs that shipped a fix are visible.
- **Debian and Ubuntu (LTS).** The host is read from `/var/lib/dpkg` (nothing is run); containers, `--packages-from` lists, SBOMs and `name@version` work too. Data: OSV, which also lists open issues (reported as affected with no fix version).
- **openSUSE Leap 15.x and 16.0, and Tumbleweed.** The host is read through
  `rpm`, and containers work. Data: OSV, keyed by the *source* package (the
  library `libopenssl3` is built from `openssl-3`): amivuln reads the source
  name from the rpm database, but a package list or SBOM has to carry it (see
  the Using page). Only the security updates (`SUSE-SU`, `openSUSE-SU`) count,
  and only CVEs that shipped a fix are visible. SUSE Linux Enterprise has its
  own data and is not read yet.
- **Gentoo.** The host is read from `/var/db/pkg` (nothing is run), and
  containers work. Data: the GLSAs in the host's own Portage tree
  (`/var/db/repos/gentoo/metadata/glsa`), read offline; nothing is
  downloaded. Advisories are judged per slot, and a range with a `slot` only
  applies to a package in that slot. Only advisories that shipped a fix
  exist, so a CVE with no fix yet is not visible. The age of the source is
  the time of the last synchronisation of the tree; a tree that is missing,
  unreadable or empty makes the result incomplete. For a container or another
  machine, point `[sources.distro] path` at a directory with the `glsa-*.xml`
  files. The `arch` attribute of an advisory is not read.
- **Alpine 3.x.** The host is read from `/lib/apk/db/installed`; the same other inputs as Debian and Ubuntu. Edge and alpha images have no advisory data and are refused. Data: OSV, keyed by the origin package; only CVEs that shipped a fix are visible.
- **Flatpak runtimes.** Read from each runtime's `manifest.json`, judged by the
  NVD for the upstream version of each component with the builder's own `patches`
  and `ignored` lists applied. Slow and rate limited; see the guide.
- **Go modules and Rust crates** found in binaries, through OSV.

## Planned

The Fedora Bodhi API as a cross-check, NVD by CPE as a fallback, and
endoflife.date. Red Hat's own CSAF VEX archive would add the CVEs Red Hat
has not fixed (see below); it needs a bulk index and is not planned before
there is demand (ADR-0012).

## Arch specifics

The tracker marks a group *Vulnerable* with no fixed version for the build
that was current when the entry was written, and some entries stay that way
for years. amivuln reports an installed package as affected only when it has
the same upstream version as the recorded build (a rebuild of it is still
affected). A newer upstream version is reported as *unverified*, because the
entry cannot say whether it still applies. An install older than the recorded
build is outside the entry and is not reported.
