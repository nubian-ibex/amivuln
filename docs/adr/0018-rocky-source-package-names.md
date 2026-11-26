# ADR-0018: Rocky Linux advisories are also read by source package

- Status: Accepted (2026-11-26), amended the same day: ADR-0019 reads the source a purl or SBOM states
- Date: 2026-11-26

## Context

amivuln asked OSV about an RPM package by its installed name. OSV files many
Rocky Linux advisories under the source package only (`openssl`, not
`openssl-libs`), so a subpackage read as having fewer CVEs than it has, or none,
and the result read as complete. Separately, hosts and containers of Rocky
Linux and AlmaLinux were not recognised, because `VERSION_ID` carries the minor
release (`9.4`) and the major alone was expected.

## What was measured (2026-11-26)

Findings with a fix on the official images, against `dnf updateinfo` inside the
same image, as (package, CVE) pairs:

| Image | listed by dnf | by binary name | by both names |
| --- | --- | --- | --- |
| Rocky Linux 8 | 343 | 156 | 338 |
| Rocky Linux 9.3 | 558 | 319 | 553 |

- With `--distro rocky:9` in 1.2.0, `openssl` shows 38 high findings and
  `openssl-libs`, at the same version, none.
- AlmaLinux 8, 9 and 9.3 miss no pair by the binary name alone; their advisories
  list the binaries. A sample of three packages each on RHEL 8 and 9 showed one
  advisory filed under the source name only.
- The five pairs still missing per image are differences in the data: OSV does
  not list the CVE, or states an earlier fix than the repository does.
- Advisories of module streams also match packages outside the module: asking by
  both names on a Rocky Linux 8 image with `perl` installed gave 256 findings
  from `.module+el8` builds that `dnf` does not apply to those packages.

## Decision

- On Rocky Linux, ask OSV by the binary name and by the source name.
- Some subpackages have a version of their own (`device-mapper` from `lvm2`,
  many Perl modules from `perl`). For them the source's release, read from
  `SOURCERPM`, is asked from epoch 0 on, and a fix filed under the source name
  alone is compared with that release, leaving the epoch out of both; the fix
  shown is then the source package's version. A fix naming the binary wins.
- A fix whose release is a module build (`.module+`) does not apply to a Rocky
  Linux package installed outside a module.
- A Rocky Linux package given without its source (`name@version`, a purl,
  `--packages-from`, a package note) keeps what is found and is incomplete
  (exit 2).
- `VERSION_ID` is read by its major release, for 8 and 9. Release 10 stays
  unsupported.

## Consequences

- Rocky Linux makes up to twice as many queries.
- Inventories and SBOMs of Rocky Linux cannot give a complete result. The
  `upstream` qualifier of a purl is not read.
- Streams of one module are not told apart.
- A CVE OSV lists only for a module stream is still counted as known, so the
  unfixed list of Red Hat (ADR-0014) does not add it for the package outside the
  module.
- The same module-stream mismatch can affect AlmaLinux and RHEL 8, which this
  change does not touch.

## Amendment (2026-11-26)

ADR-0019 reads the source an SBOM or a purl states, so only a Rocky Linux
package without it is incomplete.
