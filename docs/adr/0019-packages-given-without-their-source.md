# ADR-0019: A package given without its source is not judged by name alone

- Status: Accepted (2026-11-26)
- Date: 2026-11-26

## Context

Debian, Ubuntu, Alpine and openSUSE file advisories in OSV by source package.
A host or container states the source of each package. `name@version`, a purl
and an SBOM did not carry it into amivuln, so a binary name such as `libssl3`
found nothing and the result read as complete.

## What was measured (2026-11-26)

On the official images, asking OSV for each installed name without a version:

| Image | packages | binary and source differ | source has advisories, binary none | never an advisory |
| --- | --- | --- | --- | --- |
| Debian 12 | 88 | 62 | 51 | 20 |
| Ubuntu 24.04 | 92 | 65 | 34 | 46 |
| Alpine 3.22 | 16 | 10 | 6 | 6 |
| openSUSE Leap 15.6 | 135 | 95 | 32 | 88 |

No binary whose name differs from its source had an advisory under its own name.

Where SBOMs state the source: Syft in the purl's `upstream` qualifier (the name,
`name@version`, or the source rpm's file name), omitted for deb and apk when it
equals the package's name; Trivy in the `aquasecurity:trivy:SrcName`
property.

Findings of `--sbom` against `--container` on the same image, with Syft 1.57.2
and Trivy 0.76.2, as (package, CVE, fix):

| Image | container | 1.2.1, Syft / Trivy | after, Syft / Trivy |
| --- | --- | --- | --- |
| Debian 12 | 242 | 27 / 27 and 5 wrong | 242 / 242 |
| Ubuntu 24.04 | 90 | 8 / 8 and 4 wrong | 90 / 90 |
| Alpine 3.22 | 15 | 0 / 0 | 15 / 15 |
| openSUSE Leap 15.5 | 8 | 3 / not run | 8 / not run |
| Rocky Linux 9.3 | 553 | 295 / 295 | 553 / 553 |

The wrong ones came from a deb epoch lost from the purl. On Rocky Linux an SBOM
also lists the CVEs Red Hat has not fixed, which the container run does not.

## Options for a name without a source

1. Report the result as incomplete (exit 2) when OSV holds nothing under it.
2. List the package as unresolved (exit 3), leaving the result complete.
3. Warn on stderr and keep the exit code.

## Decision

- Read the source an input states: the purl's `upstream` qualifier and Trivy's
  properties.
- Once an SBOM names the source of any package, a deb or apk package without one
  is its own source.
- For a package from `name@version`, a purl or an inventory, on Debian, Ubuntu,
  Alpine or openSUSE, without a source and with nothing found, ask OSV whether
  it holds any advisory under the name. If it holds none, option 1.
- Rocky Linux keeps ADR-0018: without a source the result is incomplete, because
  both names can have advisories there.
- Packages of the dpkg database are marked `package_db`: they were marked
  `user_input`, and a missing `Source:` field there means the package's own name.

## Consequences

- A package that never had an advisory, given without its source, is reported as
  incomplete although nothing applies to it.
- A binary name that is also the name of an unrelated source with advisories
  passes as that source. None was seen on the measured images.
- A document merged from tools that state the source differently can have a
  binary taken as its own source.
- The JSON field `provenance` changes from `user_input` to `package_db` for
  Debian and Ubuntu hosts and containers.
- One more query for each such package that found nothing.
