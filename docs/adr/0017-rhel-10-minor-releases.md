# ADR-0017: RHEL 10 is judged by its minor release

- Status: Accepted (2026-11-26)
- Date: 2026-11-26
- Amends: ADR-0012

## Context

ADR-0012 reads RHEL 8 and 9 from the OSV ecosystems
`Red Hat:enterprise_linux:N::baseos|appstream|crb`. RHEL 10 was asked the same
way and OSV holds nothing under those names, so every RHEL 10 host and image
read as clean and complete in 1.2.0 and earlier. OSV files RHEL 10 by minor
release, `Red Hat:enterprise_linux:10.0`, `10.1`, `10.2` and `10.3`, with no
repository suffix.

## What was measured (2026-11-26)

- The same CVE is often fixed in more than one minor, with different builds. For
  the kernel, 133 of 988 CVEs are (openssh 8 of 29). CVE-2025-39766 is fixed in
  10.1 by `6.12.0-124.52.1` and in 10.2 by `6.12.0-211.16.1`.
- Asking every minor and taking any fix at or below the installed version as
  patched, the ADR-0012 rule, hides it: a 10.2 host at `211.10.1` is above the
  10.1 fix and would read as patched.
- A UBI 10.0 image, scanned with the rule below, against Red Hat's Security Data
  API for 10 of its source packages: Red Hat lists 145 affected (package, CVE)
  pairs and 144 are reported. The one missing is fixed only in the Extended
  Update Support stream of 10.2. All 44 sampled fix versions exist at Red Hat.
- The `updateinfo` of the UBI repositories is empty, so it cannot serve as
  ground truth.

## Options

1. Judge by the host's minor release: ask that minor and the later ones.
2. Ask every minor and require the highest fix. Never hides a CVE, but reports
   up to date hosts as affected whenever a later minor has a fix.
3. Leave RHEL 10 incomplete until Red Hat's data can be read another way.

## Decision

Option 1.

- The minor comes from `VERSION_ID` (host and container) or from
  `--distro rhel:10.2`. The release is kept as `major * 100 + minor`, as
  openSUSE Leap already is; RHEL 8 and 9 keep the major alone.
- The ecosystems asked are the host's minor and every later one, up to 10.10. A
  fix of an earlier minor says nothing about a host on a later one.
- A RHEL 10 given without a minor asks every minor, keeps what it finds, and is
  incomplete (exit 2).
- The `enterprise_linux_eus` streams are not asked, as the `rhel_eus` ones are
  not for 8 and 9.

## Consequences

- A host on an earlier minor can be shown a fix that only a later minor ships,
  even when its own stream is up to date. It is the safe direction, and the fix
  version names the minor.
- A fix published only in an Extended Update Support stream is not seen. A host
  with that subscription gets a lower bound.
- A minor newer than the data holds nothing, and the check for a release without
  data makes the result incomplete rather than clean.
- Red Hat publishes no list of unfixed CVEs for RHEL 10 (ADR-0014), so the
  result stays a lower bound there.
- OSV may move RHEL 10 to other names again. An ecosystem that answers nothing
  for the probe package reads as incomplete, not as clean.
