# ADR-0016: SUSE Linux Enterprise source

- Status: Proposed
- Date: 2026-11-25

## Context

openSUSE Leap and Tumbleweed are read through OSV (ADR-0012, ecosystem
`openSUSE:Leap 15.6`). SUSE Linux Enterprise (SLES) was then listed as "a small
step from openSUSE", which the first measurement disproved: OSV does not file a
SLES advisory under a release the way it does for Leap. Each advisory is filed
under a product and a module (`SUSE:Linux Enterprise Module for Basesystem
15 SP6`), and a query by the product name returns nothing.

## What was measured (2026-11-25)

- OSV ecosystems, from `querybatch` on `openssl-3` against the base `SUSE`
  ecosystem: `SUSE:Linux Enterprise Module for Basesystem 15 SP6` and `SP7`,
  `... Module for Web and Scripting 15 SP7`, `SUSE:Linux Enterprise Server
  15 SP6-LTSS`, `SUSE:Linux Enterprise Server 16.0`, `... Server for SAP
  Applications 15 SP6`, `SUSE:Linux Micro 6.0` and `6.2`. The bare `SUSE`
  ecosystem returns the advisories of several service packs at once.
- The same `openssl-3` (`3.1.4-150600.2.1`) asked under the Basesystem module
  of its own service pack answers 8 advisories, with fixes
  (`3.1.4-150600.5.7.1` and later) in the same version scheme as the rpm.
  The module query is the one that works.
- The release of every SLE rpm encodes the service pack:
  `openssl-3.1.4-150600.2.1` is 15 SP6 (`150600`), and `15.6` on Leap maps the
  same way. This is the filter a host needs, and it needs no zypper.
- A SUSE BCI container (`registry.suse.com/suse/sle15:15.6`) is freely
  pullable and reports `ID=sles`, `VERSION_ID="15.6"`; it is enough to develop
  and test against, with no subscription.
- `SUSE-SU` records state no severity (no `severity` entry at all), so SLES
  findings read `unknown` (see the severity note in the guide, and the
  `--fail-on` warning added in 1.2.0).

## Options

1. Query every `SUSE:...` ecosystem of the service pack the release encodes
   (Basesystem plus Server Applications, LTSS, and the module list), and keep
   the advisories whose `affected` names the package, as Red Hat already does
   across its repositories (ADR-0012: one question per repository).
2. Read the module list from the host (`/etc/zypp/repos.d`, or `SUSEConnect
   --status-text`) and query only those. More precise, but it needs the
   subscription tooling and a schema to parse.
3. Query the bare `SUSE` ecosystem and filter by version. Rejected: the
   answer mixes service packs, and a fix published for SP7 (a newer rpm
   version) would read as a fix for SP6 (the ADR-0008 stale-Vulnerable rule
   exists for exactly this shape of mistake).

## Decision

Option 1, and only for hosts whose release says so:

- `os_release` accepts `ID=sles` (and `ID=sled`, same repositories) with
  `VERSION_ID` as `15.SP`, `16.0` and the like, mapping to the existing
  `Opensuse` ecosystem value family or a sibling one, so the rpm comparator
  and the `--distro` plumbing are reused.
- The ecosystems asked are, for a 15.SP release: the Basesystem and Server
  Applications modules of that SP, plus the `...-LTSS` ecosystem of the same
  SP, mirroring what SUSE publishes. A 16.0 release asks its `SUSE:Linux
  Enterprise Server 16.0` ecosystem.
- Advisories are matched per package by the rule 1.2.0 introduced: only a fix
  that names the package counts.
- Support end: when SUSE drops a service pack, OSV stops gaining records. Like
  Ubuntu interim releases, a past-support SP is reported as incomplete (exit
  2), with the date table in the code and a test.
- The BCI images are the development and CI target; a real registered SLES is
  the acceptance test before the feature ships.

## Consequences

- No new dependency, and no zypper: the rpm database and the release string
  carry everything.
- A package of a module the list does not cover gets no advisories and reads
  unverified (not clean) if the tracker coverage check fires; the module list
  is the risk to watch, and the coverage probe (fix/osv-no-data-fails) catches
  a wrong list instead of reading it as clean.
- openSUSE Leap keeps its own ecosystem and gains nothing.
- `--distro sles:15.6` names the same mapping as the host read.
