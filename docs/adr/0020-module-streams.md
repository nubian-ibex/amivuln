# ADR-0020: The unfixed CVEs of a module stream are read by the stream

- Status: Accepted (2026-11-26)
- Date: 2026-11-26
- Amends: ADR-0014

## Context

Red Hat's OVAL file names the components of a module stream with the stream,
`nodejs:22/nodejs`. amivuln asked by the package name alone, so a package
installed from a module got none of them and the result read as complete.

## What was measured (2026-11-26)

- RHEL 8 lists 88 streams, 1778 (module, stream, CVE) entries; RHEL 9, 28
  streams and 685.
- With 1.2.3, the entries of the installed stream that were missed: 204 of 280
  (package, CVE) pairs on a UBI 8 image with `nodejs:22`, 240 of 320 on UBI 9
  with `nodejs:22`, 34 of 70 on AlmaLinux 8 with `nodejs:20`, `postgresql:13`
  and `nginx:1.20`. With the rule below, none, as a host, a container, and an
  SBOM from Syft or Trivy.
- Red Hat also states CVEs for a component without a stream
  (`nodejs: Fix deferred`), so the plain name cannot be dropped.
- `rpm` states the stream in `%{MODULARITYLABEL}` (`name:stream:version:context`),
  also for the database of a container. rpm 4.11 (RHEL 7) rejects the tag with an
  error, and rpm 4.14.3 of openSUSE Leap exits 0 and writes nothing.
- Syft states the label in the property `syft:metadata:modularityLabel`, Trivy
  in `aquasecurity:trivy:Modularitylabel` and in the purl.
- Fixes of other streams cannot simply be dropped: of 84 CVEs of `nodejs` that
  AlmaLinux 8 reported on stream 20 only because another stream fixed them, Red
  Hat defers the fix for stream 20 in 7 and states nothing for it in 76.

## Decision

- Read the module label of RHEL 8 and later, Rocky Linux and AlmaLinux packages.
  When `rpm` refuses the format or writes nothing, ask again without it.
- Read it from a purl's `modularitylabel` qualifier and from the SBOM properties
  of Syft and Trivy.
- A package with a stream gets the entries of `stream/name` and of
  `stream/source` besides those of the plain names.
- An entry of the stream reopens a CVE that read as patched, since the fix that
  settled it can be another stream's. An open finding keeps its fix version.
- A package built for a module and given without its stream makes the
  `redhat-oval` source failed and required: the result is incomplete (exit 2).

## Consequences

- Streams are still not told apart in the fixes. A package can be reported with
  the fix version of another stream, and a CVE that Red Hat does not list for its
  stream can read as patched because of one.
- On a rebuild that fixed a stream before Red Hat did, the CVE is reported as
  unfixed until Red Hat's file drops it.
- A host whose `rpm` does not know the tag cannot judge the module packages of a
  container: the result is incomplete.
- The disabled unfixed list, and RHEL 10, which has none, stay as before.
