# Roadmap

What amivuln intends to do, and not to do, over the next year. Dates are
intentions, not promises: the project has one maintainer today and the order
below follows what blocks a 1.0 first.

## Before 1.0

1.0 means the JSON output, the exit codes, the configuration keys and the
command line are a contract for a major version. The code for that is in
place; what remains is trust and people:

- a second maintainer with release permission, so that the project survives
  the absence of one person;
- an independent security review with a published report, which must include
  the one module that contains `unsafe` code (the sandbox for the version
  probe);
- the public benchmark run against more targets, with a ground truth that does
  not share its source with the tools, and with cve-bin-tool measured;
- OpenSSF Scorecard of 8.5 or more and the Silver badge.

## After 1.0, in rough order

1. **Unfixed Red Hat CVEs.** RHEL results come from OSV, which only has
   advisories that shipped a fix. An index built from Red Hat's CSAF VEX data
   would show the CVEs Red Hat has not fixed. See ADR-0012.
2. **Kernel CVEs.** Matching by stable branch and awareness of live patches
   needs its own design study first, because of the volume.
3. **Fleet checks over SSH.** Copy the static binary, run it, aggregate. No
   agent stays behind.
4. **More distributions on demand:** openSUSE, NixOS and Gentoo, as people ask
   for them in issues.
5. **Flatpak runtimes,** read from the installed runtimes.
6. **SBOM and VEX output** for the host, in CycloneDX and OpenVEX.
7. **Known mitigations,** a curated list of "CVE to configuration that
   mitigates it".
8. **An optional local explanation** of a finding, off by default, that never
   sends data off the machine.

## What it will not do

- Run or apply the update commands it prints.
- Send anything that identifies the host, or collect telemetry.
- Replace the distribution's data with a generic upstream version match.
- Run as a resident agent or require a server.
- Support Windows or macOS hosts.

The detailed plan, including the work already finished, is tracked in the
issues and in the architecture decision records under `docs/adr`.
