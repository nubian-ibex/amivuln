# Roadmap

What amivuln intends to do, and not to do, over the next year. Dates are
intentions, not promises: the project has one maintainer today and the order
below follows what blocks a 1.0 first.

## Before 1.0

1.0 means the JSON output, the exit codes, the configuration keys and the
command line are a contract for a major version. An internal audit in
November 2026 found code work, now done: the container export is hardened and
reads the archive as a stream (nothing is stored, and the size limit stops the
running program), reads the rpm
database of current Fedora images and the pacman database of Arch images, a
Fedora or Arch image is judged by its own data from any host, redirects never leave HTTPS, the webhook
uses the scan's network settings and is not retried, the advisory limit is
reported where the cut happens, the cache is pruned, OSV queries are batched
and advisories fetched in parallel (a Debian container went from 39 s to 5 s
cold), and file owners are looked up in one pass.

The feature scope of 1.0 is one item, because it changes the output formats
the contract covers: **SBOM and VEX output** for the host, as CycloneDX and
OpenVEX (`-f cyclonedx`, `-f openvex`). Everything else is 1.x work.

The rest is trust and people, and the security review comes after the code
above so that it sees the final code:

- a second maintainer with release permission, so that the project survives
  the absence of one person (this also unlocks the OpenSSF Silver criteria
  `bus_factor` and `access_continuity`, and Scorecard's Code-Review);
- an independent security review with a published report, which must include
  the one module that contains `unsafe` code (the sandbox for the version
  probe);
- the public benchmark run against more targets, with a ground truth that does
  not share its source with the tools, and with cve-bin-tool measured;
- OpenSSF Scorecard of 8.5 or more. Without a second person it is reachable
  by about February 2027: the Maintained check starts scoring once the
  repository is 90 days old, and Signed-Releases reaches 10 once every recent
  release carries provenance;
- the OpenSSF Silver badge, which needs the second person above and the
  translatable messages of item 4 in the 1.x list.

## After 1.0 (1.x), in rough order

1. **More distributions.** openSUSE (Leap and Tumbleweed, through OSV) and
   Gentoo (the GLSAs of the host's own Portage tree, with a version
   comparator checked against Portage) are done. NixOS is not: OSV has no
   NixOS data, the Nixpkgs security tracker is a web application with no
   data interface to read, and Nix has no distribution fix status, which the
   rule "the distribution's data decides" cannot do without a design
   decision. SUSE Linux Enterprise is in OSV and is a small step from
   openSUSE.
2. **Flatpak applications.** The runtimes are done (`--flatpak`); applications
   bundle their own libraries and carry no manifest of components, so they are
   not read yet.
3. **Known mitigations,** a curated list of "CVE to configuration that
   mitigates it".
4. **More languages and the rest of the messages.** The mechanism is in
   place (message catalogs, English and Brazilian Portuguese, chosen from the
   locale). The `--help` text, the configuration errors and the messages of
   the libraries are still English only, and Spanish, German and French
   catalogs would need a native reviewer.
5. **An optional local explanation** of a finding, off by default, that never
   sends data off the machine.
6. **Unfixed Red Hat CVEs.** RHEL results come from OSV, which only has
   advisories that shipped a fix. An index built from Red Hat's CSAF VEX data
   shows the CVEs Red Hat has not fixed. It needs an architecture decision
   record first. See ADR-0012.
7. **Kernel CVEs.** Matching by stable branch and awareness of live patches
   needs its own design study first, because of the volume.
8. **Fleet checks over SSH.** Copy the static binary, run it, aggregate. No
   agent stays behind.

## What it will not do

- Run or apply the update commands it prints.
- Send anything that identifies the host, or collect telemetry.
- Replace the distribution's data with a generic upstream version match.
- Run as a resident agent or require a server.
- Support Windows or macOS hosts.

The detailed plan, including the work already finished, is tracked in the
issues and in the architecture decision records under `docs/adr`.
