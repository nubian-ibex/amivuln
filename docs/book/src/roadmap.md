# Roadmap

What amivuln intends to do, and not to do, over the next year. Dates are
intentions, not promises: the project has one maintainer today and the order
below follows what matters most now that 1.0 is out.

## Where 1.0 stands

1.0.0 was released on 2026-11-24. The code, the feature scope and the contract
are done and tested, and the contract is the one 1.0.0-rc.1 published.

It was released before the people items below, which were meant to precede it
and are still open: a second maintainer with release permission and an
independent security review. Until they exist the project depends on one
person and its `unsafe` code has had no outside review. They are the first
work of the 1.x series. Their dates depend on other people, so they are not
promised; the Scorecard estimate is February or March 2027.

1.1.0 followed on 2026-11-25 with three additive changes, none of which touches
the contract: Red Hat's state for an unfixed CVE (`distro_status.vendor_state`),
the unfixed Red Hat CVEs on Rocky Linux and AlmaLinux 8 and 9, and the running
kernel marked in a full report (`package.running_kernel`). The new JSON fields
are optional fields of schema version 1.

1.2.0 followed the same day, after running the tool on real Arch, Ubuntu and
Fedora systems showed that 1.1.0 and earlier can report vulnerable systems as
clean. An interim Ubuntu release got no advisory at all, an advisory covering
several packages could give one the fix of another, and severity was often not
read, so `--fail-on` passed. All three are fixed: an interim release past its
support is now incomplete, only a fix that names the package counts, and a run
says how many findings `--fail-on` cannot judge. An EndeavourOS host is read as
Arch Linux, and the totals count only affected packages.

1.2.1 followed on 2026-11-26, because more tests after 1.2.0 found further
defects, all fixed in it. Outside Ubuntu, a release OSV has no data for read as
clean. RHEL 10 read as clean, because OSV files it by minor release; it is now
judged by the host's minor (ADR-0017). A Rocky Linux subpackage hid the CVEs
filed under its source package, and Rocky Linux and AlmaLinux hosts and
containers were not recognised (ADR-0018). An advisory naming hundreds of CVEs,
as openSUSE kernel updates do, took gigabytes of memory and aborted the run (on
Leap 15.6 with the kernel it shipped with). A closed pipe was reported as a
failure.

1.2.2 followed the same day, for inputs other than a host. A binary name given
without its source package read as clean (ADR-0019), the `apk` components of an
SBOM were not checked, and a purl lost its epoch outside Fedora, which reported
patched CVEs as affected. Red Hat's unfixed list was chosen by the host, so an
image of a Red Hat family distribution got none on another host, or the list of
the wrong release (ADR-0014).

1.2.3 followed the same day. On RHEL, Rocky Linux and AlmaLinux, a CVE fixed in
one package hid it in another that has no fix, and fixes of module streams were
applied on RHEL and AlmaLinux to packages outside the module.

1.2.4 followed the same day. On RHEL, Rocky Linux and AlmaLinux, a package of a
module stream got none of the CVEs Red Hat lists as unfixed for its stream, and
read as complete (ADR-0020). A UBI 8 image with `nodejs:22` missed 51.

1.2.5 followed on 2026-11-27 with the rest of the module stream work (ADR-0021):
a package of a stream no longer reads as affected by the fixes of the others,
and a package of the base stream has the CVEs only a module fixed reported as
unverified instead of dropped. An empty package database, list or SBOM is
unresolved (exit 3) instead of complete, an SBOM of AlmaLinux or Rocky Linux
built by Syft is read, and the packages of an Arch image are no longer marked as
user input.

1.3.0 followed the same day, for four defects that read vulnerable systems
as clean. On Debian and Ubuntu the signed kernel image (the running one
included) showed no CVE, and fixes were compared with the version of the
binary package instead of its source's, which read as clean of fixed CVEs
(`login` and `bsdutils` on Debian 13.0) and as affected by fixed ones. Of a
package with more than about 1000 OSV advisories only the first ones were
read, and the result read as complete. A Fedora image of another release
than the host's was judged by the host's updates. A package list may now
also be written in purls, which name the source package and the module
stream. Every version before 1.3.0 is yanked on crates.io; the release
notes of 1.0.0 to 1.2.5 say why. After 1.3.0, a container of an
unsupported distribution is refused with the usage exit code (64) instead
of reading as complete with no targets.

## What 1.0 meant, and what is still open

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

The feature scope of 1.0 was one item, because it changes the output formats
the contract covers, and it is done: **SBOM and VEX output** for the host, as
CycloneDX 1.6 and OpenVEX 0.2.0 (`-f cyclonedx`, `-f openvex`). The state of
each CVE comes from the distribution's own data, the output is deterministic,
and the tests validate both documents against the official schemas. See
[SBOM and VEX](guide.md#sbom-and-vex). The scope of 1.0 is now closed, and
everything else is 1.x work.

The rest is trust and people, and the security review comes after the code
above so that it sees the final code. All of it is still open:

- a second maintainer with release permission, so that the project survives
  the absence of one person (this also unlocks the OpenSSF Silver criteria
  `bus_factor` and `access_continuity`, and Scorecard's Code-Review);
- an independent security review with a published report, which must include
  the one module that contains `unsafe` code (the sandbox for the version
  probe);
- the public benchmark run against more targets, with a ground truth that does
  not share its source with the tools, and with cve-bin-tool measured;
- OpenSSF Scorecard of 8.5 or more (7.8 on 2026-11-25). Without a second
  person it is reachable by about February 2027: the Maintained check starts
  scoring once the repository is 90 days old. Vulnerabilities and
  Signed-Releases are already 10. A second person would also lift Code-Review
  and Contributors;
- the OpenSSF Silver badge (87% on 2026-11-23), which needs the second person
  above (the criteria `bus_factor` and `access_continuity`) and the answers
  still open on the form. The translatable messages are not what holds it
  back: the internationalization criterion is met.

## Known gaps

Found while testing and not fixed yet.

- CentOS Stream (`ID=centos`) is not supported, as a host or a container.
- The rpm database of a Fedora-family container is read with the host's `rpm`,
  so a host without it (Flatcar, which ships none) leaves such a container
  unresolved (exit 3). Reading the rpm database in the amivuln process, as the
  dpkg and apk databases are, would drop the dependency.
- A Rocky Linux package list is always incomplete, because it cannot name the
  source packages.
- The fixes of one module stream are not told apart from another's. A package can
  be reported as affected with the fix version of another stream (an AlmaLinux 8
  image with an old `nodejs:20` showed 336 findings beside the 91 `dnf` lists),
  and a CVE Red Hat does not list for its stream can read as patched because of
  another stream's fix. Dropping those findings is not safe: Red Hat defers or
  says nothing about most of them.
- Rocky Linux and AlmaLinux 10 are not supported.
- Only an Ubuntu interim release is judged past its support by date. Another
  release that is past support, and for which OSV still holds old advisories, is
  not marked incomplete.
- CVSS 4 vectors are not read, and some distribution advisories state no
  severity at all (openSUSE's among them), so those findings stay `unknown`.
- The text summary counts `unknown` severity with the low ones, although the
  JSON keeps them apart.
- The first run on a host with many open advisories is slow, because each
  advisory is downloaded once: over two minutes on an interim Ubuntu desktop,
  and a few seconds afterwards.

## After 1.0 (1.x), in rough order

1. **More distributions.** EndeavourOS is read as Arch Linux; other Arch
   derivatives are not, because ones that rebuild or delay packages would be
   judged wrongly. openSUSE (Leap and Tumbleweed, through OSV) and
   Gentoo (the GLSAs of the host's own Portage tree, with a version
   comparator checked against Portage) are done. NixOS is deferred (decided
   2026-11-17): OSV has no NixOS data, the Nixpkgs security tracker is a web
   application with no data interface to read, and Nix has no distribution
   fix status, which the rule "the distribution's data decides" cannot do. A
   mode with a weaker guarantee (upstream version against the package's
   version, always labelled as such) was considered and not chosen. It is
   reopened when Nixpkgs publishes machine-readable security data.
   SUSE Linux Enterprise is not the small step from openSUSE it looked like.
   OSV has a `SUSE` ecosystem, but it tags each advisory by product and module
   (for example `SUSE:Linux Enterprise Module for Basesystem 15 SP7`): a query
   by the product name finds nothing, and the bare `SUSE` ecosystem returns the
   advisories of several service packs, which would report fixes of SP7 on an
   SP6 host. ADR-0016 (proposed) records the measurements and a design; it still
   needs the list of modules to ask, and a check on a registered SLES, before
   any code.
2. **Flatpak applications.** The runtimes are done (`--flatpak`); applications
   bundle their own libraries and carry no manifest of components, so they are
   not read yet.
3. **Known mitigations.** Done with Red Hat's own data (`--mitigations`)
   instead of a list kept by this project: it covers most CVEs and states its
   source. A mitigation from another distribution, and a check that the
   setting is or is not in effect on the host, are not done.
4. **More languages and the rest of the messages.** The mechanism is in
   place (message catalogs, English and Brazilian Portuguese, chosen from the
   locale), and it now covers the `--help` text and the errors about options,
   input files and configuration values. Still English only: the messages clap
   prints for a mistyped command line, the parser errors of the configuration
   file and the messages of the libraries. The Portuguese text was written by
   the project's assistant and has no native review yet, and Spanish, German
   and French catalogs would need a native reviewer.
5. **Local explanation.** `--explain` is done as templates over the data the
   run holds. An explanation written by a local language model was left out on
   purpose: it can state what is not in the data, and it needs a runtime and a
   model on the machine. It stays open if a use is shown that the templates do
   not cover.
6. **Unfixed Red Hat CVEs.** Done for RHEL 8 and 9, and for Rocky Linux and
   AlmaLinux 8 and 9, which rebuild the same sources (ADR-0014; 1.1.0): Red
   Hat's OVAL file "including unpatched" is streamed once per cache refresh and
   its unfixed CVEs are reported as affected with no fix, with the Red Hat
   state (`Will not fix`, `Fix deferred`) in `distro_status.vendor_state`. A fix
   Red Hat shipped that a rebuild has not yet is in neither source and stays
   invisible until the rebuild's own advisory exists. RHEL 10 has no such file
   yet and stays a lower bound.
7. **Kernel CVEs.** The design study is ADR-0015: the kernel is judged by the
   distribution's data, `--kernel` checks the running one, and, since 1.1.0, a
   full report marks the package that owns it. Knowing about live patches is not
   done.
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
