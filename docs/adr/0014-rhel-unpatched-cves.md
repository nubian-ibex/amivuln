# ADR-0014: Red Hat CVEs that have no fix yet

- Status: Accepted (2026-11-17), amended 2026-11-26 (the file follows the package's release; an answer counts for its own package only; module streams: ADR-0020)
- Date: 2026-11-14
- Amends: ADR-0012

## Context

ADR-0012 left one gap: RHEL results come from OSV's Red Hat ecosystem, which only holds advisories that shipped a fix, so a CVE Red Hat has not fixed (state `Affected`, `Will not fix`, `Fix deferred`, `Out of support scope`) is invisible and a RHEL result is a lower bound. The roadmap named CSAF VEX as the way to close it and listed three open questions. This ADR measures the options.

## What was measured (2026-11-14)

- CSAF VEX archive: `csaf_vex_2026-11-08.tar.zst` is 412,129,297 bytes. One document, CVE-2024-6387, is 4.7 MB (its product tree names 2,000+ products by NEVRA and container digest). 76,774 documents are listed in `changes.csv`. Reading it means a 400 MB first download and a parser for a very large product tree, to learn a handful of facts per CVE.
- Security Data API, per CVE (`cve/CVE-ID.json`): a few KB, with `package_state` per product and package. The package filter of `cve.json?package=P` returned 175 CVEs for openssl since 2023, and a state check on the first 60 took 25 s (0.4 s each) and found one unfixed CVE for RHEL 9. A host with hundreds of source packages would need tens of thousands of requests. This is option 1 of ADR-0012 and it does not scale.
- OVAL v2 "including unpatched": `rhel-9-including-unpatched.oval.xml.bz2` is 10.8 MB (RHEL 8: 8.2 MB; the plain `rhel-9.oval.xml.bz2` with fixed CVEs only is 1.5 MB). Expanded it is 656 MB of XML with 25,986 vulnerability definitions. Each carries the CVE id, the severity and an `<affected><resolution state="Affected|Will not fix|Fix deferred|Out of support scope"><component>PACKAGE</component>...` block, the same states as `package_state`. There is no `rhel-10-including-unpatched` file (HTTP 404): RHEL 10 would stay a lower bound.

## Options

1. Per-CVE or per-package fan-out through the Security Data API. Rejected: request count.
2. CSAF VEX bulk archive. Rejected: 412 MB for data the OVAL file gives in 11 MB.
3. OVAL "including unpatched", streamed once per run (or per day), reduced to `(CVE, state, component, severity)` and cached. 11 MB to download, 656 MB to stream through, a small index to keep.

## Decision

Accepted: option 3 for RHEL 8 and 9, and keep the lower-bound statement for RHEL 10 until Red Hat publishes the file.

- A package installed on the host is matched by its component name against the `Affected`, `Fix deferred`, `Will not fix` and `Out of support scope` resolutions; each is reported affected with no fixed version, and `Will not fix` and `Out of support scope` carry that reason in the evidence. They are never counted as clean.
- OSV stays the source of fixed versions; this adds only the CVEs OSV cannot show. A CVE present in both keeps the OSV verdict (a fix exists).
- The stream is read through a bounded decompressor and a bounded XML reader, with limits on the compressed size, the expanded size and the element depth.
- The reduced index is stored in the cache under a key of its own and refreshed daily.

## Cost and risk

- A new dependency to read bzip2 (a pure-Rust one is preferred), which must pass `cargo deny` and `cargo vet` and be justified in the PR as CONTRIBUTING requires.
- Streaming 656 MB of XML takes seconds to tens of seconds on a modern machine; it must not run when the cache holds a fresh index.
- The OVAL component names are binary or source package names as Red Hat writes them; the match must try both and is the first thing to verify against a real host.
- Red Hat's terms for the data: it is published openly, but the licence for a derived index kept in this project's offline database is not established and must be checked before it is redistributed.

## Acceptance, 2026-11-17

The maintainer accepted the dependency and the decision. What was settled and measured when it was built:

- **Licence.** Red Hat publishes its security data, OVAL files included, under CC BY 4.0 (access.redhat.com/security/data). A derived index may be redistributed, in the offline database for one, if it credits Red Hat and links the original; the documentation and the source do.
- **Dependency.** `bzip2-rs` 0.1.2, a bzip2 decoder in 100% safe Rust (`forbid(unsafe_code)`), MIT or Apache-2.0, with two small dependencies. `libbz2-rs-sys` is maintained more actively but is a port full of `unsafe` under a different licence; a decoder for a frozen format needs no maintenance, and the input is capped (64 MB compressed, 2 GiB expanded, depth 24).
- **Measured on the real RHEL 9 file.** 10 s in release to stream the 656 MB, 800,000 `(component, CVE)` pairs but about 12,700 distinct rows (the kernel is listed with hundreds of sub-packages), a reduced index of 18 MB read back in 0.14 s. The index is cached with the other sources' lifetime (`cache_ttl`), not daily.
- **Matching.** By binary name, then by source package name. A CVE that OSV answers keeps OSV's answer.
- **Done afterwards.** The Red Hat state is in the output as the additive field `distro_status.vendor_state` of schema version 1, in the text output, and in the analysis of CycloneDX and OpenVEX.
- **Done afterwards.** Rocky Linux and AlmaLinux 8 and 9 rebuild Red Hat's sources, so a CVE Red Hat has not fixed has no fix in them either: they read the file of the same major release. A fix Red Hat shipped that the rebuild has not is in neither source and stays invisible until the rebuild's advisory exists.
- **Not done.** RHEL 10 is not covered, and Red Hat marks the OVAL v2 files as in maintenance mode, to be deprecated: when they go, the source reads CSAF or the new format instead.

## Not decided here

The first open question of ADR-0012 (hundreds of MB acceptable) is answered by option 3: 11 MB. The stream question (EUS, E4S) does not arise for unfixed CVEs, which have no stream. Implementation: see the acceptance above.

## Amendment (2026-11-26)

The file was chosen by the host's distribution. An image scanned from a host
outside the Red Hat family got no unfixed CVE and still read as complete (a UBI
9 image showed none of 476), and on a host, or with `--distro`, of another
release the wrong file was applied. The file is now chosen by the release of
each package: one per release in the run, applied to its packages only. Their
reports are one `redhat-oval` entry, which tells a failure first, then a release
without a file.

## Amendment (2026-11-26, second)

An unfixed CVE was left out when OSV had answered it for any package of the
release in the run, so a fix of one package hid the CVE of another that has
none. A RHEL 9 list with an old `openssl` hid 49 CVEs of `compat-openssl11`, and
the 50 sampled of such pairs are unfixed according to Red Hat's Security Data
API. Only the package's own findings and settled CVEs keep an entry out now, so
what is reported for a package does not depend on the others in the run.

Red Hat's two sources can disagree: for CVE-2026-119374 the OVAL file lists
`sqlite-libs` of RHEL 8 as affected while the API says `sqlite` is not. The file
decides.
