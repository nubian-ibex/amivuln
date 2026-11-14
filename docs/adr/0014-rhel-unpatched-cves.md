# ADR-0014: Red Hat CVEs that have no fix yet

- Status: Proposed
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

Proposed: option 3 for RHEL 8 and 9, and keep the lower-bound statement for RHEL 10 until Red Hat publishes the file.

- A package installed on the host is matched by its component name against the `Affected`, `Fix deferred`, `Will not fix` and `Out of support scope` resolutions; each is reported affected with no fixed version, and `Will not fix` and `Out of support scope` carry that reason in the evidence. They are never counted as clean.
- OSV stays the source of fixed versions; this adds only the CVEs OSV cannot show. A CVE present in both keeps the OSV verdict (a fix exists).
- The stream is read through a bounded decompressor and a bounded XML reader, with limits on the compressed size, the expanded size and the element depth.
- The reduced index is stored in the cache under a key of its own and refreshed daily.

## Cost and risk

- A new dependency to read bzip2 (a pure-Rust one is preferred), which must pass `cargo deny` and `cargo vet` and be justified in the PR as CONTRIBUTING requires.
- Streaming 656 MB of XML takes seconds to tens of seconds on a modern machine; it must not run when the cache holds a fresh index.
- The OVAL component names are binary or source package names as Red Hat writes them; the match must try both and is the first thing to verify against a real host.
- Red Hat's terms for the data: it is published openly, but the licence for a derived index kept in this project's offline database is not established and must be checked before it is redistributed.

## Not decided here

The first open question of ADR-0012 (hundreds of MB acceptable) is answered by option 3: 11 MB. The stream question (EUS, E4S) does not arise for unfixed CVEs, which have no stream. Implementation waits for the maintainer to accept the new dependency.
