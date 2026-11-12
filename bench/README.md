# Benchmark: one target

Compares amivuln with Grype, Trivy and cve-bin-tool on a single target:
wall-clock time, false positives (CVEs reported that do not affect the build)
and false negatives (affecting CVEs not reported).

## Method

1. Pick an image and one source package in it. The target here is the
   `libc6` and `libc-bin` binaries of `docker.io/library/debian:12.0`, source
   package `glibc`, installed version `2.36-9`. Backported fixes are common in
   glibc, so a matcher that ignores them reports many false positives.
2. Build the ground truth by hand in `truth/`: for each CVE the distribution
   tracker lists for that source package and release, whether the installed
   build is affected. The file records the source, the date and the rule.
3. Run `bench/run.sh IMAGE TRUTH OUT [PKGS]`. It exports the image to a root
   file system, runs each tool that is installed, keeps the CVE ids reported
   for the packages of the target, and counts true positives, false positives
   and false negatives against the truth. It also times each tool: one warm-up
   run, then the median of `RUNS` runs (default 5).
4. Publish the tool versions, the distribution release and the date next to
   every number.

A tool that is missing or cannot run is reported as such, never as zero.

## Result (2026-11-12)

Target: glibc 2.36-9 on Debian 12.0. Truth: 46 CVEs from the Debian security
tracker (`bench/truth/glibc-bookworm-2.36-9.tsv`): 20 fixed in a later
bookworm update and 26 still open.

- amivuln 0.0.14 plus the open-issue fix in this commit: reported 46, true
  positives 46, false positives 0, false negatives 0. Median 0.6 to 0.8 s,
  including `podman export` of the container and the OSV queries.
- Grype 0.121.3 (database schema v6.1.10, built 2026-11-11): reported 44, true
  positives 44, false positives 0, false negatives 2. Median 2.35 s.
- Trivy 0.76.2: reported 44, true positives 44, false positives 0, false
  negatives 2. Median 0.21 s.
- cve-bin-tool 3.4: **not measured.** It needs the NVD data and none of the
  three ways to get it worked here: `json-mirror` and `json-nvd` ended with
  "No data in CVE Database", `api2` without a key was refused, and the default
  run needs `gsutil`. The backport false-positive behaviour this benchmark
  was designed to expose belongs to tools that match upstream versions, so the
  missing row is the one that would have told the most.

Grype and Trivy both miss `CVE-2026-100290` and `CVE-2026-115819`, which the
tracker lists as open with no assigned fix.

Machine: Fedora 44, 24 cores, warm databases and caches, network available.

## What this does and does not show

- **The truth and the tools share a source.** The truth is the Debian tracker.
  Grype, Trivy and amivuln (through OSV's Debian records, which are generated
  from it) all read it. The result measures how well each tool turns that
  data into a verdict for an installed version, not how complete the data is.
  An independent truth (for example a manually audited list) would be needed
  for that.
- **One target, one release.** Nothing here generalises to other packages,
  ecosystems or to the language-package scanners of these tools.
- **The tools do different work.** amivuln was given the container (it reads
  the dpkg database), Grype and Trivy catalogued the exported file system. The
  timings include those differences and are not a pure matching benchmark.
- **A first run of this benchmark found a real amivuln bug.** amivuln first
  scored 20 true positives and 26 false negatives: OSV returned the 26 open
  CVEs (records with an `introduced` event and no `fixed` event), and amivuln
  discarded every record that offered no fix. They are now reported as
  affected with no fix version.

## Fairness rules

- Run every tool with its defaults on the same input, with a warm database,
  and say so.
- Do not tune one tool's flags without giving the others the same attention.
- Keep the raw output of a run (`OUT/*.json`) with the published numbers so
  anyone can recount.
