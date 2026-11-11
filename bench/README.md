# Benchmark: one target

Compares amivuln with cve-bin-tool, Grype and Trivy on a single installed
binary: wall-clock time, false positives caused by distribution backports and
false negatives.

## Method

1. Pick a binary owned by a distribution package, for example `/usr/bin/curl`.
2. Build the ground truth by hand in `truth/NAME.txt`, one CVE id per line:
   the CVEs that really affect the installed build. Start from the
   distribution's own security tracker for that exact package version, and
   record the source and date in a comment. Lines without a CVE id are
   ignored.
3. Run `bench/run.sh /usr/bin/curl bench/truth/curl.txt out/curl`.
4. Report the tool versions, the distribution release, the date and the
   vulnerability database age next to every number.

A false positive is a CVE a tool reports that the truth does not list (the
usual cause is a fix the distribution backported without changing the
version). A false negative is a CVE in the truth the tool did not report.

## Fairness rules

- Run every tool with its defaults on the same file, with a warm database and
  no network where the tool allows it, and say so.
- Do not tune one tool's flags without giving the others the same attention.
- Publish the raw JSON from `out/` with the results so anyone can recount.
- Time is one run after a warm-up run; repeat at least five times and report
  the median.

## Status

`run.sh` has not yet been run against Grype, Trivy or cve-bin-tool: their
command lines follow each tool's documentation and need a first real run
before any number is published. No results are published yet.
