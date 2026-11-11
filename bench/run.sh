#!/bin/sh
# SPDX-FileCopyrightText: 2026 amivuln contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# One-target benchmark: runs amivuln, Grype, Trivy and cve-bin-tool on the
# same file, times each run and compares the CVE ids with a hand-labelled
# ground truth. Needs GNU date, jq and whichever tools are installed; a
# missing tool is reported and skipped, never silently scored as zero.
#
# usage: bench/run.sh TARGET_FILE TRUTH_FILE OUT_DIR
set -eu

if [ "$#" -ne 3 ]; then
    echo "usage: $0 TARGET_FILE TRUTH_FILE OUT_DIR" >&2
    exit 64
fi
target=$1
truth=$2
out=$3
mkdir -p "$out"

# Ids must be bare CVE ids, sorted, one per line.
norm() { grep -Eo 'CVE-[0-9]{4}-[0-9]{4,}' | sort -u; }
norm <"$truth" >"$out/truth.ids"

now_ms() { echo $(($(date +%s%N) / 1000000)); }

# run NAME CMD... : runs CMD with stdout in OUT/NAME.json, records the time.
run() {
    name=$1
    shift
    start=$(now_ms)
    if "$@" >"$out/$name.json" 2>"$out/$name.err"; then status=ok; else status="exit-$?"; fi
    end=$(now_ms)
    echo "$name $((end - start)) $status" >>"$out/times.txt"
}

: >"$out/times.txt"

if command -v amivuln >/dev/null 2>&1; then
    run amivuln amivuln --format json --offline "$target"
    jq -r '.targets[].findings[].id' "$out/amivuln.json" | norm >"$out/amivuln.ids"
else
    echo "amivuln skipped: not installed" >>"$out/times.txt"
fi
if command -v grype >/dev/null 2>&1; then
    run grype grype "file:$target" -o json
    jq -r '.matches[].vulnerability.id' "$out/grype.json" | norm >"$out/grype.ids"
else
    echo "grype skipped: not installed" >>"$out/times.txt"
fi
if command -v trivy >/dev/null 2>&1; then
    run trivy trivy fs --scanners vuln --format json --quiet "$target"
    jq -r '.Results[]?.Vulnerabilities[]?.VulnerabilityID' "$out/trivy.json" | norm >"$out/trivy.ids"
else
    echo "trivy skipped: not installed" >>"$out/times.txt"
fi
if command -v cve-bin-tool >/dev/null 2>&1; then
    run cve-bin-tool cve-bin-tool --format json --output-file "$out/cve-bin-tool.json" --quiet "$target"
    jq -r '.[].cve_number' "$out/cve-bin-tool.json" | norm >"$out/cve-bin-tool.ids"
else
    echo "cve-bin-tool skipped: not installed" >>"$out/times.txt"
fi

# false positives: reported but not in the truth; false negatives: in the
# truth but not reported.
for ids in "$out"/*.ids; do
    tool=$(basename "$ids" .ids)
    [ "$tool" = truth ] && continue
    fp=$(comm -23 "$ids" "$out/truth.ids" | wc -l)
    fn=$(comm -13 "$ids" "$out/truth.ids" | wc -l)
    echo "$tool false_positives=$fp false_negatives=$fn"
done >"$out/summary.txt"

cat "$out/times.txt" "$out/summary.txt"
