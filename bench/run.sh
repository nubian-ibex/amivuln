#!/bin/sh
# SPDX-FileCopyrightText: 2026 amivuln contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# One-target benchmark: scans one container image with amivuln, Grype, Trivy
# and (when it can get its data) cve-bin-tool, keeps the CVE ids reported for
# the packages of one source package, times each tool and counts true
# positives, false positives and false negatives against a ground-truth file.
#
# usage: bench/run.sh IMAGE TRUTH_FILE OUT_DIR [PKGS]
#   IMAGE       a container image, for example docker.io/library/debian:12.0
#   TRUTH_FILE  TSV: CVE, class, fixed, urgency; classes starting with
#               "affected" are the truth (see bench/truth)
#   PKGS        comma-separated binary packages of the target source package
#               (default: libc6,libc-bin)
# Needs podman, jq, GNU date and whichever tools are installed. A tool that is
# missing or cannot run is reported, never scored as zero. Set RUNS to change
# the number of timed runs (default 5, after one warm-up run).
set -eu

if [ "$#" -lt 3 ]; then
    echo "usage: $0 IMAGE TRUTH_FILE OUT_DIR [PKGS]" >&2
    exit 64
fi
image=$1
truth=$2
out=$3
pkgs=${4:-libc6,libc-bin}
runs=${RUNS:-5}
mkdir -p "$out"
pkgs_json=$(printf '%s' "$pkgs" | jq -R 'split(",")')

# The truth: CVE ids whose class starts with "affected".
grep -v '^#' "$truth" | awk -F'\t' '$2 ~ /^affected/ {print $1}' | sort -u >"$out/truth.ids"

cid=$(podman create -q "$image" true)
trap 'podman rm -f "$cid" >/dev/null 2>&1 || true' EXIT
rm -rf "${out:?}/rootfs" && mkdir -p "$out/rootfs"
podman export "$cid" | tar -x -C "$out/rootfs" --exclude=dev 2>/dev/null || true

now_ms() { echo $(($(date +%s%N) / 1000000)); }

# timed NAME CMD...: one warm-up run, then $runs timed runs; the last run's
# stdout is kept in OUT/NAME.json and the median is written to times.txt.
timed() {
    name=$1
    shift
    if ! "$@" >"$out/$name.json" 2>"$out/$name.err"; then
        echo "$name could not run (see $out/$name.err)" >>"$out/times.txt"
        return 1
    fi
    : >"$out/$name.ms"
    i=0
    while [ "$i" -lt "$runs" ]; do
        start=$(now_ms)
        "$@" >"$out/$name.json" 2>>"$out/$name.err" || true
        echo $(($(now_ms) - start)) >>"$out/$name.ms"
        i=$((i + 1))
    done
    echo "$name median_ms=$(sort -n "$out/$name.ms" | awk '{a[NR]=$1} END {print a[int((NR+1)/2)]}')" >>"$out/times.txt"
}

: >"$out/times.txt"

if command -v amivuln >/dev/null 2>&1; then
    if timed amivuln amivuln --container "$cid" --format json; then
        jq -r --argjson pkgs "$pkgs_json" \
            '.targets[] | select(.package.name as $n | $pkgs | index($n)) | .findings[].id' \
            "$out/amivuln.json" | sort -u >"$out/amivuln.ids"
    fi
else
    echo "amivuln skipped: not installed" >>"$out/times.txt"
fi
if command -v grype >/dev/null 2>&1; then
    if timed grype grype "dir:$out/rootfs" -o json; then
        jq -r --argjson pkgs "$pkgs_json" \
            '.matches[] | select(.artifact.name as $n | $pkgs | index($n)) | .vulnerability.id, (.relatedVulnerabilities[]?.id)' \
            "$out/grype.json" | grep -E '^CVE-' | sort -u >"$out/grype.ids"
    fi
else
    echo "grype skipped: not installed" >>"$out/times.txt"
fi
if command -v trivy >/dev/null 2>&1; then
    if timed trivy trivy rootfs --scanners vuln --format json --quiet "$out/rootfs"; then
        jq -r --argjson pkgs "$pkgs_json" \
            '.Results[]?.Vulnerabilities[]? | select(.PkgName as $n | $pkgs | index($n)) | .VulnerabilityID' \
            "$out/trivy.json" | grep -E '^CVE-' | sort -u >"$out/trivy.ids"
    fi
else
    echo "trivy skipped: not installed" >>"$out/times.txt"
fi
if command -v cve-bin-tool >/dev/null 2>&1; then
    # cve-bin-tool matches the upstream version of a binary against NVD, so it
    # is pointed at the library file, not the image.
    lib=$(find "$out/rootfs" -name 'libc.so.6' | head -n 1)
    if [ -n "$lib" ] && cve-bin-tool -f json -o "$out/cve-bin-tool.json" "$lib" >"$out/cve-bin-tool.err" 2>&1; then
        jq -r '.[].cve_number' "$out/cve-bin-tool.json" | sort -u >"$out/cve-bin-tool.ids"
    else
        echo "cve-bin-tool could not run (see $out/cve-bin-tool.err)" >>"$out/times.txt"
    fi
else
    echo "cve-bin-tool skipped: not installed" >>"$out/times.txt"
fi

# TP: reported and in the truth. FP: reported, not in the truth. FN: in the
# truth, not reported.
for ids in "$out"/*.ids; do
    tool=$(basename "$ids" .ids)
    [ "$tool" = truth ] && continue
    tp=$(comm -12 "$ids" "$out/truth.ids" | wc -l)
    fp=$(comm -23 "$ids" "$out/truth.ids" | wc -l)
    fn=$(comm -13 "$ids" "$out/truth.ids" | wc -l)
    echo "$tool reported=$(wc -l <"$ids") tp=$tp fp=$fp fn=$fn"
done >"$out/summary.txt"

cat "$out/times.txt" "$out/summary.txt"
