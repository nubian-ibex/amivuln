#!/usr/bin/env bash
# Benchmarks amivuln and appends one row per case to $OUT.
# Rows: host runtime case seconds targets findings cache_rows rss_kb
#
# Env:
#   BIN      the amivuln binary (the published static one on remote hosts)
#   HOST     a label for the machine
#   MODE     host    : machine cases only (VMs, this host)
#              containers: machine cases plus the images of IMAGES
#   DOCKER_NESTED  1: --container cases also run through a Debian runner with
#              the host's docker CLI and socket mounted (rows marked -nested)
#
# SPDX-FileCopyrightText: 2026 amivuln contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
set -u
BIN=${BIN:?}
HOSTL=${HOST:?}
MODE=${MODE:?}
IMAGES=${IMAGES:-}
OUT=${OUT:?}
W=$(mktemp -d /var/tmp/amivuln-bench.XXXXXX 2>/dev/null || mktemp -d /tmp/amivuln-bench.XXXXXX)
mkdir -p "$W"
touch "$OUT"
TIME=/usr/bin/time
HAS_TIME=0
[ -x "$TIME" ] && HAS_TIME=1

now() { date +%s%N; }

counts() { # json cache_dir
    python3 - "$1" "$2" <<'E'
import json, sqlite3, sys
d = json.load(open(sys.argv[1]))
t = len(d.get("targets", [])); f = sum(len(x.get("findings", [])) for x in d.get("targets", []))
rows = "-"
try:
    c = sqlite3.connect(f"file:{sys.argv[2]}/amivuln/cache.sqlite?mode=ro", uri=True)
    rows = c.execute("select count(*) from http_cache").fetchone()[0]
except Exception:
    pass
print(f"{t}\t{f}\t{rows}")
E
}

# amivuln HOST-RUN args...: on this machine, timed, json to $W/run.json.
amivuln() {
    if [ "$HAS_TIME" = 1 ]; then
        "$TIME" -f '%M' -o "$W/rss" "$BIN" "$@" >"$W/run.json" 2>"$W/err"
    else
        "$BIN" "$@" >"$W/run.json" 2>"$W/err"
        echo - >"$W/rss"
    fi
}

# bench CASE LABEL args...: one cold run (empty cache) and one warm.
bench() {
    c=$1; label=$2; shift 2
    rm -rf "$W/cache-$c"; mkdir -p "$W/cache-$c"
    export XDG_CACHE_HOME="$W/cache-$c"
    start=$(now); amivuln "$@"; code=$?
    ms=$((($(now) - start) / 1000000))
    read -r t f r <<EOF
$(counts "$W/run.json" "$W/cache-$c")
EOF
    echo -e "$HOSTL\t$label\t$c\t$ms\t$t\t$f\t$r\t$(cat "$W/rss")" >>"$OUT"
    [ "$code" = 0 ] || echo "  $c exit=$code: $(head -c 140 "$W/err")" >&2
    start=$(now); amivuln "$@"
    ms=$((($(now) - start) / 1000000))
    read -r t f r <<EOF
$(counts "$W/run.json" "$W/cache-$c")
EOF
    echo -e "$HOSTL\t$label\t$c-warm\t$ms\t$t\t$f\t$r\t$(cat "$W/rss")" >>"$OUT"
}

# The machine cases: skipped on the Flatcar (its host scan is refused).
if [ "$MODE" != containers ]; then
    bench all-cold host --all -f json
    bench kernel host --kernel -f json
    bench pkg host openssl -f json
    bench path host /usr/bin/bash -f json
    bench pending host pending -f json
    bench services host services -f json
    for fmt in sarif cyclonedx openvex prometheus csv markdown; do
        bench "fmt-$fmt" host --all -f "$fmt"
    done
    bench offline host --all -f json --offline
fi

# The container cases, per runtime.
ctr() { # label image nested create_bin
    label=$1; img=$2; nested=${3:-}; create_bin=${4:-docker}
    n=${img##*/}
    n=${n%:*}; n=${n//\//-}
    id=$("$create_bin" create "$img" sh)
    rm -rf "$W/cache-c$n"; mkdir -p "$W/cache-c$n"
    export XDG_CACHE_HOME="$W/cache-c$n"
    start=$(now)
    if [ -n "$nested" ]; then
        docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
            -v "$W/cache-c$n:/cache" -e XDG_CACHE_HOME=/cache \
            amivuln-runner amivuln --container "$id" -f json >"$W/run.json" 2>"$W/err"
    else
        "$BIN" --container "$id" -f json >"$W/run.json" 2>"$W/err"
    fi
    code=$?
    ms=$((($(now) - start) / 1000000))
    read -r t f r <<EOF
$(counts "$W/run.json" "$W/cache-c$n")
EOF
    echo -e "$HOSTL\t$label\tctr-$n\t$ms\t$t\t$f\t$r\t-" >>"$OUT"
    [ "$code" = 0 ] || echo "  ctr-$n exit=$code: $(head -c 140 "$W/err")" >&2
    "$create_bin" rm -f "$id" >/dev/null
}

RUNTIME_BIN=podman
command -v docker >/dev/null && RUNTIME_BIN=docker
cp -L /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem "$W/ca.pem" 2>/dev/null ||
    cp -L /etc/ssl/certs/ca-certificates.crt "$W/ca.pem" 2>/dev/null

if [ "${NESTED_ONLY:-0}" != 1 ] && [ "$MODE" != host ]; then
    # amivuln picks podman when it exists; the direct pass follows that.
    DIRECT_BIN=$RUNTIME_BIN
    command -v podman >/dev/null && DIRECT_BIN=podman
    for img in $IMAGES; do
        ctr "$DIRECT_BIN-direct" "$img" "" "$DIRECT_BIN"
    done
fi

if [ "${DOCKER_NESTED:-0}" = 1 ] && [ -n "$IMAGES" ]; then
    for img in $IMAGES; do
        ctr docker-nested "$img" nested docker
    done
fi
rm -rf "$W"
