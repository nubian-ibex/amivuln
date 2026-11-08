#!/bin/sh
# SPDX-FileCopyrightText: 2026 amivuln contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# `amivuln restart` against a real replaced file. Run as root in a throwaway
# container with the binary mounted at /usr/local/bin/amivuln:
#   podman run --rm -v ./amivuln:/usr/local/bin/amivuln:ro -v ./tests/integration/restart-in-container.sh:/t.sh:ro \
#     registry.fedoraproject.org/fedora:latest sh /t.sh
# A running `sleep` has its executable replaced (as an update would do); amivuln
# must report the process, the replaced path and the package that owns it, and
# exit 1. Without the replacement it must exit 0.
set -eu
amivuln restart >/dev/null && echo "clean before replacement: ok"
cp /usr/bin/sleep /tmp/sleep.new
sleep 600 &
sleep 0.3
mv /tmp/sleep.new /usr/bin/sleep
set +e
out=$(amivuln restart --color never)
code=$?
set -e
echo "$out"
[ "$code" -eq 1 ] || { echo "expected exit 1, got $code" >&2; exit 1; }
echo "$out" | grep -q "executable replaced: /usr/bin/sleep" || { echo "replaced executable not reported" >&2; exit 1; }
echo "ok"
