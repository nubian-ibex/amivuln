#!/bin/sh
# SPDX-FileCopyrightText: 2026 amivuln contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# ADR-0008: compare amivuln with arch-audit in an archlinux container (same
# mounting scheme as fedora-vs-dnf.sh). They are expected to differ on stale
# "Vulnerable" tracker entries: amivuln reports those as unverified.
set -u
pacman -Sy --noconfirm >/dev/null 2>&1
pacman -S --noconfirm --needed arch-audit python >/dev/null 2>&1
# Add more packages so the comparison is not trivially empty.
pacman -S --noconfirm --needed openssl curl sqlite zlib libxml2 libpng freetype2 expat git vim nginx apache postgresql-libs gnutls krb5 openssh python-pip imagemagick ffmpeg >/dev/null 2>&1
echo "installed: $(pacman -Q | wc -l) packages"
arch-audit -u 2>/dev/null > /tmp/oracle_all.txt || true
arch-audit 2>/dev/null > /tmp/oracle.txt || true
echo "arch-audit lines: $(wc -l < /tmp/oracle.txt)"; head -3 /tmp/oracle.txt
amivuln --all -f json > /tmp/amivuln.json; echo "amivuln exit=$?"
python3 - <<'PY'
import json,re
d=json.load(open('/tmp/amivuln.json'))
aff={t['package']['name'] for t in d['targets'] if t['findings']}
unv={t['package']['name'] for t in d['targets'] if t['unverified']}
print("amivuln affected packages:",len(aff),"unverified-only:",len(unv-aff),"of",len(d['targets']),"complete",d['complete'])
names=set()
for line in open('/tmp/oracle.txt'):
    m=re.match(r'^(?:Package\s+)?(\S+)\s+is affected',line)
    if m: names.add(m.group(1))
print("arch-audit packages:",len(names), sorted(names)[:12])
print("only in amivuln:",sorted(aff-names))
print("only in arch-audit:",sorted(names-aff))
PY
