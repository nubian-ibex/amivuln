#!/bin/sh
# SPDX-FileCopyrightText: 2026 amivuln contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Spike S1 (ADR-0007): compare amivuln with dnf on a real Fedora system.
# Run inside a fedora:latest container with the amivuln binary mounted at
# /usr/local/bin/amivuln and this script at /s1.sh, with network access:
#   podman run --rm -v ./amivuln:/usr/local/bin/amivuln:ro -v ./tests/integration/fedora-vs-dnf.sh:/s1.sh:ro \
#     registry.fedoraproject.org/fedora:latest sh -c "dnf -q -y install python3; sh /s1.sh"
# 50 packages are installed from the release repo only, so many have pending
# security updates. dnf (updates enabled) is the oracle; the packages and fixed
# versions it lists must match the ones amivuln reports.
dnf -q -y install --disablerepo=updates --setopt=install_weak_deps=False \
  nginx curl openssl sqlite python3-requests python3-urllib3 libxml2 libpng freetype expat zlib-ng-compat \
  bind-utils git vim-enhanced tar gzip bzip2 xz glibc-langpack-en httpd openssh-server pcre2 libcurl \
  gnutls libtiff libjpeg-turbo krb5-libs cups-libs ImageMagick-libs libwebp unzip zip rsync wget2 \
  python3-jinja2 python3-cryptography postgresql sudo less file-libs bash systemd-libs dbus-libs \
  nss libgcrypt libssh2 > /tmp/install.log 2>&1
echo "installed: $(rpm -qa | wc -l) packages"
# Oracle: dnf's own view of security advisories applicable to installed packages, updates repo enabled.
dnf -q updateinfo list --security --installed-versions 2>/dev/null > /tmp/oracle.txt || dnf -q updateinfo list --security > /tmp/oracle.txt 2>/dev/null
echo "oracle lines: $(wc -l < /tmp/oracle.txt)"
head -3 /tmp/oracle.txt
amivuln --all -f json > /tmp/amivuln.json; echo "amivuln exit=$?"
python3 - <<'PY'
import json,re,subprocess
d=json.load(open('/tmp/amivuln.json'))
ours={t['package']['name'] for t in d['targets'] if t['findings']}
print("amivuln: packages with affected findings:",len(ours),"of",len(d['targets']),"complete",d['complete'])
# parse oracle: last column is NEVRA; derive package name by stripping version-release.arch
names=set()
for line in open('/tmp/oracle.txt'):
    parts=line.split()
    if len(parts)<5 or not parts[0].startswith("FEDORA-"): continue
    nevra=parts[-3]
    m=re.match(r'^(.*)-[^-]+-[^-]+\.[^.]+$',nevra)
    if m: names.add(m.group(1))
print("dnf oracle: packages with security advisories:",len(names))
print("only in amivuln (possible false positives):",sorted(ours-names))
print("only in dnf (possible false negatives):",sorted(names-ours))
print("agree:",len(ours&names))
PY
