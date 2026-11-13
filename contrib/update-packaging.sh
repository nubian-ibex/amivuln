#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 amivuln contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Points the AUR, Nix and RPM recipes at a published release.
# Usage: contrib/update-packaging.sh 0.1.0
set -euo pipefail

ver=${1:?usage: update-packaging.sh VERSION}
repo=nubian-ibex/amivuln
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fetch() { gh release download "v$ver" --repo "$repo" --pattern "$1" --output "$work/$1"; }
sum() { cut -d' ' -f1 "$work/$1"; }

fetch source.tar.gz.sha256
fetch amivuln-x86_64-unknown-linux-musl.tar.zst.sha256
fetch amivuln-aarch64-unknown-linux-musl.tar.zst.sha256

src=$(sum source.tar.gz.sha256)
x86=$(sum amivuln-x86_64-unknown-linux-musl.tar.zst.sha256)
arm=$(sum amivuln-aarch64-unknown-linux-musl.tar.zst.sha256)
sri=sha256-$(printf '%s' "$src" | xxd -r -p | base64)

sed -i "s/^pkgver=.*/pkgver=$ver/; s/^pkgrel=.*/pkgrel=1/; s/^sha256sums=.*/sha256sums=('$src')/" "$root/contrib/aur/amivuln/PKGBUILD"
sed -i "s/^pkgver=.*/pkgver=$ver/; s/^pkgrel=.*/pkgrel=1/; s/^sha256sums_x86_64=.*/sha256sums_x86_64=('$x86')/; s/^sha256sums_aarch64=.*/sha256sums_aarch64=('$arm')/" "$root/contrib/aur/amivuln-bin/PKGBUILD"
sed -i "s/^  version = \".*\";/  version = \"$ver\";/; s#hash = \"sha256-.*\";#hash = \"$sri\";#" "$root/contrib/nix/amivuln.nix"

spec=$root/contrib/rpm/amivuln.spec
sed -i "s/^Version:.*/Version:        $ver/" "$spec"
if ! grep -q -- "- $ver-1\$" "$spec"; then
    sed -i "/^%changelog/a * $(LC_ALL=C date -u '+%a %b %d %Y') amivuln contributors <noreply@github.com> - $ver-1\n- Update to $ver\n" "$spec"
fi
echo "updated to $ver"
