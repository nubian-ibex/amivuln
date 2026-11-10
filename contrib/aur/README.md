# AUR packages

`amivuln/PKGBUILD` builds the release source tarball; `amivuln-bin/PKGBUILD`
installs the static release binary. Both pin the checksums of the release they
name. Publishing to the AUR needs the maintainer's AUR account:

```bash
# per release: bump pkgver, update sha256sums from the release's .sha256 files
cd amivuln-bin && makepkg --printsrcinfo > .SRCINFO
git add PKGBUILD .SRCINFO && git commit -m "upgpkg: amivuln-bin 0.0.9-1"
```

`makepkg --verifysource` checks the checksums; `gh attestation verify` checks
build provenance of the downloaded archive.
