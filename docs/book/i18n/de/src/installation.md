# Installation

## Aus einem Release

Jedes Release unter
[github.com/nubian-ibex/amivuln/releases](https://github.com/nubian-ibex/amivuln/releases)
enthält:

- statische `musl`-Tarballs für `x86_64` und `aarch64`, die auf jeder
  Linux-Distribution laufen;
- `gnu`-Tarballs für `x86_64` und `aarch64`, gelinkt gegen glibc 2.34 oder neuer
  (Debian 12, Ubuntu 22.04, Fedora 35, RHEL 9 und neuer);
- Pakete in den Formaten `.deb`, `.rpm`, `.apk` und Arch (`.pkg.tar.zst`), die
  das Binary, die Man-Pages und die Shell-Vervollständigungen installieren;
- ein CycloneDX-SBOM, `SHA256SUMS` und dessen cosign-Signatur.

Die Tarballs enthalten außerdem `man/` und `completions/`.

## Von crates.io

```bash
cargo install amivuln --locked
```

Dies kompiliert aus dem Quellcode und benötigt einen C-Compiler (SQLite wird
mitkompiliert). Die Vollbild-Oberfläche ist optional:
`cargo install amivuln --locked --features tui`.

`cargo binstall amivuln` überspringt die Kompilierung und lädt stattdessen das
statische `musl`-Archiv des Releases herunter.

## Heruntergeladenes prüfen

```bash
gh attestation verify amivuln-x86_64-unknown-linux-musl.tar.zst --repo nubian-ibex/amivuln
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp '^https://github.com/nubian-ibex/amivuln/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum -c SHA256SUMS --ignore-missing
```

Die Pakete `.rpm` und `.deb` sind noch nicht mit einem Repository-Schlüssel
signiert. Prüfen Sie sie vor der Installation mit den obigen Befehlen und
verwenden Sie für die `.rpm` `rpm -i --nosignature`.

## Shell-Vervollständigungen und Man-Pages

Die Pakete installieren sie. Kopieren Sie aus einem Tarball
`completions/amivuln.bash`, `completions/_amivuln` oder
`completions/amivuln.fish` in das Vervollständigungsverzeichnis Ihrer Shell und
`man/*.1` in ein Verzeichnis im `MANPATH`. `amivuln completions bash|zsh|fish`
gibt sie ebenfalls aus.
