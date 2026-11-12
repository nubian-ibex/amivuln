# Instalación

## Desde una versión publicada

Cada versión en
[github.com/nubian-ibex/amivuln/releases](https://github.com/nubian-ibex/amivuln/releases)
contiene:

- tarballs `musl` estáticos para `x86_64` y `aarch64`, que funcionan en
  cualquier distribución Linux;
- tarballs `gnu` para `x86_64` y `aarch64`, enlazados con glibc 2.34 o
  posterior (Debian 12, Ubuntu 22.04, Fedora 35, RHEL 9 y posteriores);
- paquetes `.deb`, `.rpm`, `.apk` y de Arch (`.pkg.tar.zst`) que instalan el
  binario, las páginas de manual y los autocompletados del shell;
- un SBOM CycloneDX, `SHA256SUMS` y su firma cosign.

Los tarballs también incluyen `man/` y `completions/`.

## Desde crates.io

```bash
cargo install amivuln --locked
```

Compila desde el código fuente y necesita un compilador de C (SQLite se compila
dentro). La interfaz de pantalla completa es opcional:
`cargo install amivuln --locked --features tui`.

`cargo binstall amivuln` evita la compilación y descarga el archivo `musl`
estático de la versión.

## Verifique lo que descargó

```bash
gh attestation verify amivuln-x86_64-unknown-linux-musl.tar.zst --repo nubian-ibex/amivuln
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp '^https://github.com/nubian-ibex/amivuln/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum -c SHA256SUMS --ignore-missing
```

Los paquetes `.rpm` y `.deb` todavía no están firmados con una clave de
repositorio. Compruébelos con los comandos anteriores antes de instalarlos y
use `rpm -i --nosignature` para el `.rpm`.

## Autocompletados y páginas de manual

Los paquetes los instalan. Desde un tarball, copie `completions/amivuln.bash`,
`completions/_amivuln` o `completions/amivuln.fish` al directorio de
autocompletado de su shell y `man/*.1` a un directorio del `MANPATH`.
`amivuln completions bash|zsh|fish` también los imprime.
