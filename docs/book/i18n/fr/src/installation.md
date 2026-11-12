# Installation

## Depuis une version publiée

Chaque version sur
[github.com/nubian-ibex/amivuln/releases](https://github.com/nubian-ibex/amivuln/releases)
contient :

- des tarballs `musl` statiques pour `x86_64` et `aarch64`, qui fonctionnent sur
  toute distribution Linux ;
- des tarballs `gnu` pour `x86_64` et `aarch64`, liés à la glibc 2.34 ou plus
  récente (Debian 12, Ubuntu 22.04, Fedora 35, RHEL 9 et suivantes) ;
- des paquets `.deb`, `.rpm`, `.apk` et Arch (`.pkg.tar.zst`) qui installent le
  binaire, les pages de manuel et les complétions du shell ;
- un SBOM CycloneDX, `SHA256SUMS` et sa signature cosign.

Les tarballs contiennent aussi `man/` et `completions/`.

## Depuis crates.io

```bash
cargo install amivuln --locked
```

Cela compile depuis les sources et demande un compilateur C (SQLite est compilé
avec). L'interface plein écran est facultative :
`cargo install amivuln --locked --features tui`.

`cargo binstall amivuln` évite la compilation et télécharge l'archive `musl`
statique de la version.

## Vérifier ce que vous avez téléchargé

```bash
gh attestation verify amivuln-x86_64-unknown-linux-musl.tar.zst --repo nubian-ibex/amivuln
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp '^https://github.com/nubian-ibex/amivuln/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum -c SHA256SUMS --ignore-missing
```

Les paquets `.rpm` et `.deb` ne sont pas encore signés par une clé de dépôt.
Vérifiez-les avec les commandes ci-dessus avant de les installer et utilisez
`rpm -i --nosignature` pour le `.rpm`.

## Complétions du shell et pages de manuel

Les paquets les installent. Depuis un tarball, copiez
`completions/amivuln.bash`, `completions/_amivuln` ou
`completions/amivuln.fish` dans le répertoire de complétion de votre shell et
`man/*.1` dans un répertoire du `MANPATH`. `amivuln completions bash|zsh|fish`
les affiche aussi.
