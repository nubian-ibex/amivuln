# Instalação

## A partir de um release

Cada release em
[github.com/nubian-ibex/amivuln/releases](https://github.com/nubian-ibex/amivuln/releases)
contém:

- tarballs `musl` estáticos para `x86_64` e `aarch64`, que rodam em qualquer
  distribuição Linux;
- tarballs `gnu` para `x86_64` e `aarch64`, ligados à glibc 2.34 ou mais nova
  (Debian 12, Ubuntu 22.04, Fedora 35, RHEL 9 e posteriores);
- pacotes `.deb`, `.rpm`, `.apk` e Arch (`.pkg.tar.zst`) que instalam o
  binário, as páginas de manual e os autocompletes do shell;
- um SBOM CycloneDX, o `SHA256SUMS` e sua assinatura cosign.

Os tarballs também trazem `man/` e `completions/`.

## A partir do crates.io

```bash
cargo install amivuln --locked
```

Isso compila a partir do código-fonte e exige um compilador C (o SQLite é
compilado junto). A interface de tela cheia é opcional:
`cargo install amivuln --locked --features tui`.

`cargo binstall amivuln` evita a compilação e baixa o arquivo `musl` estático
do release.

## Verifique o que você baixou

```bash
gh attestation verify amivuln-x86_64-unknown-linux-musl.tar.zst --repo nubian-ibex/amivuln
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp '^https://github.com/nubian-ibex/amivuln/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum -c SHA256SUMS --ignore-missing
```

Os pacotes `.rpm` e `.deb` ainda não são assinados com chave de repositório.
Confira-os com os comandos acima antes de instalar e use
`rpm -i --nosignature` para o `.rpm`.

## Autocompletes e páginas de manual

Os pacotes já os instalam. A partir de um tarball, copie
`completions/amivuln.bash`, `completions/_amivuln` ou
`completions/amivuln.fish` para o diretório de autocomplete do seu shell e
`man/*.1` para um diretório do `MANPATH`. `amivuln completions bash|zsh|fish`
também os imprime.
