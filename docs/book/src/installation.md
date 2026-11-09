# Installation

## From a release

Every release at
[github.com/nubian-ibex/amivuln/releases](https://github.com/nubian-ibex/amivuln/releases)
contains:

- static `musl` tarballs for `x86_64` and `aarch64`, which run on any Linux
  distribution;
- `gnu` tarballs for `x86_64` and `aarch64`, linked against glibc 2.34 or newer
  (Debian 12, Ubuntu 22.04, Fedora 35, RHEL 9 and later);
- `.deb`, `.rpm`, `.apk` and Arch (`.pkg.tar.zst`) packages that install the
  binary, the man pages and the shell completions;
- a CycloneDX SBOM, `SHA256SUMS` and its cosign signature.

The tarballs also contain `man/` and `completions/`.

## From crates.io

```bash
cargo install amivuln --locked
```

This builds from source and needs a C compiler (SQLite is compiled in).

`cargo binstall amivuln` skips the build and downloads the static `musl`
release archive instead.

## Verify what you downloaded

```bash
gh attestation verify amivuln-x86_64-unknown-linux-musl.tar.zst --repo nubian-ibex/amivuln
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp '^https://github.com/nubian-ibex/amivuln/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum -c SHA256SUMS --ignore-missing
```

The `.rpm` and `.deb` packages are not signed with a repository key yet. Check
them with the commands above before installing, and use
`rpm -i --nosignature` for the `.rpm`.

## Shell completions and man pages

The packages install them. From a tarball, copy `completions/amivuln.bash`,
`completions/_amivuln` or `completions/amivuln.fish` to your shell's completion
directory and `man/*.1` to a directory on `MANPATH`. `amivuln completions
bash|zsh|fish` also prints them.
