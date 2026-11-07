# Reproducible builds

Release binaries are built with `--locked`, a pinned toolchain (`rust-toolchain.toml`) and path remapping, so two independent builds of the same commit produce identical bytes.

## Reproduce locally

```bash
git clone https://github.com/nubian-ibex/amivuln && cd amivuln
git checkout <tag>
export SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"
export RUSTFLAGS="--remap-path-prefix=$HOME=/home/builder --remap-path-prefix=$PWD=/src"
cargo build --release --locked --target x86_64-unknown-linux-musl -p amivuln
sha256sum target/x86_64-unknown-linux-musl/release/amivuln
```

Compare the hash with the one listed in the release `SHA256SUMS` or in the `reproducible` workflow summary. Note that release archives are produced by `dist`; the check above compares the bare binary.

## CI verification

The `reproducible` workflow builds the same commit on two different runner images and directories and fails if the SHA-256 differs.

## Software bill of materials

- `cargo cyclonedx` produces a CycloneDX SBOM per crate.
- Release binaries are built with `cargo auditable`, which embeds the dependency list in the binary.

## Known limitation

Two builds of the same commit on `ubuntu-22.04` and `ubuntu-24.04` runners produced different hashes (observed 2026-11-07), while two builds on the same image in different directories were identical. The musl target is linked with the host toolchain, so the build environment is part of the input. The CI check therefore compares builds on one runner image; reproducing a release requires the same environment (planned: a pinned build container).
