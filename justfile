default: ci

fmt:
    cargo fmt --all

lint:
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings

test:
    cargo nextest run --workspace --all-features --locked --no-tests=pass

doc:
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features --locked

deny:
    cargo deny check

audit:
    cargo audit

vet:
    cargo vet --locked

typos:
    typos

reuse:
    reuse lint

actions:
    actionlint
    zizmor .github/workflows

cov:
    cargo llvm-cov nextest --workspace --all-features --lcov --output-path lcov.info

ci: fmt-check lint test doc deny audit vet typos reuse actions

fmt-check:
    cargo fmt --all --check
