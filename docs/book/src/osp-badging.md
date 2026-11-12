# OpenSSF security insights form

You can reach the badge form at bestpractices.dev. Each criterion the OSPS
baseline asks for, and the evidence this repository already gives, is
summarized here. Copy the justification beside each the status on the form
and link back to the file or workflow.

| # | Criterion | Where the evidence is | Into a badge justification |
|---|---|---|---|
| AC-01 | Access control (GitHub enforced) | Org 2FA + branch ruleset `main` | "GitHub enforced branch ruleset on the default branch; SSO 2FA at the org is on." |
| AC-02 | Repository access control | GitHub roles (read from push), ruleset removes deletion and force-push | "Default-branch history is protected by ruleset; only the maintainer account has write access." |
| AC-03 | Releases are immutable | `release` environment with a required reviewer; tag ruleset denies update and deletion on `refs/tags/v*` | "Release artifacts are pipeline-published from signed tags created through an environment that only the maintainer can approve." |
| B-01 | Build script exists | `justfile`, `cargo xtask` | "cargo + just build (`cargo build --release --locked; just`)." |
| B-02 | Build from a source published release | `dist` release pack + `cargo publish` gated by crate | "Release artifact built from checked-out source in CI (release.yml)." |
| B-03 | Documented build instructions | README quickstart, `docs/book/src/installation.md` | "README and install guide include `cargo install` and signature verification." |
| DC-01 | Documents what it does | README overview + docs book |
| DC-02 | README names basic commands | `amivuln <pkg>`; JSON output; exit codes | "README quickstart." |
| DC-03 | Project website | <https://ibexwall.com/amivuln/> (also at nubian-ibex.github.io/amivuln) | "Documentation site built from docs/book by CI." |
| DC-04 | Contribution instructions | CONTRIBUTING.md | "CONTRIBUTING.md covers setup, just targets, and conventional commit sign-off." |
| DP-01 | Source and binary distributions covered | docs/security.md + release guide | "SECURITY.md holds the reporting channel, SLAs and verification steps." |
| O-01 | Maintainers documented | MAINTAINERS.md and GOVERNANCE.md | "The maintainer and the governance model are documented." |
| O-02 | Licensing | REUSE.toml + SPDX headers + `reuse lint` gate | "REUSE enforces SPDX headers on every file and disallows worsening licenses." |
| Q-01 | CI performs style checks and clippy | clippy `-D warnings` blocking on `lint` | "CI blocks the release patch on clippy `-D warnings`." |
| Q-02 | CI blocks code compile | Empty required checks on `build-a`/`build-b`, `test` | "CI gates develop branches on nextest runs (build+test jobs)." |
| Q-03 | Test framework defined | `cargo test` and nextest declared | "Tests run through cargo nextest with recorded fixtures." |
| Q-04 | CI blocks on test change | The build gate denies merge when tests fail | "The ruleset enforces the checks on every PR." |
| Q-05 | Security-relevant tests exist | `tests/ground-truth.rs` recorded HTTP fixtures | "Ground truth captures real advisory HTTP payloads as fixtures." |
| Q-06 | Docs and compat | jsonschema steps in CI | "rustdoc -D warnings plus the release JSON-schema gate block regressions." |
| SA-01 | Static exchange analysis | `cargo astray`: audit, deny, vet | "cargo `audit`, `deny` and `vet` run per PR (advisory DB, license + sources, provenance audits)." |
| SA-02 | Dependabot / Dependabot security alerts | enabled at the repo | "Dependabot security updates are on; Dependabot PRs are auto-tracked." |
| S-02 | Tag provenance | cosign keyless + SLSA attestation at release | "Releases are cosigned keyless and carry SLSA `attestations` (release.yml's actions/attest step)." |
| S-03 | Release attestation verified | `gh attestation verify` in README and amivuln-action | "The composite action refuses unattested binaries before execution." |
| D-01 | System invokes defenses | `sources` block in all output, `complete` flag and exit 2 | "Every run states exactly what answered, its age, and whether the result was complete." |
| T-01 | Unit tests on package versions | proptest ground truth and `amivuln-version` test | "Comparators get property-tested against `rpmvercmp`, and are cross-checked with the reference tools." |

The rows follow the badge form. The criteria that need people, a second
maintainer and an independent security review, are on the
[roadmap](roadmap.md).
