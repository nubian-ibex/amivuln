# Governance

## Model

amivuln follows a BDFL model: the lead maintainer makes the final decision on
scope, releases and policy, informed by public discussion in issues and pull
requests. Significant design decisions are recorded as ADRs in `docs/adr` so
that the reasoning outlives the discussion.

## Roles

- **Users and contributors.** Anyone who opens an issue, comments, or sends a
  pull request. Contributions follow [CONTRIBUTING.md](CONTRIBUTING.md) and the
  [Code of Conduct](CODE_OF_CONDUCT.md).
- **Maintainers.** People with write access to the repository, who review and
  merge pull requests. They are listed in [MAINTAINERS.md](MAINTAINERS.md).
- **Release maintainers.** The subset of maintainers who can approve the
  `release` environment, which publishes to crates.io and GitHub Releases.
  Today this is the lead maintainer alone.

## How decisions are made

1. Small changes: a pull request, passing the full CI, merged by a maintainer.
2. Changes to behaviour that users rely on (output, exit codes, configuration)
   or to the supply chain: discussed in an issue first, and recorded in an ADR
   when the decision is not obvious from the code.
3. Disagreements: the lead maintainer decides after the discussion, and says
   why in the issue.

## Becoming a maintainer

Sustained, reviewed contributions over several months, agreement with the
project's security and privacy principles, and a signed-commit setup with
two-factor authentication on the GitHub account. The lead maintainer proposes
the addition in an issue, and it takes effect after a week without a
substantive objection.

## Continuity

The project does not yet meet the goal of two maintainers with release
permission. Recruiting a second one is the first item of the
[roadmap](https://ibexwall.com/amivuln/roadmap.html), and 1.0 waits
for it.
