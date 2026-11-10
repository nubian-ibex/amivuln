# Support policy

## Versions

Before 1.0 only the latest release receives fixes, security or otherwise. From
1.0 the latest minor release receives security fixes, and a security fix is
backported to the previous minor for 90 days after a new minor ships.

## Minimum supported Rust version

The MSRV is the `rust-version` in `Cargo.toml` (1.97 today) and the `msrv` CI
job builds with it on every change. It is raised only in a minor release,
never in a patch release, and every raise is named in the changelog.

## What is a contract

- **JSON output.** Documents carry `schema_version`. Within a version, fields
  are never removed, renamed or retyped; a new field or a new enum value is an
  additive change and ships in a minor release with a note in the changelog and
  the published [schema](json-schema.md). Breaking the shape means a new
  `schema_version`. The golden documents under `tests/golden` pin the exact
  output, field order included, and must keep validating against the current
  schema; a change to them is visible in review.
- **Exit codes.** 0, 1, 2, 3, 64, 65 and 70 and their precedence are stable.
- **Configuration.** Keys are not removed or renamed within a major version;
  new keys have defaults that keep today's behavior.
- **Command line.** Flags are not removed or repurposed within a major
  version. Text output (`summary`, `detail`) is for humans and may change.

## Platforms

Linux on x86_64 and aarch64 (static `musl` and `glibc` builds). macOS and
Windows are not supported.
