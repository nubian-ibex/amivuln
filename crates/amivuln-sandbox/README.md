# amivuln-sandbox

Landlock and seccomp confinement for the amivuln version probe.

> **Internal crate.** `amivuln-sandbox` is part of [amivuln](https://crates.io/crates/amivuln). It is published because the binary depends on it, and it carries **no API stability promise** before 1.0: any release may change or remove public items. If you want the tool, install `amivuln`.

## What is in it

`probe` runs a target binary with a fixed argument list (normally `--version`) in a child that has lost, before `exec`:

- every write to the file system (Landlock; reads are limited to the system library directories and the target's own directory),
- the ability to open sockets or reach other processes (seccomp),
- privileges (`no_new_privs`, and a drop to `nobody` when run as root),
- resources (2 s of CPU time, no file growth, no core dumps, 64 open files).

The call is also bounded in wall-clock time and output size. When the kernel cannot enforce the confinement the probe fails with `SandboxError::Unsupported`; it never runs unconfined.

This is the only crate in the workspace that contains `unsafe` code. It lives in a single module with a `SAFETY` comment on every block.

## Part of amivuln

[amivuln](https://github.com/nubian-ibex/amivuln) reports which CVEs apply to the packages on a Linux host, taking the patches the distribution already shipped into account. Documentation: <https://nubian-ibex.github.io/amivuln/>.

## License

Licensed under either of [Apache License, Version 2.0](https://github.com/nubian-ibex/amivuln/blob/main/LICENSE-APACHE) or [MIT license](https://github.com/nubian-ibex/amivuln/blob/main/LICENSE-MIT) at your option.
