# amivuln-resolve

Resolves what the user asked about (package, file, systemd unit, `name@version`, purl) to a package reference.

> **Internal crate.** `amivuln-resolve` is part of [amivuln](https://crates.io/crates/amivuln). It is published because the binary depends on it, and it carries **no API stability promise** before 1.0: any release may change or remove public items. If you want the tool, install `amivuln`.

## What is in it

- `parse_target`: the inference rules, in order: purl, path, unit, `name@version`, installed package name.
- `RpmResolver` and `PacmanResolver`: installed-package lookups through `rpm` and `pacman`, behind the `PackageResolver` trait. Several installed versions or owners are an error, never a guess; multilib builds count as one package.
- `exe_for_unit`: `.service` unit to executable through `systemctl show`, `/proc/PID/exe` and an `ExecStart` fallback, flagging a binary replaced on disk.
- `from_name_version` and `from_purl`: packages built from user input without looking at the host.
- `SystemRunner`: the real `ProcessRunner`. It runs only `rpm`, `pacman` and `systemctl`, from fixed absolute paths, without a shell, with a cleared environment and `LC_ALL=C`, a timeout and an output cap. User text always follows `--`.
- `parse_os_release`: Fedora and Arch detection.

Logic is tested with a scripted fake runner; a few tests also run the host tools when present.

## Part of amivuln

[amivuln](https://github.com/nubian-ibex/amivuln) reports which CVEs apply to the packages on a Linux host, taking the patches the distribution already shipped into account. Documentation: <https://ibexwall.com/amivuln/>. Architecture: <https://ibexwall.com/amivuln/architecture.html>.

## License

Licensed under either of [Apache License, Version 2.0](https://github.com/nubian-ibex/amivuln/blob/main/LICENSE-APACHE) or [MIT license](https://github.com/nubian-ibex/amivuln/blob/main/LICENSE-MIT) at your option.
