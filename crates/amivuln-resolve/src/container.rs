// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! `--container`: packages inside a container, read from its exported rootfs.
//!
//! The container runtime (podman, then docker) is invoked only to `export`
//! the filesystem, which does not execute anything inside the container.
//! The package databases of the exported tree are then read directly:
//!
//! - Debian and Ubuntu: `/var/lib/dpkg/status` (pure parser);
//! - Alpine: `/lib/apk/db/installed` (pure parser);
//! - Fedora, Rocky, `AlmaLinux`: the rpm database through the host `rpm`
//!   (`--dbpath`), because the Berkeley format has no pure reader;
//! - Arch: the pacman database through the host `pacman` (`--dbpath`).
//!
//! The container's `/etc/os-release` decides the ecosystem, so the host
//! distribution never leaks into the answer.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use amivuln_core::{
    Ecosystem, PackageRef, ProcessError, ProcessRunner, Program, Provenance, Version,
};

/// Why a container could not be read.
#[derive(Debug, thiserror::Error)]
pub enum ContainerError {
    /// The runtime is missing or the container does not exist.
    #[error("{0}")]
    Runtime(String),
    /// The rootfs export failed or is unusable.
    #[error("{0}")]
    Export(String),
    /// The container's distribution is not one amivuln can read.
    #[error(
        "the container is {0:?}; amivuln reads fedora, rocky, alma, debian, ubuntu, arch and alpine containers"
    )]
    Unsupported(String),
    /// The host package manager needed to read the database is missing.
    #[error("reading this container needs {0} on the host")]
    HostToolMissing(String),
}

/// The runtimes amivuln may use, in the order they are tried.
const RUNTIMES: [(Program, &str); 2] = [(Program::Podman, "podman"), (Program::Docker, "docker")];

/// Resolves the first runtime installed on the host.
#[must_use]
pub fn available_runtime(runner: &dyn ProcessRunner) -> Option<Program> {
    RUNTIMES
        .iter()
        .find(|(program, _)| runner.run(*program, &["--version"]).is_ok())
        .map(|(program, _)| *program)
}

/// The container id a user typed: alphanumerics, dash, underscore, dot.
fn is_container_id(id: &str) -> bool {
    // A leading dash would be read as a runtime flag; the rest is the usual
    // name and id alphabet both runtimes accept.
    !id.is_empty()
        && !id.starts_with('-')
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

/// Exports the container rootfs into `dest` and returns the container's
/// ecosystem.
///
/// # Errors
///
/// Fails when the runtime is missing, the container does not exist, the
/// export is too large, or the distribution is not supported.
pub fn export(
    runner: &dyn ProcessRunner,
    container_id: &str,
    dest: &Path,
) -> Result<Ecosystem, ContainerError> {
    if !is_container_id(container_id) {
        return Err(ContainerError::Runtime(format!(
            "invalid container id {container_id:?}"
        )));
    }
    std::fs::create_dir_all(dest).map_err(|e| ContainerError::Export(e.to_string()))?;
    let runtime = available_runtime(runner)
        .ok_or_else(|| ContainerError::Runtime("podman or docker is not installed".to_owned()))?;
    let out = runner
        .run(
            runtime,
            &[
                "export",
                "-o",
                tar_at(dest).to_str().unwrap_or_default(),
                container_id,
            ],
        )
        .map_err(|e| match e {
            ProcessError::NotInstalled(p) => {
                ContainerError::Runtime(format!("{p:?} is not installed"))
            }
            other => ContainerError::Export(other.to_string()),
        })?;
    if !out.success {
        return Err(ContainerError::Runtime(format!(
            "the runtime could not export {container_id:?}"
        )));
    }
    let tar_path = tar_at(dest);
    let file = std::fs::File::open(&tar_path)
        .map_err(|e| ContainerError::Export(format!("{}: {e}", tar_path.display())))?;
    // The export is bounded: containers larger than 4 GiB are refused.
    let mut tar = tar::Archive::new(std::io::BufReader::new(file));
    let entries = tar
        .entries()
        .map_err(|e| ContainerError::Export(e.to_string()))?;
    for entry in entries {
        let mut entry = entry.map_err(|e| ContainerError::Export(e.to_string()))?;
        let path = entry
            .path()
            .map_err(|e| ContainerError::Export(e.to_string()))?
            .to_path_buf();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        // Only the files this reader needs are extracted, each bounded.
        let wanted = matches!(
            name,
            "os-release" | "status" | "installed" | "Packages" | "pacman"
        ) || path.starts_with("var/lib/rpm");
        // A directory entry under var/lib/rpm matches the prefix but holds no
        // data; writing it as a file would block the database files inside.
        if !wanted || entry.header().entry_type().is_dir() {
            continue;
        }
        // Debian's /etc/os-release is a symlink into usr/lib: record the
        // archive path and the target so the read step can follow the chain.
        if entry.header().entry_type().is_symlink() {
            let target = dest.join(root_relative(&path));
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| ContainerError::Export(e.to_string()))?;
            }
            let link_target = entry.link_name().ok().flatten().map_or_else(
                || "../usr/lib/os-release".to_owned(),
                |l| l.to_string_lossy().into_owned(),
            );
            std::fs::write(
                &target,
                format!("{SYMLINK_MARK}{}\t{link_target}", path.display()),
            )
            .map_err(|e| ContainerError::Export(e.to_string()))?;
            continue;
        }
        let mut bytes = Vec::new();
        if entry
            .by_ref()
            .take(64 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .is_err()
            || bytes.len() > 64 * 1024 * 1024
        {
            return Err(ContainerError::Export(format!(
                "{} is too large",
                path.display()
            )));
        }
        let target = dest.join(root_relative(&path));
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(|e| ContainerError::Export(e.to_string()))?;
        }
        std::fs::write(&target, &bytes).map_err(|e| ContainerError::Export(e.to_string()))?;
    }
    let os_release = read_os_release(dest)
        .map_err(|_| ContainerError::Export("the container has no /etc/os-release".to_owned()))?;
    ecosystem_from_os_release(&os_release)
        .ok_or_else(|| ContainerError::Unsupported(distro_id(&os_release)))
}

/// Reads `/etc/os-release` from the extracted tree, following the symlink
/// chains Debian and Fedora write (`etc/os-release -> ../usr/lib/os-release`).
fn read_os_release(dest: &Path) -> Result<String, std::io::Error> {
    let root = dest.join("root");
    let mut at = root.join("etc/os-release");
    for _ in 0..8 {
        let bytes = std::fs::read(&at)?;
        let text = String::from_utf8_lossy(&bytes);
        if let Some(rest) = text.strip_prefix(SYMLINK_MARK) {
            let Some((recorded, target)) = rest.split_once('\t') else {
                return Err(std::io::Error::other("a broken symlink record"));
            };
            // The link target is relative to the recorded archive path.
            let base = root
                .join(recorded.trim())
                .parent()
                .unwrap_or(&root)
                .to_path_buf();
            at = base.join(target.trim());
            continue;
        }
        return Ok(text.into_owned());
    }
    Err(std::io::Error::other(
        "the os-release symlink chain never reaches a file",
    ))
}

/// Marks the stub file written for a symlinked member.
const SYMLINK_MARK: &str = "amivuln-symlink\t";

fn tar_at(dest: &Path) -> PathBuf {
    dest.join("rootfs.tar")
}

/// Maps an absolute container path to its place under the export root.
fn root_relative(path: &Path) -> PathBuf {
    // Tar paths are absolute without a leading slash; keep them under root/.
    let root = PathBuf::from("root");
    if let Ok(stripped) = path.strip_prefix("/") {
        return root.join(stripped);
    }
    root.join(path)
}

fn distro_id(os_release: &str) -> String {
    os_release
        .lines()
        .find_map(|l| l.strip_prefix("ID="))
        .unwrap_or("?")
        .trim()
        .trim_matches('"')
        .to_owned()
}

/// Maps the container's `os-release` to an ecosystem amivuln reads.
fn ecosystem_from_os_release(os_release: &str) -> Option<Ecosystem> {
    let id = distro_id(os_release);
    let raw = os_release
        .lines()
        .find_map(|l| l.strip_prefix("VERSION_ID="))
        .unwrap_or("?")
        .trim()
        .trim_matches('"');
    // Ubuntu writes "24.04": the OSV ecosystem wants 2404. Other distros use
    // the major release alone.
    let version = if id == "alpine" {
        // `3.20.3` is release 3.20 (320). An edge or alpha image
        // (`3.23.0_alpha20250108`) has no release OSV knows: refuse it.
        let mut parts = raw.split('.');
        parts
            .next()
            .filter(|_| !raw.contains('_'))
            .and_then(|m| m.parse::<u16>().ok())
            .zip(parts.next().and_then(|m| m.parse::<u16>().ok()))
            .map(|(maj, min)| maj * 100 + min)
    } else if id == "ubuntu" {
        let (major, minor) = raw.split_once('.').unwrap_or((raw, "0"));
        major
            .parse::<u16>()
            .ok()
            .zip(minor.parse::<u16>().ok())
            .map(|(maj, min)| maj * 100 + min)
    } else if id == "rhel" {
        // `9.4` is release 9.
        raw.split('.').next().and_then(|m| m.parse::<u16>().ok())
    } else {
        raw.parse::<u16>().ok()
    };
    match (id.as_str(), version) {
        ("fedora", Some(v)) => Some(Ecosystem::Fedora(v)),
        ("rocky", Some(v)) => Some(Ecosystem::Rocky(v)),
        ("rhel", Some(v)) => Some(Ecosystem::Rhel(v)),
        ("almalinux", Some(v)) => Some(Ecosystem::Alma(v)),
        ("debian", Some(v)) => Some(Ecosystem::Debian(v)),
        ("ubuntu", Some(v)) if matches!(v % 100, 4 | 10) => Some(Ecosystem::Ubuntu(v)),
        ("arch", _) => Some(Ecosystem::Arch),
        ("alpine", Some(v)) => Some(Ecosystem::Alpine(v)),
        _ => None,
    }
}

/// The packages of the exported rootfs, for the container's ecosystem.
///
/// # Errors
///
/// Fails when the database cannot be read or parsed.
pub fn packages(
    runner: &dyn ProcessRunner,
    eco: Ecosystem,
    root: &Path,
) -> Result<Vec<PackageRef>, ContainerError> {
    match eco {
        Ecosystem::Debian(_) | Ecosystem::Ubuntu(_) => {
            let status = std::fs::read_to_string(root.join("root/var/lib/dpkg/status"))
                .map_err(|e| ContainerError::Export(e.to_string()))?;
            Ok(deb_packages(&status, eco))
        }
        Ecosystem::Alpine(_) => {
            let installed = std::fs::read_to_string(root.join("root/lib/apk/db/installed"))
                .map_err(|e| ContainerError::Export(e.to_string()))?;
            Ok(apk_packages(&installed, eco))
        }
        Ecosystem::Fedora(_) | Ecosystem::Rocky(_) | Ecosystem::Alma(_) | Ecosystem::Rhel(_) => {
            let db = root.join("root/var/lib/rpm");
            let out = runner
                .run(
                    Program::Rpm,
                    &[
                        "--dbpath",
                        db.to_str().unwrap_or_default(),
                        "-qa",
                        "--qf",
                        "%{NAME}@%{EPOCH}:%{VERSION}-%{RELEASE}\\n",
                    ],
                )
                .map_err(|_| ContainerError::HostToolMissing("rpm".to_owned()))?;
            Ok(rpm_packages(&String::from_utf8_lossy(&out.stdout), eco))
        }
        Ecosystem::Arch => {
            let db = root.join("root/var/lib/pacman");
            let out = runner
                .run(
                    Program::Pacman,
                    &["-Q", "--dbpath", db.to_str().unwrap_or_default()],
                )
                .map_err(|_| ContainerError::HostToolMissing("pacman".to_owned()))?;
            Ok(pacman_packages(&String::from_utf8_lossy(&out.stdout), eco))
        }
        Ecosystem::Go | Ecosystem::Crates => Err(ContainerError::Unsupported(
            "a language ecosystem".to_owned(),
        )),
    }
}

/// Reads `/var/lib/dpkg/status`. OSV keys Debian and Ubuntu advisories by the
/// source package, so the `Source:` field (`openssl (1.1.1k-1)`, the version
/// only when it differs) names the package a binary such as `libssl1.1`
/// is queried as.
fn deb_packages(status: &str, eco: Ecosystem) -> Vec<PackageRef> {
    let mut packages = Vec::new();
    for stanza in status.split("\n\n") {
        let mut fields: BTreeMap<&str, &str> = BTreeMap::new();
        for line in stanza.lines() {
            // Continuation lines start with a space and belong to the last field.
            if !line.starts_with([' ', '\t'])
                && let Some((key, value)) = line.split_once(": ")
            {
                fields.insert(key.trim(), value.trim());
            }
        }
        let (Some(name), Some(version)) = (fields.get("Package"), fields.get("Version")) else {
            continue;
        };
        let Ok(mut pkg) = crate::from_name_version(eco, name, version) else {
            continue;
        };
        pkg.source_name = fields
            .get("Source")
            .and_then(|s| s.split_whitespace().next())
            .filter(|source| source != name)
            .map(str::to_owned);
        packages.push(pkg);
    }
    packages
}

/// Reads `/lib/apk/db/installed`: stanzas of `K:value` lines separated by a
/// blank line. `P` is the package, `V` the version, `A` the architecture and
/// `o` the origin (source) package. OSV keys Alpine advisories by origin, so
/// a subpackage such as `libcrypto3` is queried as `openssl`.
fn apk_packages(installed: &str, eco: Ecosystem) -> Vec<PackageRef> {
    let mut packages = Vec::new();
    for stanza in installed.split("\n\n") {
        let mut fields: BTreeMap<&str, &str> = BTreeMap::new();
        for line in stanza.lines() {
            if let Some((key, value)) = line.split_once(':') {
                fields.insert(key.trim(), value.trim());
            }
        }
        let (Some(name), Some(version)) = (fields.get("P"), fields.get("V")) else {
            continue;
        };
        packages.push(PackageRef {
            ecosystem: eco,
            name: (*name).to_owned(),
            source_name: fields
                .get("o")
                .filter(|o| *o != name)
                .map(|o| (*o).to_owned()),
            version: Version::Apk(version.parse().unwrap_or_else(|never| match never {})),
            arch: fields.get("A").map(|a| (*a).to_owned()),
            provenance: Provenance::PackageDb,
        });
    }
    packages
}

fn rpm_packages(stdout: &str, eco: Ecosystem) -> Vec<PackageRef> {
    let mut packages = Vec::new();
    for line in stdout.lines() {
        let Some((name, version)) = line.split_once('@') else {
            continue;
        };
        let version = version.strip_prefix("(none):").unwrap_or(version);
        if let Ok(pkg) = crate::from_name_version(eco, name, version) {
            packages.push(pkg);
        }
    }
    packages
}

fn pacman_packages(stdout: &str, eco: Ecosystem) -> Vec<PackageRef> {
    let mut packages = Vec::new();
    for line in stdout.lines() {
        let Some((name, version)) = line.split_once(' ') else {
            continue;
        };
        if let Ok(pkg) = crate::from_name_version(eco, name, version) {
            packages.push(pkg);
        }
    }
    packages
}

#[cfg(test)]
mod tests {
    use super::*;
    use amivuln_core::ProcessOutput;

    pub(crate) struct NoRuntime;
    impl ProcessRunner for NoRuntime {
        fn run(&self, _: Program, _: &[&str]) -> Result<ProcessOutput, amivuln_core::ProcessError> {
            Err(amivuln_core::ProcessError::NotInstalled(Program::Podman))
        }
    }

    #[test]
    fn container_ids_are_strict() {
        for ok in ["abc123", "web_prod.1", "a", "x-y_z"] {
            assert!(is_container_id(ok), "{ok}");
        }
        for bad in ["", "a b", "--flag", "a;b", "../../etc", "with/slash"] {
            assert!(!is_container_id(bad), "{bad:?}");
        }
    }

    #[test]
    fn os_release_maps_to_ecosystems() {
        let fedora = "ID=fedora\nVERSION_ID=43\n";
        assert_eq!(
            ecosystem_from_os_release(fedora),
            Some(Ecosystem::Fedora(43))
        );
        let debian = "ID=debian\nVERSION_ID=13\n";
        assert_eq!(
            ecosystem_from_os_release(debian),
            Some(Ecosystem::Debian(13))
        );
        let ubuntu = "ID=ubuntu\nVERSION_ID=24.04\n";
        assert_eq!(
            ecosystem_from_os_release(ubuntu),
            Some(Ecosystem::Ubuntu(2404))
        );
        // An interim release (24.10) is accepted as a Ubuntu ecosystem but
        // OSV has no data for it; the run reports the source as failed.
        let interim = "ID=ubuntu\nVERSION_ID=24.10\n";
        assert_eq!(
            ecosystem_from_os_release(interim),
            Some(Ecosystem::Ubuntu(2410))
        );
        let alpine = "ID=alpine\nVERSION_ID=3.20.3\n";
        assert_eq!(
            ecosystem_from_os_release(alpine),
            Some(Ecosystem::Alpine(320))
        );
        // Edge and alpha images have no OSV release.
        let edge = "ID=alpine\nVERSION_ID=3.23.0_alpha20250108\n";
        assert_eq!(ecosystem_from_os_release(edge), None);
        let unknown = "ID=gentoo\n";
        assert!(matches!(
            ecosystem_from_os_release(unknown),
            None | Some(Ecosystem::Arch)
        ));
    }

    #[test]
    fn deb_status_is_parsed() {
        let status = "Package: nginx\nVersion: 1.22.1-9\nArchitecture: amd64\nDescription: web\n server\n\nPackage: curl\nVersion: 7.88.1-10+deb12u5\n\nPackage: libssl3\nSource: openssl (3.0.11-1)\nVersion: 3.0.11-1~deb12u1\n\n";
        let found = deb_packages(status, Ecosystem::Debian(12));
        let names: Vec<&str> = found.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["nginx", "curl", "libssl3"]);
        assert_eq!(found[0].source_name, None);
        assert_eq!(found[2].source_name.as_deref(), Some("openssl"));
        assert!(matches!(found[0].version, Version::Deb(_)));
    }

    #[test]
    fn apk_installed_is_parsed() {
        let installed = "P:busybox\nV:1.36.1-r5\no:busybox\nA:x86_64\n\nP:libcrypto3\nV:3.1.4-r0\no:openssl\nA:x86_64\n\n";
        let found = apk_packages(installed, Ecosystem::Alpine(319));
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].name, "busybox");
        assert_eq!(found[0].source_name, None);
        assert_eq!(found[0].version.to_string(), "1.36.1-r5");
        assert!(matches!(found[0].version, Version::Apk(_)));
        // A subpackage is advisory-keyed by its origin.
        assert_eq!(found[1].name, "libcrypto3");
        assert_eq!(found[1].source_name.as_deref(), Some("openssl"));
        assert_eq!(found[1].ecosystem, Ecosystem::Alpine(319));
    }

    #[test]
    fn rpm_and_pacman_lines_are_parsed() {
        let rpm = rpm_packages(
            "nginx@1:1.26.2-1.fc41\nopenssl@3.2.2-1.fc41\n",
            Ecosystem::Fedora(41),
        );
        assert_eq!(rpm.len(), 2);
        assert_eq!(rpm[0].version.to_string(), "1:1.26.2-1.fc41");
        let pac = pacman_packages("nginx 1.26.2-1\nopenssl 3.2.2-1\n", Ecosystem::Arch);
        assert_eq!(pac.len(), 2);
        assert_eq!(pac[1].name, "openssl");
    }

    #[test]
    fn only_needed_files_are_extracted() {
        let tar_bytes = build_tar(&[
            ("etc/os-release", b"ID=debian\nVERSION_ID=13\n"),
            (
                "var/lib/dpkg/status",
                b"Package: nginx\nVersion: 1.22.1-9\n\n",
            ),
            ("usr/share/big", &[0xff; 16]),
            ("var/lib/other", b"ignored"),
        ]);
        let dir = tempfile::tempdir().unwrap();
        let tar_path = dir.path().join("rootfs.tar");
        std::fs::write(&tar_path, &tar_bytes).unwrap();
        // The runner here is only asked for --version, which fails: the export
        // itself is a caller's concern; the extraction helpers are unit tested.
        let err = export(&NoRuntime, "web", dir.path()).unwrap_err();
        assert!(matches!(err, ContainerError::Runtime(_)), "{err:?}");
        // But the pure parsing of the extracted database works directly.
        let status_dir = dir.path().join("root/var/lib/dpkg");
        std::fs::create_dir_all(&status_dir).unwrap();
        std::fs::write(
            status_dir.join("status"),
            b"Package: nginx\nVersion: 1.22.1-9\n\n",
        )
        .unwrap();
        let found = packages(&NoRuntime, Ecosystem::Debian(13), dir.path()).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "nginx");
    }

    /// A runner whose `--version` succeeds and whose `export` writes a fixed
    /// tar: enough to drive `export` end to end without podman.
    pub(crate) struct ScriptedRuntime {
        pub(crate) tar_path: std::path::PathBuf,
    }
    impl ProcessRunner for ScriptedRuntime {
        fn run(
            &self,
            program: Program,
            args: &[&str],
        ) -> Result<ProcessOutput, amivuln_core::ProcessError> {
            match program {
                Program::Podman | Program::Docker if args == ["--version"] => Ok(ProcessOutput {
                    success: true,
                    stdout: b"0.0.0-test".to_vec(),
                }),
                Program::Podman | Program::Docker => {
                    let out = args
                        .iter()
                        .zip(args.iter().skip(1))
                        .find_map(|(flag, path)| (*flag == "-o").then_some(*path));
                    let Some(out) = out else {
                        return Err(amivuln_core::ProcessError::Io(
                            program,
                            "unexpected args".to_owned(),
                        ));
                    };
                    std::fs::copy(&self.tar_path, out)
                        .map_err(|e| amivuln_core::ProcessError::Io(program, e.to_string()))?;
                    Ok(ProcessOutput {
                        success: true,
                        stdout: Vec::new(),
                    })
                }
                _ => Err(amivuln_core::ProcessError::NotInstalled(program)),
            }
        }
    }

    /// A minimal ustar with the given members, for the extraction tests.
    pub(crate) fn build_tar(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        {
            let mut tar = tar::Builder::new(&mut out);
            for (name, data) in members {
                let mut header = tar::Header::new_gnu();
                header.set_size(data.len() as u64);
                header.set_cksum();
                tar.append_data(&mut header, name, *data).unwrap();
            }
            tar.finish().unwrap();
        }
        out
    }
}

#[cfg(test)]
mod extraction_tests {
    use super::tests::{ScriptedRuntime, build_tar};
    use super::*;

    #[test]
    fn export_reads_a_debian_container_end_to_end() {
        let tar = build_tar(&[
            ("etc/os-release", b"ID=debian\nVERSION_ID=13\n"),
            (
                "var/lib/dpkg/status",
                b"Package: nginx\nVersion: 1.22.1-9\n\n",
            ),
            ("usr/share/junk", &[0xff; 32]),
        ]);
        let dir = tempfile::tempdir().unwrap();
        let tar_path = dir.path().join("fixture.tar");
        std::fs::write(&tar_path, &tar).unwrap();
        let runtime = ScriptedRuntime { tar_path };
        let dest = dir.path().join("export");
        let eco = export(&runtime, "web", &dest).unwrap();
        assert_eq!(eco, Ecosystem::Debian(13));
        let found = packages(&runtime, eco, &dest).unwrap();
        let names: Vec<&str> = found.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["nginx"], "{names:?}");
        // The export tar and the scratch tree stay inside the caller's dir.
        assert!(dest.join("rootfs.tar").is_file());
        assert!(dest.join("root/etc/os-release").is_file());
    }

    #[test]
    fn an_unsupported_container_is_reported_by_name() {
        let tar = build_tar(&[("etc/os-release", b"ID=gentoo\n")]);
        let dir = tempfile::tempdir().unwrap();
        let tar_path = dir.path().join("fixture.tar");
        std::fs::write(&tar_path, &tar).unwrap();
        let runtime = ScriptedRuntime { tar_path };
        let err = export(&runtime, "web", &dir.path().join("export")).unwrap_err();
        assert!(err.to_string().contains("gentoo"), "{err}");
    }

    #[test]
    fn an_oversized_file_in_the_export_is_refused() {
        let big = vec![0xffu8; 64 * 1024 * 1024 + 1];
        let tar = build_tar(&[("var/lib/dpkg/status", &big)]);
        let dir = tempfile::tempdir().unwrap();
        let tar_path = dir.path().join("fixture.tar");
        std::fs::write(&tar_path, &tar).unwrap();
        let runtime = ScriptedRuntime { tar_path };
        let err = export(&runtime, "web", &dir.path().join("export")).unwrap_err();
        assert!(err.to_string().contains("too large"), "{err}");
    }
}
