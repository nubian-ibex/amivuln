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

use std::io::Read;
use std::path::{Component, Path, PathBuf};

use amivuln_core::{Ecosystem, PackageRef, ProcessError, ProcessRunner, Program};

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
    // The archive is read as the runtime writes it and never stored: an image
    // of any size costs only the few files that are copied out.
    let mut stream = runner
        .stream(runtime, &["export", container_id])
        .map_err(|e| match e {
            ProcessError::NotInstalled(p) => {
                ContainerError::Runtime(format!("{p:?} is not installed"))
            }
            other => ContainerError::Export(other.to_string()),
        })?;
    extract_wanted(&mut stream, dest, MAX_EXPORT_BYTES)?;
    let succeeded = stream
        .finish()
        .map_err(|e| ContainerError::Export(e.to_string()))?;
    if !succeeded {
        return Err(ContainerError::Runtime(format!(
            "the runtime could not export {container_id:?}"
        )));
    }
    let os_release = read_os_release(dest)
        .map_err(|_| ContainerError::Export("the container has no /etc/os-release".to_owned()))?;
    ecosystem_from_os_release(&os_release)
        .ok_or_else(|| ContainerError::Unsupported(distro_id(&os_release)))
}

/// A reader that fails once more than `left` bytes have gone through it.
struct Capped<R> {
    inner: R,
    left: u64,
}

impl<R: Read> Read for Capped<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        let n_u64 = n as u64;
        if n_u64 > self.left {
            return Err(std::io::Error::other(
                "the export is larger than the size limit",
            ));
        }
        self.left -= n_u64;
        Ok(n)
    }
}

/// Copies the package database files and os-release out of the export into
/// `dest/root`, each bounded. At most `limit` bytes are read from `export`;
/// the rest of the stream is consumed so the program can finish.
fn extract_wanted(export: &mut dyn Read, dest: &Path, limit: u64) -> Result<(), ContainerError> {
    let capped = Capped {
        inner: export,
        left: limit,
    };
    let mut tar = tar::Archive::new(std::io::BufReader::new(capped));
    let entries = tar
        .entries()
        .map_err(|e| ContainerError::Export(e.to_string()))?;
    for entry in entries {
        let mut entry = entry.map_err(|e| ContainerError::Export(e.to_string()))?;
        let path = entry
            .path()
            .map_err(|e| ContainerError::Export(e.to_string()))?
            .to_path_buf();
        // A member that climbs out of the archive root (`..`) is never what a
        // runtime writes; refuse the export instead of guessing.
        let Some(path) = clean_member(&path) else {
            return Err(ContainerError::Export(format!(
                "unsafe path in the export: {}",
                path.display()
            )));
        };
        let wanted = WANTED_FILES.iter().any(|f| path == Path::new(f))
            || WANTED_DIRS.iter().any(|d| path.starts_with(d));
        // A directory entry under var/lib/rpm matches the prefix but holds no
        // data; writing it as a file would block the database files inside.
        if !wanted || entry.header().entry_type().is_dir() {
            continue;
        }
        // Debian's /etc/os-release is a symlink into usr/lib: record the
        // archive path and the target so the read step can follow the chain.
        if entry.header().entry_type().is_symlink() {
            let target = dest.join("root").join(&path);
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
        let target = dest.join("root").join(&path);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(|e| ContainerError::Export(e.to_string()))?;
        }
        std::fs::write(&target, &bytes).map_err(|e| ContainerError::Export(e.to_string()))?;
    }
    // Read the end of the archive too, so the program is not left blocked on
    // a full pipe and the size limit covers the whole stream.
    let mut rest = tar.into_inner();
    std::io::copy(&mut rest, &mut std::io::sink())
        .map_err(|e| ContainerError::Export(e.to_string()))?;
    Ok(())
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
            at = root.join(resolve_link(
                Path::new(recorded.trim()),
                Path::new(target.trim()),
            ));
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

/// Files copied out of an export, relative to the container root.
const WANTED_FILES: [&str; 4] = [
    "etc/os-release",
    "usr/lib/os-release",
    "var/lib/dpkg/status",
    "lib/apk/db/installed",
];
/// Directories copied out of an export: the rpm and pacman databases.
const WANTED_DIRS: [&str; 3] = [
    "var/lib/rpm",
    "usr/lib/sysimage/rpm",
    "var/lib/pacman/local",
];

/// Largest container export read.
const MAX_EXPORT_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// The member path relative to the container root, or `None` when it has a
/// `..` (or a Windows prefix) and could point outside it.
fn clean_member(path: &Path) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    for part in path.components() {
        match part {
            Component::Normal(p) => out.push(p),
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir | Component::Prefix(_) => return None,
        }
    }
    Some(out)
}

/// Where a symlink at `link` (relative to the container root) points, kept
/// inside the root the way the kernel does at `/`: `..` stops there and an
/// absolute target starts there, never on the host.
fn resolve_link(link: &Path, target: &Path) -> PathBuf {
    let mut out: Vec<&std::ffi::OsStr> = Vec::new();
    if !target.has_root() {
        out.extend(
            link.parent()
                .into_iter()
                .flat_map(Path::components)
                .filter_map(|c| match c {
                    Component::Normal(p) => Some(p),
                    _ => None,
                }),
        );
    }
    for part in target.components() {
        match part {
            Component::Normal(p) => out.push(p),
            Component::ParentDir => {
                out.pop();
            }
            Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
        }
    }
    out.iter().collect()
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
    let version = if id == "opensuse-leap" {
        // `15.6` is 1506, `16.0` is 1600.
        raw.split_once('.')
            .and_then(|(maj, min)| Some(maj.parse::<u16>().ok()? * 100 + min.parse::<u16>().ok()?))
    } else if id == "alpine" {
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
        ("opensuse-leap", Some(v)) => Some(Ecosystem::Opensuse(v)),
        ("opensuse-tumbleweed", _) => Some(Ecosystem::Opensuse(0)),
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
    let found = read_packages(runner, eco, root)?;
    // Every distribution image has packages; none means the database was not
    // found or not read, and reporting "no CVEs" for it would be a lie.
    if found.is_empty() {
        return Err(ContainerError::Export(
            "no installed packages found in the container's package database".to_owned(),
        ));
    }
    Ok(found)
}

fn read_packages(
    runner: &dyn ProcessRunner,
    eco: Ecosystem,
    root: &Path,
) -> Result<Vec<PackageRef>, ContainerError> {
    match eco {
        Ecosystem::Debian(_) | Ecosystem::Ubuntu(_) => {
            let status = std::fs::read_to_string(root.join("root/var/lib/dpkg/status"))
                .map_err(|e| ContainerError::Export(e.to_string()))?;
            Ok(crate::dpkg::parse_status(&status, eco))
        }
        Ecosystem::Alpine(_) => {
            let installed = std::fs::read_to_string(root.join("root/lib/apk/db/installed"))
                .map_err(|e| ContainerError::Export(e.to_string()))?;
            Ok(crate::apk::parse_installed(&installed, eco))
        }
        Ecosystem::Fedora(_)
        | Ecosystem::Rocky(_)
        | Ecosystem::Alma(_)
        | Ecosystem::Rhel(_)
        | Ecosystem::Opensuse(_) => {
            // Fedora 36+ and RHEL 9+ keep the database in /usr/lib/sysimage/rpm;
            // /var/lib/rpm is only a symlink to it there.
            let sysimage = root.join("root/usr/lib/sysimage/rpm");
            let db = if sysimage.is_dir() {
                sysimage
            } else {
                root.join("root/var/lib/rpm")
            };
            let out = runner
                .run(
                    Program::Rpm,
                    &[
                        "--dbpath",
                        db.to_str().unwrap_or_default(),
                        "-qa",
                        "--qf",
                        crate::rpm::QUERY_FORMAT,
                    ],
                )
                .map_err(|_| ContainerError::HostToolMissing("rpm".to_owned()))?;
            if !out.success {
                return Err(ContainerError::Export(
                    "rpm could not read the container's database".to_owned(),
                ));
            }
            crate::rpm::parse_installed(&String::from_utf8_lossy(&out.stdout), eco)
                .map_err(|e| ContainerError::Export(e.to_string()))
        }
        Ecosystem::Arch => {
            let db = root.join("root/var/lib/pacman");
            let out = runner
                .run(
                    Program::Pacman,
                    &["-Q", "--dbpath", db.to_str().unwrap_or_default()],
                )
                .map_err(|_| ContainerError::HostToolMissing("pacman".to_owned()))?;
            if !out.success {
                return Err(ContainerError::Export(
                    "pacman could not read the container's database".to_owned(),
                ));
            }
            Ok(pacman_packages(&String::from_utf8_lossy(&out.stdout), eco))
        }
        Ecosystem::Go | Ecosystem::Crates => Err(ContainerError::Unsupported(
            "a language ecosystem".to_owned(),
        )),
    }
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
    use amivuln_core::{ProcessOutput, Version};

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
        let leap = "ID=\"opensuse-leap\"\nVERSION_ID=\"15.6\"\n";
        assert_eq!(
            ecosystem_from_os_release(leap),
            Some(Ecosystem::Opensuse(1506))
        );
        assert_eq!(
            ecosystem_from_os_release("ID=\"opensuse-leap\"\nVERSION_ID=\"16.0\"\n"),
            Some(Ecosystem::Opensuse(1600))
        );
        // Tumbleweed has a date for VERSION_ID and one rolling ecosystem.
        assert_eq!(
            ecosystem_from_os_release("ID=\"opensuse-tumbleweed\"\nVERSION_ID=\"20251107\"\n"),
            Some(Ecosystem::Opensuse(0))
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
        let found = crate::dpkg::parse_status(status, Ecosystem::Debian(12));
        let names: Vec<&str> = found.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["nginx", "curl", "libssl3"]);
        assert_eq!(found[0].source_name, None);
        assert_eq!(found[2].source_name.as_deref(), Some("openssl"));
        assert!(matches!(found[0].version, Version::Deb(_)));
    }

    #[test]
    fn apk_installed_is_parsed() {
        let installed = "P:busybox\nV:1.36.1-r5\no:busybox\nA:x86_64\n\nP:libcrypto3\nV:3.1.4-r0\no:openssl\nA:x86_64\n\n";
        let found = crate::apk::parse_installed(installed, Ecosystem::Alpine(319));
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
        let rpm = crate::rpm::parse_installed(
            "1\tnginx\t1.26.2\t1.fc41\tx86_64\tnginx-1.26.2-1.fc41.src.rpm\n(none)\topenssl\t3.2.2\t1.fc41\tx86_64\topenssl-3.2.2-1.fc41.src.rpm\n",
            Ecosystem::Fedora(41),
        )
        .unwrap();
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
                _ => Err(amivuln_core::ProcessError::NotInstalled(program)),
            }
        }

        fn stream(
            &self,
            program: Program,
            args: &[&str],
        ) -> Result<Box<dyn amivuln_core::ProcessStream>, amivuln_core::ProcessError> {
            assert_eq!(args.first(), Some(&"export"), "only export is streamed");
            let file = std::fs::File::open(&self.tar_path)
                .map_err(|e| amivuln_core::ProcessError::Io(program, e.to_string()))?;
            Ok(Box::new(FileStream {
                file,
                success: true,
            }))
        }
    }

    /// A finished export read from a file, standing in for the runtime.
    pub(crate) struct FileStream {
        pub(crate) file: std::fs::File,
        pub(crate) success: bool,
    }
    impl Read for FileStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.file.read(buf)
        }
    }
    impl amivuln_core::ProcessStream for FileStream {
        fn finish(self: Box<Self>) -> Result<bool, amivuln_core::ProcessError> {
            Ok(self.success)
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
    use amivuln_core::ProcessOutput;

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
        // Only the copied files land in the scratch tree: the archive is not stored.
        assert!(!dest.join("rootfs.tar").exists());
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

    #[test]
    fn a_member_that_climbs_out_of_the_export_is_refused() {
        // tar::Builder refuses `..` names, so the header is written raw.
        let mut bytes = Vec::new();
        {
            let mut tar = tar::Builder::new(&mut bytes);
            let mut header = tar::Header::new_gnu();
            let name = b"var/lib/rpm/../../../../outside";
            header.as_old_mut().name[..name.len()].copy_from_slice(name);
            header.set_size(1);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_cksum();
            tar.append(&header, &b"x"[..]).unwrap();
            tar.finish().unwrap();
        }
        let dir = tempfile::tempdir().unwrap();
        let tar_path = dir.path().join("fixture.tar");
        std::fs::write(&tar_path, &bytes).unwrap();
        let runtime = ScriptedRuntime { tar_path };
        let err = export(&runtime, "web", &dir.path().join("export")).unwrap_err();
        assert!(err.to_string().contains("unsafe path"), "{err}");
        assert!(!dir.path().join("outside").exists());
    }

    #[test]
    fn symlink_targets_stay_inside_the_container() {
        let at = |link: &str, target: &str| resolve_link(Path::new(link), Path::new(target));
        assert_eq!(
            at("etc/os-release", "../usr/lib/os-release"),
            PathBuf::from("usr/lib/os-release")
        );
        // An absolute target is the container's, not the host's.
        assert_eq!(
            at("etc/os-release", "/usr/lib/os-release"),
            PathBuf::from("usr/lib/os-release")
        );
        assert_eq!(
            at("etc/os-release", "../../../../etc/shadow"),
            PathBuf::from("etc/shadow")
        );
        assert_eq!(
            clean_member(Path::new("./etc/os-release")),
            Some(PathBuf::from("etc/os-release"))
        );
        assert_eq!(clean_member(Path::new("a/../b")), None);
    }

    /// Appends one member with an explicit entry type to a tar under test.
    fn add_member(
        tar: &mut tar::Builder<&mut Vec<u8>>,
        name: &str,
        kind: tar::EntryType,
        data: &[u8],
    ) {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(kind);
        header.set_size(data.len() as u64);
        header.set_cksum();
        tar.append_data(&mut header, name, data).unwrap();
    }

    /// Regression: the `var/lib/rpm/` directory entry matched the wanted
    /// prefix and was written as an empty file, so the database inside it
    /// could not be extracted and every UBI container failed.
    #[test]
    fn a_rpm_directory_entry_does_not_block_the_database() {
        let mut bytes = Vec::new();
        {
            let mut tar = tar::Builder::new(&mut bytes);
            add_member(
                &mut tar,
                "etc/os-release",
                tar::EntryType::Regular,
                b"ID=rhel\nVERSION_ID=\"9.4\"\n",
            );
            add_member(&mut tar, "var/lib/rpm/", tar::EntryType::Directory, b"");
            add_member(
                &mut tar,
                "var/lib/rpm/rpmdb.sqlite",
                tar::EntryType::Regular,
                b"db",
            );
            tar.finish().unwrap();
        }
        let dir = tempfile::tempdir().unwrap();
        let tar_path = dir.path().join("fixture.tar");
        std::fs::write(&tar_path, &bytes).unwrap();
        let runtime = ScriptedRuntime { tar_path };
        let dest = dir.path().join("export");
        assert_eq!(export(&runtime, "ubi", &dest).unwrap(), Ecosystem::Rhel(9));
        assert!(dest.join("root/var/lib/rpm/rpmdb.sqlite").is_file());
    }

    #[test]
    fn an_export_over_the_limit_is_refused_while_it_streams() {
        let tar = build_tar(&[
            ("etc/os-release", b"ID=debian\nVERSION_ID=13\n"),
            ("usr/share/filler", &vec![1u8; 4096]),
        ]);
        let dir = tempfile::tempdir().unwrap();
        let tar_path = dir.path().join("fixture.tar");
        std::fs::write(&tar_path, &tar).unwrap();
        let mut stream = ScriptedRuntime { tar_path }
            .stream(Program::Podman, &["export", "web"])
            .unwrap();
        let err = extract_wanted(&mut stream, &dir.path().join("export"), 1024).unwrap_err();
        assert!(
            err.to_string().contains("larger than the size limit"),
            "{err}"
        );
        // A limit that fits reads the same archive.
        let mut stream = ScriptedRuntime {
            tar_path: dir.path().join("fixture.tar"),
        }
        .stream(Program::Podman, &["export", "web"])
        .unwrap();
        extract_wanted(&mut stream, &dir.path().join("export2"), 1 << 20).unwrap();
        assert!(dir.path().join("export2/root/etc/os-release").is_file());
    }

    /// Regression: the container reader dropped the source package name, and
    /// openSUSE advisories are filed under it (`libopenssl3` is built from
    /// `openssl-3`), so a container with a vulnerable library read as clean.
    #[test]
    fn a_container_keeps_the_source_package_of_each_rpm() {
        let found = crate::rpm::parse_installed(
            "(none)\tlibopenssl3\t3.1.4\t150600.5.12.1\tx86_64\topenssl-3-3.1.4-150600.5.12.1.src.rpm\n\
             (none)\tgpg-pubkey\t3dbdc284\t53a46b5f\t(none)\t(none)\n",
            Ecosystem::Opensuse(1506),
        )
        .unwrap();
        assert_eq!(found.len(), 1, "gpg-pubkey is not software");
        assert_eq!(found[0].name, "libopenssl3");
        assert_eq!(found[0].source_name.as_deref(), Some("openssl-3"));
    }

    /// Regression: the pacman database lives in `var/lib/pacman/local/<pkg>/desc`,
    /// which was never extracted, so an Arch container read as unreadable.
    #[test]
    fn the_pacman_database_is_extracted_and_other_files_called_status_are_not() {
        let big = vec![0u8; 65 * 1024 * 1024];
        let tar = build_tar(&[
            ("etc/os-release", b"ID=arch\n"),
            ("var/lib/pacman/local/acl-2.4.0-1/desc", b"%NAME%\nacl\n"),
            // An application file with a database-like name, over the limit.
            ("srv/app/status", &big),
        ]);
        let dir = tempfile::tempdir().unwrap();
        let tar_path = dir.path().join("fixture.tar");
        std::fs::write(&tar_path, &tar).unwrap();
        let dest = dir.path().join("export");
        let eco = export(&ScriptedRuntime { tar_path }, "arch", &dest).unwrap();
        assert_eq!(eco, Ecosystem::Arch);
        assert!(
            dest.join("root/var/lib/pacman/local/acl-2.4.0-1/desc")
                .is_file()
        );
        assert!(!dest.join("root/srv/app/status").exists());
    }

    /// Answers `rpm` with fixed output and remembers the `--dbpath` it got.
    struct FakeRpm {
        success: bool,
        stdout: &'static str,
        dbpath: std::sync::Mutex<String>,
    }
    impl ProcessRunner for FakeRpm {
        fn run(
            &self,
            _: Program,
            args: &[&str],
        ) -> Result<ProcessOutput, amivuln_core::ProcessError> {
            if let Some(i) = args.iter().position(|a| *a == "--dbpath") {
                *self.dbpath.lock().unwrap() = args[i + 1].to_owned();
            }
            Ok(ProcessOutput {
                success: self.success,
                stdout: self.stdout.as_bytes().to_vec(),
            })
        }
    }

    /// Regression: Fedora 36+ keeps the database in /usr/lib/sysimage/rpm and
    /// /var/lib/rpm is a symlink, so only the link was extracted and the
    /// container reported zero packages as a complete result.
    #[test]
    fn the_sysimage_rpm_database_is_extracted_and_read() {
        let mut bytes = Vec::new();
        {
            let mut tar = tar::Builder::new(&mut bytes);
            add_member(
                &mut tar,
                "etc/os-release",
                tar::EntryType::Regular,
                b"ID=fedora\nVERSION_ID=44\n",
            );
            add_member(
                &mut tar,
                "usr/lib/sysimage/rpm/",
                tar::EntryType::Directory,
                b"",
            );
            add_member(
                &mut tar,
                "usr/lib/sysimage/rpm/rpmdb.sqlite",
                tar::EntryType::Regular,
                b"db",
            );
            let mut link = tar::Header::new_gnu();
            link.set_entry_type(tar::EntryType::Symlink);
            link.set_size(0);
            tar.append_link(&mut link, "var/lib/rpm", "../../usr/lib/sysimage/rpm")
                .unwrap();
            tar.finish().unwrap();
        }
        let dir = tempfile::tempdir().unwrap();
        let tar_path = dir.path().join("fixture.tar");
        std::fs::write(&tar_path, &bytes).unwrap();
        let dest = dir.path().join("export");
        let eco = export(&ScriptedRuntime { tar_path }, "f44", &dest).unwrap();
        assert!(
            dest.join("root/usr/lib/sysimage/rpm/rpmdb.sqlite")
                .is_file()
        );
        let rpm = FakeRpm {
            success: true,
            stdout: "(none)\tbash\t5.2.37\t1.fc44\tx86_64\tbash-5.2.37-1.fc44.src.rpm\n",
            dbpath: std::sync::Mutex::default(),
        };
        let found = packages(&rpm, eco, &dest).unwrap();
        assert_eq!(found[0].name, "bash");
        assert!(rpm.dbpath.lock().unwrap().ends_with("usr/lib/sysimage/rpm"));
    }

    #[test]
    fn an_empty_or_unreadable_database_is_an_error_not_a_clean_result() {
        let dir = tempfile::tempdir().unwrap();
        let empty = FakeRpm {
            success: true,
            stdout: "",
            dbpath: std::sync::Mutex::default(),
        };
        let err = packages(&empty, Ecosystem::Fedora(44), dir.path()).unwrap_err();
        assert!(err.to_string().contains("no installed packages"), "{err}");
        let failed = FakeRpm {
            success: false,
            stdout: "",
            dbpath: std::sync::Mutex::default(),
        };
        let err = packages(&failed, Ecosystem::Fedora(44), dir.path()).unwrap_err();
        assert!(err.to_string().contains("could not read"), "{err}");
    }
}
