// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Installed package lookup on Debian and Ubuntu, read from the dpkg database.
//!
//! No program is run: `/var/lib/dpkg/status` lists the packages and
//! `/var/lib/dpkg/info/*.list` the files each one owns. Every read is bounded.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use amivuln_core::{Ecosystem, PackageRef, Provenance};

use crate::{PackageResolver, ResolveError};

/// Largest database file read.
const MAX_DB_BYTES: u64 = 256 * 1024 * 1024;
/// Largest per-package file list read.
const MAX_LIST_BYTES: u64 = 64 * 1024 * 1024;

/// One installed package with the architecture dpkg records for it.
struct Entry {
    package: PackageRef,
    arch: Option<String>,
}

/// Reads at most `limit` bytes of a text file.
pub(crate) fn read_bounded(path: &Path, limit: u64) -> Result<String, ResolveError> {
    let unreadable =
        |e: std::io::Error| ResolveError::Unreadable(format!("{}: {e}", path.display()));
    let file = std::fs::File::open(path).map_err(unreadable)?;
    let mut text = String::new();
    file.take(limit + 1)
        .read_to_string(&mut text)
        .map_err(unreadable)?;
    if text.len() as u64 > limit {
        return Err(ResolveError::Unreadable(format!(
            "{} is larger than {limit} bytes",
            path.display()
        )));
    }
    Ok(text)
}

/// Parses `status` content into the installed packages.
///
/// OSV keys Debian and Ubuntu advisories by the source package and its
/// version, so the `Source:` field (`openssl`, or `lvm2 (2.03.31-2)` when the
/// version differs) names what a binary such as `libssl3` is asked about as. A
/// signed package is asked about as what `Built-Using:` says was signed. A
/// package that was removed but kept its configuration (`config-files`) is not
/// installed and is skipped.
pub(crate) fn parse_status(status: &str, eco: Ecosystem) -> Vec<PackageRef> {
    entries(status, eco)
        .into_iter()
        .map(|e| e.package)
        .collect()
}

fn entries(status: &str, eco: Ecosystem) -> Vec<Entry> {
    let mut out = Vec::new();
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
        if fields
            .get("Status")
            .is_some_and(|s| s.split_whitespace().last() != Some("installed"))
        {
            continue;
        }
        let Ok(mut package) = crate::from_name_version(eco, name, version) else {
            continue;
        };
        // Read from the database, so a missing `Source:` means the source is
        // the package itself, not that nobody said.
        package.provenance = Provenance::PackageDb;
        if let Some((source, source_version)) = fields.get("Source").map(|s| source_field(s)) {
            let signed = fields
                .get("Built-Using")
                .filter(|_| is_signing_source(eco, source))
                .and_then(|built| built_from(source, built));
            let (source, source_version) = signed.unwrap_or((source, source_version));
            crate::set_source(&mut package, source, source_version);
            if package.source_name.as_deref() == Some(package.name.as_str()) {
                package.source_name = None;
            }
        }
        out.push(Entry {
            package,
            arch: fields.get("Architecture").map(|a| (*a).to_owned()),
        });
    }
    out
}

/// `name (version)`, the version only when it is not the binary's.
fn source_field(field: &str) -> (&str, Option<&str>) {
    match field.split_once(' ') {
        Some((name, version)) => (
            name,
            version
                .trim()
                .strip_prefix('(')
                .and_then(|v| v.strip_suffix(')')),
        ),
        None => (field, None),
    }
}

/// Whether advisories name the source that was signed instead of this one.
/// Debian files none under a signed source; Ubuntu does for its boot loaders,
/// so only its kernels are looked through.
fn is_signing_source(eco: Ecosystem, source: &str) -> bool {
    source.starts_with("linux-signed")
        || (matches!(eco, Ecosystem::Debian(_)) && source.contains("-signed"))
}

/// The source and version a signed package was built from, out of a
/// `Built-Using:` field such as `linux (= 6.12.118-1)`.
fn built_from<'a>(signed: &str, built_using: &'a str) -> Option<(&'a str, Option<&'a str>)> {
    let mut entries = built_using.split(',').filter_map(|entry| {
        let (name, version) = entry.trim().split_once(" (= ")?;
        Some((name, version.strip_suffix(')')?))
    });
    let (name, version) = if signed.starts_with("linux-signed") {
        entries.find(|(name, _)| name.starts_with("linux"))?
    } else {
        entries.next()?
    };
    Some((name, Some(version)))
}

/// The same file seen through `/bin` and `/usr/bin` (merged `/usr`): dpkg
/// lists the path the package shipped, which may not be the one the user typed.
pub(crate) fn path_variants(path: &str) -> Vec<String> {
    let mut variants = vec![path.to_owned()];
    for dir in ["bin", "sbin", "lib", "lib64"] {
        if let Some(rest) = path.strip_prefix(&format!("/usr/{dir}/")) {
            variants.push(format!("/{dir}/{rest}"));
        } else if let Some(rest) = path.strip_prefix(&format!("/{dir}/")) {
            variants.push(format!("/usr/{dir}/{rest}"));
        }
    }
    variants
}

/// Resolver backed by the dpkg database files.
#[derive(Debug, Clone)]
pub struct DpkgResolver {
    eco: Ecosystem,
    status: PathBuf,
    info: PathBuf,
}

impl DpkgResolver {
    /// A resolver for the running system.
    #[must_use]
    pub fn new(eco: Ecosystem) -> Self {
        Self::under(eco, Path::new("/"))
    }

    /// A resolver for a dpkg database below `root`.
    #[must_use]
    pub fn under(eco: Ecosystem, root: &Path) -> Self {
        let base = root.join("var/lib/dpkg");
        Self {
            eco,
            status: base.join("status"),
            info: base.join("info"),
        }
    }

    fn installed(&self) -> Result<Vec<Entry>, ResolveError> {
        Ok(entries(
            &read_bounded(&self.status, MAX_DB_BYTES)?,
            self.eco,
        ))
    }
}

impl DpkgResolver {
    /// For each path, the `info/<stem>.list` names that list it. Every list
    /// is read once, however many paths are asked.
    fn stems_by_path(&self, paths: &[&str]) -> Result<Vec<Vec<String>>, ResolveError> {
        let mut wanted: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for (i, path) in paths.iter().enumerate() {
            for variant in path_variants(path.trim_end_matches('/')) {
                wanted.insert(variant, i);
            }
        }
        let dir = std::fs::read_dir(&self.info)
            .map_err(|e| ResolveError::Unreadable(format!("{}: {e}", self.info.display())))?;
        let mut owners: Vec<Vec<String>> = paths.iter().map(|_| Vec::new()).collect();
        for item in dir.flatten() {
            let file = item.file_name();
            let Some(stem) = file.to_str().and_then(|n| n.strip_suffix(".list")) else {
                continue;
            };
            let Ok(list) = read_bounded(&item.path(), MAX_LIST_BYTES) else {
                continue;
            };
            for line in list.lines() {
                if let Some(&i) = wanted.get(line)
                    && let Some(stems) = owners.get_mut(i)
                {
                    stems.push(stem.to_owned());
                }
            }
        }
        for stems in &mut owners {
            stems.sort();
            stems.dedup();
        }
        Ok(owners)
    }

    /// The installed package behind the owner stems of one path.
    fn package_of(
        path: &str,
        stems: &[String],
        installed: &[Entry],
    ) -> Result<PackageRef, ResolveError> {
        match stems {
            [one] => {
                // `libc6:amd64` for a multiarch package, `bash` otherwise.
                let (name, arch) = one
                    .split_once(':')
                    .map_or((one.as_str(), None), |(n, a)| (n, Some(a)));
                installed
                    .iter()
                    .find(|e| {
                        e.package.name == name && arch.is_none_or(|a| e.arch.as_deref() == Some(a))
                    })
                    .map(|e| e.package.clone())
                    .ok_or_else(|| ResolveError::NotFound(path.to_owned()))
            }
            [] => Err(ResolveError::NotFound(path.to_owned())),
            many => Err(ResolveError::Ambiguous(path.to_owned(), many.join(", "))),
        }
    }
}

impl PackageResolver for DpkgResolver {
    fn owner_of(&self, path: &str) -> Result<PackageRef, ResolveError> {
        self.owners_of(&[path.to_owned()])
            .into_iter()
            .next()
            .unwrap_or_else(|| Err(ResolveError::NotFound(path.to_owned())))
    }

    fn owners_of(&self, paths: &[String]) -> Vec<Result<PackageRef, ResolveError>> {
        let fail = |e: &ResolveError| {
            paths
                .iter()
                .map(|_| Err(ResolveError::Unreadable(e.to_string())))
                .collect()
        };
        let asked: Vec<&str> = paths.iter().map(String::as_str).collect();
        let stems = match self.stems_by_path(&asked) {
            Ok(s) => s,
            Err(e) => return fail(&e),
        };
        let installed = match self.installed() {
            Ok(i) => i,
            Err(e) => return fail(&e),
        };
        paths
            .iter()
            .zip(stems)
            .map(|(path, stems)| {
                if path.chars().any(char::is_control) {
                    return Err(ResolveError::NotFound(path.escape_default().to_string()));
                }
                Self::package_of(path, &stems, &installed)
            })
            .collect()
    }

    fn by_name(&self, name: &str) -> Result<PackageRef, ResolveError> {
        let found: Vec<Entry> = self
            .installed()?
            .into_iter()
            .filter(|e| e.package.name == name)
            .collect();
        let Some(first) = found.first() else {
            return Err(ResolveError::NotFound(name.to_owned()));
        };
        // Several architectures of one library at one version are one answer.
        if found
            .iter()
            .any(|e| e.package.version.to_string() != first.package.version.to_string())
        {
            let versions: Vec<String> = found
                .iter()
                .map(|e| e.package.version.to_string())
                .collect();
            return Err(ResolveError::Ambiguous(
                name.to_owned(),
                versions.join(", "),
            ));
        }
        Ok(first.package.clone())
    }

    fn list_all(&self) -> Result<Vec<PackageRef>, ResolveError> {
        let mut pkgs = parse_status(&read_bounded(&self.status, MAX_DB_BYTES)?, self.eco);
        pkgs.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(pkgs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATUS: &str = "\
Package: bash
Status: install ok installed
Architecture: amd64
Version: 5.2.15-2+b7

Package: libssl3
Status: install ok installed
Architecture: amd64
Source: openssl (3.0.11-1)
Version: 3.0.11-1~deb12u2
Description: Secure Sockets Layer toolkit
 continued line

Package: oldpkg
Status: deinstall ok config-files
Architecture: amd64
Version: 1.0-1

Package: libc6
Status: install ok installed
Architecture: amd64
Source: glibc
Version: 2.36-9+deb12u7
";

    fn tree() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("var/lib/dpkg");
        std::fs::create_dir_all(base.join("info")).unwrap();
        std::fs::write(base.join("status"), STATUS).unwrap();
        std::fs::write(
            base.join("info/bash.list"),
            "/bin/bash\n/usr/share/doc/bash\n",
        )
        .unwrap();
        std::fs::write(
            base.join("info/libc6:amd64.list"),
            "/lib/x86_64-linux-gnu/libc.so.6\n",
        )
        .unwrap();
        std::fs::write(
            base.join("info/libssl3:amd64.list"),
            "/usr/lib/x86_64-linux-gnu/libssl.so.3\n",
        )
        .unwrap();
        dir
    }

    #[test]
    fn removed_packages_are_skipped_and_sources_are_kept() {
        let found = parse_status(STATUS, Ecosystem::Debian(12));
        let names: Vec<&str> = found.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(
            names,
            ["bash", "libssl3", "libc6"],
            "config-files is not installed"
        );
        assert_eq!(found[0].source_name, None);
        assert_eq!(found[1].source_name.as_deref(), Some("openssl"));
        assert_eq!(found[2].source_name.as_deref(), Some("glibc"));
    }

    /// Name, source and source version of each package of a status file.
    fn sources(status: &str, eco: Ecosystem) -> Vec<(String, Option<String>, Option<String>)> {
        parse_status(status, eco)
            .into_iter()
            .map(|p| (p.name, p.source_name, p.source_vr))
            .collect()
    }

    fn row(
        name: &str,
        source: Option<&str>,
        vr: Option<&str>,
    ) -> (String, Option<String>, Option<String>) {
        (
            name.to_owned(),
            source.map(str::to_owned),
            vr.map(str::to_owned),
        )
    }

    #[test]
    fn the_version_of_the_source_is_kept_when_it_differs() {
        let status = "Package: dmsetup\nSource: lvm2 (2.03.31-2)\nVersion: 2:1.02.205-2\n\n\
                      Package: bash\nSource: bash (5.2.15-2)\nVersion: 5.2.15-2+b7\n\n\
                      Package: libssl3\nSource: openssl\nVersion: 3.0.11-1\n";
        assert_eq!(
            sources(status, Ecosystem::Debian(13)),
            [
                row("dmsetup", Some("lvm2"), Some("2.03.31-2")),
                row("bash", None, Some("5.2.15-2")),
                row("libssl3", Some("openssl"), None),
            ]
        );
    }

    /// A signed image is packaged by a source of its own that advisories do not
    /// name: what was signed is what has them.
    #[test]
    fn a_signed_package_is_judged_by_what_was_signed() {
        let debian = "Package: linux-image-6.12.118+deb13-amd64\n\
                      Source: linux-signed-amd64 (6.12.118+1)\nVersion: 6.12.118-1\n\
                      Built-Using: linux (= 6.12.118-1)\n\n\
                      Package: grub-efi-amd64-signed\n\
                      Source: grub-efi-amd64-signed (1+2.12+9)\nVersion: 1+2.12+9\n\
                      Built-Using: grub2 (= 2.12-9)\n\n\
                      Package: linux-image-6.12.1-amd64\n\
                      Source: linux-signed-amd64 (6.12.1+1)\nVersion: 6.12.1-1\n";
        assert_eq!(
            sources(debian, Ecosystem::Debian(13)),
            [
                row("linux-image-6.12.118+deb13-amd64", Some("linux"), None),
                row("grub-efi-amd64-signed", Some("grub2"), Some("2.12-9")),
                row("linux-image-6.12.1-amd64", Some("linux"), None),
            ]
        );
        // Ubuntu files advisories under its signed boot loader's own name.
        let ubuntu = "Package: grub-efi-amd64-signed\nSource: grub2-signed (1.215)\n\
                      Version: 1.215+2.14-2ubuntu1\nBuilt-Using: grub2 (= 2.14-2ubuntu1)\n\n\
                      Package: linux-image-6.8.0-31-generic\nSource: linux-signed-hwe-6.8 (6.8.0-31.31)\n\
                      Version: 6.8.0-31.31\nBuilt-Using: linux-hwe-6.8 (= 6.8.0-31.31)\n";
        assert_eq!(
            sources(ubuntu, Ecosystem::Ubuntu(2404)),
            [
                row("grub-efi-amd64-signed", Some("grub2-signed"), Some("1.215")),
                row("linux-image-6.8.0-31-generic", Some("linux-hwe-6.8"), None),
            ]
        );
    }

    #[test]
    fn a_package_of_the_database_is_not_user_input() {
        let status = "Package: bash\nStatus: install ok installed\nVersion: 5.2-1\n";
        let found = parse_status(status, Ecosystem::Debian(12));
        assert_eq!(found[0].provenance, amivuln_core::Provenance::PackageDb);
    }

    #[test]
    fn the_resolver_lists_and_finds_by_name() {
        let dir = tree();
        let r = DpkgResolver::under(Ecosystem::Debian(12), dir.path());
        let all = r.list_all().unwrap();
        assert_eq!(
            all.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(),
            ["bash", "libc6", "libssl3"]
        );
        assert_eq!(
            r.by_name("bash").unwrap().version.to_string(),
            "5.2.15-2+b7"
        );
        assert!(matches!(
            r.by_name("oldpkg"),
            Err(ResolveError::NotFound(_))
        ));
        assert!(matches!(r.by_name("nope"), Err(ResolveError::NotFound(_))));
    }

    #[test]
    fn a_file_is_traced_to_its_package_through_merged_usr() {
        let dir = tree();
        let r = DpkgResolver::under(Ecosystem::Debian(12), dir.path());
        assert_eq!(r.owner_of("/bin/bash").unwrap().name, "bash");
        // The list says /bin/bash; the user typed the /usr path.
        assert_eq!(r.owner_of("/usr/bin/bash").unwrap().name, "bash");
        assert_eq!(
            r.owner_of("/usr/lib/x86_64-linux-gnu/libc.so.6")
                .unwrap()
                .name,
            "libc6"
        );
        assert!(matches!(
            r.owner_of("/etc/unowned"),
            Err(ResolveError::NotFound(_))
        ));
        assert!(matches!(
            r.owner_of("/bin/\nbash"),
            Err(ResolveError::NotFound(_))
        ));
    }

    #[test]
    fn many_paths_are_answered_in_order_from_one_pass() {
        let dir = tree();
        let r = DpkgResolver::under(Ecosystem::Debian(12), dir.path());
        let paths = [
            "/usr/bin/bash".to_owned(),
            "/etc/unowned".to_owned(),
            "/lib/x86_64-linux-gnu/libc.so.6".to_owned(),
        ];
        let got = r.owners_of(&paths);
        assert_eq!(got.len(), 3);
        assert_eq!(got[0].as_ref().unwrap().name, "bash");
        assert!(matches!(got[1], Err(ResolveError::NotFound(_))));
        assert_eq!(got[2].as_ref().unwrap().name, "libc6");
    }

    #[test]
    fn a_missing_database_is_reported_not_hidden() {
        let dir = tempfile::tempdir().unwrap();
        let r = DpkgResolver::under(Ecosystem::Debian(12), dir.path());
        assert!(matches!(r.list_all(), Err(ResolveError::Unreadable(_))));
    }

    #[test]
    fn two_versions_of_one_name_are_ambiguous() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("var/lib/dpkg");
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(
            base.join("status"),
            "Package: libx\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.0-1\n\nPackage: libx\nStatus: install ok installed\nArchitecture: i386\nVersion: 1.0-2\n",
        )
        .unwrap();
        let r = DpkgResolver::under(Ecosystem::Debian(12), dir.path());
        assert!(matches!(
            r.by_name("libx"),
            Err(ResolveError::Ambiguous(..))
        ));
    }
}
