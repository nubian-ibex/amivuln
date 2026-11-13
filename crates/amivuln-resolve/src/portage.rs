// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Installed package lookup on Gentoo, read from the Portage database.
//!
//! No program is run: `/var/db/pkg/<category>/<name>-<version>/` holds one
//! directory per installed package, with `SLOT` and `CONTENTS` inside. A name
//! is `category/name` (`dev-libs/openssl`), the way advisories write it.

use std::path::{Path, PathBuf};

use amivuln_core::{Ecosystem, PackageRef, Provenance, Version};
use amivuln_version::GentooVersion;

use crate::dpkg::{path_variants, read_bounded};
use crate::{PackageResolver, ResolveError};

/// Largest `CONTENTS` or `SLOT` file read.
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
/// Most installed packages listed; a real system has a few thousand.
const MAX_PACKAGES: usize = 100_000;

/// One installed package and where its files are recorded.
struct Installed {
    package: PackageRef,
    dir: PathBuf,
}

/// Splits a directory name such as `glibc-2.38-r10` into the package name and
/// the version: at the first `-` after which the rest is a valid ebuild
/// version, so a name may itself contain digits and hyphens (`gtk+-3.24.41`).
fn split_pf(pf: &str) -> Option<(&str, &str)> {
    pf.match_indices('-').find_map(|(at, _)| {
        let (name, version) = (pf.get(..at)?, pf.get(at + 1..)?);
        (!name.is_empty() && GentooVersion::is_valid(version)).then_some((name, version))
    })
}

/// The slot of an installed package: the part of `SLOT` before `/` (the rest
/// is the sub-slot, which advisories do not use).
fn read_slot(dir: &Path) -> Option<String> {
    let text = read_bounded(&dir.join("SLOT"), 4096).ok()?;
    let slot = text.lines().next()?.split('/').next()?.trim();
    (!slot.is_empty()).then(|| slot.to_owned())
}

/// Resolver backed by the Portage database files.
#[derive(Debug, Clone)]
pub struct PortageResolver {
    db: PathBuf,
}

impl PortageResolver {
    /// A resolver for the running system.
    #[must_use]
    pub fn new() -> Self {
        Self::under(Path::new("/"))
    }

    /// A resolver for a Portage database below `root`.
    #[must_use]
    pub fn under(root: &Path) -> Self {
        Self {
            db: root.join("var/db/pkg"),
        }
    }

    fn installed(&self) -> Result<Vec<Installed>, ResolveError> {
        let unreadable =
            |p: &Path, e: std::io::Error| ResolveError::Unreadable(format!("{}: {e}", p.display()));
        let mut out = Vec::new();
        for category in std::fs::read_dir(&self.db)
            .map_err(|e| unreadable(&self.db, e))?
            .flatten()
        {
            let category_name = category.file_name().to_string_lossy().into_owned();
            // Files and hidden entries sit next to the categories.
            if category_name.starts_with('.') || !category.path().is_dir() {
                continue;
            }
            let Ok(entries) = std::fs::read_dir(category.path()) else {
                continue;
            };
            for entry in entries.flatten() {
                let pf = entry.file_name().to_string_lossy().into_owned();
                let Some((name, version)) = split_pf(&pf) else {
                    continue;
                };
                if out.len() >= MAX_PACKAGES {
                    return Err(ResolveError::Unreadable(format!(
                        "{} lists more than {MAX_PACKAGES} packages",
                        self.db.display()
                    )));
                }
                out.push(Installed {
                    package: PackageRef {
                        ecosystem: Ecosystem::Gentoo,
                        name: format!("{category_name}/{name}"),
                        source_name: None,
                        version: Version::Gentoo(
                            version.parse().unwrap_or_else(|never| match never {}),
                        ),
                        arch: None,
                        slot: read_slot(&entry.path()),
                        provenance: Provenance::PackageDb,
                    },
                    dir: entry.path(),
                });
            }
        }
        out.sort_by(|a, b| {
            a.package.name.cmp(&b.package.name).then_with(|| {
                a.package
                    .version
                    .to_string()
                    .cmp(&b.package.version.to_string())
            })
        });
        Ok(out)
    }
}

impl Default for PortageResolver {
    fn default() -> Self {
        Self::new()
    }
}

/// The path of an `obj` or `sym` line of a `CONTENTS` file. A directory is
/// shared by many packages and owns nothing.
fn recorded_path(line: &str) -> Option<&str> {
    if let Some(rest) = line.strip_prefix("obj ") {
        // `obj <path> <md5> <mtime>`; the path may hold spaces.
        let mut parts = rest.rsplitn(3, ' ');
        parts.next()?;
        parts.next()?;
        parts.next()
    } else if let Some(rest) = line.strip_prefix("sym ") {
        // `sym <path> -> <target> <mtime>`.
        rest.split_once(" -> ").map(|(path, _)| path)
    } else {
        None
    }
}

impl PackageResolver for PortageResolver {
    fn owner_of(&self, path: &str) -> Result<PackageRef, ResolveError> {
        self.owners_of(&[path.to_owned()])
            .into_iter()
            .next()
            .unwrap_or_else(|| Err(ResolveError::NotFound(path.to_owned())))
    }

    fn owners_of(&self, paths: &[String]) -> Vec<Result<PackageRef, ResolveError>> {
        let installed = match self.installed() {
            Ok(i) => i,
            Err(e) => {
                return paths
                    .iter()
                    .map(|_| Err(ResolveError::Unreadable(e.to_string())))
                    .collect();
            }
        };
        let mut wanted: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for (i, path) in paths.iter().enumerate() {
            for variant in path_variants(path.trim_end_matches('/')) {
                wanted.insert(variant, i);
            }
        }
        // For each asked path, the indexes of the packages that record it.
        let mut owners: Vec<Vec<usize>> = paths.iter().map(|_| Vec::new()).collect();
        for (n, pkg) in installed.iter().enumerate() {
            let Ok(contents) = read_bounded(&pkg.dir.join("CONTENTS"), MAX_FILE_BYTES) else {
                continue;
            };
            for line in contents.lines() {
                if let Some(&i) = recorded_path(line).and_then(|p| wanted.get(p))
                    && let Some(list) = owners.get_mut(i)
                    && !list.contains(&n)
                {
                    list.push(n);
                }
            }
        }
        paths
            .iter()
            .zip(owners)
            .map(|(path, list)| {
                if path.chars().any(char::is_control) {
                    return Err(ResolveError::NotFound(path.escape_default().to_string()));
                }
                match list.as_slice() {
                    [one] => installed
                        .get(*one)
                        .map(|i| i.package.clone())
                        .ok_or_else(|| ResolveError::NotFound(path.clone())),
                    [] => Err(ResolveError::NotFound(path.clone())),
                    many => Err(ResolveError::Ambiguous(
                        path.clone(),
                        many.iter()
                            .filter_map(|n| installed.get(*n))
                            .map(|i| i.package.name.clone())
                            .collect::<Vec<_>>()
                            .join(", "),
                    )),
                }
            })
            .collect()
    }

    fn by_name(&self, name: &str) -> Result<PackageRef, ResolveError> {
        // `openssl` or `dev-libs/openssl`.
        let found: Vec<PackageRef> = self
            .installed()?
            .into_iter()
            .map(|i| i.package)
            .filter(|p| p.name == name || p.name.rsplit_once('/').is_some_and(|(_, n)| n == name))
            .collect();
        match found.as_slice() {
            [] => Err(ResolveError::NotFound(name.to_owned())),
            [one] => Ok(one.clone()),
            many => Err(ResolveError::Ambiguous(
                name.to_owned(),
                many.iter()
                    .map(|p| format!("{} {}", p.name, p.version))
                    .collect::<Vec<_>>()
                    .join(", "),
            )),
        }
    }

    fn list_all(&self) -> Result<Vec<PackageRef>, ResolveError> {
        Ok(self.installed()?.into_iter().map(|i| i.package).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("var/db/pkg");
        let add = |cat: &str, pf: &str, slot: &str, contents: &str| {
            let p = db.join(cat).join(pf);
            std::fs::create_dir_all(&p).unwrap();
            std::fs::write(p.join("SLOT"), slot).unwrap();
            std::fs::write(p.join("CONTENTS"), contents).unwrap();
        };
        add(
            "sys-libs",
            "glibc-2.38-r10",
            "2.2\n",
            "dir /usr\ndir /usr/lib64\nobj /usr/lib64/libc.so.6 d41d8cd98f00b204e9800998ecf8427e 1700000000\nsym /usr/lib64/libc.so -> libc.so.6 1700000000\n",
        );
        add(
            "dev-lang",
            "python-3.11.9",
            "3.11/3.11\n",
            "obj /usr/bin/python3.11 aa 1\n",
        );
        add(
            "dev-lang",
            "python-3.12.4",
            "3.12/3.12\n",
            "obj /usr/bin/python3.12 bb 1\n",
        );
        add(
            "x11-libs",
            "gtk+-3.24.41",
            "3\n",
            "obj /usr/lib64/libgtk with space.so cc 1\n",
        );
        add("app-misc", "foo-2-1.0_p1-r2", "0\n", "");
        std::fs::write(db.join("stray-file"), "x").unwrap();
        std::fs::create_dir_all(db.join(".hidden/x-1.0")).unwrap();
        dir
    }

    #[test]
    fn a_directory_name_splits_into_a_name_and_a_version() {
        for (pf, want) in [
            ("glibc-2.38-r10", Some(("glibc", "2.38-r10"))),
            ("gtk+-3.24.41", Some(("gtk+", "3.24.41"))),
            ("foo-2-1.0_p1-r2", Some(("foo-2", "1.0_p1-r2"))),
            ("libxml2-2.12.0", Some(("libxml2", "2.12.0"))),
            ("openssl-3.0.12_rc1", Some(("openssl", "3.0.12_rc1"))),
            ("noversion", None),
            ("-1.0", None),
            ("name-", None),
        ] {
            assert_eq!(split_pf(pf), want, "{pf}");
        }
    }

    #[test]
    fn packages_are_listed_with_their_category_version_and_slot() {
        let dir = tree();
        let r = PortageResolver::under(dir.path());
        let all = r.list_all().unwrap();
        let names: Vec<String> = all
            .iter()
            .map(|p| {
                format!(
                    "{} {} {}",
                    p.name,
                    p.version,
                    p.slot.as_deref().unwrap_or("-")
                )
            })
            .collect();
        assert_eq!(
            names,
            [
                "app-misc/foo-2 1.0_p1-r2 0",
                "dev-lang/python 3.11.9 3.11",
                "dev-lang/python 3.12.4 3.12",
                "sys-libs/glibc 2.38-r10 2.2",
                "x11-libs/gtk+ 3.24.41 3",
            ]
        );
        assert!(all.iter().all(|p| p.ecosystem == Ecosystem::Gentoo));
    }

    #[test]
    fn a_name_is_found_with_or_without_its_category() {
        let dir = tree();
        let r = PortageResolver::under(dir.path());
        assert_eq!(r.by_name("glibc").unwrap().name, "sys-libs/glibc");
        assert_eq!(
            r.by_name("sys-libs/glibc").unwrap().version.to_string(),
            "2.38-r10"
        );
        // Two slots of one package are two answers, never one picked silently.
        assert!(matches!(
            r.by_name("python"),
            Err(ResolveError::Ambiguous(..))
        ));
        assert!(matches!(r.by_name("nope"), Err(ResolveError::NotFound(_))));
    }

    #[test]
    fn a_file_is_traced_to_the_package_that_recorded_it() {
        let dir = tree();
        let r = PortageResolver::under(dir.path());
        assert_eq!(
            r.owner_of("/usr/lib64/libc.so.6").unwrap().name,
            "sys-libs/glibc"
        );
        // A symlink is recorded too; a directory owns nothing.
        assert_eq!(
            r.owner_of("/usr/lib64/libc.so").unwrap().name,
            "sys-libs/glibc"
        );
        assert!(matches!(
            r.owner_of("/usr/lib64"),
            Err(ResolveError::NotFound(_))
        ));
        assert_eq!(
            r.owner_of("/usr/lib64/libgtk with space.so").unwrap().name,
            "x11-libs/gtk+"
        );
        let many = r.owners_of(&["/usr/bin/python3.12".to_owned(), "/etc/none".to_owned()]);
        assert_eq!(many[0].as_ref().unwrap().version.to_string(), "3.12.4");
        assert!(matches!(many[1], Err(ResolveError::NotFound(_))));
        assert!(matches!(
            r.owner_of("/bin/\nx"),
            Err(ResolveError::NotFound(_))
        ));
    }

    #[test]
    fn a_missing_database_is_reported_not_hidden() {
        let dir = tempfile::tempdir().unwrap();
        let r = PortageResolver::under(dir.path());
        assert!(matches!(r.list_all(), Err(ResolveError::Unreadable(_))));
    }
}
