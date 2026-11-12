// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Installed package lookup on Alpine, read from the apk database.
//!
//! No program is run: `/lib/apk/db/installed` holds one stanza per package
//! (`P` name, `V` version, `A` architecture, `o` origin, then `F` directories
//! each followed by the `R` files in it).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use amivuln_core::{Ecosystem, PackageRef, Provenance, Version};

use crate::dpkg::read_bounded;
use crate::{PackageResolver, ResolveError};

/// Largest database read.
const MAX_DB_BYTES: u64 = 256 * 1024 * 1024;

/// Parses the stanzas of `installed` into packages.
///
/// OSV keys Alpine advisories by the origin package, so a subpackage such as
/// `libcrypto3` is asked about as `openssl`.
pub(crate) fn parse_installed(installed: &str, eco: Ecosystem) -> Vec<PackageRef> {
    let mut packages = Vec::new();
    for stanza in installed.split("\n\n") {
        let mut fields: BTreeMap<&str, &str> = BTreeMap::new();
        for line in stanza.lines() {
            // `F:` and `R:` repeat; only the single-valued fields matter here.
            if let Some((key, value)) = line.split_once(':')
                && matches!(key, "P" | "V" | "A" | "o")
            {
                fields.insert(key, value.trim());
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

/// The packages whose stanza lists `path` (without a leading slash).
fn owners_of(installed: &str, path: &str) -> Vec<String> {
    let mut owners = Vec::new();
    for stanza in installed.split("\n\n") {
        let (mut name, mut dir, mut hit) = (None, "", false);
        for line in stanza.lines() {
            match line.split_once(':') {
                Some(("P", v)) => name = Some(v.trim()),
                Some(("F", v)) => dir = v.trim(),
                Some(("R", file)) => {
                    let full = if dir.is_empty() {
                        file.trim().to_owned()
                    } else {
                        format!("{dir}/{}", file.trim())
                    };
                    hit |= full == path;
                }
                _ => {}
            }
        }
        if let (true, Some(name)) = (hit, name) {
            owners.push(name.to_owned());
        }
    }
    owners.sort();
    owners.dedup();
    owners
}

/// Resolver backed by the apk database file.
#[derive(Debug, Clone)]
pub struct ApkResolver {
    eco: Ecosystem,
    db: PathBuf,
}

impl ApkResolver {
    /// A resolver for the running system.
    #[must_use]
    pub fn new(eco: Ecosystem) -> Self {
        Self::under(eco, Path::new("/"))
    }

    /// A resolver for an apk database below `root`.
    #[must_use]
    pub fn under(eco: Ecosystem, root: &Path) -> Self {
        Self {
            eco,
            db: root.join("lib/apk/db/installed"),
        }
    }

    fn text(&self) -> Result<String, ResolveError> {
        read_bounded(&self.db, MAX_DB_BYTES)
    }
}

impl PackageResolver for ApkResolver {
    fn owner_of(&self, path: &str) -> Result<PackageRef, ResolveError> {
        if path.chars().any(char::is_control) {
            return Err(ResolveError::NotFound(path.escape_default().to_string()));
        }
        let text = self.text()?;
        let owners = owners_of(&text, path.trim_start_matches('/').trim_end_matches('/'));
        match owners.as_slice() {
            [name] => parse_installed(&text, self.eco)
                .into_iter()
                .find(|p| &p.name == name)
                .ok_or_else(|| ResolveError::NotFound(path.to_owned())),
            [] => Err(ResolveError::NotFound(path.to_owned())),
            many => Err(ResolveError::Ambiguous(path.to_owned(), many.join(", "))),
        }
    }

    fn by_name(&self, name: &str) -> Result<PackageRef, ResolveError> {
        parse_installed(&self.text()?, self.eco)
            .into_iter()
            .find(|p| p.name == name)
            .ok_or_else(|| ResolveError::NotFound(name.to_owned()))
    }

    fn list_all(&self) -> Result<Vec<PackageRef>, ResolveError> {
        let mut pkgs = parse_installed(&self.text()?, self.eco);
        pkgs.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(pkgs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DB: &str = "\
C:Q1abc=
P:busybox
V:1.36.1-r5
A:x86_64
o:busybox
F:bin
R:busybox
F:etc
R:securetty

C:Q1def=
P:libcrypto3
V:3.1.4-r0
A:x86_64
o:openssl
F:lib
R:libcrypto.so.3

";

    fn tree() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("lib/apk/db")).unwrap();
        std::fs::write(dir.path().join("lib/apk/db/installed"), DB).unwrap();
        dir
    }

    #[test]
    fn stanzas_become_packages_with_their_origin() {
        let found = parse_installed(DB, Ecosystem::Alpine(319));
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].source_name, None);
        assert_eq!(found[1].name, "libcrypto3");
        assert_eq!(found[1].source_name.as_deref(), Some("openssl"));
        assert_eq!(found[1].arch.as_deref(), Some("x86_64"));
    }

    #[test]
    fn the_resolver_finds_by_name_and_by_file() {
        let dir = tree();
        let r = ApkResolver::under(Ecosystem::Alpine(319), dir.path());
        assert_eq!(r.list_all().unwrap().len(), 2);
        assert_eq!(
            r.by_name("busybox").unwrap().version.to_string(),
            "1.36.1-r5"
        );
        assert_eq!(r.owner_of("/bin/busybox").unwrap().name, "busybox");
        assert_eq!(
            r.owner_of("/lib/libcrypto.so.3").unwrap().name,
            "libcrypto3"
        );
        assert!(matches!(
            r.owner_of("/bin/nothing"),
            Err(ResolveError::NotFound(_))
        ));
        assert!(matches!(r.by_name("nope"), Err(ResolveError::NotFound(_))));
    }

    #[test]
    fn a_missing_database_is_reported_not_hidden() {
        let dir = tempfile::tempdir().unwrap();
        let r = ApkResolver::under(Ecosystem::Alpine(319), dir.path());
        assert!(matches!(r.list_all(), Err(ResolveError::Unreadable(_))));
    }
}
