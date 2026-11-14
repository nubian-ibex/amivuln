// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Installed Flatpak runtimes, read from their `manifest.json`.
//!
//! A runtime built by freedesktop-sdk (which the GNOME and KDE runtimes sit
//! on) ships `files/manifest.json`: one module per component with its upstream
//! version and an `x-cpe` block that names the NVD vendor and product, the CVEs
//! the build patched (`patches`) and the ones its maintainers decided do not
//! apply (`ignored`). Nothing is run: the files are read from the installation
//! directories, each bounded.
//!
//! A package here is one component of one runtime: `org.freedesktop.Platform/
//! 25.08/openssl`.

use std::path::PathBuf;

use amivuln_core::{Ecosystem, PackageRef, Provenance, UpstreamInfo, Version};
use serde::Deserialize;

use crate::ResolveError;

/// Largest manifest read; a real one is about 0.5 MB.
const MAX_MANIFEST_BYTES: u64 = 32 * 1024 * 1024;
/// Most components read from one manifest.
const MAX_MODULES: usize = 20_000;

#[derive(Deserialize)]
struct RawManifest {
    #[serde(default)]
    modules: Vec<RawModule>,
}

#[derive(Deserialize)]
struct RawModule {
    #[serde(default)]
    name: String,
    #[serde(default, rename = "x-cpe")]
    cpe: Option<RawCpe>,
}

#[derive(Deserialize)]
struct RawCpe {
    #[serde(default)]
    vendor: Option<String>,
    #[serde(default)]
    product: Option<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    patches: Vec<String>,
    #[serde(default)]
    ignored: Vec<String>,
}

/// One installed runtime and what could not be read from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Runtime {
    /// `org.freedesktop.Platform/25.08`.
    pub id: String,
    /// Components with no version or no product (not checkable), by name.
    pub unchecked: Vec<String>,
}

/// The components of the installed runtimes, and the runtimes they come from.
#[derive(Debug, Default)]
pub struct Runtimes {
    /// One entry per checkable component.
    pub packages: Vec<PackageRef>,
    /// The runtimes found, each with its unchecked components.
    pub runtimes: Vec<Runtime>,
}

/// A CPE name part is lower-case letters, digits and `._+-` only.
fn cpe_part(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-' | b'+')
        })
}

/// The components of one runtime manifest.
///
/// # Errors
///
/// [`ResolveError::Parse`] when the document is not a manifest.
pub fn parse_manifest(
    text: &str,
    runtime: &str,
) -> Result<(Vec<PackageRef>, Vec<String>), ResolveError> {
    let raw: RawManifest =
        serde_json::from_str(text).map_err(|e| ResolveError::Parse(format!("{runtime}: {e}")))?;
    let (mut packages, mut unchecked) = (Vec::new(), Vec::new());
    for module in raw.modules.into_iter().take(MAX_MODULES) {
        let Some(cpe) = module.cpe else {
            unchecked.push(module.name);
            continue;
        };
        let (Some(product), Some(version)) = (cpe.product, cpe.version) else {
            unchecked.push(module.name);
            continue;
        };
        // The vendor defaults to the product, as the builder's own tooling does.
        let vendor = cpe.vendor.unwrap_or_else(|| product.clone());
        if !cpe_part(&vendor) || !cpe_part(&product) || version.is_empty() {
            unchecked.push(module.name);
            continue;
        }
        packages.push(PackageRef {
            ecosystem: Ecosystem::Flatpak,
            name: format!("{runtime}/{product}"),
            source_name: Some(module.name),
            version: Version::Upstream(version.parse().unwrap_or_else(|never| match never {})),
            arch: None,
            slot: None,
            upstream: Some(UpstreamInfo {
                vendor,
                product,
                patched: cpe.patches,
                ignored: cpe.ignored,
            }),
            provenance: Provenance::PackageDb,
        });
    }
    packages.sort_by(|a, b| a.name.cmp(&b.name));
    packages.dedup_by(|a, b| a.name == b.name);
    Ok((packages, unchecked))
}

/// The installation directories: the system one and the user's, where Flatpak
/// itself looks (`FLATPAK_SYSTEM_DIR`, then `/var/lib/flatpak`;
/// `FLATPAK_USER_DIR`, then `$HOME/.local/share/flatpak`).
#[must_use]
pub fn installations(var: impl Fn(&str) -> Option<String>) -> Vec<PathBuf> {
    let dir = |name: &str| var(name).filter(|v| !v.is_empty()).map(PathBuf::from);
    let mut dirs =
        vec![dir("FLATPAK_SYSTEM_DIR").unwrap_or_else(|| PathBuf::from("/var/lib/flatpak"))];
    if let Some(user) = dir("FLATPAK_USER_DIR")
        .or_else(|| dir("HOME").map(|home| home.join(".local/share/flatpak")))
    {
        dirs.push(user);
    }
    dirs
}

/// Reads the runtimes of the installations in `dirs`.
///
/// Only the active commit of each branch is read. A runtime with no
/// `manifest.json` (a runtime not built by freedesktop-sdk) is listed with no
/// components, never skipped silently.
///
/// # Errors
///
/// [`ResolveError::Unreadable`] when a manifest is larger than the limit or
/// cannot be read.
pub fn read_runtimes(dirs: &[PathBuf]) -> Result<Runtimes, ResolveError> {
    let mut out = Runtimes::default();
    for dir in dirs {
        let Ok(ids) = std::fs::read_dir(dir.join("runtime")) else {
            continue;
        };
        let mut ids: Vec<_> = ids.flatten().map(|e| e.path()).collect();
        ids.sort();
        for id_dir in ids {
            let Some(id) = id_dir
                .file_name()
                .and_then(|n| n.to_str())
                .map(str::to_owned)
            else {
                continue;
            };
            let Ok(arches) = std::fs::read_dir(&id_dir) else {
                continue;
            };
            for arch in arches.flatten() {
                let Ok(branches) = std::fs::read_dir(arch.path()) else {
                    continue;
                };
                for branch in branches.flatten() {
                    let branch_name = branch.file_name().to_string_lossy().into_owned();
                    let runtime = format!("{id}/{branch_name}");
                    let manifest = branch.path().join("active/files/manifest.json");
                    if !manifest.is_file() {
                        out.runtimes.push(Runtime {
                            id: runtime,
                            unchecked: vec!["no manifest.json".to_owned()],
                        });
                        continue;
                    }
                    let text = crate::dpkg::read_bounded(&manifest, MAX_MANIFEST_BYTES)?;
                    let (packages, unchecked) = parse_manifest(&text, &runtime)?;
                    out.packages.extend(packages);
                    out.runtimes.push(Runtime {
                        id: runtime,
                        unchecked,
                    });
                }
            }
        }
    }
    out.packages.sort_by(|a, b| a.name.cmp(&b.name));
    out.packages.dedup_by(|a, b| a.name == b.name);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANIFEST: &str = r#"{"//NOTE":"x","modules":[
      {"name":"bootstrap/glibc.bst","x-cpe":{"product":"glibc","version":"2.42","ignored":["CVE-2010-4756"]}},
      {"name":"components/bash.bst","x-cpe":{"vendor":"gnu","product":"bash","version":"5.3","patches":["CVE-2019-18276"]}},
      {"name":"bootstrap/symlinks.bst","x-cpe":{"product":"symlinks"}},
      {"name":"components/nocpe.bst"},
      {"name":"components/odd.bst","x-cpe":{"product":"Bad Name","version":"1.0"}},
      {"name":"components/inject.bst","x-cpe":{"product":"zlib","version":"1.0&cpeName=other"}}
    ]}"#;

    #[test]
    fn components_are_read_with_their_builder_notes() {
        let (packages, unchecked) =
            parse_manifest(MANIFEST, "org.freedesktop.Platform/25.08").unwrap();
        let names: Vec<&str> = packages.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "org.freedesktop.Platform/25.08/bash",
                "org.freedesktop.Platform/25.08/glibc",
                // The version is not checked here; the lookup refuses it.
                "org.freedesktop.Platform/25.08/zlib",
            ]
        );
        let bash = &packages[0];
        let up = bash.upstream.as_ref().unwrap();
        assert_eq!((up.vendor.as_str(), up.product.as_str()), ("gnu", "bash"));
        assert_eq!(up.patched, ["CVE-2019-18276"]);
        // The vendor defaults to the product.
        assert_eq!(packages[1].upstream.as_ref().unwrap().vendor, "glibc");
        assert_eq!(
            packages[1].upstream.as_ref().unwrap().ignored,
            ["CVE-2010-4756"]
        );
        assert_eq!(bash.version.to_string(), "5.3");
        assert_eq!(bash.ecosystem, Ecosystem::Flatpak);
        // No version, no x-cpe and an unsafe product name are not checkable.
        assert_eq!(
            unchecked,
            [
                "bootstrap/symlinks.bst",
                "components/nocpe.bst",
                "components/odd.bst"
            ]
        );
    }

    #[test]
    fn an_installation_is_read_through_the_active_commit_of_each_branch() {
        let dir = tempfile::tempdir().unwrap();
        let branch = dir.path().join("runtime/org.example.Platform/x86_64/1.0");
        std::fs::create_dir_all(branch.join("abc123/files")).unwrap();
        std::fs::write(branch.join("abc123/files/manifest.json"), MANIFEST).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("abc123", branch.join("active")).unwrap();
        // An extension with no manifest is listed, not skipped.
        std::fs::create_dir_all(
            dir.path()
                .join("runtime/org.example.Locale/x86_64/stable/active/files"),
        )
        .unwrap();
        let found = read_runtimes(&[dir.path().to_owned(), dir.path().join("missing")]).unwrap();
        assert_eq!(found.packages.len(), 3);
        assert_eq!(found.runtimes.len(), 2);
        let bare = found
            .runtimes
            .iter()
            .find(|r| r.id.contains("Locale"))
            .unwrap();
        assert_eq!(bare.unchecked, ["no manifest.json"]);
    }

    #[test]
    fn a_broken_manifest_is_an_error_and_the_directories_follow_flatpak() {
        assert!(parse_manifest("{not json", "r").is_err());
        let var = |pairs: &'static [(&'static str, &'static str)]| {
            installations(|n| {
                pairs
                    .iter()
                    .find(|(k, _)| *k == n)
                    .map(|(_, v)| (*v).to_owned())
            })
        };
        assert_eq!(
            var(&[("HOME", "/home/u")]),
            [
                PathBuf::from("/var/lib/flatpak"),
                PathBuf::from("/home/u/.local/share/flatpak")
            ]
        );
        assert_eq!(
            var(&[
                ("FLATPAK_SYSTEM_DIR", "/s"),
                ("FLATPAK_USER_DIR", "/u"),
                ("HOME", "/h")
            ]),
            [PathBuf::from("/s"), PathBuf::from("/u")]
        );
    }
}
