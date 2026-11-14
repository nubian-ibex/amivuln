// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Package identity.

use core::cmp::Ordering;
use core::fmt;

use amivuln_version::{
    ApkVersion, DebVersion, GentooVersion, PacmanVersion, RpmEvr, SemverVersion, UpstreamVersion,
};

/// Package ecosystem, which decides the version-comparison algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ecosystem {
    /// Fedora, with the release number (for example 41).
    Fedora(u16),
    /// Arch Linux (rolling).
    Arch,
    /// Debian, with the release number (for example 12).
    Debian(u16),
    /// Rocky Linux, release 8 or 9.
    Rocky(u16),
    /// `AlmaLinux`, release 8 or 9.
    Alma(u16),
    /// Red Hat Enterprise Linux, major release 8, 9 or 10.
    Rhel(u16),
    /// Ubuntu, an LTS release: 2004 to 9904, where 2404 is 24.04.
    Ubuntu(u16),
    /// Go modules (OSV ecosystem `Go`), found in binaries by their build info.
    Go,
    /// Rust crates (OSV ecosystem `crates.io`), found by cargo-auditable.
    Crates,
    /// Alpine Linux, with the release as `major * 100 + minor` (320 is 3.20).
    Alpine(u16),
    /// `openSUSE`: Leap as `major * 100 + minor` (1506 is Leap 15.6), and 0 for
    /// the rolling Tumbleweed.
    Opensuse(u16),
    /// Gentoo (rolling): packages are `category/name`, versions are ebuild
    /// versions, and the advisories are the GLSAs.
    Gentoo,
    /// A component of an installed Flatpak runtime, known by its upstream
    /// product and version (no distribution fix status exists for it).
    Flatpak,
}

impl Ecosystem {
    /// The OSV ecosystem string, when OSV covers this ecosystem.
    #[must_use]
    pub fn osv_ecosystem(&self) -> Option<String> {
        match self {
            Self::Debian(v) => Some(format!("Debian:{v}")),
            Self::Rocky(v) => Some(format!("Rocky Linux:{v}")),
            Self::Alma(v) => Some(format!("AlmaLinux:{v}")),
            // Red Hat splits a release by repository; the BaseOS stream is the
            // primary one, `osv_ecosystems` lists the rest.
            Self::Rhel(v) => Some(format!("Red Hat:enterprise_linux:{v}::baseos")),
            // The OSV ecosystem keeps the decimal form (Ubuntu:24.04:LTS).
            Self::Ubuntu(v) => Some(format!("Ubuntu:{}.{:02}:LTS", v / 100, v % 100)),
            Self::Go => Some("Go".to_owned()),
            Self::Crates => Some("crates.io".to_owned()),
            // OSV names Alpine releases `Alpine:v3.20`, with no zero padding.
            Self::Alpine(v) => Some(format!("Alpine:v{}.{}", v / 100, v % 100)),
            Self::Opensuse(0) => Some("openSUSE:Tumbleweed".to_owned()),
            Self::Opensuse(v) => Some(format!("openSUSE:Leap {}.{}", v / 100, v % 100)),
            Self::Fedora(_) | Self::Arch | Self::Gentoo | Self::Flatpak => None,
        }
    }

    /// Every OSV ecosystem a package of this release can be filed under.
    ///
    /// Red Hat files an advisory under the repository a package ships in
    /// (`baseos`, `appstream`, `crb`) and the rpm database does not record
    /// which one, so each is asked. Every other ecosystem has exactly one.
    #[must_use]
    pub fn osv_ecosystems(&self) -> Vec<String> {
        match self {
            Self::Rhel(v) => ["baseos", "appstream", "crb"]
                .iter()
                .map(|repo| format!("Red Hat:enterprise_linux:{v}::{repo}"))
                .collect(),
            other => other.osv_ecosystem().into_iter().collect(),
        }
    }

    /// True for language ecosystems, whose versions are semantic versions and
    /// whose advisories OSV matches by version range rather than by distro fix.
    #[must_use]
    pub fn is_language(&self) -> bool {
        matches!(self, Self::Go | Self::Crates)
    }
}

impl Ecosystem {
    /// The purl namespace for this ecosystem.
    #[must_use]
    pub fn purl_namespace(&self) -> &'static str {
        match self {
            Self::Fedora(_) => "pkg:rpm/fedora",
            Self::Arch => "pkg:alpm/arch",
            Self::Debian(_) => "pkg:deb/debian",
            Self::Ubuntu(_) => "pkg:deb/ubuntu",
            Self::Rocky(_) => "pkg:rpm/rocky",
            Self::Alma(_) => "pkg:rpm/alma",
            Self::Rhel(_) => "pkg:rpm/redhat",
            Self::Alpine(_) => "pkg:apk/alpine",
            Self::Opensuse(_) => "pkg:rpm/opensuse",
            // purl has no type for ebuilds yet.
            Self::Gentoo => "pkg:generic/gentoo",
            Self::Flatpak => "pkg:generic/flatpak",
            Self::Go => "pkg:golang",
            Self::Crates => "pkg:cargo",
        }
    }
}

/// How the package identity was established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provenance {
    /// Read from the package manager database.
    PackageDb,
    /// Supplied by the user on the command line (`name@version`, purl).
    UserInput,
    /// Read from the file itself: a `.note.package` entry.
    EmbeddedNote,
    /// Read from the file itself: Go build information or cargo-auditable data.
    EmbeddedBuildInfo,
    /// A version banner string found in the file. Low confidence: the
    /// distribution may have backported fixes without changing the banner.
    StringHeuristic,
}

/// A version tagged with its ecosystem; only versions of the same kind compare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Version {
    /// RPM `epoch:version-release`.
    Rpm(RpmEvr),
    /// pacman `epoch:version-release`.
    Pacman(PacmanVersion),
    /// Debian `[epoch:]upstream[-revision]`.
    Deb(DebVersion),
    /// Alpine `apk` version.
    Apk(ApkVersion),
    /// Gentoo ebuild version.
    Gentoo(GentooVersion),
    /// An upstream version as the component's authors write it.
    Upstream(UpstreamVersion),
    /// Semantic version, for Go modules and crates.
    Semver(SemverVersion),
}

impl Version {
    /// Compares two versions, or returns `None` when their kinds differ.
    #[must_use]
    pub fn compare(&self, other: &Self) -> Option<Ordering> {
        match (self, other) {
            (Self::Rpm(a), Self::Rpm(b)) => Some(a.cmp(b)),
            (Self::Pacman(a), Self::Pacman(b)) => Some(a.cmp(b)),
            (Self::Deb(a), Self::Deb(b)) => Some(a.cmp(b)),
            (Self::Apk(a), Self::Apk(b)) => Some(a.cmp(b)),
            (Self::Gentoo(a), Self::Gentoo(b)) => Some(a.cmp(b)),
            (Self::Upstream(a), Self::Upstream(b)) => Some(a.cmp(b)),
            (Self::Semver(a), Self::Semver(b)) => Some(a.cmp(b)),
            _ => None,
        }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rpm(v) => v.fmt(f),
            Self::Pacman(v) => v.fmt(f),
            Self::Deb(v) => v.fmt(f),
            Self::Apk(v) => v.fmt(f),
            Self::Gentoo(v) => v.fmt(f),
            Self::Upstream(v) => v.fmt(f),
            Self::Semver(v) => v.fmt(f),
        }
    }
}

/// What the builder of a component states about it: the NVD names to look it
/// up by, and the CVEs it has already dealt with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamInfo {
    /// The NVD vendor.
    pub vendor: String,
    /// The NVD product.
    pub product: String,
    /// CVEs the build carries a patch for.
    pub patched: Vec<String>,
    /// CVEs the builder decided do not apply.
    pub ignored: Vec<String>,
}

/// An installed (or user-specified) package.
#[derive(Debug, Clone, PartialEq)]
pub struct PackageRef {
    /// Ecosystem the package belongs to.
    pub ecosystem: Ecosystem,
    /// Binary package name.
    pub name: String,
    /// Source package name, when it differs (advisories often use it).
    pub source_name: Option<String>,
    /// Installed version.
    pub version: Version,
    /// Architecture, when known.
    pub arch: Option<String>,
    /// What the builder of an upstream-versioned component declares about it.
    pub upstream: Option<UpstreamInfo>,
    /// The slot a Gentoo package is installed in (several versions of one
    /// package can coexist, and an advisory names the slots it covers).
    pub slot: Option<String>,
    /// How this identity was established.
    pub provenance: Provenance,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mixed_kinds_do_not_compare() {
        let rpm = Version::Rpm("1.0-1".parse().unwrap_or_else(|n| match n {}));
        let pac = Version::Pacman("1.0-1".parse().unwrap_or_else(|n| match n {}));
        assert_eq!(rpm.compare(&pac), None);
        assert_eq!(rpm.compare(&rpm), Some(Ordering::Equal));
    }

    #[test]
    fn rhel_family_osv_ecosystems() {
        assert_eq!(
            Ecosystem::Rocky(9).osv_ecosystem().as_deref(),
            Some("Rocky Linux:9")
        );
        assert_eq!(
            Ecosystem::Alma(8).osv_ecosystem().as_deref(),
            Some("AlmaLinux:8")
        );
    }

    #[test]
    fn namespaces() {
        assert_eq!(Ecosystem::Fedora(41).purl_namespace(), "pkg:rpm/fedora");
        assert_eq!(Ecosystem::Arch.purl_namespace(), "pkg:alpm/arch");
        assert_eq!(Ecosystem::Debian(12).purl_namespace(), "pkg:deb/debian");
        assert_eq!(Ecosystem::Ubuntu(2404).purl_namespace(), "pkg:deb/ubuntu");
        assert_eq!(
            Ecosystem::Debian(12).osv_ecosystem().as_deref(),
            Some("Debian:12")
        );
        assert_eq!(
            Ecosystem::Ubuntu(2404).osv_ecosystem().as_deref(),
            Some("Ubuntu:24.04:LTS")
        );
        assert_eq!(Ecosystem::Fedora(41).osv_ecosystem(), None);
        assert_eq!(Ecosystem::Arch.osv_ecosystem(), None);
        assert_eq!(
            Ecosystem::Alpine(320).osv_ecosystem().as_deref(),
            Some("Alpine:v3.20")
        );
        assert_eq!(
            Ecosystem::Alpine(309).osv_ecosystem().as_deref(),
            Some("Alpine:v3.9")
        );
        assert_eq!(Ecosystem::Alpine(320).purl_namespace(), "pkg:apk/alpine");
        assert_eq!(
            Ecosystem::Opensuse(1506).osv_ecosystem().as_deref(),
            Some("openSUSE:Leap 15.6")
        );
        assert_eq!(
            Ecosystem::Opensuse(1600).osv_ecosystem().as_deref(),
            Some("openSUSE:Leap 16.0")
        );
        assert_eq!(
            Ecosystem::Opensuse(0).osv_ecosystem().as_deref(),
            Some("openSUSE:Tumbleweed")
        );
        assert_eq!(
            Ecosystem::Opensuse(1506).purl_namespace(),
            "pkg:rpm/opensuse"
        );
        assert_eq!(
            Ecosystem::Rhel(9).osv_ecosystem().as_deref(),
            Some("Red Hat:enterprise_linux:9::baseos")
        );
        assert_eq!(
            Ecosystem::Rhel(9).osv_ecosystems(),
            [
                "Red Hat:enterprise_linux:9::baseos",
                "Red Hat:enterprise_linux:9::appstream",
                "Red Hat:enterprise_linux:9::crb"
            ]
        );
        assert_eq!(Ecosystem::Debian(12).osv_ecosystems(), ["Debian:12"]);
        assert!(Ecosystem::Fedora(44).osv_ecosystems().is_empty());
        assert_eq!(Ecosystem::Rhel(9).purl_namespace(), "pkg:rpm/redhat");
    }
}
