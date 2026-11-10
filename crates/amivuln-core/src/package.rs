// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Package identity.

use core::cmp::Ordering;
use core::fmt;

use amivuln_version::{DebVersion, PacmanVersion, RpmEvr, SemverVersion};

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
    /// Ubuntu, an LTS release: 2004 to 9904, where 2404 is 24.04.
    Ubuntu(u16),
    /// Go modules (OSV ecosystem `Go`), found in binaries by their build info.
    Go,
    /// Rust crates (OSV ecosystem `crates.io`), found by cargo-auditable.
    Crates,
}

impl Ecosystem {
    /// The OSV ecosystem string, when OSV covers this ecosystem.
    #[must_use]
    pub fn osv_ecosystem(&self) -> Option<String> {
        match self {
            Self::Debian(v) => Some(format!("Debian:{v}")),
            Self::Rocky(v) => Some(format!("Rocky Linux:{v}")),
            Self::Alma(v) => Some(format!("AlmaLinux:{v}")),
            // The OSV ecosystem keeps the decimal form (Ubuntu:24.04:LTS).
            Self::Ubuntu(v) => Some(format!("Ubuntu:{}.{:02}:LTS", v / 100, v % 100)),
            Self::Go => Some("Go".to_owned()),
            Self::Crates => Some("crates.io".to_owned()),
            Self::Fedora(_) | Self::Arch => None,
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
            Self::Semver(v) => v.fmt(f),
        }
    }
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
    }
}
