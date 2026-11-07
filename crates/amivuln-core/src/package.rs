// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Package identity.

use core::cmp::Ordering;
use core::fmt;

use amivuln_version::{PacmanVersion, RpmEvr};

/// Package ecosystem, which decides the version-comparison algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ecosystem {
    /// Fedora, with the release number (for example 41).
    Fedora(u16),
    /// Arch Linux (rolling).
    Arch,
}

impl Ecosystem {
    /// The purl namespace for this ecosystem.
    #[must_use]
    pub fn purl_namespace(self) -> &'static str {
        match self {
            Self::Fedora(_) => "pkg:rpm/fedora",
            Self::Arch => "pkg:alpm/arch",
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
}

/// A version tagged with its ecosystem; only versions of the same kind compare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Version {
    /// RPM `epoch:version-release`.
    Rpm(RpmEvr),
    /// pacman `epoch:version-release`.
    Pacman(PacmanVersion),
}

impl Version {
    /// Compares two versions, or returns `None` when their kinds differ.
    #[must_use]
    pub fn compare(&self, other: &Self) -> Option<Ordering> {
        match (self, other) {
            (Self::Rpm(a), Self::Rpm(b)) => Some(a.cmp(b)),
            (Self::Pacman(a), Self::Pacman(b)) => Some(a.cmp(b)),
            _ => None,
        }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rpm(v) => v.fmt(f),
            Self::Pacman(v) => v.fmt(f),
        }
    }
}

/// An installed (or user-specified) package.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    fn namespaces() {
        assert_eq!(Ecosystem::Fedora(41).purl_namespace(), "pkg:rpm/fedora");
        assert_eq!(Ecosystem::Arch.purl_namespace(), "pkg:alpm/arch");
    }
}
