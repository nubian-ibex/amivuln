// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Source health reporting.

use core::time::Duration;

/// Identifier of a data source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SourceId {
    /// Arch Linux Security Tracker.
    ArchTracker,
    /// Fedora repository `updateinfo` metadata.
    FedoraUpdateinfo,
    /// OSV.dev (Debian, Ubuntu and later the RHEL family).
    Osv,
    /// Fedora Bodhi.
    Bodhi,
    /// CISA Known Exploited Vulnerabilities.
    Kev,
    /// FIRST EPSS.
    Epss,
    /// NVD 2.0 API, for products with no distro data.
    Nvd,
}

impl SourceId {
    /// Stable identifier used in output.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ArchTracker => "arch-tracker",
            Self::FedoraUpdateinfo => "fedora-updateinfo",
            Self::Osv => "osv",
            Self::Bodhi => "bodhi",
            Self::Kev => "kev",
            Self::Epss => "epss",
            Self::Nvd => "nvd",
        }
    }
}

/// Outcome of querying a source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceStatus {
    /// Fresh answer.
    Ok,
    /// Answered from cache older than the TTL but within `stale_max_age`.
    Stale,
    /// No answer and no usable cache.
    Failed(String),
    /// Deliberately not queried.
    Skipped(String),
}

impl SourceStatus {
    /// Stable label used in output.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Stale => "stale",
            Self::Failed(_) => "failed",
            Self::Skipped(_) => "skipped",
        }
    }
}

/// One entry per consulted source, present in every output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceReport {
    /// Which source.
    pub source: SourceId,
    /// What happened.
    pub status: SourceStatus,
    /// Age of the data used.
    pub age: Duration,
    /// Whether an answer from this source is mandatory for a complete result.
    pub required: bool,
}

/// A result is complete unless a required source failed.
///
/// Stale data within `stale_max_age` counts as an answer; `Skipped` required
/// sources do not (skipping a required source is a degradation).
#[must_use]
pub fn is_complete(reports: &[SourceReport]) -> bool {
    reports
        .iter()
        .all(|r| !r.required || matches!(r.status, SourceStatus::Ok | SourceStatus::Stale))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(status: SourceStatus, required: bool) -> SourceReport {
        SourceReport {
            source: SourceId::Osv,
            status,
            age: Duration::ZERO,
            required,
        }
    }

    #[test]
    fn required_failure_is_incomplete() {
        assert!(!is_complete(&[report(
            SourceStatus::Failed("x".into()),
            true
        )]));
        assert!(!is_complete(&[report(
            SourceStatus::Skipped("x".into()),
            true
        )]));
    }

    #[test]
    fn optional_failure_and_stale_are_complete() {
        assert!(is_complete(&[
            report(SourceStatus::Failed("x".into()), false),
            report(SourceStatus::Stale, true),
            report(SourceStatus::Ok, true),
        ]));
        assert!(is_complete(&[]));
    }
}
