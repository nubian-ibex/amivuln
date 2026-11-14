// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Upstream versions, as the authors of a component write them.
//!
//! There is no packaging grammar here (`2.42`, `1.2.13`, `20250812`, `6_5`),
//! so the order is the one `rpm` uses for version strings: runs of digits
//! compare as numbers and runs of letters as text. It is only used to sort and
//! compare two versions of the same component; which CVEs apply to a version
//! is decided by the NVD, not by this order.

use core::cmp::Ordering;
use core::fmt;
use core::str::FromStr;

use crate::rpmvercmp;

/// A version string, ordered like an `rpm` version.
#[derive(Debug, Clone)]
pub struct UpstreamVersion(String);

impl UpstreamVersion {
    /// The version exactly as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for UpstreamVersion {
    type Err = core::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_owned()))
    }
}

impl fmt::Display for UpstreamVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl PartialEq for UpstreamVersion {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for UpstreamVersion {}

impl PartialOrd for UpstreamVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for UpstreamVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        rpmvercmp(&self.0, &other.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_compare_as_numbers() {
        let v = |s: &str| s.parse::<UpstreamVersion>().unwrap_or_else(|n| match n {});
        assert!(v("1.10") > v("1.9"));
        assert!(v("20250812") > v("20241231"));
        assert_eq!(v("3.5.9"), v("3.5.9"));
        assert_eq!(v("2.42").to_string(), "2.42");
        assert_eq!(v("1.2.13").as_str(), "1.2.13");
    }
}
