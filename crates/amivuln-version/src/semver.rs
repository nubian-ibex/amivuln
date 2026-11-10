// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Semantic Versioning 2.0.0 ordering, as used by Go modules and crates.io.
//!
//! A leading `v` is accepted (Go writes `v1.2.3`). Build metadata after `+`
//! is ignored for ordering, as the specification requires. Numeric parts are
//! compared as unbounded integers. Go pseudo-versions such as
//! `v0.0.0-20210101000000-abcdef123456` are ordinary pre-release versions of
//! the form `X.Y.Z-pre`, so they order by their timestamp component.

use core::cmp::Ordering;
use core::fmt;

use crate::cmp_numeric;

/// A parsed semantic version.
#[derive(Debug, Clone)]
pub struct SemverVersion {
    raw: String,
    core: [String; 3],
    pre: Vec<String>,
}

/// Why a string is not a semantic version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemverError(pub String);

impl fmt::Display for SemverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} is not a semantic version", self.0)
    }
}

impl core::error::Error for SemverError {}

impl SemverVersion {
    /// Parses `[v]MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]`.
    ///
    /// Missing minor and patch parts are read as zero (`v1.2` is `1.2.0`),
    /// because Go and a few advisories abbreviate them.
    ///
    /// # Errors
    ///
    /// Fails when a numeric part is not a run of ASCII digits.
    pub fn parse(text: &str) -> Result<Self, SemverError> {
        let bad = || SemverError(text.chars().take(64).collect());
        let body = text.strip_prefix('v').unwrap_or(text);
        let body = body.split('+').next().unwrap_or_default();
        let (core_text, pre_text) = match body.split_once('-') {
            Some((core, pre)) => (core, Some(pre)),
            None => (body, None),
        };
        let mut parts = core_text.split('.');
        let mut core: [String; 3] = [String::new(), "0".to_owned(), "0".to_owned()];
        for slot in &mut core {
            let Some(part) = parts.next() else { break };
            if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
                return Err(bad());
            }
            part.clone_into(slot);
        }
        if core.first().is_none_or(String::is_empty) || parts.next().is_some() {
            return Err(bad());
        }
        let pre = match pre_text {
            None => Vec::new(),
            Some("") => return Err(bad()),
            Some(p) => p.split('.').map(str::to_owned).collect(),
        };
        if pre
            .iter()
            .any(|id| id.is_empty() || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
        {
            return Err(bad());
        }
        Ok(Self {
            raw: text.to_owned(),
            core,
            pre,
        })
    }
}

// Equality follows the ordering (so `v1.2` equals `1.2.0` and build metadata
// is ignored), which keeps `Eq` and `Ord` consistent.
impl PartialEq for SemverVersion {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for SemverVersion {}

impl Default for SemverVersion {
    fn default() -> Self {
        Self {
            raw: "0.0.0".to_owned(),
            core: ["0".to_owned(), "0".to_owned(), "0".to_owned()],
            pre: Vec::new(),
        }
    }
}

impl fmt::Display for SemverVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

impl PartialOrd for SemverVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SemverVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        for (a, b) in self.core.iter().zip(&other.core) {
            let ord = cmp_numeric(a.as_bytes(), b.as_bytes());
            if ord != Ordering::Equal {
                return ord;
            }
        }
        // A version without pre-release is greater than one with.
        match (self.pre.is_empty(), other.pre.is_empty()) {
            (true, true) => return Ordering::Equal,
            (true, false) => return Ordering::Greater,
            (false, true) => return Ordering::Less,
            (false, false) => {}
        }
        for (a, b) in self.pre.iter().zip(&other.pre) {
            let numeric = |s: &str| s.bytes().all(|c| c.is_ascii_digit());
            let ord = match (numeric(a), numeric(b)) {
                (true, true) => cmp_numeric(a.as_bytes(), b.as_bytes()),
                (true, false) => Ordering::Less,
                (false, true) => Ordering::Greater,
                (false, false) => a.cmp(b),
            };
            if ord != Ordering::Equal {
                return ord;
            }
        }
        self.pre.len().cmp(&other.pre.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(text: &str) -> SemverVersion {
        SemverVersion::parse(text).unwrap_or_else(|e| SemverVersion {
            raw: e.to_string(),
            core: Default::default(),
            pre: Vec::new(),
        })
    }

    #[test]
    fn the_specification_ordering_chain_holds() {
        // semver.org section 11.
        let chain = [
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
            "1.0.1",
            "1.1.0",
            "2.0.0",
        ];
        for pair in chain.windows(2) {
            assert!(v(pair[0]) < v(pair[1]), "{} < {}", pair[0], pair[1]);
        }
    }

    #[test]
    fn go_forms_and_build_metadata() {
        assert_eq!(v("v1.2.3"), v("1.2.3"));
        assert_eq!(v("1.2.3+build.5"), v("1.2.3"));
        assert_eq!(v("v1.2"), v("1.2.0"));
        assert_eq!(v("v1.2").to_string(), "v1.2");
        assert!(v("v0.0.0-20210101000000-abcdef123456") < v("v0.0.0-20220101000000-abcdef123456"));
        assert!(v("v1.10.0") > v("v1.9.0"));
        assert!(v("99999999999999999999999.0.0") > v("1.0.0"));
    }

    #[test]
    fn junk_is_rejected() {
        for bad in [
            "",
            "v",
            "1.2.3.4",
            "1.a.3",
            "1.2.3-",
            "1.2.3-a..b",
            "1.2.3-é",
            "-1.0.0",
        ] {
            assert!(SemverVersion::parse(bad).is_err(), "{bad:?}");
        }
    }
}
