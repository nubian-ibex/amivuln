// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Debian version comparison (`dpkg --compare-versions`).
//!
//! `[epoch:]upstream[-revision]`. Upstream and revision are compared with the
//! `verrevcmp` algorithm from dpkg: alternating non-digit and digit runs, where
//! in a non-digit run letters sort before every other character, `~` sorts
//! before everything including the end of the string, and digit runs compare
//! as unbounded integers.

use core::cmp::Ordering;
use core::fmt;
use core::str::FromStr;

use crate::{cmp_numeric, split_while};

/// Sort weight of one byte in a non-digit run.
fn order(c: Option<u8>) -> i32 {
    match c {
        None => 0,
        Some(b'~') => -1,
        Some(c) if c.is_ascii_digit() => 0,
        Some(c) if c.is_ascii_alphabetic() => i32::from(c),
        Some(c) => i32::from(c) + 256,
    }
}

/// Compares an upstream version or a revision.
#[must_use]
pub fn debvercmp(a: &str, b: &str) -> Ordering {
    let (mut a, mut b) = (a.as_bytes(), b.as_bytes());
    while !a.is_empty() || !b.is_empty() {
        // Non-digit prefix, compared character by character with `order`.
        while a.first().is_some_and(|c| !c.is_ascii_digit())
            || b.first().is_some_and(|c| !c.is_ascii_digit())
        {
            let (ac, bc) = (order(a.first().copied()), order(b.first().copied()));
            if ac != bc {
                return ac.cmp(&bc);
            }
            a = a.get(1..).unwrap_or_default();
            b = b.get(1..).unwrap_or_default();
        }
        // Digit run: unbounded integers.
        let (da, ra) = split_while(a, |c| c.is_ascii_digit());
        let (db, rb) = split_while(b, |c| c.is_ascii_digit());
        let ord = cmp_numeric(da, db);
        if ord != Ordering::Equal {
            return ord;
        }
        a = ra;
        b = rb;
    }
    Ordering::Equal
}

/// A Debian `[epoch:]upstream[-revision]` version.
#[derive(Debug, Clone)]
pub struct DebVersion {
    epoch: String,
    upstream: String,
    revision: String,
}

impl DebVersion {
    /// The epoch, `0` when absent.
    #[must_use]
    pub fn epoch(&self) -> &str {
        &self.epoch
    }

    /// The upstream version.
    #[must_use]
    pub fn upstream(&self) -> &str {
        &self.upstream
    }

    /// The Debian revision, empty when absent.
    #[must_use]
    pub fn revision(&self) -> &str {
        &self.revision
    }
}

impl FromStr for DebVersion {
    type Err = core::convert::Infallible;

    /// Parsing never fails; dpkg's own validity rules are not enforced because
    /// installed packages can carry odd versions and must still compare.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let digits = s.bytes().take_while(u8::is_ascii_digit).count();
        let (epoch, rest) = match s.get(digits..).and_then(|r| r.strip_prefix(':')) {
            Some(rest) if digits > 0 => (s.get(..digits).unwrap_or("0"), rest),
            _ => ("0", s),
        };
        let (upstream, revision) = rest.rsplit_once('-').unwrap_or((rest, ""));
        Ok(Self {
            epoch: epoch.to_owned(),
            upstream: upstream.to_owned(),
            revision: revision.to_owned(),
        })
    }
}

impl fmt::Display for DebVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.epoch != "0" {
            write!(f, "{}:", self.epoch)?;
        }
        f.write_str(&self.upstream)?;
        if !self.revision.is_empty() {
            write!(f, "-{}", self.revision)?;
        }
        Ok(())
    }
}

impl PartialEq for DebVersion {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for DebVersion {}

impl PartialOrd for DebVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DebVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        cmp_numeric(self.epoch.as_bytes(), other.epoch.as_bytes())
            .then_with(|| debvercmp(&self.upstream, &other.upstream))
            .then_with(|| debvercmp(&self.revision, &other.revision))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Ordering::{Equal, Greater, Less};

    fn v(s: &str) -> DebVersion {
        s.parse().unwrap_or_else(|never| match never {})
    }

    /// Cases from the dpkg test suite and the Debian policy manual.
    const CASES: &[(&str, &str, Ordering)] = &[
        ("1.0", "1.0", Equal),
        ("1.0-1", "1.0-2", Less),
        ("1.0-2", "1.0-1", Greater),
        ("1.0", "1.0-0", Equal),
        ("1.0", "1.0-1", Less),
        ("0:1.0", "1.0", Equal),
        ("1:0.5", "9.9", Greater),
        ("2:1.0", "1:9.0", Greater),
        ("1.0~rc1", "1.0", Less),
        ("1.0", "1.0~rc1", Greater),
        ("1.0~rc1", "1.0~rc2", Less),
        ("1.0~~", "1.0~", Less),
        ("1.0~", "1.0", Less),
        ("1.0a", "1.0", Greater),
        ("1.0+b1", "1.0", Greater),
        ("1.0+b1", "1.0a", Greater),
        ("1.0.1", "1.0", Greater),
        ("1.10", "1.9", Greater),
        ("1.01", "1.1", Equal),
        ("1.0-1~bpo12+1", "1.0-1", Less),
        ("1.0-1+deb12u1", "1.0-1", Greater),
        ("3.0.11-1~deb12u1", "3.0.11-1~deb12u2", Less),
        ("3.0.11-1~deb12u2", "3.0.18-1~deb12u2", Less),
        ("5.2.15-2+b2", "5.2.15-2", Greater),
        ("2.40-1ubuntu3.1", "2.40-1ubuntu3", Greater),
        ("a", "b", Less),
        ("a", "A", Greater),
        ("a", "+", Less),
        ("", "", Equal),
        ("", "1", Less),
        (
            "99999999999999999999999",
            "99999999999999999999998",
            Greater,
        ),
    ];

    #[test]
    fn dpkg_table() {
        for &(a, b, want) in CASES {
            assert_eq!(v(a).cmp(&v(b)), want, "{a:?} vs {b:?}");
            assert_eq!(v(b).cmp(&v(a)), want.reverse(), "{b:?} vs {a:?}");
        }
    }

    #[test]
    fn parsing_and_display() {
        let x = v("1:2.3-4-5");
        assert_eq!((x.epoch(), x.upstream(), x.revision()), ("1", "2.3-4", "5"));
        assert_eq!(x.to_string(), "1:2.3-4-5");
        assert_eq!(v("1.0").revision(), "");
        assert_eq!(v("0:1.0-1").to_string(), "1.0-1");
        assert_eq!(v("a:1.0").epoch(), "0");
    }

    #[test]
    fn properties_hold_on_corpus() {
        let alphabet = ["0", "1", "10", "a", "B", "~", "+", ".", "-", ":"];
        let mut corpus = vec![String::new()];
        let mut layer = vec![String::new()];
        for _ in 0..3 {
            let mut next = Vec::new();
            for s in &layer {
                for t in alphabet {
                    next.push(format!("{s}{t}"));
                }
            }
            corpus.extend(next.iter().cloned());
            layer = next;
        }
        for a in &corpus {
            assert_eq!(debvercmp(a, a), Equal);
            for b in &corpus {
                assert_eq!(debvercmp(a, b), debvercmp(b, a).reverse(), "{a:?} {b:?}");
            }
        }
        let sample: Vec<&String> = corpus.iter().step_by(31).collect();
        for a in &sample {
            for b in &sample {
                for c in &sample {
                    if debvercmp(a, b) != Greater && debvercmp(b, c) != Greater {
                        assert_ne!(debvercmp(a, c), Greater, "{a:?} {b:?} {c:?}");
                    }
                }
            }
        }
    }
}
