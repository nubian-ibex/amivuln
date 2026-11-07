// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! pacman version comparison (`alpm_pkg_vercmp` from libalpm).

use core::cmp::Ordering;
use core::fmt;
use core::str::FromStr;

use crate::{cmp_numeric, split_evr, split_while};

/// Compares two version strings with the libalpm segment algorithm.
///
/// Unlike RPM there is no `~` or `^` handling, differing separator lengths
/// break ties, and a trailing alphabetic segment marks a pre-release
/// (`1.5b` is older than `1.5`).
#[must_use]
pub fn alpm_vercmp(a: &str, b: &str) -> Ordering {
    if a == b {
        return Ordering::Equal;
    }
    let (mut one, mut two) = (a.as_bytes(), b.as_bytes());
    while !one.is_empty() && !two.is_empty() {
        let (sep1, after1) = split_while(one, |c| !c.is_ascii_alphanumeric());
        let (sep2, after2) = split_while(two, |c| !c.is_ascii_alphanumeric());
        one = after1;
        two = after2;
        let (Some(&o), Some(_)) = (one.first(), two.first()) else {
            break;
        };
        if sep1.len() != sep2.len() {
            return sep1.len().cmp(&sep2.len());
        }

        let numeric = o.is_ascii_digit();
        let pred: fn(u8) -> bool = if numeric {
            |c| c.is_ascii_digit()
        } else {
            |c| c.is_ascii_alphabetic()
        };
        let (run1, tail1) = split_while(one, pred);
        let (run2, tail2) = split_while(two, pred);

        if run2.is_empty() {
            return if numeric {
                Ordering::Greater
            } else {
                Ordering::Less
            };
        }

        let ord = if numeric {
            cmp_numeric(run1, run2)
        } else {
            run1.cmp(run2)
        };
        if ord != Ordering::Equal {
            return ord;
        }
        one = tail1;
        two = tail2;
    }

    if one.is_empty() && two.is_empty() {
        return Ordering::Equal;
    }
    // A remaining alphabetic tail never beats an empty string; any other
    // remaining tail makes that side newer.
    let one_alpha = one.first().is_some_and(u8::is_ascii_alphabetic);
    let two_alpha = two.first().is_some_and(u8::is_ascii_alphabetic);
    if (one.is_empty() && !two_alpha) || one_alpha {
        Ordering::Less
    } else {
        Ordering::Greater
    }
}

/// Compares two full pacman versions, `[epoch:]version[-release]`.
///
/// Mirrors `alpm_pkg_vercmp`: the release is compared only when both sides
/// have one.
#[must_use]
pub fn pacman_vercmp(a: &str, b: &str) -> Ordering {
    if a == b {
        return Ordering::Equal;
    }
    let (ea, va, ra) = split_evr(a);
    let (eb, vb, rb) = split_evr(b);
    cmp_numeric(ea.as_bytes(), eb.as_bytes())
        .then_with(|| alpm_vercmp(va, vb))
        .then_with(|| match (ra, rb) {
            (Some(ra), Some(rb)) => alpm_vercmp(ra, rb),
            _ => Ordering::Equal,
        })
}

/// A pacman package version string with libalpm ordering.
#[derive(Debug, Clone)]
pub struct PacmanVersion(String);

impl PacmanVersion {
    /// The version exactly as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for PacmanVersion {
    type Err = core::convert::Infallible;

    /// Parsing never fails: any string has a pacman interpretation.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_owned()))
    }
}

impl fmt::Display for PacmanVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl PartialEq for PacmanVersion {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for PacmanVersion {}

impl PartialOrd for PacmanVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PacmanVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        pacman_vercmp(&self.0, &other.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Ordering::{Equal, Greater, Less};

    /// Values checked against `vercmp` from pacman 7.1.0 (libalpm 16.0.1) in
    /// an `archlinux` container on 2026-11-07.
    const CASES: &[(&str, &str, Ordering)] = &[
        ("1.5.0", "1.5.0", Equal),
        ("1.5.1", "1.5.0", Greater),
        ("1.5.1", "1.5", Greater),
        ("1.5.0-1", "1.5.0-1", Equal),
        ("1.5.0-1", "1.5.0-2", Less),
        ("1.5.0-1", "1.5.1-1", Less),
        ("1.5.0-2", "1.5.1-1", Less),
        ("1.5-1", "1.5b-1", Greater),
        ("1.5b-1", "1.5-1", Less),
        ("1:1.0-1", "2.0-1", Greater),
        ("1.0-1", "1.0", Equal),
        ("1.0", "1.0-1", Equal),
        ("1.0a", "1.0alpha", Less),
        ("1.0alpha", "1.0b", Less),
        ("1.0", "1.0.0", Less),
        ("2.0", "10.0", Less),
        ("1.0.1", "1.0.a", Greater),
    ];

    #[test]
    fn pacman_vercmp_table() {
        for &(a, b, want) in CASES {
            assert_eq!(pacman_vercmp(a, b), want, "pacman_vercmp({a:?}, {b:?})");
        }
    }

    #[test]
    fn version_type_orders() {
        let v = |s: &str| {
            s.parse::<PacmanVersion>()
                .unwrap_or_else(|never| match never {})
        };
        assert!(v("1.0-1") < v("1.0-2"));
        assert_eq!(v("1:1.0-1").to_string(), "1:1.0-1");
        assert_eq!(v("3.2-1").as_str(), "3.2-1");
    }

    fn corpus() -> Vec<String> {
        let alphabet = ["0", "1", "10", "a", "b", "rc", ".", "_", ".."];
        let mut out = vec![String::new()];
        let mut layer = vec![String::new()];
        for _ in 0..3 {
            let mut next = Vec::new();
            for s in &layer {
                for t in alphabet {
                    next.push(format!("{s}{t}"));
                }
            }
            out.extend(next.iter().cloned());
            layer = next;
        }
        out
    }

    #[test]
    fn properties_hold_on_corpus() {
        let c = corpus();
        for a in &c {
            assert_eq!(alpm_vercmp(a, a), Equal, "reflexive {a:?}");
            for b in &c {
                assert_eq!(
                    alpm_vercmp(a, b),
                    alpm_vercmp(b, a).reverse(),
                    "antisymmetric {a:?} {b:?}"
                );
            }
        }
    }
}
