// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! RPM version comparison (`rpmvercmp` and epoch:version-release).

use core::cmp::Ordering;
use core::fmt;
use core::str::FromStr;

use crate::{advance, cmp_numeric, split_evr, split_while};

/// Separators are everything that is not alphanumeric, `~` or `^`.
fn is_separator(c: u8) -> bool {
    !c.is_ascii_alphanumeric() && c != b'~' && c != b'^'
}

/// Compares two version (or release) strings with the RPM algorithm.
///
/// Rules, as implemented by `rpmvercmp` in rpm 4.x: runs of digits compare as
/// integers, runs of letters compare lexically, a numeric segment beats an
/// alphabetic one, `~` sorts before everything (even the end of the string),
/// and `^` sorts after the end of the string but before any other segment.
#[must_use]
pub fn rpmvercmp(a: &str, b: &str) -> Ordering {
    if a == b {
        return Ordering::Equal;
    }
    let (mut one, mut two) = (a.as_bytes(), b.as_bytes());
    while !one.is_empty() || !two.is_empty() {
        one = split_while(one, is_separator).1;
        two = split_while(two, is_separator).1;
        let (o, t) = (one.first().copied(), two.first().copied());

        if o == Some(b'~') || t == Some(b'~') {
            if o != Some(b'~') {
                return Ordering::Greater;
            }
            if t != Some(b'~') {
                return Ordering::Less;
            }
            one = advance(one);
            two = advance(two);
            continue;
        }

        if o == Some(b'^') || t == Some(b'^') {
            if o.is_none() {
                return Ordering::Less;
            }
            if t.is_none() {
                return Ordering::Greater;
            }
            if o != Some(b'^') {
                return Ordering::Greater;
            }
            if t != Some(b'^') {
                return Ordering::Less;
            }
            one = advance(one);
            two = advance(two);
            continue;
        }

        let (Some(o), Some(_)) = (o, t) else { break };

        let numeric = o.is_ascii_digit();
        let pred: fn(u8) -> bool = if numeric {
            |c| c.is_ascii_digit()
        } else {
            |c| c.is_ascii_alphabetic()
        };
        let (seg1, rest1) = split_while(one, pred);
        let (seg2, rest2) = split_while(two, pred);

        // Segments of different kinds: numeric is newer than alphabetic.
        if seg2.is_empty() {
            return if numeric {
                Ordering::Greater
            } else {
                Ordering::Less
            };
        }

        let ord = if numeric {
            cmp_numeric(seg1, seg2)
        } else {
            seg1.cmp(seg2)
        };
        if ord != Ordering::Equal {
            return ord;
        }
        one = rest1;
        two = rest2;
    }

    match (one.is_empty(), two.is_empty()) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Less,
        _ => Ordering::Greater,
    }
}

/// An RPM `epoch:version-release` triple.
///
/// A missing epoch is treated as `0`. A missing release on either side skips
/// the release comparison, which is how rpm compares dependency ranges and is
/// what lets `nginx@1.26.2` match `1.26.2-1.fc41`.
#[derive(Debug, Clone)]
pub struct RpmEvr {
    epoch: String,
    version: String,
    release: Option<String>,
}

impl RpmEvr {
    /// The epoch as written, `0` when absent.
    #[must_use]
    pub fn epoch(&self) -> &str {
        &self.epoch
    }

    /// The upstream version part.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// The release part, when present.
    #[must_use]
    pub fn release(&self) -> Option<&str> {
        self.release.as_deref()
    }
}

impl FromStr for RpmEvr {
    type Err = core::convert::Infallible;

    /// Parsing never fails: any string has an EVR interpretation.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (epoch, version, release) = split_evr(s);
        Ok(Self {
            epoch: epoch.to_owned(),
            version: version.to_owned(),
            release: release.map(str::to_owned),
        })
    }
}

impl fmt::Display for RpmEvr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.epoch != "0" {
            write!(f, "{}:", self.epoch)?;
        }
        f.write_str(&self.version)?;
        if let Some(release) = &self.release {
            write!(f, "-{release}")?;
        }
        Ok(())
    }
}

impl PartialEq for RpmEvr {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for RpmEvr {}

impl PartialOrd for RpmEvr {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// The release comparison is skipped when one side has none, so equality is
// not transitive across missing releases; this mirrors rpm dependency
// semantics and is why callers comparing installed against fixed versions
// should always pass full EVRs.
impl Ord for RpmEvr {
    fn cmp(&self, other: &Self) -> Ordering {
        cmp_numeric(self.epoch.as_bytes(), other.epoch.as_bytes())
            .then_with(|| rpmvercmp(&self.version, &other.version))
            .then_with(|| match (&self.release, &other.release) {
                (Some(a), Some(b)) => rpmvercmp(a, b),
                _ => Ordering::Equal,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Ordering::{Equal, Greater, Less};

    /// Cases from the rpm test suite (`tests/rpmvercmp.at`).
    const CASES: &[(&str, &str, Ordering)] = &[
        ("1.0", "1.0", Equal),
        ("1.0", "2.0", Less),
        ("2.0", "1.0", Greater),
        ("2.0.1", "2.0.1", Equal),
        ("2.0", "2.0.1", Less),
        ("2.0.1", "2.0", Greater),
        ("5.5p1", "5.5p1", Equal),
        ("5.5p1", "5.5p2", Less),
        ("5.5p2", "5.5p1", Greater),
        ("5.5p10", "5.5p10", Equal),
        ("5.5p1", "5.5p10", Less),
        ("5.5p10", "5.5p1", Greater),
        ("10xyz", "10.1xyz", Less),
        ("10.1xyz", "10xyz", Greater),
        ("xyz10", "xyz10", Equal),
        ("xyz10", "xyz10.1", Less),
        ("xyz10.1", "xyz10", Greater),
        ("xyz.4", "xyz.4", Equal),
        ("xyz.4", "8", Less),
        ("8", "xyz.4", Greater),
        ("xyz.4", "2", Less),
        ("2", "xyz.4", Greater),
        ("5.5p2", "5.6p1", Less),
        ("5.6p1", "5.5p2", Greater),
        ("5.6p1", "6.5p1", Less),
        ("6.5p1", "5.6p1", Greater),
        ("6.0.rc1", "6.0", Greater),
        ("6.0", "6.0.rc1", Less),
        ("10b2", "10a1", Greater),
        ("10a2", "10b2", Less),
        ("1.0aa", "1.0aa", Equal),
        ("1.0a", "1.0aa", Less),
        ("1.0aa", "1.0a", Greater),
        ("10.0001", "10.0001", Equal),
        ("10.0001", "10.1", Equal),
        ("10.1", "10.0001", Equal),
        ("10.0001", "10.0039", Less),
        ("10.0039", "10.0001", Greater),
        ("4.999.9", "5.0", Less),
        ("5.0", "4.999.9", Greater),
        ("20101121", "20101121", Equal),
        ("20101121", "20101122", Less),
        ("20101122", "20101121", Greater),
        ("2_0", "2_0", Equal),
        ("2.0", "2_0", Equal),
        ("2_0", "2.0", Equal),
        ("a", "a", Equal),
        ("a+", "a+", Equal),
        ("a+", "a_", Equal),
        ("a_", "a+", Equal),
        ("+a", "+a", Equal),
        ("+a", "_a", Equal),
        ("_a", "+a", Equal),
        ("+_", "+_", Equal),
        ("_+", "+_", Equal),
        ("+", "_", Equal),
        ("_", "+", Equal),
        ("1.0~rc1", "1.0~rc1", Equal),
        ("1.0~rc1", "1.0", Less),
        ("1.0", "1.0~rc1", Greater),
        ("1.0~rc1", "1.0~rc2", Less),
        ("1.0~rc2", "1.0~rc1", Greater),
        ("1.0~rc1~git123", "1.0~rc1~git123", Equal),
        ("1.0~rc1~git123", "1.0~rc1", Less),
        ("1.0~rc1", "1.0~rc1~git123", Greater),
        ("1.0^", "1.0^", Equal),
        ("1.0^", "1.0", Greater),
        ("1.0", "1.0^", Less),
        ("1.0^git1", "1.0^git1", Equal),
        ("1.0^git1", "1.0", Greater),
        ("1.0", "1.0^git1", Less),
        ("1.0^git1", "1.0^git2", Less),
        ("1.0^git2", "1.0^git1", Greater),
        ("1.0^git1", "1.01", Less),
        ("1.01", "1.0^git1", Greater),
        ("1.0^20160101", "1.0^20160101", Equal),
        ("1.0^20160101", "1.0.1", Less),
        ("1.0.1", "1.0^20160101", Greater),
        ("1.0^20160101^git1", "1.0^20160101^git1", Equal),
        ("1.0^20160102", "1.0^20160101^git1", Greater),
        ("1.0^20160101^git1", "1.0^20160102", Less),
        ("1.0~rc1^git1", "1.0~rc1^git1", Equal),
        ("1.0~rc1^git1", "1.0~rc1", Greater),
        ("1.0~rc1", "1.0~rc1^git1", Less),
        ("1.0^git1~pre", "1.0^git1~pre", Equal),
        ("1.0^git1", "1.0^git1~pre", Greater),
        ("1.0^git1~pre", "1.0^git1", Less),
    ];

    #[test]
    fn rpmvercmp_table() {
        for &(a, b, want) in CASES {
            assert_eq!(rpmvercmp(a, b), want, "rpmvercmp({a:?}, {b:?})");
        }
    }

    #[test]
    fn non_ascii_acts_as_separator() {
        assert_eq!(rpmvercmp("1.é2", "1.2"), Equal);
        assert_eq!(rpmvercmp("", ""), Equal);
        assert_eq!(rpmvercmp("", "1"), Less);
    }

    fn evr(s: &str) -> RpmEvr {
        s.parse().unwrap_or_else(|never| match never {})
    }

    #[test]
    fn evr_epoch_dominates() {
        assert!(evr("1:1.0-1") > evr("9.9-9"));
        assert_eq!(evr("0:1.0-1"), evr("1.0-1"));
        assert!(evr("2:1.0-1") > evr("1:9.0-1"));
    }

    #[test]
    fn evr_release_and_missing_release() {
        assert!(evr("1.26.2-1.fc41") < evr("1.26.3-1.fc41"));
        assert!(evr("1.26.2-1.fc41") < evr("1.26.2-2.fc41"));
        assert_eq!(evr("1.26.2"), evr("1.26.2-1.fc41"));
        assert!(evr("1.26.2") < evr("1.26.3-1.fc41"));
    }

    #[test]
    fn evr_display_roundtrip() {
        assert_eq!(evr("1:1.26.2-1.fc41").to_string(), "1:1.26.2-1.fc41");
        assert_eq!(evr("0:1.0-1").to_string(), "0:1.0-1".replacen("0:", "", 1));
        assert_eq!(evr("1.0").to_string(), "1.0");
        assert_eq!(evr("1:2-3").epoch(), "1");
        assert_eq!(evr("1:2-3").version(), "2");
        assert_eq!(evr("1:2-3").release(), Some("3"));
    }

    /// Deterministic corpus generator (no external crates, no randomness).
    fn corpus() -> Vec<String> {
        let alphabet = [
            "0", "1", "10", "01", "a", "b", "rc", ".", "_", "~", "^", "-",
        ];
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
            assert_eq!(rpmvercmp(a, a), Equal, "reflexive {a:?}");
            for b in &c {
                assert_eq!(
                    rpmvercmp(a, b),
                    rpmvercmp(b, a).reverse(),
                    "antisymmetric {a:?} {b:?}"
                );
            }
        }
        // Transitivity on a thinner sample (full cube is too large).
        let sample: Vec<&String> = c.iter().step_by(37).collect();
        for a in &sample {
            for b in &sample {
                for d in &sample {
                    if rpmvercmp(a, b) != Greater && rpmvercmp(b, d) != Greater {
                        assert_ne!(rpmvercmp(a, d), Greater, "transitive {a:?} {b:?} {d:?}");
                    }
                }
            }
        }
    }
}
