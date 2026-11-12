// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Alpine `apk` version comparison.
//!
//! A version is `digits(.digits)*[letter](_suffix[digits])*[-rdigits]`. The
//! order was derived from `apk version -t` (see `tests/apk_reference.txt`):
//!
//! - numbers compare numerically, except that a later component with a
//!   leading zero compares as text (`1.02` is older than `1.1`);
//! - `_alpha`, `_beta`, `_pre` and `_rc` sort before the bare version and
//!   `_cvs`, `_svn`, `_git`, `_hg` and `_p` sort after it;
//! - at the first token that differs in kind: a pre-release suffix is the
//!   lowest, then the revision, then a post-release suffix, then a letter,
//!   then a number;
//! - a longer version beats a shorter one unless its extra token is a
//!   pre-release suffix, and `-r0` beats no revision at all.
//!
//! A string that does not follow the grammar is compared byte by byte, so
//! the order stays total and nothing panics.

use core::cmp::Ordering;
use core::fmt;
use core::str::FromStr;

use crate::cmp_numeric;

/// Suffix names in ascending order; the first four are pre-releases.
const SUFFIXES: [&str; 9] = ["alpha", "beta", "pre", "rc", "cvs", "svn", "git", "hg", "p"];
const PRE_RELEASES: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    /// A number; `first` marks the leading component.
    Number {
        digits: String,
        first: bool,
    },
    Letter(u8),
    Suffix {
        rank: usize,
        digits: String,
    },
    Revision(String),
}

impl Token {
    /// Rank used when two tokens at the same position differ in kind.
    fn kind_rank(&self) -> u8 {
        match self {
            Self::Suffix { rank, .. } if *rank < PRE_RELEASES => 0,
            Self::Revision(_) => 1,
            Self::Suffix { .. } => 2,
            Self::Letter(_) => 3,
            Self::Number { .. } => 4,
        }
    }

    fn is_pre_release(&self) -> bool {
        matches!(self, Self::Suffix { rank, .. } if *rank < PRE_RELEASES)
    }

    fn cmp_same_kind(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::Number { digits: a, first }, Self::Number { digits: b, .. }) => {
                if !first && (a.starts_with('0') || b.starts_with('0')) {
                    a.cmp(b)
                } else {
                    cmp_numeric(a.as_bytes(), b.as_bytes())
                }
            }
            (Self::Letter(a), Self::Letter(b)) => a.cmp(b),
            (
                Self::Suffix {
                    rank: ra,
                    digits: da,
                },
                Self::Suffix {
                    rank: rb,
                    digits: db,
                },
            ) => ra
                .cmp(rb)
                .then_with(|| cmp_numeric(da.as_bytes(), db.as_bytes())),
            (Self::Revision(a), Self::Revision(b)) => cmp_numeric(a.as_bytes(), b.as_bytes()),
            _ => self.kind_rank().cmp(&other.kind_rank()),
        }
    }
}

fn take_digits(s: &str) -> (&str, &str) {
    let end = s
        .bytes()
        .position(|b| !b.is_ascii_digit())
        .unwrap_or(s.len());
    s.split_at(end)
}

/// Parses the grammar, or returns `None` for anything else.
fn tokenize(s: &str) -> Option<Vec<Token>> {
    let (digits, mut rest) = take_digits(s);
    if digits.is_empty() {
        return None;
    }
    let mut tokens = vec![Token::Number {
        digits: digits.to_owned(),
        first: true,
    }];
    while let Some(c) = rest.bytes().next() {
        if c == b'.' {
            let (digits, tail) = take_digits(rest.get(1..)?);
            if digits.is_empty() {
                return None;
            }
            tokens.push(Token::Number {
                digits: digits.to_owned(),
                first: false,
            });
            rest = tail;
        } else if c.is_ascii_lowercase() {
            tokens.push(Token::Letter(c));
            rest = rest.get(1..)?;
        } else if c == b'_' {
            let after = rest.get(1..)?;
            // `p` is a prefix of nothing else, but `pre` starts with `p`, so
            // try the longer names first.
            let (rank, name) = SUFFIXES
                .iter()
                .enumerate()
                .filter(|(_, n)| after.starts_with(**n))
                .max_by_key(|(_, n)| n.len())?;
            let (digits, tail) = take_digits(after.get(name.len()..)?);
            tokens.push(Token::Suffix {
                rank,
                digits: digits.to_owned(),
            });
            rest = tail;
        } else {
            let after = rest.strip_prefix("-r")?;
            let (digits, tail) = take_digits(after);
            // The revision ends the version.
            (!digits.is_empty() && tail.is_empty()).then_some(())?;
            tokens.push(Token::Revision(digits.to_owned()));
            rest = tail;
        }
    }
    Some(tokens)
}

/// Compares two apk version strings.
#[must_use]
pub fn apk_vercmp(a: &str, b: &str) -> Ordering {
    if a == b {
        return Ordering::Equal;
    }
    let (Some(ta), Some(tb)) = (tokenize(a), tokenize(b)) else {
        return a.as_bytes().cmp(b.as_bytes());
    };
    for i in 0..ta.len().max(tb.len()) {
        match (ta.get(i), tb.get(i)) {
            (Some(x), Some(y)) => {
                let ord = x.cmp_same_kind(y);
                if ord != Ordering::Equal {
                    return ord;
                }
            }
            (Some(x), None) => {
                return if x.is_pre_release() {
                    Ordering::Less
                } else {
                    Ordering::Greater
                };
            }
            (None, Some(y)) => {
                return if y.is_pre_release() {
                    Ordering::Greater
                } else {
                    Ordering::Less
                };
            }
            (None, None) => {}
        }
    }
    Ordering::Equal
}

/// An apk package version string with apk-tools ordering.
#[derive(Debug, Clone)]
pub struct ApkVersion(String);

impl ApkVersion {
    /// The version exactly as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for ApkVersion {
    type Err = core::convert::Infallible;

    /// Parsing never fails: a string outside the grammar still has a
    /// (byte-wise) order.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_owned()))
    }
}

impl fmt::Display for ApkVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl PartialEq for ApkVersion {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for ApkVersion {}

impl PartialOrd for ApkVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ApkVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        apk_vercmp(&self.0, &other.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every pair from the real `apk version -t`, both directions.
    #[test]
    fn matches_the_reference_tool() {
        let table = include_str!("../tests/apk_reference.txt");
        let mut checked = 0;
        for line in table.lines().filter(|l| !l.starts_with('#')) {
            let mut f = line.split_whitespace();
            let (Some(a), Some(b), Some(op)) = (f.next(), f.next(), f.next()) else {
                continue;
            };
            let want = match op {
                "<" => Ordering::Less,
                ">" => Ordering::Greater,
                _ => Ordering::Equal,
            };
            assert_eq!(apk_vercmp(a, b), want, "apk_vercmp({a:?}, {b:?})");
            assert_eq!(apk_vercmp(b, a), want.reverse(), "apk_vercmp({b:?}, {a:?})");
            checked += 1;
        }
        assert!(checked > 900, "the table shrank to {checked} pairs");
    }

    #[test]
    fn invalid_strings_order_without_panicking() {
        for (a, b) in [
            ("", "1.0"),
            ("9.2p1-r0", "9.2p1-r1"),
            ("x", "x"),
            ("1..2", "1.2"),
        ] {
            assert_eq!(apk_vercmp(a, b), apk_vercmp(b, a).reverse());
        }
        assert_eq!(apk_vercmp("9.2p1-r0", "9.2p1-r1"), Ordering::Less);
    }

    #[test]
    fn version_type_orders() {
        let v = |s: &str| {
            s.parse::<ApkVersion>()
                .unwrap_or_else(|never| match never {})
        };
        assert!(v("3.1.4-r0") < v("3.1.4-r1"));
        assert!(v("1.0_rc1") < v("1.0"));
        assert_eq!(v("3.20.1-r0").to_string(), "3.20.1-r0");
    }
}
