// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Gentoo ebuild version comparison (PMS section 3.2).
//!
//! A version is `digits(.digits)*[letter](_suffix[digits])*[-rdigits]`:
//!
//! - the first number compares as an integer; a later component compares as
//!   an integer too, unless either side starts with `0`, when the two are
//!   compared as text with the trailing zeros removed (`1.01` is older than
//!   `1.1`, and `1.0` equals `1.00`);
//! - more components win (`1.0` is older than `1.0.0`);
//! - then the letter: none, then `a`, `b` and so on;
//! - then the suffixes in order, `_alpha < _beta < _pre < _rc < (none) < _p`,
//!   each with an optional number that counts as 0 when it is missing;
//! - then the revision, where no revision and `-r0` are the same.
//!
//! The order is checked against the real `portage.versions.vercmp`: see
//! `tests/gentoo_reference.txt`, 1444 versions in the order the tool sorted
//! them. A string outside the grammar is compared byte by byte, so the order
//! is total and nothing panics.

use core::cmp::Ordering;
use core::fmt;
use core::str::FromStr;

use crate::cmp_numeric;

/// Suffix names with their rank. `_p` sorts after a missing suffix, the rest
/// before it.
const SUFFIXES: [(&str, usize); 5] = [("alpha", 0), ("beta", 1), ("pre", 2), ("rc", 3), ("p", 5)];
/// The rank of "no suffix", between `rc` and `p`.
const NO_SUFFIX: usize = 4;

/// A version split into the parts the comparison looks at.
struct Parsed<'a> {
    /// The dot-separated numbers.
    numbers: Vec<&'a [u8]>,
    letter: Option<u8>,
    /// `(rank, number)` of each suffix.
    suffixes: Vec<(usize, &'a [u8])>,
    revision: &'a [u8],
}

/// Reads a run of digits from the front of `s`.
fn digits(s: &[u8]) -> (&[u8], &[u8]) {
    crate::split_while(s, |c| c.is_ascii_digit())
}

fn parse(version: &str) -> Option<Parsed<'_>> {
    let (mut rest, mut numbers) = (version.as_bytes(), Vec::new());
    loop {
        let (number, tail) = digits(rest);
        if number.is_empty() {
            return None;
        }
        numbers.push(number);
        rest = tail;
        match rest.split_first() {
            Some((b'.', tail)) => rest = tail,
            _ => break,
        }
    }
    let letter = match rest.split_first() {
        Some((c, tail)) if c.is_ascii_lowercase() => {
            rest = tail;
            Some(*c)
        }
        _ => None,
    };
    let mut suffixes = Vec::new();
    while let Some(tail) = rest.strip_prefix(b"_") {
        let word_len = tail.iter().take_while(|c| c.is_ascii_lowercase()).count();
        let (word, tail) = tail.split_at(word_len);
        let rank = SUFFIXES
            .iter()
            .find(|(name, _)| name.as_bytes() == word)
            .map(|(_, rank)| *rank)?;
        let (number, tail) = digits(tail);
        suffixes.push((rank, number));
        rest = tail;
    }
    let revision = match rest.strip_prefix(b"-r") {
        Some(tail) => {
            let (number, tail) = digits(tail);
            if number.is_empty() || !tail.is_empty() {
                return None;
            }
            rest = tail;
            number
        }
        None => b"".as_slice(),
    };
    rest.is_empty().then_some(Parsed {
        numbers,
        letter,
        suffixes,
        revision,
    })
}

/// Compares two components after the first.
fn cmp_component(a: &[u8], b: &[u8]) -> Ordering {
    if a.first() == Some(&b'0') || b.first() == Some(&b'0') {
        let strip = |s: &[u8]| {
            let end = s.iter().rposition(|&c| c != b'0').map_or(0, |i| i + 1);
            s.get(..end).unwrap_or_default().to_vec()
        };
        strip(a).cmp(&strip(b))
    } else {
        cmp_numeric(a, b)
    }
}

fn cmp_parsed(a: &Parsed<'_>, b: &Parsed<'_>) -> Ordering {
    let first = match (a.numbers.first(), b.numbers.first()) {
        (Some(x), Some(y)) => cmp_numeric(x, y),
        _ => Ordering::Equal,
    };
    first
        .then_with(|| {
            a.numbers
                .iter()
                .zip(&b.numbers)
                .skip(1)
                .map(|(x, y)| cmp_component(x, y))
                .find(|o| o.is_ne())
                .unwrap_or(Ordering::Equal)
        })
        .then_with(|| a.numbers.len().cmp(&b.numbers.len()))
        .then_with(|| a.letter.cmp(&b.letter))
        .then_with(|| {
            let longest = a.suffixes.len().max(b.suffixes.len());
            (0..longest)
                .map(|i| {
                    let (rx, nx) = a.suffixes.get(i).copied().unwrap_or((NO_SUFFIX, b""));
                    let (ry, ny) = b.suffixes.get(i).copied().unwrap_or((NO_SUFFIX, b""));
                    rx.cmp(&ry).then_with(|| cmp_numeric(nx, ny))
                })
                .find(|o| o.is_ne())
                .unwrap_or(Ordering::Equal)
        })
        .then_with(|| cmp_numeric(a.revision, b.revision))
}

/// Compares two Gentoo ebuild versions (without the package name).
#[must_use]
pub fn gentoo_vercmp(a: &str, b: &str) -> Ordering {
    match (parse(a), parse(b)) {
        (Some(x), Some(y)) => cmp_parsed(&x, &y),
        _ => a.as_bytes().cmp(b.as_bytes()),
    }
}

/// An ebuild version as written, ordered as Portage orders it.
#[derive(Debug, Clone)]
pub struct GentooVersion(String);

impl GentooVersion {
    /// True when `text` follows the ebuild version grammar; a package
    /// directory name is split where the tail passes this.
    #[must_use]
    pub fn is_valid(text: &str) -> bool {
        parse(text).is_some()
    }

    /// The version exactly as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for GentooVersion {
    type Err = core::convert::Infallible;

    /// Parsing never fails: a string outside the grammar still has a
    /// (byte-wise) order.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_owned()))
    }
}

impl fmt::Display for GentooVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl PartialEq for GentooVersion {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for GentooVersion {}

impl PartialOrd for GentooVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for GentooVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        gentoo_vercmp(&self.0, &other.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every pair of the table, both directions: each class is equal inside
    /// and below every later class.
    #[test]
    fn matches_portage() {
        let table = include_str!("../tests/gentoo_reference.txt");
        let classes: Vec<Vec<&str>> = table
            .lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
            .map(|l| l.split_whitespace().collect())
            .collect();
        assert!(
            classes.len() > 1000,
            "the table shrank to {}",
            classes.len()
        );
        let mut pairs = 0u32;
        for (i, class) in classes.iter().enumerate() {
            for a in class {
                for b in class {
                    assert_eq!(gentoo_vercmp(a, b), Ordering::Equal, "{a} == {b}");
                }
                for later in classes.iter().skip(i + 1) {
                    for b in later {
                        assert_eq!(gentoo_vercmp(a, b), Ordering::Less, "{a} < {b}");
                        assert_eq!(gentoo_vercmp(b, a), Ordering::Greater, "{b} > {a}");
                        pairs += 1;
                    }
                }
            }
        }
        assert!(pairs > 500_000, "only {pairs} pairs were checked");
    }

    #[test]
    fn the_cases_that_set_gentoo_apart() {
        assert_eq!(gentoo_vercmp("1.0-r0", "1.0"), Ordering::Equal);
        assert_eq!(gentoo_vercmp("1.0-r1", "1.0-r0"), Ordering::Greater);
        assert_eq!(gentoo_vercmp("1.0", "1.00"), Ordering::Equal);
        assert_eq!(gentoo_vercmp("1.01", "1.1"), Ordering::Less);
        assert_eq!(gentoo_vercmp("5", "5.0"), Ordering::Less);
        assert_eq!(gentoo_vercmp("1.0_p1", "1.0"), Ordering::Greater);
        assert_eq!(gentoo_vercmp("1.0_rc1", "1.0"), Ordering::Less);
    }

    #[test]
    fn text_outside_the_grammar_still_has_an_order() {
        for bad in ["", "abc", "1..2", "1.0-r", "1.0_zeta", "1.0-rx", "1.0 "] {
            assert_eq!(gentoo_vercmp(bad, bad), Ordering::Equal, "{bad:?}");
            assert_ne!(gentoo_vercmp(bad, "1.0"), Ordering::Equal, "{bad:?}");
            assert_eq!(
                gentoo_vercmp(bad, "1.0"),
                gentoo_vercmp("1.0", bad).reverse(),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn the_type_orders_and_prints_the_text() {
        let a: GentooVersion = "3.0.12-r1".parse().unwrap_or_else(|n| match n {});
        let b: GentooVersion = "3.0.12".parse().unwrap_or_else(|n| match n {});
        assert!(a > b);
        assert_eq!(a.to_string(), "3.0.12-r1");
        assert_eq!(b.as_str(), "3.0.12");
    }
}
