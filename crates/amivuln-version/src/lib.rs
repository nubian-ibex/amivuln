// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Version comparison for package ecosystems.
//!
//! The comparators are pure functions over strings. Segments are compared as
//! ASCII only, matching the reference implementations (`rpmvercmp` in rpm and
//! `alpm_pkg_vercmp` in libalpm), so non-ASCII bytes behave as separators.

#![forbid(unsafe_code)]

mod apk;
mod deb;
mod gentoo;
mod pacman;
mod rpm;
mod semver;

pub use apk::{ApkVersion, apk_vercmp};
pub use deb::{DebVersion, debvercmp};
pub use gentoo::{GentooVersion, gentoo_vercmp};
pub use pacman::{PacmanVersion, alpm_vercmp, pacman_vercmp};
pub use rpm::{RpmEvr, rpmvercmp};
pub use semver::{SemverError, SemverVersion};

use core::cmp::Ordering;

/// Splits `s` at the first byte that does not satisfy `pred`.
fn split_while(s: &[u8], pred: impl Fn(u8) -> bool) -> (&[u8], &[u8]) {
    let end = s.iter().position(|&c| !pred(c)).unwrap_or(s.len());
    s.split_at(end)
}

/// Drops the first byte of `s`, if any.
fn advance(s: &[u8]) -> &[u8] {
    s.get(1..).unwrap_or_default()
}

/// Compares two ASCII digit runs as unbounded integers.
fn cmp_numeric(a: &[u8], b: &[u8]) -> Ordering {
    let a = split_while(a, |c| c == b'0').1;
    let b = split_while(b, |c| c == b'0').1;
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

/// Splits an `[epoch:]version[-release]` string, returning `(epoch, version, release)`.
///
/// The epoch is only recognised when it is a non-empty run of digits followed
/// by `:`. The release starts after the last `-`.
fn split_evr(evr: &str) -> (&str, &str, Option<&str>) {
    let digits = evr.bytes().take_while(u8::is_ascii_digit).count();
    let (epoch, rest) = match evr.get(digits..).and_then(|r| r.strip_prefix(':')) {
        Some(rest) if digits > 0 => (evr.get(..digits).unwrap_or("0"), rest),
        _ => ("0", evr),
    };
    match rest.rsplit_once('-') {
        Some((version, release)) => (epoch, version, Some(release)),
        None => (epoch, rest, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_evr_cases() {
        assert_eq!(split_evr("1:2.3-4"), ("1", "2.3", Some("4")));
        assert_eq!(split_evr("2.3-4"), ("0", "2.3", Some("4")));
        assert_eq!(split_evr("2.3"), ("0", "2.3", None));
        assert_eq!(split_evr(":2.3"), ("0", ":2.3", None));
        assert_eq!(split_evr("a:2.3"), ("0", "a:2.3", None));
        assert_eq!(split_evr("1.0-2-3"), ("0", "1.0-2", Some("3")));
        assert_eq!(split_evr(""), ("0", "", None));
    }

    #[test]
    fn numeric_ignores_leading_zeros() {
        assert_eq!(cmp_numeric(b"0010", b"10"), Ordering::Equal);
        assert_eq!(cmp_numeric(b"9", b"10"), Ordering::Less);
        assert_eq!(cmp_numeric(b"", b"0"), Ordering::Equal);
        // Larger than u128: must not overflow.
        assert_eq!(
            cmp_numeric(b"99999999999999999999999999999999999999999", b"1"),
            Ordering::Greater
        );
    }
}

/// Makes `cargo test` run the code examples in the README.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
