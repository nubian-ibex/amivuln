// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Data sources: parsers, an HTTP client and cache-aware fetching.
//!
//! Parsers take bytes so they can be tested with recorded fixtures and
//! fuzzed. [`http`] performs bounded, conditional requests and [`fetch`]
//! combines it with the cache so every answer carries a source status.

#![forbid(unsafe_code)]

pub mod arch;
pub mod epss;
pub mod fedora;
pub mod fetch;
pub mod http;
pub mod kev;
pub mod nvd;
pub mod osv;
pub mod resilience;

/// True for identifiers shaped like `CVE-YYYY-NNNN...`. Identifiers from the
/// network that do not match are dropped rather than shown to the user.
pub(crate) fn is_cve_id(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("CVE-") else {
        return false;
    };
    let Some((year, seq)) = rest.split_once('-') else {
        return false;
    };
    year.len() == 4
        && year.bytes().all(|b| b.is_ascii_digit())
        && (4..=12).contains(&seq.len())
        && seq.bytes().all(|b| b.is_ascii_digit())
}
