// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Version banner strings found in binaries, for a curated set of C products.
//!
//! The patterns are the exact banners the upstream projects print in their
//! version report (`OpenSSL 3.2.2`, `curl/8.5.0`, `zlib 1.3.1`, `SQLite version 3.45.1`,
//! `nginx/1.26.2`). The match is a byte prefix search, so the scan is linear in
//! the file size and never matches more than the known banner formats.
//!
//! These hits are **heuristic**: the embedded upstream version tells you what
//! was compiled in, but the distribution may have backported fixes without
//! changing the banner. Every formatter must carry the low-confidence mark.

/// Largest file scanned for version banners.
pub const MAX_STRING_FILE: u64 = 512 * 1024 * 1024;

/// A version banner found in a binary.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct StringHit {
    /// Product name, lowercase, matching the distro package name.
    pub name: String,
    /// Upstream version as printed by the product.
    pub version: String,
    /// Which banner produced the hit.
    pub banner: &'static str,
}

/// The curated banners, with the product name they identify.
///
/// Each banner is the exact prefix the upstream project writes, and the
/// version starts at the first byte after the prefix. The version alphabet
/// is checked against the characters that follow, so `OpenSSL 3` without
/// digits and dots is not a match.
const BANNERS: &[(&[u8], &str)] = &[
    (b"OpenSSL ", "openssl"),
    (b"curl/", "curl"),
    (b"zlib version ", "zlib"),
    (b"SQLite version ", "sqlite"),
    (b"nginx/", "nginx"),
    (b"liblzma ", "xz"),
    (b"Brotli ", "brotli"),
    (b"libpng version ", "libpng"),
    (b"libxml ", "libxml2"),
    (b"PCRE2 version ", "pcre2"),
    (b"expat_", "expat"),
    (b"libevent ", "libevent"),
    (b"OpenLDAP ", "openldap"),
    (b"GNUTLS ", "gnutls"),
];

/// Scans `bytes` for every curated banner and returns the hits, deduplicated.
///
/// The scan is linear: for each banner, the first-byte candidates are found
/// with a skip-ahead loop, the same approach the embedded-metadata scanner
/// uses. The version is the longest run of version-alphabet bytes after the
/// banner, which stops at the separator the product uses.
#[must_use]
pub fn detect_strings(bytes: &[u8]) -> Vec<StringHit> {
    let mut found: std::collections::BTreeSet<StringHit> = std::collections::BTreeSet::new();
    for (banner, name) in BANNERS {
        let mut from = 0usize;
        while let Some(at) = find_from(bytes, banner, from) {
            let after = at + banner.len();
            let Some(rest) = bytes.get(after..) else {
                break;
            };
            let end = rest
                .iter()
                .position(|b| *b == b' ' || *b == b'\n' || *b == b'\r' || *b == 0)
                .unwrap_or(rest.len());
            let version_bytes = rest.get(..end).unwrap_or_default();
            let version = String::from_utf8_lossy(version_bytes).into_owned();
            if !version.is_empty()
                && version.len() <= 32
                && version
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
                && version.bytes().next().is_some_and(|b| b.is_ascii_digit())
            {
                found.insert(StringHit {
                    name: (*name).to_owned(),
                    version: version.clone(),
                    banner: std::str::from_utf8(banner).unwrap_or_default(),
                });
            }
            from = after;
        }
    }
    found.into_iter().collect()
}

/// Finds the first occurrence of `needle` at or after `from`.
fn find_from(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    let first = *needle.first()?;
    let mut at = from;
    while at < haystack.len() {
        let hit = at + haystack.get(at..)?.iter().position(|&b| b == first)?;
        if haystack
            .get(hit..hit.checked_add(needle.len())?)
            .is_some_and(|w| w == needle)
        {
            return Some(hit);
        }
        at = hit + 1;
    }
    None
}

/// Reads `path` and scans it for version banners.
///
/// # Errors
///
/// Fails when the file cannot be read or is too large.
pub fn detect(path: &std::path::Path) -> Result<Vec<StringHit>, String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if meta.len() > MAX_STRING_FILE {
        return Err(format!(
            "{} is larger than {MAX_STRING_FILE} bytes",
            path.display()
        ));
    }
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(detect_strings(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn banners_in_a_synthetic_binary() {
        let mut bytes = vec![0x7f, b'E', b'L', b'F', 0x02, 0x01];
        bytes.extend_from_slice(&[0u8; 64]);
        bytes.extend_from_slice(b"OpenSSL 3.2.2 26 Feb 2025\n");
        bytes.extend_from_slice(b"curl/8.5.0\n");
        bytes.extend_from_slice(b"zlib version 1.3.1\n");
        bytes.extend_from_slice(b"SQLite version 3.45.1\n");
        bytes.extend_from_slice(b"nginx/1.26.2\n");
        bytes.extend_from_slice(&[0u8; 16]);
        let found = detect_strings(&bytes);
        let names: Vec<(&str, &str)> = found
            .iter()
            .map(|h| (h.name.as_str(), h.version.as_str()))
            .collect();
        assert_eq!(
            names,
            [
                ("curl", "8.5.0"),
                ("nginx", "1.26.2"),
                ("openssl", "3.2.2"),
                ("sqlite", "3.45.1"),
                ("zlib", "1.3.1"),
            ]
        );
    }

    #[test]
    fn version_run_stops_at_the_separator() {
        // "OpenSSL 3.2.2" followed by a space then other text.
        let bytes = b"prefix OpenSSL 3.2.2 suffix";
        let found = detect_strings(bytes);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].version, "3.2.2");
    }

    #[test]
    fn a_banner_without_digits_is_not_a_hit() {
        // "OpenSSL " followed by non-digit characters.
        let bytes = b"OpenSSL done";
        assert!(detect_strings(bytes).is_empty());
    }

    #[test]
    fn empty_and_garbage_input_are_misses() {
        assert!(detect_strings(b"").is_empty());
        assert!(detect_strings(&[0u8; 1024]).is_empty());
        let junk: Vec<u8> = (0..1024u32)
            .map(|i| u8::try_from(i % 251).unwrap_or(0))
            .collect();
        assert!(detect_strings(&junk).is_empty());
    }

    #[test]
    fn a_mutation_storm_never_panics() {
        // Deterministic xorshift mutation over a seed with real banners.
        let mut state = 0xdead_beef_cafe_f00d_u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let seed = b"OpenSSL 3.2.2\nzlib 1.3.1\ncurl/8.5.0\n";
        for _ in 0..2000 {
            let mut bytes = seed.to_vec();
            for _ in 0..(next() % 8) {
                let at = usize::try_from(next() % bytes.len() as u64).unwrap_or(0);
                if let Some(b) = bytes.get_mut(at) {
                    *b = u8::try_from(next() % 256).unwrap_or(0);
                }
            }
            if next() % 3 == 0 {
                bytes.truncate(usize::try_from(next() % bytes.len() as u64).unwrap_or(0));
            }
            let _ = detect_strings(&bytes);
        }
    }
}
