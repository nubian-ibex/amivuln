// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! CISA Known Exploited Vulnerabilities catalog.
//!
//! Source: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`.

use std::collections::BTreeMap;

use serde::Deserialize;

/// Upper bound for the catalog (about 1.8 MB in 2026-11).
pub const MAX_RESPONSE_BYTES: usize = 32 * 1024 * 1024;

/// Failures while reading the catalog.
#[derive(Debug, thiserror::Error)]
pub enum KevError {
    /// The response exceeds [`MAX_RESPONSE_BYTES`].
    #[error("KEV catalog is {0} bytes, above the {MAX_RESPONSE_BYTES} byte limit")]
    TooLarge(usize),
    /// Not the expected JSON document.
    #[error("KEV catalog is not valid JSON of the expected shape: {0}")]
    Invalid(#[from] serde_json::Error),
}

#[derive(Debug, Deserialize)]
struct Raw {
    vulnerabilities: Vec<RawEntry>,
}

#[derive(Debug, Deserialize)]
struct RawEntry {
    #[serde(rename = "cveID")]
    cve: String,
    #[serde(rename = "dateAdded")]
    date_added: String,
    #[serde(rename = "knownRansomwareCampaignUse", default)]
    ransomware: String,
}

/// One catalog entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KevEntry {
    /// Date CISA added the CVE, `YYYY-MM-DD`.
    pub added: String,
    /// True when CISA marks it as used in ransomware campaigns.
    pub ransomware: bool,
}

/// The parsed catalog.
#[derive(Debug, Default)]
pub struct Kev {
    entries: BTreeMap<String, KevEntry>,
}

/// `YYYY-MM-DD` shape check; anything else from the network is dropped.
fn is_date(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 10
        && b.iter().enumerate().all(|(i, c)| match i {
            4 | 7 => *c == b'-',
            _ => c.is_ascii_digit(),
        })
}

impl Kev {
    /// Parses the catalog JSON. Entries with an unexpected CVE id or date
    /// shape are skipped rather than trusted.
    ///
    /// # Errors
    ///
    /// Fails on oversized or malformed input.
    pub fn parse(bytes: &[u8]) -> Result<Self, KevError> {
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(KevError::TooLarge(bytes.len()));
        }
        let raw: Raw = serde_json::from_slice(bytes)?;
        let entries = raw
            .vulnerabilities
            .into_iter()
            .filter(|e| crate::is_cve_id(&e.cve) && is_date(&e.date_added))
            .map(|e| {
                (
                    e.cve,
                    KevEntry {
                        added: e.date_added,
                        ransomware: e.ransomware == "Known",
                    },
                )
            })
            .collect();
        Ok(Self { entries })
    }

    /// The entry for a CVE, when it is in the catalog.
    #[must_use]
    pub fn get(&self, cve: &str) -> Option<&KevEntry> {
        self.entries.get(cve)
    }

    /// Number of entries kept.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &[u8] = include_bytes!(
        "../../../tests/fixtures/http/kev/2026-11-08/known_exploited_vulnerabilities.json"
    );

    #[test]
    fn parses_recorded_catalog() {
        let k = Kev::parse(FIXTURE).unwrap();
        assert_eq!(k.len(), 2);
        let ransom = k.get("CVE-2026-59310").unwrap();
        assert_eq!(ransom.added, "2026-08-18");
        assert!(ransom.ransomware);
        let plain = k.get("CVE-2026-19868").unwrap();
        assert!(!plain.ransomware);
        assert!(k.get("CVE-2024-6387").is_none());
    }

    #[test]
    fn hostile_entries_are_skipped() {
        let json = br#"{"vulnerabilities":[
            {"cveID":"CVE-0000-0001","dateAdded":"2026-01-02","knownRansomwareCampaignUse":"Known"},
            {"cveID":"\u001b[31mCVE-0000-0002","dateAdded":"2026-01-02"},
            {"cveID":"CVE-0000-0003","dateAdded":"yesterday"}]}"#;
        let k = Kev::parse(json).unwrap();
        assert_eq!(k.len(), 1);
        assert!(k.get("CVE-0000-0001").unwrap().ransomware);
    }

    #[test]
    fn rejects_bad_input() {
        assert!(matches!(Kev::parse(b"[]"), Err(KevError::Invalid(_))));
        assert!(matches!(Kev::parse(b"{"), Err(KevError::Invalid(_))));
        assert!(matches!(
            Kev::parse(&vec![b' '; MAX_RESPONSE_BYTES + 1]),
            Err(KevError::TooLarge(_))
        ));
        assert!(Kev::parse(b"{\"vulnerabilities\":[]}").unwrap().is_empty());
    }
}
