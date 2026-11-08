// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! FIRST EPSS scores.
//!
//! Source: `https://api.first.org/data/v1/epss?cve=CVE-A,CVE-B`. The API
//! returns numbers as strings. Only CVE ids are sent, never host data.

use std::collections::BTreeMap;

use serde::Deserialize;

/// Upper bound for an EPSS response.
pub const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// Failures while reading a response.
#[derive(Debug, thiserror::Error)]
pub enum EpssError {
    /// The response exceeds [`MAX_RESPONSE_BYTES`].
    #[error("EPSS response is {0} bytes, above the {MAX_RESPONSE_BYTES} byte limit")]
    TooLarge(usize),
    /// Not the expected JSON document.
    #[error("EPSS response is not valid JSON of the expected shape: {0}")]
    Invalid(#[from] serde_json::Error),
    /// The API reported a non-OK status.
    #[error("EPSS API status {0:?}")]
    Status(String),
}

#[derive(Debug, Deserialize)]
struct Raw {
    status: String,
    #[serde(default)]
    data: Vec<RawScore>,
}

#[derive(Debug, Deserialize)]
struct RawScore {
    cve: String,
    epss: String,
    percentile: String,
    date: String,
}

/// An EPSS score for one CVE.
#[derive(Debug, Clone, PartialEq)]
pub struct Epss {
    /// Probability of exploitation in the next 30 days, 0.0 to 1.0.
    pub score: f64,
    /// Percentile among all scored CVEs, 0.0 to 1.0.
    pub percentile: f64,
    /// Date of the score, `YYYY-MM-DD`.
    pub date: String,
}

/// Scores keyed by CVE.
#[derive(Debug, Default)]
pub struct EpssScores {
    scores: BTreeMap<String, Epss>,
}

/// A finite number inside 0.0..=1.0.
fn unit(s: &str) -> Option<f64> {
    s.parse::<f64>().ok().filter(|v| (0.0..=1.0).contains(v))
}

impl EpssScores {
    /// Parses an API response. Entries with an unexpected CVE id, number or
    /// date are skipped. CVEs EPSS does not know are simply absent.
    ///
    /// # Errors
    ///
    /// Fails on oversized or malformed input or a non-OK API status.
    pub fn parse(bytes: &[u8]) -> Result<Self, EpssError> {
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(EpssError::TooLarge(bytes.len()));
        }
        let raw: Raw = serde_json::from_slice(bytes)?;
        if raw.status != "OK" {
            return Err(EpssError::Status(raw.status.chars().take(40).collect()));
        }
        let scores = raw
            .data
            .into_iter()
            .filter_map(|r| {
                let b = r.date.as_bytes();
                let date_ok = b.len() == 10 && b.get(4) == Some(&b'-') && b.get(7) == Some(&b'-');
                (crate::is_cve_id(&r.cve) && date_ok).then_some(())?;
                Some((
                    r.cve,
                    Epss {
                        score: unit(&r.epss)?,
                        percentile: unit(&r.percentile)?,
                        date: r.date,
                    },
                ))
            })
            .collect();
        Ok(Self { scores })
    }

    /// The score for a CVE.
    #[must_use]
    pub fn get(&self, cve: &str) -> Option<&Epss> {
        self.scores.get(cve)
    }

    /// Number of scores kept.
    #[must_use]
    pub fn len(&self) -> usize {
        self.scores.len()
    }

    /// True when empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.scores.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &[u8] = include_bytes!("../../../tests/fixtures/http/epss/2026-11-08/epss.json");

    #[test]
    fn parses_recorded_response() {
        let s = EpssScores::parse(FIXTURE).unwrap();
        assert_eq!(s.len(), 2);
        let regress = s.get("CVE-2024-6387").unwrap();
        assert!((regress.score - 0.995_06).abs() < 1e-9);
        assert!((regress.percentile - 0.999_45).abs() < 1e-9);
        assert_eq!(regress.date, "2026-11-07");
        assert!(s.get("CVE-0000-0001").is_none());
    }

    #[test]
    fn out_of_range_and_garbage_values_are_skipped() {
        let json = br#"{"status":"OK","data":[
          {"cve":"CVE-0000-0001","epss":"1.5","percentile":"0.5","date":"2026-01-01"},
          {"cve":"CVE-0000-0002","epss":"NaN","percentile":"0.5","date":"2026-01-01"},
          {"cve":"CVE-0000-0003","epss":"0.5","percentile":"0.5","date":"2026-01-01"}]}"#;
        let s = EpssScores::parse(json).unwrap();
        assert_eq!(s.len(), 1);
        assert!(s.get("CVE-0000-0003").is_some());
    }

    #[test]
    fn errors() {
        assert!(matches!(
            EpssScores::parse(br#"{"status":"ERROR","data":[]}"#),
            Err(EpssError::Status(_))
        ));
        assert!(matches!(
            EpssScores::parse(b"nope"),
            Err(EpssError::Invalid(_))
        ));
        assert!(matches!(
            EpssScores::parse(&vec![b' '; MAX_RESPONSE_BYTES + 1]),
            Err(EpssError::TooLarge(_))
        ));
        assert!(EpssScores::parse(br#"{"status":"OK"}"#).unwrap().is_empty());
    }
}
