// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! OSV.dev: the only structured source for Debian, Ubuntu, Rocky and `AlmaLinux`.
//!
//! `POST /v1/querybatch` with `{package: {name, ecosystem}, version}` per
//! query (ecosystems `Debian:12`, `Ubuntu:24.04`, ...). The response lists
//! vulnerability ids; each is fetched with `GET /v1/vulns/{id}`. A Debian or
//! Ubuntu advisory id is `DEBIAN-CVE-...` / `UBUNTU-CVE-...`, and `upstream`
//! carries the plain CVE ids. An `ECOSYSTEM` range states the version that
//! fixed the issue, so distro awareness works like the other sources.
//!
//! Querying sends only package name, ecosystem and version.

use std::collections::BTreeMap;

use serde::Deserialize;

/// Upper bound for one advisory.
pub const MAX_ADVISORY_BYTES: usize = 4 * 1024 * 1024;

/// Failures while reading OSV data.
#[derive(Debug, thiserror::Error)]
pub enum OsvError {
    /// The advisory is larger than [`MAX_ADVISORY_BYTES`].
    #[error("OSV advisory is {0} bytes, above the {MAX_ADVISORY_BYTES} byte limit")]
    TooLarge(usize),
    /// Not the expected JSON shape.
    #[error("OSV data is not valid JSON of the expected shape: {0}")]
    Invalid(#[from] serde_json::Error),
}

#[derive(Debug, Deserialize)]
pub(crate) struct BatchResponse {
    pub(crate) results: Vec<BatchResult>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct BatchResult {
    #[serde(default)]
    pub(crate) vulns: Vec<BatchId>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct BatchId {
    pub(crate) id: String,
}

/// Builds the `querybatch` request body for one query.
///
/// # Errors
///
/// Serialization of plain strings cannot fail, but the request is what carries
/// the query, so the error is surfaced instead of an empty body.
pub fn batch_request(name: &str, ecosystem: &str, version: &str) -> Result<String, OsvError> {
    // The endpoint takes {"queries": [...]}; a bare object answers `{}`.
    serde_json::to_string(&serde_json::json!({
        "queries": [{
            "package": {"name": name, "ecosystem": ecosystem},
            "version": version
        }]
    }))
    .map_err(OsvError::Invalid)
}

/// Decodes a `querybatch` response, ignoring ids that do not look like
/// `<DISTRO>-CVE-...`.
///
/// # Errors
///
/// Fails on malformed JSON.
pub fn parse_batch(bytes: &[u8]) -> Result<Vec<String>, OsvError> {
    let r: BatchResponse = serde_json::from_slice(bytes)?;
    Ok(r.results
        .into_iter()
        .flat_map(|res| res.vulns)
        .map(|v| v.id)
        .filter(|id| is_advisory_id(id))
        .collect())
}

/// Accepts `DEBIAN-CVE-...`/`UBUNTU-CVE-...` and the Rocky/Alma errata ids
/// `RLSA-YYYY:NNNN` and `ALSA-YYYY:NNNN`; anything else is dropped so an id
/// from the response never reaches a URL unchecked.
fn is_advisory_id(id: &str) -> bool {
    if let Some((prefix, rest)) = id.split_once('-') {
        if matches!(prefix, "RLSA" | "ALSA") {
            return rest.split_once(':').is_some_and(|(y, n)| {
                !y.is_empty()
                    && !n.is_empty()
                    && y.bytes().all(|b| b.is_ascii_digit())
                    && n.bytes().all(|b| b.is_ascii_digit())
            });
        }
        return crate::is_cve_id(rest);
    }
    crate::is_cve_id(id)
}

#[derive(Debug, Deserialize)]
struct RawVuln {
    #[serde(default)]
    affected: Vec<RawAffected>,
    #[serde(default)]
    upstream: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawAffected {
    package: Option<RawPackage>,
    #[serde(default)]
    ranges: Vec<RawRange>,
}

#[derive(Debug, Deserialize)]
struct RawPackage {
    ecosystem: String,
}

#[derive(Debug, Deserialize)]
struct RawRange {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    events: Vec<RawEvent>,
}

#[derive(Debug, Deserialize)]
struct RawEvent(BTreeMap<String, String>);

/// What OSV says about one CVE for one package on one distro release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsvEntry {
    /// Advisory id, for example `DEBIAN-CVE-2023-5363`.
    pub advisory: String,
    /// CVE ids this advisory covers, sorted.
    pub cves: Vec<String>,
    /// First fixed version, when published. `None` means the distro has not
    /// fixed it yet, which mirrors the other sources.
    pub fixed: Option<String>,
}

/// Advisories grouped by CVE.
#[derive(Debug, Default)]
pub struct OsvData {
    by_cve: BTreeMap<String, Vec<OsvEntry>>,
}

impl OsvData {
    /// Parses one advisory document.
    ///
    /// # Errors
    ///
    /// Fails on oversized or malformed input.
    pub fn parse_advisory(bytes: &[u8], ecosystem: &str) -> Result<Self, OsvError> {
        if bytes.len() > MAX_ADVISORY_BYTES {
            return Err(OsvError::TooLarge(bytes.len()));
        }
        let raw: RawVuln = serde_json::from_slice(bytes)?;
        let advisory = raw
            .affected
            .iter()
            .filter(|a| a.package.as_ref().is_some_and(|p| p.ecosystem == ecosystem))
            .flat_map(|a| {
                a.ranges
                    .iter()
                    .filter(|r| r.kind == "ECOSYSTEM")
                    .filter_map(|r| r.events.iter().find_map(|e| e.0.get("fixed").cloned()))
            })
            .min();
        let cves: Vec<String> = raw
            .upstream
            .iter()
            .filter(|c| crate::is_cve_id(c))
            .cloned()
            .collect();
        Ok(Self::from_entries(vec![OsvEntry {
            advisory: advisory.clone().unwrap_or_default(),
            cves,
            fixed: advisory,
        }]))
    }

    /// Combines parsed advisories.
    #[must_use]
    pub fn from_entries(entries: Vec<OsvEntry>) -> Self {
        let mut by_cve: BTreeMap<String, Vec<OsvEntry>> = BTreeMap::new();
        for e in entries {
            for cve in e.cves.clone() {
                by_cve.entry(cve).or_default().push(e.clone());
            }
        }
        // Several advisories may cover one CVE; the lowest fix wins, matching
        // the Fedora rule: installed at or above any published fix is patched.
        for list in by_cve.values_mut() {
            list.sort_by(|a, b| a.fixed.cmp(&b.fixed));
        }
        Self { by_cve }
    }

    /// The earliest fix published for a CVE, when any.
    #[must_use]
    pub fn fix_for(&self, cve: &str) -> Option<&str> {
        self.by_cve
            .get(cve)
            .and_then(|l| l.first())
            .and_then(|e| e.fixed.as_deref())
    }

    /// Every advisory entry.
    #[must_use]
    pub fn entries(&self) -> Vec<OsvEntry> {
        self.by_cve.values().flatten().cloned().collect()
    }

    /// Every CVE id recorded, sorted.
    #[must_use]
    pub fn ids(&self) -> Vec<String> {
        self.by_cve.keys().cloned().collect()
    }

    /// True when the data has a record of the CVE.
    #[must_use]
    pub fn knows(&self, cve: &str) -> bool {
        self.by_cve.contains_key(cve)
    }

    /// Number of CVEs recorded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_cve.len()
    }

    /// True when empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_cve.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advisory_ids_accept_errata_and_reject_noise() {
        for ok in ["DEBIAN-CVE-2023-5363", "RLSA-2024:2463", "ALSA-2024:2463"] {
            assert!(is_advisory_id(ok), "{ok}");
        }
        for bad in ["RLSA-2024", "RLSA-x:1", "RLSA-2024:1/../x", "GHSA-xxxx", ""] {
            assert!(!is_advisory_id(bad), "{bad}");
        }
    }

    #[test]
    fn batch_request_and_response() {
        let req = batch_request("openssl", "Debian:12", "3.0.11-1~deb12u1").unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&req).unwrap(),
            serde_json::json!({
                "queries": [{
                    "package": {"name": "openssl", "ecosystem": "Debian:12"},
                    "version": "3.0.11-1~deb12u1"
                }]
            })
        );
        let ids = parse_batch(
            br#"{"results":[{"vulns":[{"id":"DEBIAN-CVE-2023-5363"},{"id":"CVE-0000-0001"},{"id":"UBUNTU-CVE-2024-13176"},{"id":"GHSA-xxxx"}]},{"vulns":[]}]}"#,
        )
        .unwrap();
        assert_eq!(ids, ["DEBIAN-CVE-2023-5363", "UBUNTU-CVE-2024-13176"]);
        assert!(parse_batch(br#"{"results":[]}"#).unwrap().is_empty());
        assert!(parse_batch(b"[]").is_err());
    }

    #[test]
    fn advisory_parses_the_ecosystem_fix_and_upstream_cves() {
        let json = br#"{
            "id": "DEBIAN-CVE-2023-5363",
            "upstream": ["CVE-2023-5363", "GHSA-xxxx"],
            "affected": [{
                "package": {"name": "openssl", "ecosystem": "Debian:12"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.0.11-1~deb12u2"}]}],
                "versions": ["3.0.10-1"]
            }, {
                "package": {"name": "openssl", "ecosystem": "Debian:13"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.0.12-1"}]}]
            }],
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}]
        }"#;
        let d = OsvData::parse_advisory(json, "Debian:12").unwrap();
        assert_eq!(d.fix_for("CVE-2023-5363"), Some("3.0.11-1~deb12u2"));
        assert!(d.knows("CVE-2023-5363"));
        assert!(!d.knows("GHSA-xxxx"));
        assert_eq!(d.len(), 1);
    }

    #[test]
    fn an_advisory_without_a_fix_is_not_a_statement() {
        let json = br#"{
            "id": "UBUNTU-CVE-2026-0001",
            "upstream": ["CVE-2026-0001"],
            "affected": [{
                "package": {"name": "x", "ecosystem": "Ubuntu:24.04:LTS"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]
            }]
        }"#;
        let d = OsvData::parse_advisory(json, "Debian:12").unwrap();
        assert!(d.knows("CVE-2026-0001"));
        assert_eq!(d.fix_for("CVE-2026-0001"), None);
    }

    #[test]
    fn oversized_and_malformed_input_is_rejected() {
        assert!(matches!(
            OsvData::parse_advisory(&vec![b' '; MAX_ADVISORY_BYTES + 1], "Debian:12"),
            Err(OsvError::TooLarge(_))
        ));
        assert!(
            OsvData::parse_advisory(b"{}", "Debian:12")
                .unwrap()
                .is_empty()
        );
        assert!(OsvData::parse_advisory(b"[", "Debian:12").is_err());
    }

    /// Fixture recorded from the real API on 2026-11-08.
    const ADVISORY: &[u8] =
        include_bytes!("../../../tests/fixtures/http/osv/2026-11-08/DEBIAN-CVE-2023-5363.json");

    #[test]
    fn recorded_debian_advisory() {
        let d = OsvData::parse_advisory(ADVISORY, "Debian:12").unwrap();
        assert_eq!(d.fix_for("CVE-2023-5363"), Some("3.0.11-1~deb12u2"));
    }
}
