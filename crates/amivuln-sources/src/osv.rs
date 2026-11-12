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

/// Accepts `DEBIAN-CVE-...`/`UBUNTU-CVE-...`/`ALPINE-CVE-...`, the Debian and
/// Ubuntu advisory ids `DSA-N-N`, `DLA-N-N` and `USN-N-N`, and the Rocky/Alma
/// errata ids `RLSA-YYYY:NNNN` and `ALSA-YYYY:NNNN`, and the Red Hat ids
/// `RHSA-YYYY:NNNN` and `RHBA-YYYY:NNNN`; anything else is dropped so an id
/// from the response never reaches a URL unchecked.
fn is_advisory_id(id: &str) -> bool {
    is_language_advisory_id(id) || is_distro_advisory_id(id)
}

/// `GO-YYYY-NNNN`, `RUSTSEC-YYYY-NNNN` and `GHSA-xxxx-xxxx-xxxx`.
fn is_language_advisory_id(id: &str) -> bool {
    let digits = |s: &str, min: usize| s.len() >= min && s.bytes().all(|b| b.is_ascii_digit());
    let mut parts = id.split('-');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some("GO" | "RUSTSEC"), Some(year), Some(seq), None) => digits(year, 4) && digits(seq, 4),
        (Some("GHSA"), Some(a), Some(b), Some(c)) => {
            parts.next().is_none()
                && [a, b, c].iter().all(|g| {
                    g.len() == 4
                        && g.bytes()
                            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
                })
        }
        _ => false,
    }
}

fn is_distro_advisory_id(id: &str) -> bool {
    if let Some((prefix, rest)) = id.split_once('-') {
        if matches!(prefix, "RLSA" | "ALSA" | "RHSA" | "RHBA") {
            return rest.split_once(':').is_some_and(|(y, n)| {
                !y.is_empty()
                    && !n.is_empty()
                    && y.bytes().all(|b| b.is_ascii_digit())
                    && n.bytes().all(|b| b.is_ascii_digit())
            });
        }
        // Debian and Ubuntu security advisories (`DSA-5169-1`, `DLA-3942-1`,
        // `USN-6000-1`): OSV answers with these alone for releases whose
        // per-CVE records stopped, such as Debian 11.
        if matches!(prefix, "DSA" | "DLA" | "USN") {
            return rest.split_once('-').is_some_and(|(n, rev)| {
                !n.is_empty()
                    && !rev.is_empty()
                    && n.bytes().all(|b| b.is_ascii_digit())
                    && rev.bytes().all(|b| b.is_ascii_digit())
            });
        }
        return crate::is_cve_id(rest);
    }
    crate::is_cve_id(id)
}

#[derive(Debug, Deserialize)]
struct RawVuln {
    #[serde(default)]
    id: String,
    #[serde(default)]
    affected: Vec<RawAffected>,
    #[serde(default)]
    upstream: Vec<String>,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    database_specific: Option<RawDatabaseSpecific>,
    #[serde(default)]
    references: Vec<RawReference>,
}

#[derive(Debug, Deserialize)]
struct RawReference {
    #[serde(default)]
    url: String,
}

/// Red Hat does not put a severity in the record; it links the classification
/// page of the advisory's rating (`.../classification/#important`).
fn severity_from_references(references: &[RawReference]) -> Option<String> {
    references.iter().find_map(|r| {
        let rating = r
            .url
            .strip_prefix("https://access.redhat.com/security/updates/classification/#")?;
        matches!(rating, "low" | "moderate" | "important" | "critical")
            .then(|| rating.to_ascii_uppercase())
    })
}

/// The vendor block; only the textual severity GitHub advisories carry.
#[derive(Debug, Deserialize)]
struct RawDatabaseSpecific {
    #[serde(default)]
    severity: Option<String>,
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
    #[serde(default)]
    name: String,
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
    /// Every `(package, fixed version)` pair for the ecosystem. Language
    /// advisories list one range per release branch, so the fix that matters
    /// depends on the installed version.
    pub fixes: Vec<(String, String)>,
    /// Textual severity (`CRITICAL`, `HIGH`, `MODERATE`, `LOW`) when the
    /// advisory database states one, upper-cased.
    pub severity: Option<String>,
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
        let mut fixes: Vec<(String, String)> = Vec::new();
        for affected in &raw.affected {
            let Some(package) = affected
                .package
                .as_ref()
                .filter(|p| p.ecosystem == ecosystem)
            else {
                continue;
            };
            for range in affected
                .ranges
                .iter()
                .filter(|r| matches!(r.kind.as_str(), "ECOSYSTEM" | "SEMVER"))
            {
                for event in &range.events {
                    if let Some(fixed) = event.0.get("fixed") {
                        fixes.push((package.name.clone(), fixed.clone()));
                    }
                }
            }
        }
        // Distro advisories keep their historical meaning: the first range's
        // fix, lowest across packages of the release.
        let lowest_fix = raw
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
        let mut cves: Vec<String> = raw
            .upstream
            .iter()
            .chain(raw.aliases.iter())
            .filter(|c| crate::is_cve_id(c))
            .cloned()
            .collect();
        // A language advisory without a CVE alias is reported under its own
        // id instead of vanishing.
        if cves.is_empty() && is_language_advisory_id(&raw.id) {
            cves.push(raw.id.clone());
        }
        cves.sort();
        cves.dedup();
        Ok(Self::from_entries(vec![OsvEntry {
            advisory: lowest_fix.clone().unwrap_or_default(),
            cves,
            fixed: lowest_fix,
            fixes,
            severity: raw
                .database_specific
                .and_then(|d| d.severity)
                .map(|v| v.to_ascii_uppercase())
                .or_else(|| severity_from_references(&raw.references)),
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

    /// Every `(package, fixed version)` pair recorded for a CVE.
    #[must_use]
    pub fn fixes_for(&self, cve: &str) -> Vec<(String, String)> {
        self.by_cve
            .get(cve)
            .into_iter()
            .flatten()
            .flat_map(|e| e.fixes.iter().cloned())
            .collect()
    }

    /// The most severe textual severity recorded for a CVE, when any.
    #[must_use]
    pub fn severity_for(&self, cve: &str) -> Option<&str> {
        let rank = |s: &str| match s {
            "CRITICAL" => 4,
            "HIGH" => 3,
            "MODERATE" | "MEDIUM" => 2,
            "LOW" => 1,
            _ => 0,
        };
        self.by_cve
            .get(cve)?
            .iter()
            .filter_map(|e| e.severity.as_deref())
            .max_by_key(|s| rank(s))
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
    fn language_advisories_carry_cves_and_every_fix() {
        let go = include_bytes!(
            "../../../tests/fixtures/http/osv/2026-11-10-lang/GHSA-4374-p667-p6c8.json"
        );
        let d = OsvData::parse_advisory(go, "Go").unwrap();
        assert!(d.knows("CVE-2023-39325"));
        let entry = d.entries().into_iter().next().unwrap();
        assert_eq!(
            entry.fixes,
            [("golang.org/x/net".to_owned(), "0.17.0".to_owned())]
        );

        let rust = include_bytes!(
            "../../../tests/fixtures/http/osv/2026-11-10-lang/RUSTSEC-2020-0071.json"
        );
        let d = OsvData::parse_advisory(rust, "crates.io").unwrap();
        assert!(d.knows("CVE-2020-26235"));
        let entry = d.entries().into_iter().next().unwrap();
        // One range per release branch: several fixes for one package.
        assert!(entry.fixes.len() > 3, "{:?}", entry.fixes);
        assert!(entry.fixes.iter().all(|(name, _)| name == "time"));
        // Another ecosystem's data is ignored.
        let none = OsvData::parse_advisory(rust, "Go").unwrap();
        assert!(none.entries().iter().all(|e| e.fixes.is_empty()));
    }

    #[test]
    fn language_advisory_ids_are_accepted_and_garbage_is_not() {
        for ok in ["GO-2023-2102", "RUSTSEC-2020-0071", "GHSA-4374-p667-p6c8"] {
            assert!(is_advisory_id(ok), "{ok}");
        }
        for bad in [
            "GHSA-4374-p667",
            "GHSA-ABCD-p667-p6c8",
            "GO-23-2102",
            "GHSA-4374-p667-p6c8-x",
            "RUSTSEC-2020",
        ] {
            assert!(!is_advisory_id(bad), "{bad}");
        }
    }

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
    fn distro_advisory_ids_are_validated() {
        for ok in [
            "DEBIAN-CVE-2024-6387",
            "UBUNTU-CVE-2024-6387",
            "ALPINE-CVE-2023-5678",
            "DSA-5169-1",
            "DLA-3942-2",
            "USN-6000-1",
            "RLSA-2024:1234",
            "RHSA-2024:0310",
            "RHBA-2025:6314",
        ] {
            assert!(is_advisory_id(ok), "{ok} should be accepted");
        }
        for bad in [
            "DSA-",
            "DSA-x-1",
            "DSA-5169",
            "DSA-5169-x",
            "USN-1/../x-1",
            "FOO-5169-1",
            "ALPINE-notacve",
            "RHSA-2024",
            "RHSA-x:1",
        ] {
            assert!(!is_advisory_id(bad), "{bad} should be dropped");
        }
    }

    #[test]
    fn red_hat_severity_comes_from_the_classification_link() {
        let json = br#"{
            "id": "RHSA-2024:0310",
            "upstream": ["CVE-2023-5363"],
            "references": [
                {"type": "ADVISORY", "url": "https://access.redhat.com/errata/RHSA-2024:0310"},
                {"type": "ARTICLE", "url": "https://access.redhat.com/security/updates/classification/#important"}
            ],
            "affected": [{
                "package": {"name": "openssl", "ecosystem": "Red Hat:enterprise_linux:9::baseos"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1:3.0.7-25.el9_3"}]}]
            }]
        }"#;
        let d = OsvData::parse_advisory(json, "Red Hat:enterprise_linux:9::baseos").unwrap();
        assert_eq!(d.severity_for("CVE-2023-5363"), Some("IMPORTANT"));
        assert_eq!(
            d.fixes_for("CVE-2023-5363"),
            [("openssl".to_owned(), "1:3.0.7-25.el9_3".to_owned())]
        );
        // An unknown rating is not invented.
        let other = json.to_vec();
        let other = String::from_utf8(other)
            .unwrap()
            .replace("#important", "#bogus");
        let d = OsvData::parse_advisory(other.as_bytes(), "Red Hat:enterprise_linux:9::baseos")
            .unwrap();
        assert_eq!(d.severity_for("CVE-2023-5363"), None);
    }

    #[test]
    fn recorded_debian_advisory() {
        let d = OsvData::parse_advisory(ADVISORY, "Debian:12").unwrap();
        assert_eq!(d.fix_for("CVE-2023-5363"), Some("3.0.11-1~deb12u2"));
    }
}
