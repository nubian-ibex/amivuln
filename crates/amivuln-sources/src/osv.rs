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
use std::sync::Arc;

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
    /// A `querybatch` answer does not hold one result per query.
    #[error("OSV answered {got} results for {expected} queries")]
    BatchSize {
        /// Queries sent.
        expected: usize,
        /// Results received.
        got: usize,
    },
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

/// One `querybatch` request holding several package queries, in order.
///
/// # Errors
///
/// Fails when the document cannot be serialised.
pub fn batch_request_many(queries: &[(&str, &str, &str)]) -> Result<String, OsvError> {
    let queries: Vec<_> = queries
        .iter()
        .map(|(name, ecosystem, version)| {
            serde_json::json!({
                "package": {"name": name, "ecosystem": ecosystem},
                "version": version
            })
        })
        .collect();
    serde_json::to_string(&serde_json::json!({ "queries": queries })).map_err(OsvError::Invalid)
}

/// Splits a `querybatch` answer into one single-result document per query, in
/// query order. Each part is what a one-query request would have returned, so
/// it is cached under the same key (and read back by [`parse_batch`]).
///
/// # Errors
///
/// Fails on malformed JSON or when the answer does not hold `expected`
/// results.
pub fn split_batch(bytes: &[u8], expected: usize) -> Result<Vec<Vec<u8>>, OsvError> {
    let answer: serde_json::Value = serde_json::from_slice(bytes)?;
    let results = answer
        .get("results")
        .and_then(serde_json::Value::as_array)
        .ok_or(OsvError::BatchSize { expected, got: 0 })?;
    if results.len() != expected {
        return Err(OsvError::BatchSize {
            expected,
            got: results.len(),
        });
    }
    results
        .iter()
        .map(|r| {
            serde_json::to_vec(&serde_json::json!({ "results": [r] })).map_err(OsvError::Invalid)
        })
        .collect()
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
/// errata ids `RLSA-YYYY:NNNN` and `ALSA-YYYY:NNNN`, the Red Hat ids
/// `RHSA-YYYY:NNNN` and `RHBA-YYYY:NNNN`, and the SUSE ids
/// `SUSE-SU-YYYY:NNNN-N` and `openSUSE-SU-YYYY:NNNN-N`; anything else is dropped so an id
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
        // SUSE and openSUSE security updates (`SUSE-SU-2024:3106-1`,
        // `openSUSE-SU-2024:14100-1`). The `RU` and `FU` kinds are bug fixes
        // and features: they carry no CVE and are dropped.
        if matches!(prefix, "SUSE" | "openSUSE") {
            return rest
                .strip_prefix("SU-")
                .and_then(|r| r.split_once(':'))
                .is_some_and(|(year, tail)| {
                    tail.split_once('-').is_some_and(|(n, rev)| {
                        [year, n, rev]
                            .iter()
                            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
                    })
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
    #[serde(default)]
    severity: Vec<RawSeverity>,
    #[serde(default)]
    summary: String,
}

/// A scored or rated severity: a CVSS vector, or Ubuntu's priority word.
#[derive(Debug, Deserialize)]
struct RawSeverity {
    #[serde(rename = "type", default)]
    kind: String,
    #[serde(default)]
    score: String,
    #[serde(default)]
    source: String,
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

/// A rating word in the vocabulary of [`OsvEntry::severity`]. Ubuntu's
/// `negligible` and Debian's `unimportant` are the lowest rating; anything
/// else, such as `not yet assigned`, is not a rating.
fn rating_word(word: &str) -> Option<String> {
    let rating = match word.to_ascii_lowercase().as_str() {
        "critical" => "CRITICAL",
        "high" | "important" => "HIGH",
        "medium" => "MEDIUM",
        "moderate" => "MODERATE",
        "low" | "negligible" | "unimportant" => "LOW",
        _ => return None,
    };
    Some(rating.to_owned())
}

/// The severity of an advisory, in the order of who is speaking: the
/// distribution's own rating (Ubuntu's priority, Debian's urgency, the rating
/// a Rocky Linux or `AlmaLinux` summary opens with) and only then a CVSS
/// vector, the distribution's before NVD's. Language advisories are rated by
/// their textual severity alone (ADR-0013).
fn advisory_severity(raw: &RawVuln, ecosystem: &str) -> Option<String> {
    let ubuntu = raw
        .severity
        .iter()
        .find(|s| s.kind == "Ubuntu")
        .and_then(|s| rating_word(&s.score));
    // Urgency is per package and an advisory can cover several, so it counts
    // only when every package of the release carries the same rating.
    let urgencies: std::collections::BTreeSet<Option<String>> = raw
        .affected
        .iter()
        .filter(|a| a.package.as_ref().is_some_and(|p| p.ecosystem == ecosystem))
        .map(|a| rating_word(a.ecosystem_specific.as_ref()?.urgency.as_deref()?))
        .collect();
    let debian = match urgencies.len() {
        1 => urgencies.into_iter().next().flatten(),
        _ => None,
    };
    let rebuild = (raw.id.starts_with("RLSA-") || raw.id.starts_with("ALSA-"))
        .then(|| raw.summary.split_once(':'))
        .flatten()
        .and_then(|(rating, _)| rating_word(rating));
    let vector = || {
        if matches!(ecosystem, "Go" | "crates.io") {
            return None;
        }
        let mut vectors: Vec<&RawSeverity> = raw
            .severity
            .iter()
            .filter(|s| s.kind == "CVSS_V3")
            .collect();
        vectors.sort_by_key(|s| s.source == "NVD");
        vectors
            .into_iter()
            .find_map(|s| crate::cvss::rating(&s.score))
            .map(str::to_owned)
    };
    ubuntu.or(debian).or(rebuild).or_else(vector)
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
    #[serde(default)]
    ecosystem_specific: Option<RawEcosystemSpecific>,
}

/// Only Debian's urgency is read from it.
#[derive(Debug, Deserialize)]
struct RawEcosystemSpecific {
    #[serde(default)]
    urgency: Option<String>,
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
    /// Textual severity (`CRITICAL`, `HIGH`, `MEDIUM` or `MODERATE`, `LOW`),
    /// upper-cased: the advisory database's own rating, or the rating of its
    /// CVSS vector.
    pub severity: Option<String>,
}

/// Advisories grouped by CVE.
#[derive(Debug, Default)]
pub struct OsvData {
    /// Each advisory is held once and shared by its CVEs: a kernel update
    /// names hundreds of them, and a copy under each grows with their square.
    by_cve: BTreeMap<String, Vec<Arc<OsvEntry>>>,
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
        let severity = raw
            .database_specific
            .as_ref()
            .and_then(|d| d.severity.as_ref())
            .map(|v| v.to_ascii_uppercase())
            .or_else(|| severity_from_references(&raw.references))
            .or_else(|| advisory_severity(&raw, ecosystem));
        Ok(Self::from_entries(vec![OsvEntry {
            advisory: lowest_fix.clone().unwrap_or_default(),
            cves,
            fixed: lowest_fix,
            fixes,
            severity,
        }]))
    }

    /// Combines parsed advisories.
    #[must_use]
    pub fn from_entries(entries: Vec<OsvEntry>) -> Self {
        let mut by_cve: BTreeMap<String, Vec<Arc<OsvEntry>>> = BTreeMap::new();
        for e in entries {
            let e = Arc::new(e);
            for cve in &e.cves {
                by_cve.entry(cve.clone()).or_default().push(Arc::clone(&e));
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

    /// Every advisory entry, each once, in the order of its first CVE.
    #[must_use]
    pub fn entries(&self) -> Vec<OsvEntry> {
        // The address only tells the shared entries apart; it orders nothing.
        let mut seen = std::collections::HashSet::new();
        self.by_cve
            .values()
            .flatten()
            .filter(|e| seen.insert(Arc::as_ptr(e)))
            .map(|e| OsvEntry::clone(e))
            .collect()
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

    /// A kernel update advisory names hundreds of CVEs. Taking it apart and
    /// putting it together again must not multiply it by their number.
    #[test]
    fn an_advisory_of_many_cves_is_kept_once() {
        let cves: Vec<String> = (0..300).map(|i| format!("CVE-2026-{i:04}")).collect();
        let doc = serde_json::json!({
            "id": "USN-0000-1",
            "upstream": cves,
            "affected": [{
                "package": {"name": "linux", "ecosystem": "Ubuntu:24.04:LTS"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "1.0"}]}]
            }]
        });
        let parsed =
            OsvData::parse_advisory(doc.to_string().as_bytes(), "Ubuntu:24.04:LTS").unwrap();
        assert_eq!(parsed.entries().len(), 1);
        // What the scan does with it: the entries of the advisories of one
        // package are combined again.
        let combined = OsvData::from_entries(parsed.entries());
        assert_eq!(combined.len(), 300);
        assert_eq!(combined.entries().len(), 1);
        assert_eq!(
            combined.fixes_for("CVE-2026-0299"),
            [("linux".to_owned(), "1.0".to_owned())]
        );
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
    fn a_batch_is_split_into_the_answers_of_single_queries() {
        let req = batch_request_many(&[
            ("openssl", "Debian:12", "3.0.11-1"),
            ("bash", "Debian:12", "5.2-1"),
        ])
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(&req).unwrap();
        assert_eq!(v["queries"].as_array().unwrap().len(), 2);
        let parts = split_batch(
            br#"{"results":[{"vulns":[{"id":"DEBIAN-CVE-2023-5363"}]},{}]}"#,
            2,
        )
        .unwrap();
        assert_eq!(parse_batch(&parts[0]).unwrap(), ["DEBIAN-CVE-2023-5363"]);
        assert!(parse_batch(&parts[1]).unwrap().is_empty());
        // A part has the shape of a one-query answer, so it fills the cache
        // entry a single query would have.
        let single = batch_request("openssl", "Debian:12", "3.0.11-1").unwrap();
        let first: serde_json::Value = serde_json::from_str(&req).unwrap();
        let one: serde_json::Value = serde_json::from_str(&single).unwrap();
        assert_eq!(first["queries"][0], one["queries"][0]);
        assert!(matches!(
            split_batch(br#"{"results":[{}]}"#, 2),
            Err(OsvError::BatchSize {
                expected: 2,
                got: 1
            })
        ));
        assert!(split_batch(b"{}", 1).is_err());
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
            "SUSE-SU-2024:3106-1",
            "SUSE-SU-2025:03442-1",
            "openSUSE-SU-2024:14100-1",
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
            // Recommended and feature updates carry no CVE.
            "SUSE-RU-2024:3106-1",
            "openSUSE-FU-2024:1-1",
            "SUSE-SU-2024",
            "SUSE-SU-2024:x-1",
            "SUSE-SU-2024:1-",
            "SUSE-SU-../x:1-1",
        ] {
            assert!(!is_advisory_id(bad), "{bad} should be dropped");
        }
    }

    /// The severity read from one advisory filed under `ecosystem`.
    fn severity_of(ecosystem: &str, mut doc: serde_json::Value) -> Option<String> {
        doc["upstream"] = serde_json::json!(["CVE-2026-0001"]);
        let data = OsvData::parse_advisory(doc.to_string().as_bytes(), ecosystem).unwrap();
        data.severity_for("CVE-2026-0001").map(str::to_owned)
    }

    #[test]
    fn each_distribution_states_severity_its_own_way() {
        let affected = |eco: &str, specific: serde_json::Value| {
            serde_json::json!([{
                "package": {"name": "openssl", "ecosystem": eco},
                "ecosystem_specific": specific
            }])
        };
        let cvss = |source: Option<&str>, vector: &str| {
            let mut s = serde_json::json!({"type": "CVSS_V3", "score": vector});
            if let Some(source) = source {
                s["source"] = source.into();
            }
            s
        };
        let high = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N";
        let low = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N";
        // Ubuntu's priority wins over any CVSS score.
        let ubuntu = serde_json::json!({"id": "UBUNTU-CVE-2026-0001", "severity": [
            cvss(Some("NVD"), high),
            {"type": "Ubuntu", "score": "negligible", "source": "SELF"}
        ]});
        assert_eq!(
            severity_of("Ubuntu:24.04:LTS", ubuntu).as_deref(),
            Some("LOW")
        );
        // Debian's urgency wins when Debian assigned one.
        let urgent = serde_json::json!({"id": "DEBIAN-CVE-2026-0001",
            "severity": [cvss(None, high)],
            "affected": affected("Debian:12", serde_json::json!({"urgency": "medium"}))});
        assert_eq!(severity_of("Debian:12", urgent).as_deref(), Some("MEDIUM"));
        let unimportant = serde_json::json!({"id": "DEBIAN-CVE-2026-0001",
            "affected": affected("Debian:12", serde_json::json!({"urgency": "unimportant"}))});
        assert_eq!(
            severity_of("Debian:12", unimportant).as_deref(),
            Some("LOW")
        );
        // Not assigned yet: the CVSS vector decides.
        let pending = serde_json::json!({"id": "DEBIAN-CVE-2026-0001",
            "severity": [cvss(None, high)],
            "affected": affected("Debian:12", serde_json::json!({"urgency": "not yet assigned"}))});
        assert_eq!(severity_of("Debian:12", pending).as_deref(), Some("HIGH"));
        // The rebuilds open the summary with Red Hat's rating.
        for (id, eco) in [
            ("RLSA-2026:0001", "Rocky Linux:9"),
            ("ALSA-2026:0001", "AlmaLinux:9"),
        ] {
            let doc = serde_json::json!({"id": id, "severity": [cvss(None, high)],
                "summary": "Moderate: openssl security update"});
            assert_eq!(severity_of(eco, doc).as_deref(), Some("MODERATE"), "{id}");
        }
        // The distribution's own vector is preferred to NVD's.
        let two = serde_json::json!({"id": "ALPINE-CVE-2026-0001",
            "severity": [cvss(Some("NVD"), high), cvss(None, "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L")]});
        assert_eq!(severity_of("Alpine:v3.20", two).as_deref(), Some("LOW"));
        // One advisory, two source packages rated differently: neither urgency
        // can be pinned on the package asked about, so the vector decides.
        let two = serde_json::json!({"id": "DEBIAN-CVE-2026-0001",
        "severity": [cvss(None, high)],
        "affected": [
            {"package": {"name": "minizip", "ecosystem": "Debian:12"},
             "ecosystem_specific": {"urgency": "unimportant"}},
            {"package": {"name": "zlib", "ecosystem": "Debian:12"},
             "ecosystem_specific": {"urgency": "not yet assigned"}},
        ]});
        assert_eq!(severity_of("Debian:12", two).as_deref(), Some("HIGH"));
        // A language advisory is not rated from its vector (ADR-0013).
        let rust = serde_json::json!({"id": "RUSTSEC-2026-0001", "severity": [cvss(None, high)]});
        assert_eq!(severity_of("crates.io", rust), None);
        // Nothing stated, and nothing invented.
        for doc in [
            serde_json::json!({"id": "SUSE-SU-2026:0001-1", "summary": "Security update for openssl-3"}),
            serde_json::json!({"id": "ALPINE-CVE-2026-0001", "severity": [cvss(None, low)]}),
            serde_json::json!({"id": "ALPINE-CVE-2026-0001", "severity": [cvss(None, "not a vector")]}),
        ] {
            assert_eq!(severity_of("Alpine:v3.20", doc.clone()), None, "{doc}");
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
