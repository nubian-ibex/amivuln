// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! NVD 2.0 API: CVEs by CPE name, for products with no distro data.
//!
//! The CPE mapping table is curated: the vendor and product names in NVD's
//! scheme are not always the package name (nginx is `f5:nginx`, curl is
//! `haxx:curl`). The API's rate limit without a key is 5 requests per 30
//! seconds; with a key, 50 per 30 seconds. The key goes in
//! `sources.nvd.api_key_file` (a file with the key), never on the command
//! line.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::is_cve_id;

/// Largest NVD response accepted.
pub const MAX_NVD_BYTES: usize = 4 * 1024 * 1024;

/// Why an NVD lookup could not run or its data cannot be used.
#[derive(Debug, thiserror::Error)]
pub enum NvdError {
    /// The response is larger than [`MAX_NVD_BYTES`].
    #[error("the NVD response is larger than {0} bytes")]
    TooLarge(usize),
    /// The response is not the JSON the NVD 2.0 API produces.
    #[error("the NVD response is not valid JSON: {0}")]
    Invalid(String),
    /// The NVD returned a response but not the CVEs section.
    #[error("the NVD response holds no vulnerabilities")]
    NoVulnerabilities,
}

/// The curated CPE mapping: package name to the NVD vendor and product.
///
/// The names come from the NVD CPE dictionary; they are checked against the
/// live API at the time the entry was added, and the `Check` column in the
/// roadmap is the date of that check.
#[must_use]
pub fn cpe_for(package: &str) -> Option<(&'static str, &'static str)> {
    let (vendor, product) = match package {
        "openssl" => ("openssl", "openssl"),
        "curl" => ("haxx", "curl"),
        "zlib" => ("zlib", "zlib"),
        "sqlite" => ("sqlite", "sqlite"),
        "nginx" => ("f5", "nginx"),
        "xz" => ("tukaani", "xz"),
        "brotli" => ("google", "brotli"),
        "libpng" => ("libpng", "libpng"),
        "libxml2" => ("gnome", "libxml2"),
        "pcre2" => ("pcre", "pcre2"),
        "expat" => ("libexpat", "expat"),
        "libevent" => ("libevent", "libevent"),
        "openldap" => ("openldap", "openldap"),
        "gnutls" => ("gnu", "gnutls"),
        "glib" => ("gnome", "glib"),
        _ => return None,
    };
    Some((vendor, product))
}

/// Builds the CPE 2.3 name for a package and version.
///
/// The format is `cpe:2.3:a:VENDOR:PRODUCT:VERSION:*:*:*:*:*:*:*`; the
/// version must be safe for a URL query parameter.
#[must_use]
pub fn cpe_name(package: &str, version: &str) -> Option<String> {
    let (vendor, product) = cpe_for(package)?;
    if version.is_empty()
        || version.len() > 64
        || !version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
    {
        return None;
    }
    Some(format!(
        "cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
    ))
}

#[derive(Debug, Deserialize)]
struct NvdResponse {
    #[serde(default)]
    vulnerabilities: Vec<NvdEntry>,
}

#[derive(Debug, Deserialize)]
struct NvdEntry {
    cve: NvdCve,
}

#[derive(Debug, Deserialize)]
struct NvdCve {
    id: String,
    #[serde(default)]
    metrics: NvdMetrics,
    #[serde(default)]
    descriptions: Vec<NvdDescription>,
}

#[derive(Debug, Deserialize, Default)]
#[allow(clippy::struct_field_names)]
struct NvdMetrics {
    #[serde(default, rename = "cvssMetricV40")]
    cvss_metric_v40: Vec<NvdMetric>,
    #[serde(default, rename = "cvssMetricV31")]
    cvss_metric_v31: Vec<NvdMetric>,
    #[serde(default, rename = "cvssMetricV30")]
    cvss_metric_v30: Vec<NvdMetric>,
    #[serde(default, rename = "cvssMetricV2")]
    cvss_metric_v2: Vec<NvdMetric>,
}

#[derive(Debug, Deserialize, Default)]
struct NvdMetric {
    #[serde(default, rename = "cvssData")]
    cvss_data: NvdCvssData,
}

#[derive(Debug, Deserialize, Default)]
struct NvdCvssData {
    #[serde(default, rename = "baseSeverity")]
    base_severity: Option<String>,
    #[serde(default, rename = "baseScore")]
    base_score: Option<f64>,
}

#[derive(Debug, Deserialize)]
struct NvdDescription {
    #[serde(default)]
    value: String,
}

/// A CVE from the NVD, with the best severity available.
#[derive(Debug, Clone, PartialEq)]
pub struct NvdEntry2 {
    /// CVE id, for example `CVE-2024-9143`.
    pub id: String,
    /// The package name that produced the CPE lookup.
    pub cpe_package: String,
    /// CVSS severity label, upper-case (`HIGH`, `CRITICAL`), when stated.
    pub severity: Option<String>,
    /// CVSS base score, when stated.
    pub score: Option<f64>,
    /// First English description, truncated to 512 bytes.
    pub description: String,
}

/// Parses an NVD 2.0 API response into the CVEs it holds.
///
/// # Errors
///
/// Fails on oversized or malformed input.
pub fn parse_response(bytes: &[u8], cpe_package: &str) -> Result<Vec<NvdEntry2>, NvdError> {
    if bytes.len() > MAX_NVD_BYTES {
        return Err(NvdError::TooLarge(bytes.len()));
    }
    let raw: NvdResponse =
        serde_json::from_slice(bytes).map_err(|e| NvdError::Invalid(e.to_string()))?;
    Ok(raw
        .vulnerabilities
        .into_iter()
        .filter_map(|e| {
            let cve = e.cve;
            if !is_cve_id(&cve.id) {
                return None;
            }
            let severity = best_severity(&cve.metrics);
            let description = cve
                .descriptions
                .iter()
                .find(|d| !d.value.is_empty())
                .map(|d| d.value.as_str())
                .unwrap_or_default();
            Some(NvdEntry2 {
                id: cve.id,
                cpe_package: cpe_package.to_owned(),
                severity,
                score: cve
                    .metrics
                    .cvss_metric_v31
                    .first()
                    .and_then(|m| m.cvss_data.base_score)
                    .or(cve
                        .metrics
                        .cvss_metric_v40
                        .first()
                        .and_then(|m| m.cvss_data.base_score)),
                description: description.chars().take(512).collect(),
            })
        })
        .collect())
}

/// The best severity label in the metrics, most recent CVSS version first.
fn best_severity(metrics: &NvdMetrics) -> Option<String> {
    for set in [
        &metrics.cvss_metric_v40,
        &metrics.cvss_metric_v31,
        &metrics.cvss_metric_v30,
        &metrics.cvss_metric_v2,
    ] {
        for metric in set {
            if let Some(sev) = &metric.cvss_data.base_severity {
                return Some(sev.to_ascii_uppercase());
            }
        }
    }
    None
}

/// The CVEs for a package and version, keyed by CVE id.
#[must_use]
pub fn entries_by_cve(entries: Vec<NvdEntry2>) -> BTreeMap<String, NvdEntry2> {
    entries.into_iter().map(|e| (e.id.clone(), e)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpe_mapping_is_curated() {
        assert_eq!(cpe_for("nginx"), Some(("f5", "nginx")));
        assert_eq!(cpe_for("curl"), Some(("haxx", "curl")));
        assert_eq!(cpe_for("zlib"), Some(("zlib", "zlib")));
        assert_eq!(cpe_for("unknown-product"), None);
        assert_eq!(cpe_for(""), None);
    }

    #[test]
    fn cpe_names_are_well_formed() {
        let cpe = cpe_name("nginx", "1.26.2").unwrap();
        assert_eq!(cpe, "cpe:2.3:a:f5:nginx:1.26.2:*:*:*:*:*:*:*");
        assert!(cpe_name("nginx", "").is_none());
        assert!(cpe_name("nginx", "../../etc/passwd").is_none());
        assert!(cpe_name("nginx", "1; rm -rf /").is_none());
        assert!(cpe_name("unknown-product", "1.0").is_none());
    }

    #[test]
    fn the_recorded_nvd_responses_are_parsed() {
        let openssl =
            include_bytes!("../../../tests/fixtures/http/nvd/2026-11-11/openssl-3.2.2.json");
        let entries = parse_response(openssl, "openssl").unwrap();
        assert_eq!(entries.len(), 14);
        // A CVE with V31 metrics.
        let cve = entries.iter().find(|e| e.id == "CVE-2024-9143").unwrap();
        assert_eq!(cve.severity.as_deref(), Some("HIGH"));
        // A CVE with only V2 and no severity label.
        let old = entries.iter().find(|e| e.id == "CVE-2009-1390").unwrap();
        assert_eq!(old.severity, None);
        assert!(old.description.contains("Mutt"));

        let nginx = include_bytes!("../../../tests/fixtures/http/nvd/2026-11-11/nginx-1.26.2.json");
        let entries = parse_response(nginx, "nginx").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, "CVE-2025-23419");
        assert_eq!(entries[0].severity.as_deref(), Some("MEDIUM"));

        let curl = include_bytes!("../../../tests/fixtures/http/nvd/2026-11-11/curl-8.5.0.json");
        let entries = parse_response(curl, "curl").unwrap();
        assert_eq!(entries.len(), 10);
        assert!(entries.iter().any(|e| e.id == "CVE-2024-0853"));

        let zlib = include_bytes!("../../../tests/fixtures/http/nvd/2026-11-11/zlib-1.3.1.json");
        let entries = parse_response(zlib, "zlib").unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().any(|e| e.id == "CVE-2026-22184"));
    }

    #[test]
    fn junk_and_oversized_input_fail() {
        assert!(matches!(
            parse_response(b"not json", "test"),
            Err(NvdError::Invalid(_))
        ));
        assert!(parse_response(b"{}", "test").is_ok_and(|e| e.is_empty()));
        let big = vec![b' '; MAX_NVD_BYTES + 1];
        assert!(matches!(
            parse_response(&big, "test"),
            Err(NvdError::TooLarge(_))
        ));
    }

    #[test]
    fn severity_prefers_the_newest_cvss_version() {
        let metrics = NvdMetrics {
            cvss_metric_v40: vec![],
            cvss_metric_v31: vec![NvdMetric {
                cvss_data: NvdCvssData {
                    base_severity: Some("HIGH".to_owned()),
                    base_score: Some(7.5),
                },
            }],
            cvss_metric_v30: vec![],
            cvss_metric_v2: vec![NvdMetric {
                cvss_data: NvdCvssData {
                    base_severity: Some("MEDIUM".to_owned()),
                    base_score: Some(5.0),
                },
            }],
        };
        assert_eq!(best_severity(&metrics), Some("HIGH".to_owned()));
    }
}
