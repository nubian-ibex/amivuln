// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Red Hat's security data API, for the mitigation it publishes per CVE.
//!
//! `https://access.redhat.com/hydra/rest/securitydata/cve/<CVE>.json` carries a
//! `mitigation` block for many CVEs: what to do while the fix is not installed
//! (disable a module, change a setting, run a script). The text is written for
//! Red Hat's own products, so it is shown as Red Hat's statement, never as an
//! instruction amivuln verified for the host.

use amivuln_core::Mitigation;
use serde::Deserialize;

use crate::is_cve_id;

/// Largest response read; a CVE document is a few KB.
pub const MAX_BYTES: usize = 1024 * 1024;
/// Longest mitigation text kept, in characters.
pub const MAX_TEXT_CHARS: usize = 1500;

/// Why a document could not be read.
#[derive(Debug, thiserror::Error)]
pub enum RedHatError {
    /// The response is larger than [`MAX_BYTES`].
    #[error("the Red Hat response is larger than {MAX_BYTES} bytes")]
    TooLarge,
    /// The response is not the JSON the API produces.
    #[error("the Red Hat response is not valid JSON: {0}")]
    Invalid(String),
}

#[derive(Deserialize)]
struct Document {
    #[serde(default)]
    mitigation: Option<RawMitigation>,
}

/// The API writes `{"value": "...", "lang": "en:US"}`; older records a string.
#[derive(Deserialize)]
#[serde(untagged)]
enum RawMitigation {
    Text(String),
    Block {
        #[serde(default)]
        value: String,
    },
}

/// The URL of a CVE's document, or `None` when the id is not a CVE id (an id
/// from a response never reaches a URL unchecked).
#[must_use]
pub fn document_url(base: &str, cve: &str) -> Option<String> {
    is_cve_id(cve).then(|| {
        format!(
            "{}/hydra/rest/securitydata/cve/{cve}.json",
            base.trim_end_matches('/')
        )
    })
}

/// The page a person reads for a CVE.
#[must_use]
pub fn page_url(cve: &str) -> String {
    format!("https://access.redhat.com/security/cve/{cve}")
}

/// Red Hat fills the field for most CVEs, often to say there is nothing to do
/// ("Mitigation for this issue is either not available or the currently
/// available options do not meet the Red Hat Product Security criteria...").
/// That is the absence of a mitigation, not one.
fn says_there_is_none(text: &str) -> bool {
    const OPENERS: [&str; 6] = [
        "mitigation for this issue is either not available",
        "currently there is no mitigation",
        "currently no mitigation",
        "there is no mitigation",
        "there is currently no mitigation",
        "no mitigation is available",
    ];
    let start = text.to_ascii_lowercase();
    OPENERS.iter().any(|o| start.starts_with(o))
}

/// The mitigation a CVE document states, if any.
///
/// # Errors
///
/// Fails on oversized or malformed input.
pub fn parse_mitigation(bytes: &[u8], cve: &str) -> Result<Option<Mitigation>, RedHatError> {
    if bytes.len() > MAX_BYTES {
        return Err(RedHatError::TooLarge);
    }
    let doc: Document =
        serde_json::from_slice(bytes).map_err(|e| RedHatError::Invalid(e.to_string()))?;
    let raw = match doc.mitigation {
        Some(RawMitigation::Text(t)) => t,
        Some(RawMitigation::Block { value }) => value,
        None => return Ok(None),
    };
    // Whitespace (the text is HTML-ish with line breaks and numbering) is
    // collapsed so it reads as one paragraph in any output.
    let collapsed = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.is_empty() {
        return Ok(None);
    }
    if says_there_is_none(&collapsed) {
        return Ok(None);
    }
    let text = if collapsed.chars().count() > MAX_TEXT_CHARS {
        let cut: String = collapsed.chars().take(MAX_TEXT_CHARS).collect();
        format!("{cut}...")
    } else {
        collapsed
    };
    Ok(Some(Mitigation {
        text,
        url: page_url(cve),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_block_a_plain_string_and_no_mitigation_are_read() {
        let block = br#"{"name":"CVE-2024-6387","mitigation":{"value":"1) Open\n  sshd_config.\n2) Set LoginGraceTime 0.","lang":"en:US"}}"#;
        let m = parse_mitigation(block, "CVE-2024-6387").unwrap().unwrap();
        assert_eq!(m.text, "1) Open sshd_config. 2) Set LoginGraceTime 0.");
        assert_eq!(
            m.url,
            "https://access.redhat.com/security/cve/CVE-2024-6387"
        );
        let plain = br#"{"mitigation":"Disable the module."}"#;
        assert_eq!(
            parse_mitigation(plain, "CVE-2024-1086")
                .unwrap()
                .unwrap()
                .text,
            "Disable the module."
        );
        assert_eq!(
            parse_mitigation(br#"{"name":"CVE-2022-0847"}"#, "CVE-2022-0847").unwrap(),
            None
        );
        assert_eq!(
            parse_mitigation(br#"{"mitigation":{"value":"  \n "}}"#, "CVE-2022-0847").unwrap(),
            None
        );
    }

    #[test]
    fn the_standard_no_mitigation_text_is_not_a_mitigation() {
        // The wording of real documents (CVE-2022-0847 and a util-linux CVE).
        for none in [
            "Currently there is no mitigation available for this flaw. Customers should update to fixed packages, once they are available.",
            "Mitigation for this issue is either not available or the currently available options do not meet the Red Hat Product Security criteria comprising ease of use and deployment.",
            "There is no mitigation for this flaw.",
        ] {
            let doc = format!(r#"{{"mitigation":{{"value":"{none}"}}}}"#);
            assert_eq!(
                parse_mitigation(doc.as_bytes(), "CVE-2022-0847").unwrap(),
                None,
                "{none}"
            );
        }
        // Advice that begins with a refusal of a full fix still counts.
        let doc = br#"{"mitigation":{"value":"No practical runtime mitigation is available in the shipped build. Do not pass untrusted data into printf."}}"#;
        assert!(parse_mitigation(doc, "CVE-2026-1").unwrap().is_some());
    }

    #[test]
    fn a_long_text_is_cut_and_a_bad_document_is_an_error() {
        let long = format!(r#"{{"mitigation":{{"value":"{}"}}}}"#, "word ".repeat(1000));
        let m = parse_mitigation(long.as_bytes(), "CVE-2024-6387")
            .unwrap()
            .unwrap();
        assert!(m.text.ends_with("..."));
        assert_eq!(m.text.chars().count(), MAX_TEXT_CHARS + 3);
        assert!(parse_mitigation(b"<html>", "CVE-2024-6387").is_err());
        assert!(matches!(
            parse_mitigation(&vec![b' '; MAX_BYTES + 1], "CVE-2024-6387"),
            Err(RedHatError::TooLarge)
        ));
    }

    #[test]
    fn only_a_cve_id_makes_a_url() {
        let base = "https://access.redhat.com/";
        assert_eq!(
            document_url(base, "CVE-2024-6387").as_deref(),
            Some("https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2024-6387.json")
        );
        for bad in [
            "",
            "RHSA-2024:1",
            "CVE-2024-6387/../x",
            "CVE-24-1",
            "CVE-2024-6387?x=1",
        ] {
            assert_eq!(document_url(base, bad), None, "{bad}");
        }
    }
}
