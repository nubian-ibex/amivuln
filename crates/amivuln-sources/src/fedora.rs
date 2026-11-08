// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Fedora `updateinfo` (ADR-0007).
//!
//! The repository metadata lists, per update, the package builds it ships and
//! the bugzilla bugs it closes. Fedora security bugs are titled
//! `CVE-YYYY-NNNN pkg: summary`, which is the only place CVE ids are
//! structured enough to trust: CVE ids that merely appear in a free-text
//! description (for example "regression from the fix for CVE-...") are
//! ignored, because treating them as fixed would hide a vulnerability.
//!
//! An update that closes a CVE bug states "this CVE is fixed at EVR X". A CVE
//! with no entry here says nothing: callers must treat it as unverified.

use std::collections::BTreeMap;
use std::io::Read;

use crate::is_cve_id;
use amivuln_core::{DistroStatus, Severity, Version};
use amivuln_version::RpmEvr;
use quick_xml::Reader;
use quick_xml::XmlVersion;
use quick_xml::events::{BytesStart, Event};

/// Upper bound for decompressed metadata (the F43 updates file was 62 MB).
pub const MAX_XML_BYTES: usize = 256 * 1024 * 1024;

/// Deepest element nesting accepted.
const MAX_DEPTH: usize = 16;

/// Where `repomd.xml` says the `updateinfo` file is, and its checksum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateinfoLocation {
    /// Path relative to the repository root, for example
    /// `repodata/<sha256>-updateinfo.xml.zst`.
    pub href: String,
    /// Lower-case hex SHA-256 of the compressed file, from `repomd.xml`.
    pub sha256: String,
}

impl UpdateinfoLocation {
    /// True when `data` hashes to the checksum `repomd.xml` promised.
    #[must_use]
    pub fn verify(&self, data: &[u8]) -> bool {
        use core::fmt::Write as _;
        use sha2::{Digest, Sha256};
        let hex = Sha256::digest(data)
            .iter()
            .fold(String::with_capacity(64), |mut acc, b| {
                let _ = write!(acc, "{b:02x}");
                acc
            });
        hex == self.sha256
    }
}

/// Finds the `updateinfo` file in `repomd.xml`.
///
/// Returns the path relative to the repository root and the SHA-256 the
/// metadata declares for it, so a mirror that serves different bytes is
/// detected. Only zstd-compressed files are accepted and the path is checked
/// so it cannot escape `repodata/`.
///
/// # Errors
///
/// Fails when `repomd.xml` is malformed, lists no `updateinfo`, or lists one
/// in an unsupported or suspicious form.
pub fn updateinfo_location(repomd: &[u8]) -> Result<UpdateinfoLocation, UpdateinfoError> {
    if repomd.len() > 4 * 1024 * 1024 {
        return Err(UpdateinfoError::TooLarge);
    }
    let mut reader = Reader::from_reader(repomd);
    let mut in_updateinfo = false;
    let mut sha256: Option<String> = None;
    let mut href: Option<String> = None;
    loop {
        let event = reader
            .read_event()
            .map_err(|e| UpdateinfoError::Xml(e.to_string()))?;
        match event {
            Event::Start(e) if e.name().as_ref() == "data" => {
                in_updateinfo = attr(&e, "type").as_deref() == Some("updateinfo");
            }
            Event::End(e) if e.name().as_ref() == "data" => in_updateinfo = false,
            Event::Start(e) if in_updateinfo && e.name().as_ref() == "checksum" => {
                if attr(&e, "type").as_deref() == Some("sha256") {
                    // The digest is the element text, read on the next event.
                    sha256 = Some(String::new());
                }
            }
            Event::Text(t) if in_updateinfo && sha256.as_deref() == Some("") => {
                sha256 = Some(
                    t.xml_content(XmlVersion::Implicit1_0)
                        .trim()
                        .to_ascii_lowercase(),
                );
            }
            Event::Empty(e) | Event::Start(e)
                if in_updateinfo && e.name().as_ref() == "location" =>
            {
                href = Some(
                    attr(&e, "href")
                        .ok_or_else(|| UpdateinfoError::Xml("location without href".into()))?,
                );
            }
            Event::Eof => break,
            _ => {}
        }
    }
    let href = href.ok_or_else(|| UpdateinfoError::Xml("repomd.xml lists no updateinfo".into()))?;
    let href = validate_location(&href)?;
    let sha256 = sha256
        .filter(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or_else(|| UpdateinfoError::Xml("repomd.xml gives no sha256 for updateinfo".into()))?;
    Ok(UpdateinfoLocation { href, sha256 })
}

fn validate_location(href: &str) -> Result<String, UpdateinfoError> {
    let ok = href.strip_prefix("repodata/").is_some_and(|f| {
        f.ends_with("-updateinfo.xml.zst")
            && f.len() <= 160
            && f.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'))
            && !f.contains("..")
    });
    if ok {
        Ok(href.to_owned())
    } else {
        Err(UpdateinfoError::Xml(format!(
            "unsupported updateinfo location {:?} (only repodata/*-updateinfo.xml.zst is supported)",
            href.chars().take(80).collect::<String>()
        )))
    }
}

/// Failures while reading `updateinfo`.
#[derive(Debug, thiserror::Error)]
pub enum UpdateinfoError {
    /// The decompressed data exceeds [`MAX_XML_BYTES`].
    #[error("updateinfo is larger than the {MAX_XML_BYTES} byte limit")]
    TooLarge,
    /// The zstd stream is invalid.
    #[error("invalid zstd data: {0}")]
    Zstd(String),
    /// The XML is malformed.
    #[error("invalid updateinfo XML: {0}")]
    Xml(String),
}

/// One CVE fixed in one package by one update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FedoraFix {
    /// CVE identifier.
    pub cve: String,
    /// Binary or source package name.
    pub package: String,
    /// First version that contains the fix, as stated by this update.
    pub fixed_in: RpmEvr,
    /// Severity assigned by the update.
    pub severity: Severity,
    /// Update identifier, for example `FEDORA-2026-5c75eb75d1`.
    pub update: String,
}

/// Parsed metadata, queryable by package.
#[derive(Debug, Default)]
pub struct Updateinfo {
    by_package: BTreeMap<String, Vec<FedoraFix>>,
}

/// CVE ids at the start of a bugzilla title, e.g. `CVE-A CVE-B pkg: text`.
fn leading_cves(title: &str) -> Vec<String> {
    title
        .split_whitespace()
        .map(|t| t.trim_end_matches([',', ':']))
        .take_while(|t| is_cve_id(t))
        .map(str::to_owned)
        .collect()
}

fn severity(s: &str) -> Severity {
    match s.trim() {
        "Critical" => Severity::Critical,
        "Important" => Severity::High,
        "Moderate" => Severity::Medium,
        "Low" => Severity::Low,
        _ => Severity::Unknown,
    }
}

fn attr(e: &BytesStart<'_>, name: &str) -> Option<String> {
    e.attributes()
        .flatten()
        .find(|a| a.key.as_ref() == name)
        .and_then(|a| {
            a.normalized_value(XmlVersion::Implicit1_0)
                .ok()
                .map(std::borrow::Cow::into_owned)
        })
}

#[derive(Default)]
struct UpdateState {
    id: String,
    kind: String,
    severity: String,
    cves: Vec<String>,
    packages: Vec<(String, String)>, // (name, evr)
}

impl Updateinfo {
    /// Parses decompressed `updateinfo.xml`.
    ///
    /// # Errors
    ///
    /// Fails on oversized or malformed input.
    pub fn parse(xml: &[u8]) -> Result<Self, UpdateinfoError> {
        if xml.len() > MAX_XML_BYTES {
            return Err(UpdateinfoError::TooLarge);
        }
        let mut reader = Reader::from_reader(xml);
        let mut out = Self::default();
        let mut state: Option<UpdateState> = None;
        let mut text_target: Option<&'static str> = None;
        let mut depth = 0_usize;

        loop {
            let event = reader
                .read_event()
                .map_err(|e| UpdateinfoError::Xml(e.to_string()))?;
            match event {
                Event::Start(e) => {
                    depth += 1;
                    if depth > MAX_DEPTH {
                        return Err(UpdateinfoError::Xml("nesting too deep".into()));
                    }
                    match e.name().as_ref() {
                        "update" => {
                            state = Some(UpdateState {
                                kind: attr(&e, "type").unwrap_or_default(),
                                ..UpdateState::default()
                            });
                        }
                        "id" if state.is_some() => text_target = Some("id"),
                        "severity" if state.is_some() => text_target = Some("severity"),
                        _ => Self::element(&e, state.as_mut()),
                    }
                }
                Event::Empty(e) => Self::element(&e, state.as_mut()),
                Event::Text(t) => {
                    if let (Some(target), Some(st)) = (text_target, state.as_mut()) {
                        let text = t.xml_content(XmlVersion::Implicit1_0);
                        match target {
                            "id" => text.trim().clone_into(&mut st.id),
                            _ => text.trim().clone_into(&mut st.severity),
                        }
                    }
                }
                Event::End(e) => {
                    depth = depth.saturating_sub(1);
                    text_target = None;
                    if e.name().as_ref() == "update"
                        && let Some(st) = state.take()
                    {
                        out.finish(&st);
                    }
                }
                Event::Eof => break,
                _ => {}
            }
        }
        for fixes in out.by_package.values_mut() {
            fixes.sort_by(|a, b| a.cve.cmp(&b.cve).then_with(|| a.fixed_in.cmp(&b.fixed_in)));
        }
        Ok(out)
    }

    fn element(e: &BytesStart<'_>, state: Option<&mut UpdateState>) {
        let Some(st) = state else { return };
        match e.name().as_ref() {
            "reference" if attr(e, "type").as_deref() == Some("bugzilla") => {
                if let Some(title) = attr(e, "title") {
                    st.cves.extend(leading_cves(&title));
                }
            }
            "package" => {
                let (Some(name), Some(version), Some(release)) =
                    (attr(e, "name"), attr(e, "version"), attr(e, "release"))
                else {
                    return;
                };
                let epoch = attr(e, "epoch").unwrap_or_else(|| "0".into());
                st.packages
                    .push((name, format!("{epoch}:{version}-{release}")));
            }
            _ => {}
        }
    }

    fn finish(&mut self, st: &UpdateState) {
        // A security update that names no CVE bug is still a pending security
        // fix: record it under the update id so it cannot go unreported.
        let ids: Vec<String> = if st.cves.is_empty() && st.kind == "security" && !st.id.is_empty() {
            vec![st.id.clone()]
        } else {
            st.cves.clone()
        };
        if ids.is_empty() {
            return;
        }
        let sev = severity(&st.severity);
        for (name, evr) in &st.packages {
            let fixed_in: RpmEvr = evr.parse().unwrap_or_else(|never| match never {});
            for cve in &ids {
                let list = self.by_package.entry(name.clone()).or_default();
                // The same build is often listed for several arches (src, noarch).
                if list
                    .iter()
                    .any(|f| f.cve == *cve && f.update == st.id && f.fixed_in == fixed_in)
                {
                    continue;
                }
                list.push(FedoraFix {
                    cve: cve.clone(),
                    package: name.clone(),
                    fixed_in: fixed_in.clone(),
                    severity: sev,
                    update: st.id.clone(),
                });
            }
        }
    }

    /// Parses zstd-compressed `updateinfo.xml.zst`, capping the decompressed size.
    ///
    /// # Errors
    ///
    /// Fails on invalid zstd data, oversized output or malformed XML.
    pub fn parse_zst(compressed: &[u8]) -> Result<Self, UpdateinfoError> {
        let mut decoder = ruzstd::decoding::StreamingDecoder::new(compressed)
            .map_err(|e| UpdateinfoError::Zstd(e.to_string()))?;
        let mut xml = Vec::new();
        (&mut decoder)
            .take(MAX_XML_BYTES as u64 + 1)
            .read_to_end(&mut xml)
            .map_err(|e| UpdateinfoError::Zstd(e.to_string()))?;
        Self::parse(&xml)
    }

    /// Number of (package, CVE, update) fix records.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_package.values().map(Vec::len).sum()
    }

    /// True when no fix record was loaded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_package.is_empty()
    }

    /// The earliest fix Fedora published for `cve` in any of `names`
    /// (binary package name, and its source package name when different).
    ///
    /// Returns [`DistroStatus::Fixed`] with the lowest EVR, or `None` when
    /// updateinfo says nothing about this CVE for these packages.
    #[must_use]
    pub fn status_for(&self, names: &[&str], cve: &str) -> Option<(DistroStatus, Severity)> {
        names
            .iter()
            .filter_map(|n| self.by_package.get(*n))
            .flatten()
            .filter(|f| f.cve == cve)
            .min_by(|a, b| a.fixed_in.cmp(&b.fixed_in))
            .map(|f| {
                (
                    DistroStatus::Fixed(Version::Rpm(f.fixed_in.clone())),
                    f.severity,
                )
            })
    }

    /// True when any update records this CVE as fixed.
    #[must_use]
    pub fn knows(&self, cve: &str) -> bool {
        self.by_package
            .values()
            .flatten()
            .any(|f| f.cve.eq_ignore_ascii_case(cve))
    }

    /// Every CVE recorded for a package, sorted by CVE then fixed version.
    #[must_use]
    pub fn fixes_for(&self, package: &str) -> &[FedoraFix] {
        self.by_package.get(package).map_or(&[], Vec::as_slice)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use amivuln_core::{Verdict, classify};

    const FIXTURE: &[u8] =
        include_bytes!("../../../tests/fixtures/http/fedora-updateinfo/2026-11-07/updateinfo.xml");

    fn rpm(s: &str) -> Version {
        Version::Rpm(s.parse().unwrap_or_else(|n| match n {}))
    }

    fn info() -> Updateinfo {
        Updateinfo::parse(FIXTURE).unwrap()
    }

    const REPOMD: &[u8] = br#"<?xml version="1.0"?>
<repomd xmlns="http://linux.duke.edu/metadata/repo">
  <data type="primary"><location href="repodata/aaa-primary.xml.zst"/></data>
  <data type="updateinfo">
    <checksum type="sha256">625784996700016f59df8d29ffcba5fe597a1345bdf12a9492d635b41b28f99c</checksum>
    <location href="repodata/625784996700016f59df8d29ffcba5fe597a1345bdf12a9492d635b41b28f99c-updateinfo.xml.zst"/>
  </data>
</repomd>"#;

    #[test]
    fn repomd_location_and_checksum_are_found() {
        let loc = updateinfo_location(REPOMD).unwrap();
        assert_eq!(
            loc.href,
            "repodata/625784996700016f59df8d29ffcba5fe597a1345bdf12a9492d635b41b28f99c-updateinfo.xml.zst"
        );
        assert_eq!(
            loc.sha256,
            "625784996700016f59df8d29ffcba5fe597a1345bdf12a9492d635b41b28f99c"
        );
    }

    #[test]
    fn checksum_verification_accepts_only_the_promised_bytes() {
        // sha256("abc")
        let loc = UpdateinfoLocation {
            href: "repodata/x-updateinfo.xml.zst".into(),
            sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".into(),
        };
        assert!(loc.verify(b"abc"));
        assert!(!loc.verify(b"xyz"));
        assert!(!loc.verify(b""));
    }

    #[test]
    fn repomd_without_a_valid_checksum_is_rejected() {
        let no_sum = br#"<repomd><data type="updateinfo"><location href="repodata/a-updateinfo.xml.zst"/></data></repomd>"#;
        assert!(updateinfo_location(no_sum).is_err());
        let bad = br#"<repomd><data type="updateinfo"><checksum type="sha256">xyz</checksum><location href="repodata/a-updateinfo.xml.zst"/></data></repomd>"#;
        assert!(updateinfo_location(bad).is_err());
    }

    #[test]
    fn repomd_rejects_missing_or_suspicious_locations() {
        assert!(updateinfo_location(b"<repomd></repomd>").is_err());
        for href in [
            "../etc/passwd",
            "repodata/../x-updateinfo.xml.zst",
            "repodata/a-updateinfo.xml.gz",
            "https://evil.example/x-updateinfo.xml.zst",
            "repodata/a b-updateinfo.xml.zst",
        ] {
            let xml = format!(
                r#"<repomd><data type="updateinfo"><location href="{href}"/></data></repomd>"#
            );
            assert!(updateinfo_location(xml.as_bytes()).is_err(), "{href}");
        }
    }

    #[test]
    fn single_cve_update_maps_binary_and_source_packages() {
        let i = info();
        for pkg in ["python-multipart", "python3-multipart"] {
            let (status, sev) = i.status_for(&[pkg], "CVE-2026-28356").unwrap();
            assert_eq!(status, DistroStatus::Fixed(rpm("0:1.3.1-1.fc43")));
            assert_eq!(sev, Severity::High);
        }
    }

    #[test]
    fn multi_cve_update_fixes_each_cve() {
        let i = info();
        for cve in ["CVE-2026-25884", "CVE-2026-27596", "CVE-2026-27631"] {
            assert!(i.status_for(&["mingw-exiv2"], cve).is_some(), "{cve}");
        }
    }

    #[test]
    fn epoch_is_part_of_the_fixed_version() {
        let i = info();
        let (status, _) = i.status_for(&["python3-wheel"], "CVE-2026-24049").unwrap();
        assert_eq!(status, DistroStatus::Fixed(rpm("1:0.45.1-20.fc43")));
        // An installed build without the epoch bump is older.
        assert!(matches!(
            classify(&rpm("0.45.1-20.fc43"), &status),
            Verdict::Affected { .. }
        ));
        assert_eq!(
            classify(&rpm("1:0.45.1-20.fc43"), &status),
            Verdict::Patched
        );
    }

    #[test]
    fn cve_ids_only_in_descriptions_are_ignored() {
        let i = info();
        // perl-Authen-OATH mentions a CVE in its description but has no CVE bug.
        assert!(i.fixes_for("perl-Authen-OATH").is_empty());
    }

    #[test]
    fn security_updates_without_cve_bugs_are_kept_under_the_update_id() {
        let i = info();
        let yard = i.fixes_for("rubygem-yard");
        assert_eq!(yard.len(), 1);
        assert!(yard[0].cve.starts_with("FEDORA-2026-"), "{}", yard[0].cve);
        assert_eq!(yard[0].severity, Severity::Low);
        // Plack mentions CVE ids only in its description: still reported by
        // update id, never as claimed CVE fixes.
        let plack = i.fixes_for("perl-Plack");
        assert!(plack.iter().all(|f| f.cve.starts_with("FEDORA-2026-")));
        assert!(!plack.is_empty());
    }

    #[test]
    fn updates_without_cves_leave_no_records() {
        assert!(info().fixes_for("erlang-gun").is_empty());
        assert!(info().len() >= 6);
    }

    #[test]
    fn unknown_cve_or_package_says_nothing() {
        let i = info();
        assert!(
            i.status_for(&["python-multipart"], "CVE-0000-0001")
                .is_none()
        );
        assert!(i.status_for(&["nonexistent"], "CVE-2026-28356").is_none());
    }

    #[test]
    fn earliest_fix_wins_across_updates() {
        let xml = br#"<updates>
          <update type="security"><id>U2</id><severity>Low</severity>
            <references><reference type="bugzilla" title="CVE-0000-0001 foo: x"/></references>
            <pkglist><collection><package name="foo" version="2" release="1" epoch="0" arch="x86_64"/></collection></pkglist></update>
          <update type="security"><id>U1</id><severity>Critical</severity>
            <references><reference type="bugzilla" title="CVE-0000-0001 foo: x"/></references>
            <pkglist><collection><package name="foo" version="1" release="1" epoch="0" arch="x86_64"/></collection></pkglist></update>
        </updates>"#;
        let i = Updateinfo::parse(xml).unwrap();
        let (status, sev) = i.status_for(&["foo"], "CVE-0000-0001").unwrap();
        assert_eq!(status, DistroStatus::Fixed(rpm("0:1-1")));
        assert_eq!(sev, Severity::Critical);
    }

    #[test]
    fn title_parsing_is_strict() {
        assert_eq!(
            leading_cves("CVE-0000-0001 CVE-0000-0002, pkg: text"),
            ["CVE-0000-0001", "CVE-0000-0002"]
        );
        assert!(leading_cves("pkg: fixes CVE-0000-0001").is_empty());
        assert!(leading_cves("CVE-00-1 pkg").is_empty());
    }

    #[test]
    fn malformed_and_hostile_input_is_rejected_or_harmless() {
        // Truncated and invalid-UTF-8 input must not panic, whatever they return.
        let _ = Updateinfo::parse(b"<updates><update>");
        assert!(Updateinfo::parse(b"<updates></update>").is_err());
        let deep = "<a>".repeat(100);
        assert!(matches!(
            Updateinfo::parse(deep.as_bytes()),
            Err(UpdateinfoError::Xml(_))
        ));
        let _ = Updateinfo::parse(&[0xff, 0xfe, 0x00]);
        assert!(Updateinfo::parse(b"").unwrap().is_empty());
        assert!(matches!(
            Updateinfo::parse_zst(b"not zstd"),
            Err(UpdateinfoError::Zstd(_))
        ));
    }

    #[test]
    fn zstd_roundtrip_matches_plain_parse() {
        // Frame produced with `zstd -19` from the fixture (see below).
        let compressed = include_bytes!(
            "../../../tests/fixtures/http/fedora-updateinfo/2026-11-07/updateinfo.xml.zst"
        );
        let a = Updateinfo::parse_zst(compressed).unwrap();
        assert_eq!(a.len(), info().len());
    }

    /// Run with `AMIVULN_REAL_UPDATEINFO=/path/to/updateinfo.xml.zst cargo test -- --ignored`.
    /// Not part of CI: it needs a recorded multi-megabyte file.
    #[test]
    #[ignore = "needs AMIVULN_REAL_UPDATEINFO pointing at a real updateinfo.xml.zst"]
    fn real_repository_metadata_parses() {
        let Ok(path) = std::env::var("AMIVULN_REAL_UPDATEINFO") else {
            return;
        };
        let data = std::fs::read(path).unwrap();
        let started = std::time::Instant::now();
        let info = Updateinfo::parse_zst(&data).unwrap();
        assert!(info.len() > 100);
        assert!(started.elapsed() < std::time::Duration::from_secs(30));
    }
}
