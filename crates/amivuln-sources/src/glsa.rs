// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Gentoo Linux Security Advisories (GLSA).
//!
//! An advisory is an XML file (`glsa-YYYYMM-NN.xml`) that every Portage tree
//! carries in `metadata/glsa`, so a Gentoo host judges itself offline from its
//! own copy. Each names packages as `category/name` with the version ranges
//! that are `vulnerable` and those that are `unaffected`, a range optionally
//! limited to one slot, and the CVEs it covers as references.
//!
//! Only advisories that shipped a fix exist: like Alpine, a CVE with no fix
//! yet is not visible here.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::SystemTime;

use amivuln_core::Severity;
use amivuln_version::gentoo_vercmp;
use quick_xml::Reader;
use quick_xml::XmlVersion;
use quick_xml::events::{BytesStart, Event};

use crate::is_cve_id;

/// Largest advisory file read; the biggest real one is about 57 KB.
pub const MAX_FILE_BYTES: u64 = 1024 * 1024;
/// Most advisory files read from a directory; there are under 4,000.
pub const MAX_FILES: usize = 50_000;
/// Deepest element nesting accepted.
const MAX_DEPTH: usize = 16;

/// Why an advisory or the directory could not be read.
#[derive(Debug, thiserror::Error)]
pub enum GlsaError {
    /// The directory cannot be listed.
    #[error("cannot read the GLSA directory {0}: {1}")]
    Directory(String, String),
    /// The directory holds more advisories than the limit.
    #[error("{0} holds more than {MAX_FILES} advisory files")]
    TooMany(String),
    /// An advisory is larger than the limit.
    #[error("{0} is larger than {MAX_FILE_BYTES} bytes")]
    TooLarge(String),
    /// An advisory is not the expected XML.
    #[error("{0}: {1}")]
    Invalid(String, String),
}

/// How a range compares the installed version with its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// Older than.
    Lt,
    /// Older than or equal.
    Le,
    /// Equal.
    Eq,
    /// Newer than or equal.
    Ge,
    /// Newer than.
    Gt,
    /// Same version, older revision.
    Rlt,
    /// Same version, older or equal revision.
    Rle,
    /// Same version, newer or equal revision.
    Rge,
    /// Same version, newer revision.
    Rgt,
}

impl Op {
    fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "lt" => Self::Lt,
            "le" => Self::Le,
            "eq" => Self::Eq,
            "ge" => Self::Ge,
            "gt" => Self::Gt,
            "rlt" => Self::Rlt,
            "rle" => Self::Rle,
            "rge" => Self::Rge,
            "rgt" => Self::Rgt,
            _ => return None,
        })
    }
}

/// One `<vulnerable>` or `<unaffected>` element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Range {
    /// The comparison.
    pub op: Op,
    /// The version it compares with.
    pub version: String,
    /// The slot it is limited to; `None` for every slot.
    pub slot: Option<String>,
}

/// The version without its `-rN` revision.
fn without_revision(v: &str) -> &str {
    match v.rsplit_once("-r") {
        Some((base, rev)) if !rev.is_empty() && rev.bytes().all(|b| b.is_ascii_digit()) => base,
        _ => v,
    }
}

impl Range {
    /// True when a package installed in `slot` at `installed` is inside it.
    #[must_use]
    pub fn matches(&self, installed: &str, slot: Option<&str>) -> bool {
        if !self.covers_slot(slot) {
            return false;
        }
        let order = gentoo_vercmp(installed, &self.version);
        // The `r` operators ask about the revision of the very same version.
        let same_base =
            || gentoo_vercmp(without_revision(installed), without_revision(&self.version)).is_eq();
        match self.op {
            Op::Lt => order.is_lt(),
            Op::Le => order.is_le(),
            Op::Eq => order.is_eq(),
            Op::Ge => order.is_ge(),
            Op::Gt => order.is_gt(),
            Op::Rlt => same_base() && order.is_lt(),
            Op::Rle => same_base() && order.is_le(),
            Op::Rge => same_base() && order.is_ge(),
            Op::Rgt => same_base() && order.is_gt(),
        }
    }

    /// True when the range applies to a package in this slot: it names no
    /// slot, names every slot (`*`), or names this one.
    #[must_use]
    pub fn covers_slot(&self, slot: Option<&str>) -> bool {
        match self.slot.as_deref() {
            None | Some("*") => true,
            Some(want) => slot == Some(want),
        }
    }

    /// True for a range that names a version a package can be upgraded to.
    #[must_use]
    pub fn is_fix(&self) -> bool {
        matches!(self.op, Op::Ge | Op::Gt | Op::Eq | Op::Rge | Op::Rgt)
    }
}

/// One `<package>` of an advisory.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Package {
    /// `category/name`.
    pub name: String,
    /// Ranges that are vulnerable.
    pub vulnerable: Vec<Range>,
    /// Ranges that are not, which win over `vulnerable`.
    pub unaffected: Vec<Range>,
}

/// One advisory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Glsa {
    /// `YYYYMM-NN`.
    pub id: String,
    /// The CVEs it covers.
    pub cves: Vec<String>,
    /// From the `<impact>` element.
    pub severity: Severity,
    /// The packages it names.
    pub packages: Vec<Package>,
}

/// The `<impact type=...>` of an advisory as a severity.
fn impact(text: &str) -> Severity {
    match text {
        "high" => Severity::High,
        "normal" | "medium" => Severity::Medium,
        "low" | "minimal" => Severity::Low,
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

/// The CVE id a reference link or its text names.
fn cve_of(text: &str) -> Option<String> {
    let last = text.trim().rsplit('/').next()?;
    is_cve_id(last).then(|| last.to_owned())
}

impl Glsa {
    /// Parses one advisory file.
    ///
    /// # Errors
    ///
    /// Fails on oversized or malformed input.
    pub fn parse(xml: &[u8]) -> Result<Self, String> {
        if xml.len() as u64 > MAX_FILE_BYTES {
            return Err("too large".to_owned());
        }
        let mut reader = Reader::from_reader(xml);
        let mut glsa = Self {
            id: String::new(),
            cves: Vec::new(),
            severity: Severity::Unknown,
            packages: Vec::new(),
        };
        let (mut depth, mut in_references) = (0_usize, false);
        let mut range: Option<(bool, Range)> = None;
        let mut text = String::new();
        loop {
            match reader.read_event().map_err(|e| e.to_string())? {
                Event::Start(e) => {
                    depth += 1;
                    if depth > MAX_DEPTH {
                        return Err("nesting too deep".to_owned());
                    }
                    text.clear();
                    match e.name().as_ref() {
                        "glsa" => glsa.id = attr(&e, "id").unwrap_or_default(),
                        "impact" => glsa.severity = impact(&attr(&e, "type").unwrap_or_default()),
                        "references" => in_references = true,
                        "package" => glsa.packages.push(Package {
                            name: attr(&e, "name").unwrap_or_default(),
                            ..Package::default()
                        }),
                        kind @ ("vulnerable" | "unaffected") => {
                            let op = attr(&e, "range").as_deref().and_then(Op::parse);
                            range = op.map(|op| {
                                (
                                    kind == "vulnerable",
                                    Range {
                                        op,
                                        version: String::new(),
                                        slot: attr(&e, "slot"),
                                    },
                                )
                            });
                        }
                        "uri" if in_references => {
                            if let Some(c) = attr(&e, "link").as_deref().and_then(cve_of) {
                                glsa.cves.push(c);
                            }
                        }
                        _ => {}
                    }
                }
                Event::Text(t) => text.push_str(&t.xml_content(XmlVersion::Implicit1_0)),
                Event::End(e) => {
                    depth = depth.saturating_sub(1);
                    match e.name().as_ref() {
                        "references" => in_references = false,
                        "vulnerable" | "unaffected" => {
                            if let (Some((vulnerable, mut r)), Some(p)) =
                                (range.take(), glsa.packages.last_mut())
                            {
                                text.trim().clone_into(&mut r.version);
                                if !r.version.is_empty() {
                                    if vulnerable {
                                        p.vulnerable.push(r);
                                    } else {
                                        p.unaffected.push(r);
                                    }
                                }
                            }
                        }
                        "uri" if in_references => {
                            if let Some(c) = cve_of(&text) {
                                glsa.cves.push(c);
                            }
                        }
                        _ => {}
                    }
                    text.clear();
                }
                Event::Eof => break,
                _ => {}
            }
        }
        // A file cut short parses as far as it goes; its missing end would
        // hide the packages after the cut.
        if depth != 0 {
            return Err("the file ends inside an element".to_owned());
        }
        if glsa.id.is_empty() {
            return Err("no advisory id".to_owned());
        }
        glsa.cves.sort();
        glsa.cves.dedup();
        glsa.packages.retain(|p| !p.name.is_empty());
        Ok(glsa)
    }
}

/// Every advisory of a directory, found by package.
#[derive(Debug, Default)]
pub struct GlsaData {
    advisories: Vec<Glsa>,
    by_package: BTreeMap<String, Vec<usize>>,
    cves: std::collections::BTreeSet<String>,
    /// When the data was last updated, if the tree says so.
    pub updated: Option<SystemTime>,
}

impl GlsaData {
    /// The advisories that name `package` (`category/name`).
    pub fn for_package<'a>(&'a self, package: &str) -> impl Iterator<Item = &'a Glsa> + 'a {
        self.by_package
            .get(package)
            .into_iter()
            .flatten()
            .filter_map(|i| self.advisories.get(*i))
    }

    /// True when some advisory covers this CVE.
    #[must_use]
    pub fn knows(&self, cve: &str) -> bool {
        self.cves.contains(cve)
    }

    /// The number of advisories.
    #[must_use]
    pub fn len(&self) -> usize {
        self.advisories.len()
    }

    /// True when there is no advisory.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.advisories.is_empty()
    }

    /// Adds one advisory.
    pub fn insert(&mut self, glsa: Glsa) {
        self.cves.extend(glsa.cves.iter().cloned());
        let index = self.advisories.len();
        for p in &glsa.packages {
            self.by_package
                .entry(p.name.clone())
                .or_default()
                .push(index);
        }
        self.advisories.push(glsa);
    }

    /// Reads every `glsa-*.xml` file of `dir`.
    ///
    /// A file that cannot be read fails the whole load: skipping it would hide
    /// the advisories it holds.
    ///
    /// # Errors
    ///
    /// Fails when the directory cannot be listed or any file is unreadable.
    pub fn load(dir: &Path) -> Result<Self, GlsaError> {
        let shown = dir.display().to_string();
        let entries = std::fs::read_dir(dir)
            .map_err(|e| GlsaError::Directory(shown.clone(), e.to_string()))?;
        let mut files: Vec<std::path::PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.extension().is_some_and(|e| e == "xml")
                    && p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.starts_with("glsa-"))
            })
            .collect();
        if files.len() > MAX_FILES {
            return Err(GlsaError::TooMany(shown));
        }
        files.sort();
        let mut data = Self::default();
        let mut newest: Option<SystemTime> = None;
        for file in files {
            let name = file.display().to_string();
            let meta = std::fs::metadata(&file)
                .map_err(|e| GlsaError::Invalid(name.clone(), e.to_string()))?;
            if meta.len() > MAX_FILE_BYTES {
                return Err(GlsaError::TooLarge(name));
            }
            if let Ok(modified) = meta.modified() {
                newest = newest.max(Some(modified));
            }
            let bytes = std::fs::read(&file)
                .map_err(|e| GlsaError::Invalid(name.clone(), e.to_string()))?;
            data.insert(Glsa::parse(&bytes).map_err(|e| GlsaError::Invalid(name, e))?);
        }
        // The tree records when it was synchronised; the newest advisory file
        // is only a lower bound, since a quiet month changes none.
        let synced = dir
            .parent()
            .and_then(|meta| std::fs::metadata(meta.join("timestamp.chk")).ok())
            .and_then(|m| m.modified().ok());
        data.updated = synced.or(newest);
        Ok(data)
    }
}

/// The lowest version the ranges say a package can move to above `installed`.
#[must_use]
pub fn fixed_version<'a>(
    unaffected: &'a [Range],
    installed: &str,
    slot: Option<&str>,
) -> Option<&'a str> {
    unaffected
        .iter()
        .filter(|r| r.is_fix() && r.covers_slot(slot))
        .map(|r| r.version.as_str())
        .filter(|v| gentoo_vercmp(v, installed).is_gt())
        .min_by(|a, b| gentoo_vercmp(a, b))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn fixtures() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/glsa")
    }

    fn range(op: &str, version: &str, slot: Option<&str>) -> Range {
        Range {
            op: Op::parse(op).unwrap(),
            version: version.to_owned(),
            slot: slot.map(str::to_owned),
        }
    }

    #[test]
    fn an_advisory_is_read_with_its_cves_impact_and_slot_ranges() {
        let data = GlsaData::load(&fixtures()).unwrap();
        assert_eq!(data.len(), 7);
        let firefox: Vec<&Glsa> = data.for_package("www-client/firefox").collect();
        assert_eq!(firefox.len(), 1);
        let glsa = firefox[0];
        assert_eq!(glsa.id, "202501-10");
        assert!(!glsa.cves.is_empty() && glsa.cves.iter().all(|c| is_cve_id(c)));
        assert_eq!(glsa.severity, Severity::High);
        let pkg = glsa
            .packages
            .iter()
            .find(|p| p.name == "www-client/firefox")
            .unwrap();
        assert!(
            pkg.unaffected
                .contains(&range("ge", "134.0", Some("rapid")))
        );
        assert!(
            pkg.unaffected
                .contains(&range("ge", "128.6.0", Some("esr")))
        );
        assert!(
            pkg.vulnerable
                .contains(&range("lt", "128.6.0", Some("esr")))
        );
        // A GLSA that names no CVE is still an advisory; the id is its own.
        let none = data.for_package("www-client/seamonkey").next().unwrap();
        assert!(none.cves.is_empty());
        assert!(data.knows("CVE-2022-21797"));
        assert!(!data.knows("CVE-1999-0001"));
    }

    #[test]
    fn a_range_compares_with_the_ebuild_order_and_its_slot() {
        let ge = range("ge", "2.1.0", None);
        assert!(ge.matches("2.1.0-r3", None));
        assert!(ge.matches("2.10", None));
        assert!(!ge.matches("2.1.0_rc1", None));
        assert!(range("lt", "1.0", None).matches("1.0_beta", None));
        assert!(range("le", "1.0", None).matches("1.0-r0", None));
        assert!(range("eq", "1.0", None).matches("1.0-r0", None));
        assert!(range("gt", "1.0", None).matches("1.0.1", None));
        // The revision operators look at the revision of the same version only.
        let rge = range("rge", "2.23.1-r1", None);
        assert!(rge.matches("2.23.1-r2", None));
        assert!(rge.matches("2.23.1-r1", None));
        assert!(!rge.matches("2.23.1", None), "revision 0 is older than r1");
        assert!(
            !rge.matches("2.24.1", None),
            "a different version is not a revision"
        );
        assert!(range("rlt", "2.0-r2", None).matches("2.0-r1", None));
        assert!(!range("rlt", "2.0-r2", None).matches("2.1", None));
        // A slot limits a range; `*` and none do not.
        let esr = range("lt", "128.9.0", Some("esr"));
        assert!(esr.matches("128.8.0", Some("esr")));
        assert!(!esr.matches("128.8.0", Some("stable")));
        assert!(!esr.matches("128.8.0", None));
        assert!(range("lt", "9", Some("*")).matches("1", Some("anything")));
    }

    #[test]
    fn the_fix_is_the_lowest_version_above_the_installed_one() {
        let unaffected = [
            range("ge", "8.3.12", Some("8.3")),
            range("ge", "8.2.24", Some("8.2")),
            range("lt", "5.0", None),
        ];
        assert_eq!(
            fixed_version(&unaffected, "8.2.20", Some("8.2")),
            Some("8.2.24")
        );
        assert_eq!(
            fixed_version(&unaffected, "8.3.1", Some("8.3")),
            Some("8.3.12")
        );
        // Already at the fix, a slot the advisory does not cover, and a range
        // that only says what is older are not fixes.
        assert_eq!(fixed_version(&unaffected, "8.2.24", Some("8.2")), None);
        assert_eq!(fixed_version(&unaffected, "8.1.1", Some("8.1")), None);
        assert_eq!(
            fixed_version(&unaffected, "1.0", Some("8.2")),
            Some("8.2.24")
        );
    }

    #[test]
    fn a_broken_or_oversized_advisory_fails_the_load_instead_of_vanishing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("glsa-200001-01.xml"),
            "<glsa id=\"x\"><unclosed>",
        )
        .unwrap();
        let err = GlsaData::load(dir.path()).unwrap_err().to_string();
        assert!(err.contains("glsa-200001-01.xml"), "{err}");
        std::fs::write(dir.path().join("glsa-200001-01.xml"), "<other/>").unwrap();
        assert!(
            GlsaData::load(dir.path())
                .unwrap_err()
                .to_string()
                .contains("no advisory id")
        );
        std::fs::write(
            dir.path().join("glsa-200001-01.xml"),
            vec![b' '; usize::try_from(MAX_FILE_BYTES).unwrap() + 1],
        )
        .unwrap();
        assert!(matches!(
            GlsaData::load(dir.path()),
            Err(GlsaError::TooLarge(_))
        ));
        assert!(matches!(
            GlsaData::load(&dir.path().join("missing")),
            Err(GlsaError::Directory(..))
        ));
        // Files that are not advisories are not read.
        std::fs::remove_file(dir.path().join("glsa-200001-01.xml")).unwrap();
        std::fs::write(dir.path().join("notes.txt"), "x").unwrap();
        assert!(GlsaData::load(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn markup_cannot_pull_in_data_or_nest_without_limit() {
        // An entity or an external DTD is not followed, and deep nesting fails.
        let xml = "<!DOCTYPE glsa [<!ENTITY e SYSTEM \"file:///etc/passwd\">]><glsa id=\"1-1\"><title>&e;</title></glsa>";
        assert!(
            Glsa::parse(xml.as_bytes()).is_err()
                || Glsa::parse(xml.as_bytes()).unwrap().cves.is_empty()
        );
        let deep = format!(
            "<glsa id=\"1-1\">{}{}</glsa>",
            "<a>".repeat(40),
            "</a>".repeat(40)
        );
        assert!(Glsa::parse(deep.as_bytes()).is_err());
    }
}
