// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Red Hat CVEs that have no fix yet, from Red Hat's OVAL "including
//! unpatched" file (ADR-0014).
//!
//! OSV holds only Red Hat advisories that shipped a fix, so a CVE Red Hat has
//! not fixed is invisible there. The OVAL v2 file for a RHEL release lists them
//! with a resolution state per component. It is a `.bz2` of about 11 MB that
//! expands to about 650 MB of XML, so it is streamed through bounded readers and
//! reduced to `(component, CVE, state, severity)`; only that is kept.
//!
//! The data is published by Red Hat under CC BY 4.0: what is redistributed from
//! it must credit Red Hat and link to the original.

use std::collections::BTreeMap;
use std::io::{BufReader, Read};

use amivuln_core::Severity;
use quick_xml::Reader;
use quick_xml::XmlVersion;
use quick_xml::events::Event;

use crate::is_cve_id;

/// Largest compressed file accepted; the real one for RHEL 9 is 10.8 MB.
pub const MAX_COMPRESSED_BYTES: usize = 64 * 1024 * 1024;
/// Most XML bytes read after decompression; the real one is about 650 MB.
pub const MAX_EXPANDED_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// Deepest element nesting accepted; the real data is 9 deep at most.
const MAX_DEPTH: usize = 24;
/// Most entries kept; the real index has under 100,000.
const MAX_ENTRIES: usize = 2_000_000;

/// Why the file could not be read.
#[derive(Debug, thiserror::Error)]
pub enum OvalError {
    /// The compressed file is larger than the limit.
    #[error("the OVAL file is larger than {MAX_COMPRESSED_BYTES} bytes")]
    TooLarge,
    /// The XML is larger than the limit once expanded, or too deep.
    #[error("the OVAL file expands beyond the limits")]
    Bomb,
    /// The file is not the expected data.
    #[error("invalid OVAL data: {0}")]
    Invalid(String),
}

/// Red Hat's state for a CVE it has not fixed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum State {
    /// Affected, a fix is planned.
    Affected,
    /// The fix is postponed.
    FixDeferred,
    /// Red Hat will not fix it.
    WillNotFix,
    /// The product is out of the support scope for it.
    OutOfSupportScope,
}

impl State {
    /// The words Red Hat uses.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Affected => "Affected",
            Self::FixDeferred => "Fix deferred",
            Self::WillNotFix => "Will not fix",
            Self::OutOfSupportScope => "Out of support scope",
        }
    }

    /// `Under investigation` and anything unknown is not a statement that the
    /// package is affected, so it is not kept.
    fn parse(text: &str) -> Option<Self> {
        match text {
            "Affected" => Some(Self::Affected),
            "Fix deferred" => Some(Self::FixDeferred),
            "Will not fix" => Some(Self::WillNotFix),
            "Out of support scope" => Some(Self::OutOfSupportScope),
            _ => None,
        }
    }
}

/// One unfixed CVE with Red Hat's state for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unpatched {
    /// CVE id.
    pub cve: String,
    /// What Red Hat says about it.
    pub state: State,
    /// Severity as Red Hat rates it.
    pub severity: Severity,
}

/// Unfixed CVEs by component name (a source or binary package name).
///
/// A CVE is listed against every sub-package it touches (the kernel alone has
/// hundreds), so the 12,000 rows are kept once and each component points at
/// the rows that name it.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct UnpatchedIndex {
    rows: Vec<Unpatched>,
    by_component: BTreeMap<String, Vec<u32>>,
}

fn severity_of(text: &str) -> Severity {
    match text {
        "Critical" => Severity::Critical,
        "Important" => Severity::High,
        "Moderate" => Severity::Medium,
        "Low" => Severity::Low,
        _ => Severity::Unknown,
    }
}

fn severity_word(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "Critical",
        Severity::High => "Important",
        Severity::Medium => "Moderate",
        Severity::Low => "Low",
        Severity::Unknown => "Unknown",
    }
}

/// What one `<definition>` has said so far.
#[derive(Default)]
struct Definition {
    cves: Vec<String>,
    severity: Option<String>,
    resolutions: Vec<(State, Vec<String>)>,
}

impl UnpatchedIndex {
    /// Streams a `.bz2` OVAL file into the index.
    ///
    /// # Errors
    ///
    /// Fails on an oversized file, an expansion beyond the limits, or XML that
    /// is not the expected shape.
    pub fn parse_bz2(compressed: &[u8]) -> Result<Self, OvalError> {
        if compressed.len() > MAX_COMPRESSED_BYTES {
            return Err(OvalError::TooLarge);
        }
        let decoder = bzip2_rs::DecoderReader::new(compressed);
        Self::parse_xml(decoder.take(MAX_EXPANDED_BYTES + 1))
    }

    /// Reads the XML itself. Split from [`Self::parse_bz2`] so the reader
    /// can be bounded by the caller.
    fn parse_xml(input: impl Read) -> Result<Self, OvalError> {
        let mut reader = Reader::from_reader(BufReader::with_capacity(64 * 1024, input));
        let mut buf = Vec::new();
        let mut path: Vec<String> = Vec::new();
        let mut text = String::new();
        let mut def: Option<Definition> = None;
        let mut state: Option<State> = None;
        let mut index = Self::default();
        let mut entries = 0usize;
        loop {
            buf.clear();
            let event = reader
                .read_event_into(&mut buf)
                .map_err(|e| OvalError::Invalid(e.to_string()))?;
            if reader.buffer_position() > MAX_EXPANDED_BYTES {
                return Err(OvalError::Bomb);
            }
            match event {
                Event::Start(e) => {
                    if path.len() >= MAX_DEPTH {
                        return Err(OvalError::Bomb);
                    }
                    let name = e.local_name().as_ref().to_owned();
                    text.clear();
                    match name.as_str() {
                        "definition" => {
                            let vulnerability = e.attributes().flatten().any(|a| {
                                a.key.as_ref() == "class" && a.value.as_ref() == "vulnerability"
                            });
                            def = vulnerability.then(Definition::default);
                        }
                        "resolution" if def.is_some() => {
                            state = e
                                .attributes()
                                .flatten()
                                .find(|a| a.key.as_ref() == "state")
                                .and_then(|a| {
                                    a.normalized_value(XmlVersion::Implicit1_0)
                                        .ok()
                                        .and_then(|v| State::parse(&v))
                                });
                            if let (Some(d), Some(s)) = (def.as_mut(), state) {
                                d.resolutions.push((s, Vec::new()));
                            }
                        }
                        _ => {}
                    }
                    path.push(name);
                }
                Event::Text(t) => {
                    if def.is_some() {
                        text.push_str(&t.xml_content(XmlVersion::Implicit1_0));
                    }
                }
                Event::End(_) => {
                    let name = path.pop().unwrap_or_default();
                    if let Some(d) = def.as_mut() {
                        let parent = path.last().map(String::as_str);
                        match (name.as_str(), parent) {
                            ("cve", Some("advisory")) if is_cve_id(text.trim()) => {
                                d.cves.push(text.trim().to_owned());
                            }
                            ("severity", Some("advisory")) => {
                                d.severity = Some(text.trim().to_owned());
                            }
                            ("component", Some("resolution")) => {
                                if let Some((_, components)) = d.resolutions.last_mut()
                                    && state.is_some()
                                {
                                    components.push(text.trim().to_owned());
                                }
                            }
                            _ => {}
                        }
                    }
                    if name == "resolution" {
                        state = None;
                    }
                    if name == "definition"
                        && let Some(d) = def.take()
                    {
                        entries = index.add(d, entries)?;
                    }
                    text.clear();
                }
                Event::Eof => break,
                _ => {}
            }
        }
        if index.by_component.is_empty() {
            return Err(OvalError::Invalid(
                "no unfixed CVE found: this is not an OVAL file with unpatched data".into(),
            ));
        }
        index.finish();
        Ok(index)
    }

    fn add(&mut self, def: Definition, mut entries: usize) -> Result<usize, OvalError> {
        let severity = def
            .severity
            .as_deref()
            .map_or(Severity::Unknown, severity_of);
        for (state, components) in def.resolutions {
            for cve in &def.cves {
                entries += components.len();
                if entries > MAX_ENTRIES {
                    return Err(OvalError::Bomb);
                }
                let row = u32::try_from(self.rows.len()).map_err(|_| OvalError::Bomb)?;
                self.rows.push(Unpatched {
                    cve: cve.clone(),
                    state,
                    severity,
                });
                for component in &components {
                    self.by_component
                        .entry(component.clone())
                        .or_default()
                        .push(row);
                }
            }
        }
        Ok(entries)
    }

    /// The unfixed CVEs of a component, in the order of their CVE ids.
    pub fn for_component<'a>(&'a self, name: &str) -> impl Iterator<Item = &'a Unpatched> + 'a {
        self.by_component
            .get(name)
            .into_iter()
            .flatten()
            .filter_map(|&row| self.rows.get(row as usize))
    }

    /// Number of `(component, CVE)` pairs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_component.values().map(Vec::len).sum()
    }

    /// True when nothing is listed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_component.is_empty()
    }

    /// Sorts each component's rows by CVE id and drops repeats.
    fn finish(&mut self) {
        let rows = &self.rows;
        let row = |i: u32| rows.get(i as usize);
        for list in self.by_component.values_mut() {
            list.sort_by(|&a, &b| match (row(a), row(b)) {
                (Some(a), Some(b)) => a.cve.cmp(&b.cve).then(a.state.cmp(&b.state)),
                _ => a.cmp(&b),
            });
            list.dedup_by(|a, b| row(*a) == row(*b));
        }
    }

    /// The reduced form kept in the cache: one tab-separated line per row
    /// (CVE, state, severity, components), so the 650 MB of XML is read once
    /// per refresh, not once per run.
    #[must_use]
    pub fn to_reduced(&self) -> Vec<u8> {
        let mut components_of: Vec<Vec<&str>> = vec![Vec::new(); self.rows.len()];
        for (component, rows) in &self.by_component {
            for &row in rows {
                if let Some(list) = components_of.get_mut(row as usize) {
                    list.push(component);
                }
            }
        }
        let mut out = String::new();
        for (row, components) in self.rows.iter().zip(&components_of) {
            if components.is_empty() {
                continue;
            }
            out.push_str(&row.cve);
            out.push('\t');
            out.push_str(row.state.as_str());
            out.push('\t');
            out.push_str(severity_word(row.severity));
            out.push('\t');
            out.push_str(&components.join(" "));
            out.push('\n');
        }
        out.into_bytes()
    }

    /// Reads what [`Self::to_reduced`] wrote.
    ///
    /// # Errors
    ///
    /// Fails when a line is not in that form.
    pub fn from_reduced(bytes: &[u8]) -> Result<Self, OvalError> {
        let bad = |why: &str| OvalError::Invalid(format!("a reduced line {why}"));
        let text = std::str::from_utf8(bytes).map_err(|e| OvalError::Invalid(e.to_string()))?;
        let mut index = Self::default();
        let mut entries = 0usize;
        for line in text.lines() {
            let mut f = line.split('\t');
            let (Some(cve), Some(state), Some(severity), Some(components), None) =
                (f.next(), f.next(), f.next(), f.next(), f.next())
            else {
                return Err(bad("has the wrong shape"));
            };
            let state = State::parse(state).ok_or_else(|| bad("has an unknown state"))?;
            if !is_cve_id(cve) {
                return Err(bad("has a bad CVE id"));
            }
            let def = Definition {
                cves: vec![cve.to_owned()],
                severity: Some(severity.to_owned()),
                resolutions: vec![(
                    state,
                    components
                        .split(' ')
                        .filter(|c| !c.is_empty())
                        .map(str::to_owned)
                        .collect(),
                )],
            };
            entries = index.add(def, entries)?;
        }
        index.finish();
        Ok(index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<oval_definitions><definitions>
<definition class="vulnerability" id="oval:com.redhat.cve:def:1" version="1"><metadata>
 <title>lame: x (low)</title>
 <advisory><severity>Low</severity>
  <cve href="https://access.redhat.com/security/cve/CVE-2015-9099">CVE-2015-9099</cve>
  <affected><resolution state="Will not fix"><component>lame</component><component>lame-libs</component></resolution></affected>
 </advisory></metadata></definition>
<definition class="vulnerability" id="oval:com.redhat.cve:def:2" version="1"><metadata>
 <advisory><severity>Important</severity>
  <cve>CVE-2024-0001</cve>
  <affected><resolution state="Affected"><component>openssl</component></resolution>
            <resolution state="Under investigation"><component>nginx</component></resolution></affected>
 </advisory></metadata></definition>
<definition class="patch" id="oval:com.redhat.rhsa:def:3" version="1"><metadata>
 <advisory><severity>Critical</severity><cve>CVE-2024-9999</cve>
  <affected><resolution state="Affected"><component>glibc</component></resolution></affected>
 </advisory></metadata></definition>
</definitions></oval_definitions>"#;

    #[test]
    fn unfixed_cves_are_read_by_component() {
        let index = UnpatchedIndex::parse_xml(XML.as_bytes()).unwrap();
        let lame: Vec<_> = index.for_component("lame-libs").collect();
        assert_eq!(lame.len(), 1);
        assert_eq!(lame[0].cve, "CVE-2015-9099");
        assert_eq!(lame[0].state, State::WillNotFix);
        assert_eq!(lame[0].severity, Severity::Low);
        let ssl: Vec<_> = index.for_component("openssl").collect();
        assert_eq!(
            (ssl[0].state, ssl[0].severity),
            (State::Affected, Severity::High)
        );
        assert_eq!(index.len(), 3);
    }

    #[test]
    fn under_investigation_and_non_vulnerability_definitions_are_not_kept() {
        let index = UnpatchedIndex::parse_xml(XML.as_bytes()).unwrap();
        assert_eq!(index.for_component("nginx").count(), 0);
        assert_eq!(index.for_component("glibc").count(), 0);
    }

    #[test]
    fn the_reduced_form_round_trips() {
        let index = UnpatchedIndex::parse_xml(XML.as_bytes()).unwrap();
        let back = UnpatchedIndex::from_reduced(&index.to_reduced()).unwrap();
        assert_eq!(index, back);
        assert!(UnpatchedIndex::from_reduced(b"CVE-2024-0001\tAffected\n").is_err());
        assert!(UnpatchedIndex::from_reduced(b"not-a-cve\tAffected\tLow\ta\n").is_err());
        assert!(UnpatchedIndex::from_reduced(b"CVE-2024-0001\tNope\tLow\ta\n").is_err());
    }

    #[test]
    fn a_file_with_no_unfixed_cve_is_refused() {
        let xml = "<oval_definitions><definitions/></oval_definitions>";
        assert!(matches!(
            UnpatchedIndex::parse_xml(xml.as_bytes()),
            Err(OvalError::Invalid(_))
        ));
    }

    #[test]
    fn nesting_beyond_the_limit_is_refused() {
        let deep = "<a>".repeat(MAX_DEPTH + 2);
        assert!(matches!(
            UnpatchedIndex::parse_xml(deep.as_bytes()),
            Err(OvalError::Bomb)
        ));
    }

    #[test]
    fn a_compressed_file_is_streamed_through() {
        // XML above compressed with `bzip2 -9`.
        let bz2 = include_bytes!("../../../tests/fixtures/redhat-oval/small.oval.xml.bz2");
        let index = UnpatchedIndex::parse_bz2(bz2).unwrap();
        assert_eq!(index.len(), 3);
        assert!(UnpatchedIndex::parse_bz2(b"not bzip2").is_err());
    }
}
