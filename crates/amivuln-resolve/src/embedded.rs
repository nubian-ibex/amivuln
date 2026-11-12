// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Detection of version metadata embedded in binaries (ADR-0013).
//!
//! Three formats are recognized, none of them by executing the file:
//!
//! - the systemd package note `.note.package` (FDO, note type `0x4f3c`),
//!   whose JSON payload carries the packaging system, package name and version;
//! - the Go build information block (`\xff Go buildinf:`), whose embedded
//!   `go.mod` text lists the main module and the required modules;
//! - the cargo-auditable `.dep-v0` section, a JSON array of crates.
//!
//! Everything is bounded: reads stop at a size limit and every offset is
//! validated before use, so a malformed file is a miss, never a crash.

use std::collections::BTreeSet;

/// Largest file read for embedded detection.
pub const MAX_EMBEDDED_FILE: u64 = 512 * 1024 * 1024;

/// A package detected inside a binary.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Detected {
    /// Package name: the Go module path, the crate name, or the packaged name.
    pub name: String,
    /// Version, in the ecosystem's own scheme (semver for Go and crates.io).
    pub version: String,
    /// What the detection came from.
    pub origin: Origin,
    /// The packaging system a note declares (`rpm`, `deb`, `alpm`), if any.
    pub pkg_type: Option<String>,
}

/// The embedded format a package was detected in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Origin {
    /// systemd package note.
    PackageNote,
    /// Go build information.
    GoBuildinfo,
    /// cargo-auditable dependency list.
    CargoAuditable,
}

/// Detects every package in an ELF file, deduplicated.
///
/// # Errors
///
/// Fails when the file cannot be read at all; format problems are misses.
pub fn detect(path: &std::path::Path) -> Result<Vec<Detected>, String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if meta.len() > MAX_EMBEDDED_FILE {
        return Err(format!(
            "{} is larger than {MAX_EMBEDDED_FILE} bytes",
            path.display()
        ));
    }
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(detect_bytes(&bytes))
}

/// Builds a package from the `.note.package` of `path`, for a file no package
/// database knows. The note's packaging system must match the host's: a note
/// that says `deb` on an RPM host names a version this host cannot compare.
///
/// # Errors
///
/// [`crate::ResolveError::NotFound`] when the file carries no usable note or
/// the note belongs to another packaging system.
pub fn package_from_note(
    eco: amivuln_core::Ecosystem,
    path: &std::path::Path,
) -> Result<amivuln_core::PackageRef, crate::ResolveError> {
    use amivuln_core::{Ecosystem, Provenance};
    let missing = |why: &str| crate::ResolveError::NotFound(format!("{} ({why})", path.display()));
    let found = detect(path).map_err(crate::ResolveError::Parse)?;
    let note = found
        .into_iter()
        .find(|d| d.origin == Origin::PackageNote)
        .ok_or_else(|| missing("no package owns it and it carries no .note.package"))?;
    let host_kind = match eco {
        Ecosystem::Fedora(_) | Ecosystem::Rocky(_) | Ecosystem::Alma(_) | Ecosystem::Rhel(_) => {
            "rpm"
        }
        Ecosystem::Debian(_) | Ecosystem::Ubuntu(_) => "deb",
        Ecosystem::Arch => "alpm",
        // A host is never a language ecosystem; no note can match it.
        Ecosystem::Alpine(_) => "apk",
        Ecosystem::Go | Ecosystem::Crates => "none",
    };
    let declared = note.pkg_type.as_deref().unwrap_or(host_kind);
    // Arch notes are written as `alpm` by some builders and `pacman` by others.
    let declared = if declared == "pacman" {
        "alpm"
    } else {
        declared
    };
    if declared != host_kind {
        return Err(missing(&format!(
            "its note is for {declared} packages but this host uses {host_kind}"
        )));
    }
    let mut package = crate::from_name_version(eco, &note.name, &note.version)?;
    package.provenance = Provenance::EmbeddedNote;
    Ok(package)
}

/// Most language packages taken from one file.
const MAX_LANGUAGE_PACKAGES: usize = 5000;

/// The Go modules and Rust crates a file declares, as packages. Entries whose
/// version is not a semantic version are dropped.
///
/// These are for files **no distribution package owns**: a distribution
/// backports fixes into vendored code without changing the module version, so
/// judging an owned binary's modules by version would report false positives.
///
/// # Errors
///
/// Fails when the file cannot be read.
pub fn language_packages(
    path: &std::path::Path,
) -> Result<Vec<amivuln_core::PackageRef>, crate::ResolveError> {
    use amivuln_core::{Ecosystem, PackageRef, Provenance, Version};
    let found = detect(path).map_err(crate::ResolveError::Parse)?;
    let mut out = Vec::new();
    for d in found {
        let ecosystem = match d.origin {
            Origin::GoBuildinfo => Ecosystem::Go,
            Origin::CargoAuditable => Ecosystem::Crates,
            Origin::PackageNote => continue,
        };
        let Ok(version) = amivuln_version::SemverVersion::parse(&d.version) else {
            continue;
        };
        out.push(PackageRef {
            ecosystem,
            name: d.name,
            source_name: None,
            version: Version::Semver(version),
            arch: None,
            provenance: Provenance::EmbeddedBuildInfo,
        });
        if out.len() >= MAX_LANGUAGE_PACKAGES {
            break;
        }
    }
    Ok(out)
}

/// The in-memory form of [`detect`].
#[must_use]
pub fn detect_bytes(bytes: &[u8]) -> Vec<Detected> {
    let mut found: BTreeSet<Detected> = BTreeSet::new();
    for note in elf_notes(bytes) {
        if note.name() == "FDO"
            && note.kind() == 0x4f3c
            && let Some(d) = parse_package_note(note.desc)
        {
            found.insert(d);
        }
    }
    for d in parse_go_buildinfo(bytes) {
        found.insert(d);
    }
    for d in parse_cargo_auditable(bytes) {
        found.insert(d);
    }
    found.into_iter().collect()
}

/// One ELF note: a name, a type and a payload.
struct Note<'a> {
    name: &'a str,
    kind: u32,
    desc: &'a [u8],
}

impl Note<'_> {
    fn name(&self) -> &str {
        self.name
    }

    fn kind(&self) -> u32 {
        self.kind
    }
}

/// Reads u32 little-endian, or 0 on a short slice.
fn u32le(b: &[u8]) -> u32 {
    u32::from_le_bytes([
        b.first().copied().unwrap_or(0),
        b.get(1).copied().unwrap_or(0),
        b.get(2).copied().unwrap_or(0),
        b.get(3).copied().unwrap_or(0),
    ])
}

/// Iterates notes from concatenated note records (`namesz, descsz, type,
/// name, desc` with 4-byte alignment).
fn notes_in(data: &[u8]) -> Vec<Note<'_>> {
    let mut out = Vec::new();
    let mut at = 0usize;
    // A record that runs past the end, overflows, or has a nonsensical size
    // ends the walk: notes are trusted less than the manifest above them.
    while at + 12 <= data.len() {
        let namesz = u32le(data.get(at..).unwrap_or_default()) as usize;
        let descsz = u32le(data.get(at + 4..).unwrap_or_default()) as usize;
        let kind = u32le(data.get(at + 8..).unwrap_or_default());
        let mut pos = at + 12;
        let Some(name_end) = pos.checked_add(namesz) else {
            break;
        };
        let Some(name) = data.get(pos..name_end) else {
            break;
        };
        let Ok(name) = std::str::from_utf8(name.strip_suffix(&[0]).unwrap_or(name)) else {
            break;
        };
        match round4(name_end) {
            Some(v) => pos = v,
            None => break,
        }
        let Some(desc_end) = pos.checked_add(descsz) else {
            break;
        };
        let Some(desc) = data.get(pos..desc_end) else {
            break;
        };
        out.push(Note { name, kind, desc });
        match round4(desc_end) {
            Some(v) => at = v,
            None => break,
        }
    }
    out
}

fn round4(v: usize) -> Option<usize> {
    v.checked_add(3).map(|r| r & !3)
}

/// Finds every note record in the file, via section headers or the note
/// program headers of a stripped ELF.
fn elf_notes(bytes: &[u8]) -> Vec<Note<'_>> {
    let mut out = Vec::new();
    if bytes.starts_with(b"\x7fELF") {
        if let Some(notes) = notes_from_sections(bytes) {
            out.extend(notes);
        }
        if out.is_empty() {
            out.extend(notes_from_segments(bytes));
        }
    }
    out
}

/// Field from the ELF64 header at a fixed offset.
/// Little-endian u16 at a fixed header offset.
fn e16(bytes: &[u8], off: usize) -> Option<u64> {
    let b = bytes.get(off..off.checked_add(2)?)?;
    Some(u64::from(u16::from_le_bytes([*b.first()?, *b.get(1)?])))
}

fn e64(bytes: &[u8], off: usize) -> Option<u64> {
    let b = bytes.get(off..off.checked_add(8)?)?;
    let mut array = [0u8; 8];
    array.copy_from_slice(b);
    Some(u64::from_le_bytes(array))
}

fn notes_from_sections(bytes: &[u8]) -> Option<Vec<Note<'_>>> {
    // ELF64 little-endian only: the formats this feature targets.
    if bytes.get(4).copied()? != 2 || bytes.get(5).copied()? != 1 {
        return None;
    }
    let shoff = e64(bytes, 0x28)?;
    let Ok(shentsize) = usize::try_from(e16(bytes, 0x3a)?) else {
        return None;
    };
    let shnum = e16(bytes, 0x3c)?;
    if shentsize < 64 || shnum == 0 || shnum > 65536 {
        return None;
    }
    // Section header layout (ELF64): sh_name at 0, sh_type at 4, sh_offset
    // at 24, sh_size at 32.
    let section = |i: u64| -> Option<(u32, &[u8])> {
        let at = usize::try_from(shoff.checked_add(i.checked_mul(shentsize as u64)?)?).ok()?;
        let raw = bytes.get(at..at.checked_add(shentsize)?)?;
        let sh_type = u32le(raw.get(4..)?);
        let offset = usize::try_from(u64::from_le_bytes(raw.get(24..32)?.try_into().ok()?)).ok()?;
        let size = usize::try_from(u64::from_le_bytes(raw.get(32..40)?.try_into().ok()?)).ok()?;
        let data = bytes.get(offset..offset.checked_add(size)?)?;
        Some((sh_type, data))
    };
    let mut out = Vec::new();
    for i in 0..shnum {
        // SHT_NOTE = 7.
        let (7, data) = section(i)? else {
            continue;
        };
        out.extend(notes_in(data));
    }
    Some(out)
}

fn notes_from_segments(bytes: &[u8]) -> Vec<Note<'_>> {
    // PT_NOTE = 4. ELF64 program headers are 56 bytes with p_type at 0 and
    // p_offset/p_filesz at 8 and 32.
    let mut out = Vec::new();
    let Ok(phoff) = usize::try_from(e64(bytes, 0x20).unwrap_or(0)) else {
        return out;
    };
    let Ok(phentsize) = usize::try_from(e16(bytes, 0x36).unwrap_or(0)) else {
        return out;
    };
    let Ok(phnum) = usize::try_from(e16(bytes, 0x38).unwrap_or(0)) else {
        return out;
    };
    if phentsize < 56 || phnum == 0 || phnum > 65536 {
        return out;
    }
    for i in 0..phnum {
        let Some(at) = i.checked_mul(phentsize).and_then(|v| phoff.checked_add(v)) else {
            break;
        };
        let Some(raw) = at.checked_add(phentsize).and_then(|end| bytes.get(at..end)) else {
            break;
        };
        if u32le(raw) != 4 {
            continue;
        }
        let read_u64 = |range: std::ops::Range<usize>| -> Option<u64> {
            let b = raw.get(range)?;
            Some(u64::from_le_bytes(b.try_into().ok()?))
        };
        let (Some(offset), Some(size)) = (
            read_u64(8..16).and_then(|v| usize::try_from(v).ok()),
            read_u64(32..40).and_then(|v| usize::try_from(v).ok()),
        ) else {
            break;
        };
        match offset
            .checked_add(size)
            .and_then(|end| bytes.get(offset..end))
        {
            Some(data) => out.extend(notes_in(data)),
            None => break,
        }
    }
    out
}

/// Parses the `.note.package` JSON payload: `{"type":"rpm","name":"x",
/// "version":"1:2-3"}` or with a `"purl"`.
fn parse_package_note(desc: &[u8]) -> Option<Detected> {
    let json: serde_json::Value =
        serde_json::from_slice(desc.strip_suffix(&[0]).unwrap_or(desc)).ok()?;
    let name = json.get("name")?.as_str()?.to_owned();
    if name.is_empty() {
        return None;
    }
    let version = json.get("version")?.as_str()?.to_owned();
    if version.is_empty() {
        return None;
    }
    let pkg_type = json
        .get("type")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    Some(Detected {
        name,
        version,
        origin: Origin::PackageNote,
        pkg_type,
    })
}

/// The Go build information magic.
const GO_MAGIC: &[u8] = b"\xff Go buildinf:";

/// Parses the Go buildinfo block: every required module with a version from
/// the embedded `go.mod` text (build info format v2). The main module has no
/// version of its own in the blob, so only requirements are reported.
fn parse_go_buildinfo(bytes: &[u8]) -> Vec<Detected> {
    let Some(text) = go_buildinfo_text(bytes) else {
        return Vec::new();
    };
    go_mod_packages(&text)
}

/// The embedded `go.mod` text of the buildinfo block, when well-formed.
fn go_buildinfo_text(bytes: &[u8]) -> Option<String> {
    let at = find(bytes, GO_MAGIC)?;
    let head = bytes.get(at..at.checked_add(GO_MAGIC.len() + 2)?)?;
    let ptr_size = *head.get(GO_MAGIC.len())?;
    let flags = *head.get(GO_MAGIC.len() + 1)?;
    if ptr_size != 8 && ptr_size != 4 {
        return None;
    }
    // v1 has two NUL-terminated strings and no module text; only v2 (flags
    // bit 1) embeds the `go.mod` content this parser needs.
    if flags & 2 == 0 {
        return None;
    }
    let base = at + GO_MAGIC.len() + 2;
    let read_varint = |pos: &mut usize| -> Option<u64> {
        let mut value = 0u64;
        let mut shift = 0;
        loop {
            let b = *bytes.get(*pos)?;
            *pos += 1;
            value |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return Some(value);
            }
            shift += 7;
            if shift > 63 {
                return None;
            }
        }
    };
    let mut pos = base;
    let _gover_off = read_varint(&mut pos)?;
    let _gover_len = read_varint(&mut pos)?;
    let mod_off = usize::try_from(read_varint(&mut pos)?).ok()?;
    let mod_len = usize::try_from(read_varint(&mut pos)?).ok()?;
    if mod_len == 0 || mod_len > 1024 * 1024 {
        return None;
    }
    let start = at.checked_add(mod_off)?;
    let text = bytes.get(start..start.checked_add(mod_len)?)?;
    std::str::from_utf8(text).ok().map(str::to_owned)
}

/// Extracts every versioned requirement from a `go.mod` text.
fn go_mod_packages(text: &str) -> Vec<Detected> {
    let mut found = Vec::new();
    let mut in_require = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("require (") {
            in_require = true;
            continue;
        }
        if in_require && line == ")" {
            in_require = false;
            continue;
        }
        let spec = if let Some(rest) = line.strip_prefix("require ") {
            rest
        } else if in_require && !line.is_empty() && !line.starts_with("//") {
            line
        } else {
            continue;
        };
        let mut parts = spec.split_whitespace();
        let Some(name) = parts.next() else {
            continue;
        };
        let Some(version) = parts.next() else {
            continue;
        };
        if is_module_name(name) && is_semverish(version) {
            found.push(Detected {
                name: name.to_owned(),
                version: version.to_owned(),
                origin: Origin::GoBuildinfo,
                pkg_type: None,
            });
        }
    }
    found
}

/// A module path: dot-separated with at least one slash-joined element.
fn is_module_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._/-~+".contains(&b))
        && name.contains('/')
}

/// Accepts `v1.2.3`, `v1.2.3-rc.1` and pseudo-versions.
fn is_semverish(v: &str) -> bool {
    let v = v.strip_prefix('v').unwrap_or(v);
    let core = v.split(['-', '+']).next().unwrap_or_default();
    core.split('.').count() == 3 && core.bytes().all(|b| b.is_ascii_digit() || b == b'.')
}

/// The cargo-auditable marker inside `.dep-v0`.
const AUDITABLE_MAGIC: &[u8] = b"AUDITABLE_V0D";

/// Parses the cargo-auditable dependency list: after the marker, a JSON array
/// of `[name, version, [dependencies...]]` rows.
fn parse_cargo_auditable(bytes: &[u8]) -> Vec<Detected> {
    let Some(at) = find(bytes, AUDITABLE_MAGIC) else {
        return Vec::new();
    };
    let start = at + AUDITABLE_MAGIC.len();
    let Some(window) = bytes.get(start..(start + 1024 * 1024).min(bytes.len())) else {
        return Vec::new();
    };
    let Some(end) = window.iter().rposition(|b| *b == b']') else {
        return Vec::new();
    };
    let Some(rows_json) = window.get(..=end) else {
        return Vec::new();
    };
    let Ok(rows) = serde_json::from_slice::<Vec<(String, String, Vec<String>)>>(rows_json) else {
        return Vec::new();
    };
    rows.into_iter()
        .filter(|(name, version, _)| !name.is_empty() && !version.is_empty() && name.len() <= 256)
        .map(|(name, version, _)| Detected {
            name,
            version,
            origin: Origin::CargoAuditable,
            pkg_type: None,
        })
        .collect()
}

/// Finds the first occurrence of `needle`, skipping quickly to candidates by
/// their first byte: binaries are large and this runs three times per file.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    let first = *needle.first()?;
    let mut from = 0usize;
    while let Some(rest) = haystack.get(from..) {
        let hit = from + rest.iter().position(|&b| b == first)?;
        let end = hit.checked_add(needle.len())?;
        if haystack
            .get(hit..end)
            .is_some_and(|window| window == needle)
        {
            return Some(hit);
        }
        from = hit + 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn note_section(records: &[(&str, u32, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (name, kind, desc) in records {
            let namesz = name.len() + 1;
            out.extend_from_slice(&u32::try_from(namesz).unwrap_or(0).to_le_bytes());
            out.extend_from_slice(&u32::try_from(desc.len()).unwrap_or(0).to_le_bytes());
            out.extend_from_slice(&kind.to_le_bytes());
            out.extend_from_slice(name.as_bytes());
            out.push(0);
            while out.len() % 4 != 0 {
                out.push(0);
            }
            out.extend_from_slice(desc);
            while out.len() % 4 != 0 {
                out.push(0);
            }
        }
        out
    }

    #[test]
    fn the_recorded_fixture_is_detected() {
        let bytes = include_bytes!("../../../tests/fixtures/elf/with-package-note.elf");
        let found = detect_bytes(bytes);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].name, "python3-multipart");
        assert_eq!(found[0].version, "0:1.3.0-1.fc43");
        assert_eq!(found[0].pkg_type.as_deref(), Some("rpm"));
    }

    #[test]
    fn recorded_go_and_rust_fixtures_are_detected() {
        let go = detect_bytes(include_bytes!("../../../tests/fixtures/elf/go-app.bin"));
        let names: Vec<(&str, &str)> = go
            .iter()
            .map(|d| (d.name.as_str(), d.version.as_str()))
            .collect();
        assert_eq!(
            names,
            [
                ("github.com/pkg/errors", "v0.9.1"),
                ("golang.org/x/net", "v0.7.0")
            ]
        );
        let rust = detect_bytes(include_bytes!("../../../tests/fixtures/elf/rust-app.bin"));
        let names: Vec<&str> = rust.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, ["serde", "time"]);
    }

    #[test]
    fn package_note_json_is_parsed() {
        let payload = br#"{"type":"rpm","name":"nginx","version":"1:1.26.2-1.fc41"}"#;
        let notes = note_section(&[("FDO", 0x4f3c, payload)]);
        let found = notes_in(&notes);
        assert_eq!(found.len(), 1);
        let d = parse_package_note(found[0].desc).unwrap();
        assert_eq!(d.name, "nginx");
        assert_eq!(d.version, "1:1.26.2-1.fc41");
    }

    #[test]
    fn a_file_with_a_note_section_is_detected() {
        // A minimal ELF64 with one SHT_NOTE section, hand-assembled.
        let payload = br#"{"type":"deb","name":"curl","version":"7.88.1-10"}"#;
        let notes = note_section(&[("FDO", 0x4f3c, payload)]);
        let mut file: Vec<u8> = Vec::new();
        // e_ident[16]
        file.extend_from_slice(b"\x7fELF\x02\x01\x01");
        file.extend_from_slice(&[0u8; 9]);
        file.extend_from_slice(&1u16.to_le_bytes()); // e_type
        file.extend_from_slice(&62u16.to_le_bytes()); // e_machine
        file.extend_from_slice(&1u32.to_le_bytes()); // e_version
        file.extend_from_slice(&0u64.to_le_bytes()); // e_entry
        file.extend_from_slice(&0u64.to_le_bytes()); // e_phoff (32)
        let shoff_pos = file.len();
        assert_eq!(shoff_pos, 40, "e_shoff must sit at 0x28");
        file.extend_from_slice(&0u64.to_le_bytes()); // e_shoff (40)
        file.extend_from_slice(&0u32.to_le_bytes()); // e_flags
        file.extend_from_slice(&64u16.to_le_bytes()); // e_ehsize
        file.extend_from_slice(&0u16.to_le_bytes()); // e_phentsize
        file.extend_from_slice(&0u16.to_le_bytes()); // e_phnum
        let shentsize_pos = file.len();
        assert_eq!(shentsize_pos, 58, "e_shentsize must sit at 0x3a");
        file.extend_from_slice(&64u16.to_le_bytes()); // e_shentsize
        file.extend_from_slice(&2u16.to_le_bytes()); // e_shnum
        file.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx
        assert_eq!(file.len(), 64);
        // The note section data itself.
        let note_off = file.len() as u64;
        file.extend_from_slice(&notes);
        // section 0: null
        file.extend_from_slice(&[0u8; 64]);
        // section 1: NOTE (sh_name, sh_type, sh_flags, sh_addr, sh_offset,
        // sh_size, sh_link, sh_info, sh_addralign, sh_entsize).
        file.extend_from_slice(&0u32.to_le_bytes()); // sh_name
        file.extend_from_slice(&7u32.to_le_bytes()); // sh_type = SHT_NOTE
        file.extend_from_slice(&[0u8; 16]); // sh_flags, sh_addr
        file.extend_from_slice(&note_off.to_le_bytes());
        file.extend_from_slice(&(notes.len() as u64).to_le_bytes());
        file.extend_from_slice(&[0u8; 24]); // sh_link, sh_info, align, entsize
        let shoff = note_off + notes.len() as u64;
        let start = shoff_pos;
        let range = start..start.saturating_add(8).min(file.len());
        if let Some(slot) = file.get_mut(range) {
            slot.copy_from_slice(&shoff.to_le_bytes());
        }
        let found = detect_bytes(&file);
        assert!(
            found
                .iter()
                .any(|d| d.name == "curl" && d.version == "7.88.1-10"),
            "{found:?}"
        );
    }

    #[test]
    fn go_mod_text_yields_the_requirements() {
        let text = "module example.com/app\n\ngo 1.22\n\nrequire (\n\tgithub.com/x/y v1.2.3\n\tgolang.org/x/crypto v0.17.0 // indirect\n)\n";
        let found = go_mod_packages(text);
        let names: Vec<&str> = found.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, ["github.com/x/y", "golang.org/x/crypto"]);
        assert_eq!(found[0].version, "v1.2.3");
    }

    #[test]
    fn go_buildinfo_blob_is_parsed() {
        // Build the v2 blob: magic, ptr size, flags, varint offsets into a
        // string table that follows the header.
        let text = b"module example.com/app\n\ngo 1.22\n\nrequire example.com/dep v1.2.3\n";
        let mut blob: Vec<u8> = Vec::new();
        blob.extend_from_slice(GO_MAGIC);
        blob.push(8); // pointer size
        blob.push(2); // flags: v2
        let varint = |mut v: u64, out: &mut Vec<u8>| {
            loop {
                let b = (v & 0x7f) as u8;
                v >>= 7;
                if v == 0 {
                    out.push(b);
                    break;
                }
                out.push(b | 0x80);
            }
        };
        let gover = b"go1.22.0";
        // Offsets are relative to the start of the blob: the version string
        // and the mod text sit right after these four varints.
        let strings_at = blob.len() as u64 + 4;
        varint(strings_at, &mut blob);
        varint(gover.len() as u64, &mut blob);
        varint(strings_at + gover.len() as u64, &mut blob);
        varint(text.len() as u64, &mut blob);
        blob.extend_from_slice(gover);
        blob.extend_from_slice(text);
        let found = parse_go_buildinfo(&blob);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].name, "example.com/dep");
        assert_eq!(found[0].version, "v1.2.3");
    }

    #[test]
    fn cargo_auditable_rows_are_parsed() {
        let marker = AUDITABLE_MAGIC;
        let rows = br#"[["serde","1.0.203",["serde_derive"]],["libc","0.2.153",[]]]"#;
        let mut blob: Vec<u8> = Vec::new();
        blob.extend_from_slice(marker);
        blob.extend_from_slice(rows);
        let found = parse_cargo_auditable(&blob);
        assert_eq!(
            found,
            vec![
                Detected {
                    name: "serde".to_owned(),
                    version: "1.0.203".to_owned(),
                    origin: Origin::CargoAuditable,
                    pkg_type: None
                },
                Detected {
                    name: "libc".to_owned(),
                    version: "0.2.153".to_owned(),
                    origin: Origin::CargoAuditable,
                    pkg_type: None
                }
            ]
        );
    }

    #[test]
    fn mutated_and_truncated_fixtures_never_panic() {
        // Deterministic xorshift so a failure is reproducible.
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let seeds: [&[u8]; 3] = [
            include_bytes!("../../../tests/fixtures/elf/with-package-note.elf"),
            include_bytes!("../../../tests/fixtures/elf/go-app.bin"),
            include_bytes!("../../../tests/fixtures/elf/rust-app.bin"),
        ];
        for seed in seeds {
            for _ in 0..3000 {
                let mut bytes = seed.to_vec();
                let flips = 1 + next() % 8;
                for _ in 0..flips {
                    let at = usize::try_from(next() % bytes.len() as u64).unwrap_or(0);
                    if let Some(b) = bytes.get_mut(at) {
                        *b = u8::try_from(next() % 256).unwrap_or(0);
                    }
                }
                if next() % 3 == 0 {
                    let keep = usize::try_from(next() % bytes.len() as u64).unwrap_or(0);
                    bytes.truncate(keep);
                }
                // Must return, whatever it finds.
                let _ = detect_bytes(&bytes);
            }
        }
    }

    #[test]
    fn garbage_is_a_miss_not_a_crash() {
        assert!(detect_bytes(b"not an elf at all").is_empty());
        let mut elf = b"\x7fELF\x02\x01\x01".to_vec();
        elf.extend_from_slice(&[0xffu8; 128]);
        assert!(detect_bytes(&elf).is_empty());
        assert!(parse_package_note(b"{").is_none());
        assert!(go_mod_packages("module only").is_empty());
        assert!(parse_cargo_auditable(b"AUDITABLE_V0D not json").is_empty());
    }
}
