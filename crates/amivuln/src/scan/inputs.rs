// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! The inputs a run reads besides the host: inventories, SBOMs and containers.

use super::{
    Cli, Ecosystem, PackageRef, Path, PathBuf, Scope, SystemRunner, Unresolved, from_name_version,
    resolve_all,
};

/// Largest inventory file accepted.
pub(super) const MAX_INVENTORY_BYTES: u64 = 8 * 1024 * 1024;

/// Reads `--packages-from FILE`: one `name@version` per line, `#` comments and
/// blank lines ignored. Lets a pipeline check a package list exported from
/// another host, for example `rpm -qa --qf '%{NAME}@%{EPOCH}:%{VERSION}-%{RELEASE}\n'`.
pub(super) fn read_inventory(
    path: &Path,
    eco: Ecosystem,
) -> Result<Vec<(String, PackageRef)>, String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if meta.len() > MAX_INVENTORY_BYTES {
        return Err(format!(
            "{} is larger than {MAX_INVENTORY_BYTES} bytes",
            path.display()
        ));
    }
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, version) = line.rsplit_once('@').ok_or_else(|| {
            format!(
                "{}:{}: expected name@version, got {:?}",
                path.display(),
                i + 1,
                line.chars().take(60).collect::<String>()
            )
        })?;
        // The epoch of an rpm list may read `(none):1.0-1`.
        let version = version.strip_prefix("(none):").unwrap_or(version);
        let pkg = from_name_version(eco, name, version)
            .map_err(|e| format!("{}:{}: {e}", path.display(), i + 1))?;
        out.push((name.to_owned(), pkg));
    }
    Ok(out)
}

/// Deepest component nesting and most components read from an SBOM.
pub(super) const MAX_SBOM_DEPTH: usize = 8;

pub(super) const MAX_SBOM_COMPONENTS: usize = 200_000;

pub(super) fn collect_purls(
    components: &serde_json::Value,
    depth: usize,
    seen: &mut usize,
    purls: &mut std::collections::BTreeSet<String>,
    without: &mut usize,
) -> Result<(), String> {
    let Some(list) = components.as_array() else {
        return Ok(());
    };
    for c in list {
        *seen += 1;
        if *seen > MAX_SBOM_COMPONENTS {
            return Err(format!(
                "the SBOM has more than {MAX_SBOM_COMPONENTS} components"
            ));
        }
        match c.get("purl").and_then(serde_json::Value::as_str) {
            Some(p) => {
                purls.insert(p.to_owned());
            }
            None => *without += 1,
        }
        if depth < MAX_SBOM_DEPTH
            && let Some(inner) = c.get("components")
        {
            collect_purls(inner, depth + 1, seen, purls, without)?;
        }
    }
    Ok(())
}

/// Reads `--sbom FILE`, a `CycloneDX` JSON document. rpm, deb and alpm purls
/// become packages; every other component is reported as unresolved, one entry
/// per purl type, so nothing is dropped without a trace.
pub(super) fn read_sbom(path: &Path, eco: Ecosystem) -> Result<Scope, String> {
    use std::io::Read;
    let file = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut buf = Vec::new();
    file.take(MAX_SBOM_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if buf.len() as u64 > MAX_SBOM_BYTES {
        return Err(format!(
            "{} is larger than {MAX_SBOM_BYTES} bytes",
            path.display()
        ));
    }
    let doc: serde_json::Value = serde_json::from_slice(&buf)
        .map_err(|e| format!("{}: not valid JSON: {e}", path.display()))?;
    if doc.get("bomFormat").and_then(serde_json::Value::as_str) != Some("CycloneDX") {
        return Err(format!("{}: not a CycloneDX JSON document", path.display()));
    }
    let mut purls = std::collections::BTreeSet::new();
    let (mut seen, mut without) = (0, 0);
    if let Some(c) = doc.get("components") {
        collect_purls(c, 0, &mut seen, &mut purls, &mut without)?;
    }
    let mut packages = Vec::new();
    let mut skipped: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for purl in purls {
        let kind = purl
            .strip_prefix("pkg:")
            .and_then(|r| r.split(['/', '@']).next())
            .unwrap_or("invalid")
            .to_owned();
        if matches!(kind.as_str(), "rpm" | "deb" | "alpm") {
            let pkg = amivuln_resolve::from_purl(&purl, Some(eco))
                .map_err(|e| format!("{}: {purl}: {e}", path.display()))?;
            packages.push((purl, pkg));
        } else {
            *skipped.entry(format!("pkg:{kind}")).or_default() += 1;
        }
    }
    let mut unresolved: Vec<Unresolved> = skipped
        .into_iter()
        .map(|(kind, n)| Unresolved {
            input: format!("sbom:{kind}"),
            reason: format!("{n} component(s) are not OS packages, so no distro advisory applies"),
        })
        .collect();
    if without > 0 {
        unresolved.push(Unresolved {
            input: "sbom:no-purl".to_owned(),
            reason: format!("{without} component(s) have no purl"),
        });
    }
    Ok((packages, unresolved))
}

/// Largest SBOM accepted.
pub(super) const MAX_SBOM_BYTES: u64 = 64 * 1024 * 1024;

/// The packages a command works on: the host's installed packages for `--all`,
/// a `--packages-from` inventory, and any explicit targets.
pub(crate) fn resolve_scope(
    cli: &Cli,
    targets: &[String],
    all: bool,
    eco: Ecosystem,
    probe: bool,
) -> Result<Scope, String> {
    let (mut resolved, unresolved) = resolve_all(targets, all, eco, probe);
    let mut unresolved = unresolved;
    if let Some(path) = &cli.global.packages_from {
        resolved.extend(read_inventory(path, eco)?);
    }
    if let Some(path) = &cli.global.sbom {
        let (pkgs, skipped) = read_sbom(path, eco)?;
        resolved.extend(pkgs);
        unresolved.extend(skipped);
    }
    for container_id in &cli.global.container {
        match read_container(container_id) {
            Ok((container_eco, pkgs)) => {
                // The container's own os-release decides the ecosystem: the
                // host's --distro value is not reused and never overrides it.
                resolved.extend(pkgs.into_iter().map(|pkg| {
                    let label = format!("{container_id}:{pkg_name}", pkg_name = pkg.name);
                    (label, pkg)
                }));
                let _ = container_eco;
            }
            Err(e) => unresolved.push(Unresolved {
                input: format!("--container {container_id}"),
                reason: e.to_string(),
            }),
        }
    }
    Ok((resolved, unresolved))
}

/// Reads a container's installed packages: export, then the package database.
/// Returns the container's ecosystem, for the caller's report labels.
pub(super) fn read_container(
    container_id: &str,
) -> Result<(Ecosystem, Vec<PackageRef>), amivuln_resolve::ContainerError> {
    use amivuln_resolve::{container_packages, export_container};
    let runner = SystemRunner::default();
    let dir = private_scratch_dir()
        .map_err(|e| amivuln_resolve::ContainerError::Export(format!("scratch directory: {e}")))?;
    let result = (|| {
        let eco = export_container(&runner, container_id, &dir)?;
        let packages = container_packages(&runner, eco, &dir)?;
        Ok((eco, packages))
    })();
    // The export can be large; it never outlives the run.
    let _ = std::fs::remove_dir_all(&dir);
    result
}

/// A new directory only this user can enter. Creation fails when the name is
/// taken, so a directory another user prepared in the shared temp dir (with a
/// symlink waiting for the export) is never reused.
pub(super) fn private_scratch_dir() -> std::io::Result<PathBuf> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let dir =
        std::env::temp_dir().join(format!("amivuln-container-{}-{nanos}", std::process::id()));
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(&dir)?;
    Ok(dir)
}
