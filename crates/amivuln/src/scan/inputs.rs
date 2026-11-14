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
    if cli.global.extras.kernel {
        read_kernel(eco, &mut resolved, &mut unresolved);
    }
    if cli.global.extras.flatpak {
        read_flatpak(&mut resolved, &mut unresolved);
    }
    Ok((resolved, unresolved))
}

/// True for a kernel release as the kernel writes it. It becomes part of a
/// path, so only what a release is made of is accepted.
fn is_plain_release(release: &str) -> bool {
    !release.is_empty()
        && release.len() <= 128
        && release
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-'))
}

/// The files whose owner is the kernel that is running, in the order they are
/// tried: the image of the release the kernel reports (`uname -r`).
fn kernel_images(release: &str) -> [String; 4] {
    [
        format!("/usr/lib/modules/{release}/vmlinuz"),
        format!("/boot/vmlinuz-{release}"),
        // Alpine names the image after the flavor: `6.6.52-0-lts` is `lts`.
        format!(
            "/boot/vmlinuz-{}",
            release.rsplit('-').next().unwrap_or(release)
        ),
        format!("/lib/modules/{release}/vmlinuz"),
    ]
}

/// Adds the package that owns the running kernel's image. Several kernels are
/// installed side by side on most hosts, so a package name cannot say which
/// one boots; the release the kernel reports can.
fn read_kernel(
    eco: Ecosystem,
    resolved: &mut Vec<(String, PackageRef)>,
    unresolved: &mut Vec<Unresolved>,
) {
    let fail = |reason: String| Unresolved {
        input: "--kernel".to_owned(),
        reason,
    };
    let release = match std::fs::read_to_string("/proc/sys/kernel/osrelease") {
        Ok(text) => text.trim().to_owned(),
        Err(e) => {
            unresolved.push(fail(format!("cannot read the kernel release: {e}")));
            return;
        }
    };
    if !is_plain_release(&release) {
        unresolved.push(fail(
            "the kernel release is not a plain version string".to_owned(),
        ));
        return;
    }
    let Some(image) = kernel_images(&release)
        .into_iter()
        .find(|p| std::path::Path::new(p).is_file())
    else {
        unresolved.push(fail(format!(
            "no kernel image for the running release {release} was found"
        )));
        return;
    };
    let (found, missed) = resolve_all(&[image], false, eco, false);
    unresolved.extend(missed.into_iter().map(|u| fail(u.reason)));
    resolved.extend(
        found
            .into_iter()
            .map(|(_, pkg)| (format!("--kernel {release}"), pkg)),
    );
}

/// Adds the components of the installed Flatpak runtimes. What cannot be read
/// is listed as unresolved: extensions with no manifest in one entry, a
/// runtime with components that name no version in one entry each.
fn read_flatpak(resolved: &mut Vec<(String, PackageRef)>, unresolved: &mut Vec<Unresolved>) {
    let dirs = amivuln_resolve::installations(|name| std::env::var(name).ok());
    let found = match amivuln_resolve::read_runtimes(&dirs) {
        Ok(found) => found,
        Err(e) => {
            unresolved.push(Unresolved {
                input: "--flatpak".to_owned(),
                reason: e.to_string(),
            });
            return;
        }
    };
    if found.runtimes.is_empty() {
        unresolved.push(Unresolved {
            input: "--flatpak".to_owned(),
            reason: "no Flatpak runtime is installed".to_owned(),
        });
    }
    let (bare, listed): (Vec<_>, Vec<_>) = found
        .runtimes
        .iter()
        .partition(|r| r.unchecked.iter().any(|u| u == "no manifest.json"));
    if !bare.is_empty() {
        let names: Vec<&str> = bare.iter().take(3).map(|r| r.id.as_str()).collect();
        unresolved.push(Unresolved {
            input: "--flatpak".to_owned(),
            reason: format!(
                "{} runtimes have no manifest.json, so their components are not known ({}{})",
                bare.len(),
                names.join(", "),
                if bare.len() > 3 { ", ..." } else { "" }
            ),
        });
    }
    for runtime in listed.iter().filter(|r| !r.unchecked.is_empty()) {
        unresolved.push(Unresolved {
            input: format!("--flatpak {}", runtime.id),
            reason: format!(
                "{} components name no upstream version and are not checked",
                runtime.unchecked.len()
            ),
        });
    }
    resolved.extend(found.packages.into_iter().map(|p| (p.name.clone(), p)));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_images_of_a_release_are_named_for_each_distribution_layout() {
        let images = kernel_images("6.6.52-0-lts");
        assert_eq!(images[0], "/usr/lib/modules/6.6.52-0-lts/vmlinuz");
        assert_eq!(images[1], "/boot/vmlinuz-6.6.52-0-lts");
        // Alpine's image is named after the flavor.
        assert_eq!(images[2], "/boot/vmlinuz-lts");
        assert_eq!(
            kernel_images("7.2.15-200.fc44.x86_64")[0],
            "/usr/lib/modules/7.2.15-200.fc44.x86_64/vmlinuz"
        );
    }

    #[test]
    fn only_a_plain_release_may_become_part_of_a_path() {
        for ok in [
            "7.2.15-200.fc44.x86_64",
            "6.1.0-18-amd64",
            "6.6.52-0-lts",
            "5.15.0+custom_1",
        ] {
            assert!(is_plain_release(ok), "{ok}");
        }
        for bad in [
            "",
            "../etc",
            "6.1 0",
            "6.1\n",
            "a/b",
            &"9".repeat(200),
            "6.1;rm",
        ] {
            assert!(!is_plain_release(bad), "{bad:?}");
        }
    }
}
