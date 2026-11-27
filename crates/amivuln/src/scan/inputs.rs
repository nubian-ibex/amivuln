// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! The inputs a run reads besides the host: inventories, SBOMs and containers.

use amivuln_core::TargetReport;
use amivuln_core::i18n::tr_args;

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
        return Err(tr_args(
            "file.too_large",
            &[("path", &path.display()), ("limit", &MAX_INVENTORY_BYTES)],
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

/// What a component states beside its purl.
#[derive(Default)]
pub(super) struct Stated {
    /// The source package's name and, when given, its version-release.
    source: Option<(String, Option<String>)>,
    /// The modularity label of the rpm.
    module: Option<String>,
}

/// The purls of an SBOM, each with what a component states beside it.
pub(super) type Purls = std::collections::BTreeMap<String, Stated>;

/// The value of a component's property, the first of the names found.
fn property<'a>(component: &'a serde_json::Value, names: &[&str]) -> Option<&'a str> {
    let properties = component.get("properties")?.as_array()?;
    names.iter().find_map(|wanted| {
        properties.iter().find_map(|p| {
            (p.get("name")?.as_str()? == *wanted).then(|| p.get("value")?.as_str())?
        })
    })
}

/// The modularity label Syft or Trivy states for an rpm.
fn module_label(component: &serde_json::Value) -> Option<String> {
    property(
        component,
        &[
            "syft:metadata:modularityLabel",
            "aquasecurity:trivy:Modularitylabel",
        ],
    )
    .map(str::to_owned)
}

/// The source Trivy states in a component's properties: its name and, when
/// both parts are there, its version-release.
fn trivy_source(component: &serde_json::Value) -> Option<(String, Option<String>)> {
    let trivy = |name: &str| property(component, &[&format!("aquasecurity:trivy:{name}")]);
    let release = trivy("SrcVersion")
        .zip(trivy("SrcRelease"))
        .map(|(version, release)| format!("{version}-{release}"));
    Some((trivy("SrcName")?.to_owned(), release))
}

/// Syft names the source of a deb or apk package only when it differs from the
/// binary: once the document names any, a package without one is its own.
fn fill_omitted_sources(packages: &mut [(String, PackageRef)]) {
    let omits = |eco| {
        matches!(
            eco,
            Ecosystem::Debian(_) | Ecosystem::Ubuntu(_) | Ecosystem::Alpine(_)
        )
    };
    if !packages
        .iter()
        .any(|(_, p)| omits(p.ecosystem) && p.source_name.is_some())
    {
        return;
    }
    for (_, p) in packages.iter_mut().filter(|(_, p)| omits(p.ecosystem)) {
        if p.source_name.is_none() {
            p.source_name = Some(p.name.clone());
        }
    }
}

/// Deepest component nesting and most components read from an SBOM.
pub(super) const MAX_SBOM_DEPTH: usize = 8;

pub(super) const MAX_SBOM_COMPONENTS: usize = 200_000;

pub(super) fn collect_purls(
    components: &serde_json::Value,
    depth: usize,
    seen: &mut usize,
    purls: &mut Purls,
    without: &mut usize,
) -> Result<(), String> {
    let Some(list) = components.as_array() else {
        return Ok(());
    };
    for c in list {
        *seen += 1;
        if *seen > MAX_SBOM_COMPONENTS {
            return Err(tr_args("sbom.too_many", &[("limit", &MAX_SBOM_COMPONENTS)]));
        }
        match c.get("purl").and_then(serde_json::Value::as_str) {
            Some(p) => {
                let stated = purls.entry(p.to_owned()).or_default();
                if stated.source.is_none() {
                    stated.source = trivy_source(c);
                }
                if stated.module.is_none() {
                    stated.module = module_label(c);
                }
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

/// Reads `--sbom FILE`, a `CycloneDX` JSON document. rpm, deb, apk and alpm purls
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
        return Err(tr_args(
            "file.too_large",
            &[("path", &path.display()), ("limit", &MAX_SBOM_BYTES)],
        ));
    }
    let doc: serde_json::Value = serde_json::from_slice(&buf)
        .map_err(|e| tr_args("sbom.not_json", &[("path", &path.display()), ("error", &e)]))?;
    if doc.get("bomFormat").and_then(serde_json::Value::as_str) != Some("CycloneDX") {
        return Err(tr_args("sbom.not_cyclonedx", &[("path", &path.display())]));
    }
    let mut purls = Purls::new();
    let (mut seen, mut without) = (0, 0);
    if let Some(c) = doc.get("components") {
        collect_purls(c, 0, &mut seen, &mut purls, &mut without)?;
    }
    let mut packages = Vec::new();
    let mut skipped: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for (purl, stated) in purls {
        let kind = purl
            .strip_prefix("pkg:")
            .and_then(|r| r.split(['/', '@']).next())
            .unwrap_or("invalid")
            .to_owned();
        if matches!(kind.as_str(), "rpm" | "deb" | "apk" | "alpm") {
            let mut pkg = amivuln_resolve::from_purl(&purl, Some(eco))
                .map_err(|e| format!("{}: {purl}: {e}", path.display()))?;
            if pkg.source_name.is_none()
                && let Some((name, release)) = stated.source
            {
                amivuln_resolve::set_source(&mut pkg, &name, release.as_deref());
            }
            if pkg.module_stream.is_none()
                && let Some(label) = stated.module
            {
                amivuln_resolve::set_module(&mut pkg, &label);
            }
            // The signing keys rpm lists among its packages carry no software.
            if kind == "rpm" && pkg.name == "gpg-pubkey" {
                continue;
            }
            packages.push((purl, pkg));
        } else {
            *skipped.entry(format!("pkg:{kind}")).or_default() += 1;
        }
    }
    fill_omitted_sources(&mut packages);
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
    // A list or a document that names no package checks nothing; saying so
    // keeps a failed export from reading as clean.
    let nothing = |input: &str| Unresolved {
        input: input.to_owned(),
        reason: "it names no package, so nothing was checked".to_owned(),
    };
    if let Some(path) = &cli.global.packages_from {
        let packages = read_inventory(path, eco)?;
        if packages.is_empty() {
            unresolved.push(nothing("--packages-from"));
        }
        resolved.extend(packages);
    }
    if let Some(path) = &cli.global.sbom {
        let (pkgs, skipped) = read_sbom(path, eco)?;
        if pkgs.is_empty() && skipped.is_empty() {
            unresolved.push(nothing("--sbom"));
        }
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
/// tried: the image of the release the kernel reports (`uname -r`), below
/// `root` (`/` on a host).
fn kernel_images(root: &std::path::Path, release: &str) -> Vec<PathBuf> {
    let below = |path: String| root.join(path.trim_start_matches('/'));
    vec![
        below(format!("/usr/lib/modules/{release}/vmlinuz")),
        below(format!("/boot/vmlinuz-{release}")),
        // Alpine names the image after the flavor: `6.6.52-0-lts` is `lts`.
        below(format!(
            "/boot/vmlinuz-{}",
            release.rsplit('-').next().unwrap_or(release)
        )),
        below(format!("/lib/modules/{release}/vmlinuz")),
    ]
}

/// The first kernel image of `release` that exists below `root`, as the path a
/// package database records it (without `root`).
fn find_kernel_image(root: &std::path::Path, release: &str) -> Option<String> {
    kernel_images(root, release)
        .into_iter()
        .find(|p| p.is_file())
        .and_then(|p| {
            p.strip_prefix(root)
                .ok()
                .map(|rel| format!("/{}", rel.display()))
        })
}

/// The package that owns the running kernel's image, with the release the
/// kernel reports. Several kernels are installed side by side on most hosts,
/// so a package name cannot say which one boots; the release can.
pub(crate) fn running_kernel_package(eco: Ecosystem) -> Result<(String, PackageRef), String> {
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map_err(|e| format!("cannot read the kernel release: {e}"))?
        .trim()
        .to_owned();
    if !is_plain_release(&release) {
        return Err("the kernel release is not a plain version string".to_owned());
    }
    let image = find_kernel_image(std::path::Path::new("/"), &release)
        .ok_or_else(|| format!("no kernel image for the running release {release} was found"))?;
    let (found, missed) = resolve_all(&[image], false, eco, false);
    if let Some(u) = missed.into_iter().next() {
        return Err(u.reason);
    }
    found
        .into_iter()
        .next()
        .map(|(_, pkg)| (release.clone(), pkg))
        .ok_or_else(|| format!("no package owns the kernel image of release {release}"))
}

/// Adds the package that owns the running kernel's image.
fn read_kernel(
    eco: Ecosystem,
    resolved: &mut Vec<(String, PackageRef)>,
    unresolved: &mut Vec<Unresolved>,
) {
    match running_kernel_package(eco) {
        Ok((release, pkg)) => resolved.push((format!("--kernel {release}"), pkg)),
        Err(reason) => unresolved.push(Unresolved {
            input: "--kernel".to_owned(),
            reason,
        }),
    }
}

/// Marks the report of the package that owns the running kernel. It is best
/// effort: when the kernel cannot be identified nothing is marked, and the
/// full report reads as before.
pub(crate) fn mark_running_kernel(targets: &mut [TargetReport], eco: Ecosystem) {
    if let Ok((_, kernel)) = running_kernel_package(eco) {
        mark_package(targets, &kernel);
    }
}

/// Marks the reports of exactly `kernel`: the same name, version and
/// architecture, in the same ecosystem. The other installed kernels are not.
fn mark_package(targets: &mut [TargetReport], kernel: &PackageRef) {
    for t in targets {
        let p = &t.package;
        if p.name == kernel.name
            && p.version == kernel.version
            && p.arch == kernel.arch
            && p.ecosystem == kernel.ecosystem
        {
            t.running_kernel = true;
        }
    }
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
    use amivuln_core::Provenance;

    fn kernel(version: &str) -> PackageRef {
        PackageRef {
            module_stream: None,
            source_vr: None,
            name: "kernel-core".to_owned(),
            source_name: None,
            version: amivuln_core::Version::Rpm(version.parse().unwrap()),
            arch: Some("x86_64".to_owned()),
            upstream: None,
            ecosystem: Ecosystem::Fedora(44),
            provenance: Provenance::PackageDb,
            slot: None,
        }
    }

    fn report(pkg: PackageRef) -> TargetReport {
        TargetReport {
            input: pkg.name.clone(),
            package: pkg,
            findings: Vec::new(),
            resolved: Vec::new(),
            running_kernel: false,
        }
    }

    #[test]
    fn an_sbom_apk_component_is_an_os_package() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("bom.json");
        let doc = serde_json::json!({"bomFormat": "CycloneDX", "components": [
            {"purl": "pkg:apk/alpine/zlib@1.3.1-r2"},
        ]});
        std::fs::write(&file, doc.to_string()).unwrap();
        let (packages, unresolved) = read_sbom(&file, Ecosystem::Alpine(322)).unwrap();
        assert!(unresolved.is_empty(), "{unresolved:?}");
        assert_eq!(packages[0].1.name, "zlib");
    }

    fn sbom(components: &serde_json::Value, eco: Ecosystem) -> Vec<(String, Option<String>)> {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("bom.json");
        let doc = serde_json::json!({"bomFormat": "CycloneDX", "components": components});
        std::fs::write(&file, doc.to_string()).unwrap();
        let (packages, unresolved) = read_sbom(&file, eco).unwrap();
        assert!(unresolved.is_empty(), "{unresolved:?}");
        packages
            .into_iter()
            .map(|(_, p)| (p.name, p.source_name))
            .collect()
    }

    fn pair(name: &str, source: Option<&str>) -> (String, Option<String>) {
        (name.to_owned(), source.map(str::to_owned))
    }

    #[test]
    fn a_package_without_a_source_is_its_own_once_the_sbom_names_any() {
        // Syft names the source of an apk or deb package only when it differs.
        let named = serde_json::json!([
            {"purl": "pkg:apk/alpine/libssl3@3.5.0-r0?upstream=openssl"},
            {"purl": "pkg:apk/alpine/zlib@1.3.1-r2"},
        ]);
        assert_eq!(
            sbom(&named, Ecosystem::Alpine(322)),
            [pair("libssl3", Some("openssl")), pair("zlib", Some("zlib"))]
        );
        let silent = serde_json::json!([{"purl": "pkg:apk/alpine/zlib@1.3.1-r2"}]);
        assert_eq!(sbom(&silent, Ecosystem::Alpine(322)), [pair("zlib", None)]);
    }

    #[test]
    fn the_module_stream_an_sbom_states_is_read() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("bom.json");
        // Syft and Trivy each have a property of their own.
        let doc = serde_json::json!({"bomFormat": "CycloneDX", "components": [
            {"purl": "pkg:rpm/redhat/nodejs@22.1-2.module%2Bel8.10.0%2B1%2Ba",
             "properties": [{"name": "syft:metadata:modularityLabel",
                             "value": "nodejs:22:8100020261104150431:6d880403"}]},
            {"purl": "pkg:rpm/redhat/npm@10.1-1.22.1.2.module%2Bel8.10.0%2B1%2Ba",
             "properties": [{"name": "aquasecurity:trivy:Modularitylabel",
                             "value": "nodejs:22:8100020261104150431:6d880403"}]},
        ]});
        std::fs::write(&file, doc.to_string()).unwrap();
        let (packages, _) = read_sbom(&file, Ecosystem::Rhel(8)).unwrap();
        let streams: Vec<_> = packages
            .iter()
            .map(|(_, p)| p.module_stream.as_deref())
            .collect();
        assert_eq!(streams, [Some("nodejs:22"), Some("nodejs:22")]);
    }

    #[test]
    fn the_signing_keys_of_rpm_are_not_packages() {
        let components = serde_json::json!([
            {"purl": "pkg:rpm/opensuse/gpg-pubkey@39db7c82-66c5d91a"},
            {"purl": "pkg:rpm/opensuse/zlib@1.2.13-150500.2.3?upstream=zlib-1.2.13-150500.2.3.src.rpm"},
        ]);
        assert_eq!(
            sbom(&components, Ecosystem::Opensuse(1506)),
            [pair("zlib", Some("zlib"))]
        );
    }

    #[test]
    fn the_source_trivy_states_in_a_property_is_read() {
        let components = serde_json::json!([{
            "purl": "pkg:rpm/rocky/device-mapper@1.02.181-15.el8?epoch=8",
            "properties": [
                {"name": "aquasecurity:trivy:SrcName", "value": "lvm2"},
                {"name": "aquasecurity:trivy:SrcVersion", "value": "2.03.14"},
                {"name": "aquasecurity:trivy:SrcRelease", "value": "15.el8"},
            ]
        }, {
            "purl": "pkg:rpm/rocky/zlib@1.2.11-25.el8"
        }]);
        assert_eq!(
            sbom(&components, Ecosystem::Rocky(8)),
            // An rpm without a source stays unknown: Trivy always states it.
            [pair("device-mapper", Some("lvm2")), pair("zlib", None)]
        );
    }

    #[test]
    fn only_the_running_kernel_is_marked_among_those_installed() {
        let mut targets = vec![
            report(kernel("0:7.2.15-200.fc44")),
            report(kernel("0:7.3.4-200.fc44")),
            report(PackageRef {
                name: "bash".to_owned(),
                ..kernel("0:7.3.4-200.fc44")
            }),
        ];
        mark_package(&mut targets, &kernel("0:7.3.4-200.fc44"));
        let marked: Vec<bool> = targets.iter().map(|t| t.running_kernel).collect();
        assert_eq!(marked, [false, true, false]);
    }

    #[test]
    fn the_images_of_a_release_are_named_for_each_distribution_layout() {
        let root = std::path::Path::new("/");
        let images = kernel_images(root, "6.6.52-0-lts");
        assert_eq!(
            images[0],
            PathBuf::from("/usr/lib/modules/6.6.52-0-lts/vmlinuz")
        );
        assert_eq!(images[1], PathBuf::from("/boot/vmlinuz-6.6.52-0-lts"));
        // Alpine's image is named after the flavor.
        assert_eq!(images[2], PathBuf::from("/boot/vmlinuz-lts"));
        assert_eq!(
            kernel_images(root, "7.2.15-200.fc44.x86_64")[0],
            PathBuf::from("/usr/lib/modules/7.2.15-200.fc44.x86_64/vmlinuz")
        );
    }

    #[test]
    fn the_image_of_the_running_release_is_found_and_the_others_are_not() {
        let dir = tempfile::tempdir().unwrap();
        for path in [
            "usr/lib/modules/7.2.15-200.fc44.x86_64/vmlinuz",
            "usr/lib/modules/7.2.12-200.fc44.x86_64/vmlinuz",
            "boot/vmlinuz-6.6.52-0-lts",
        ] {
            let file = dir.path().join(path);
            std::fs::create_dir_all(file.parent().unwrap()).unwrap();
            std::fs::write(file, b"image").unwrap();
        }
        // Several kernels installed: the release decides, and the path comes
        // back as a package database records it.
        assert_eq!(
            find_kernel_image(dir.path(), "7.2.15-200.fc44.x86_64").as_deref(),
            Some("/usr/lib/modules/7.2.15-200.fc44.x86_64/vmlinuz")
        );
        assert_eq!(
            find_kernel_image(dir.path(), "6.6.52-0-lts").as_deref(),
            Some("/boot/vmlinuz-6.6.52-0-lts")
        );
        // A release with no image (a container shares the host's kernel).
        assert_eq!(find_kernel_image(dir.path(), "9.9.9-none"), None);
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
