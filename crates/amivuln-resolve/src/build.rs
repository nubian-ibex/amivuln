// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Package references built from user input, without looking at the host.

use amivuln_core::{Ecosystem, PackageRef, Provenance, Version};
use amivuln_version::DebVersion;

use crate::ResolveError;

fn bad(msg: impl Into<String>) -> ResolveError {
    ResolveError::Parse(msg.into())
}

fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-' | b'@'))
}

fn valid_version(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-' | b'~' | b'^' | b':')
        })
}

/// Debian and Ubuntu versions allow a few more characters and may not start
/// with a colon: dpkg rejects that and a version starting with `:` cannot be
/// compared.
fn valid_deb_version(s: &str) -> bool {
    valid_version(s) && !s.starts_with(':')
}

fn make(ecosystem: Ecosystem, name: &str, version: &str, arch: Option<String>) -> PackageRef {
    let parsed = match ecosystem {
        Ecosystem::Fedora(_)
        | Ecosystem::Rocky(_)
        | Ecosystem::Alma(_)
        | Ecosystem::Rhel(_)
        | Ecosystem::Opensuse(_) => {
            Version::Rpm(version.parse().unwrap_or_else(|never| match never {}))
        }
        Ecosystem::Arch => Version::Pacman(version.parse().unwrap_or_else(|never| match never {})),
        Ecosystem::Debian(_) | Ecosystem::Ubuntu(_) => Version::Deb(
            version
                .parse::<DebVersion>()
                .unwrap_or_else(|never| match never {}),
        ),
        // Language packages are built by `language_package`, which validates
        // the version; this arm only keeps the match total.
        Ecosystem::Alpine(_) => {
            Version::Apk(version.parse().unwrap_or_else(|never| match never {}))
        }
        Ecosystem::Gentoo => {
            Version::Gentoo(version.parse().unwrap_or_else(|never| match never {}))
        }
        Ecosystem::Flatpak => {
            Version::Upstream(version.parse().unwrap_or_else(|never| match never {}))
        }
        Ecosystem::Go | Ecosystem::Crates => {
            Version::Semver(amivuln_version::SemverVersion::default())
        }
    };
    PackageRef {
        module_stream: None,
        source_vr: None,
        ecosystem,
        name: name.to_owned(),
        source_name: None,
        version: parsed,
        arch,
        slot: None,
        upstream: None,
        provenance: Provenance::UserInput,
    }
}

/// Records the source package an input names for `package`, and its
/// version-release when it has one of its own. A value no package manager
/// would accept is left out, so the source stays unknown.
pub fn set_source(package: &mut PackageRef, name: &str, release: Option<&str>) {
    if !valid_name(name) || name.contains('@') {
        return;
    }
    package.source_name = Some(name.to_owned());
    if is_rpm(package.ecosystem) {
        let binary = package.version.to_string();
        let binary = binary.split_once(':').map_or(binary.as_str(), |(_, vr)| vr);
        package.source_vr = release
            .filter(|vr| *vr != binary && valid_version(vr))
            .map(str::to_owned);
    }
}

/// Records the module stream a modularity label (`name:stream:version:context`)
/// names, on a RHEL, Rocky Linux or `AlmaLinux` package. A label in another
/// form is left out, so the stream stays unknown.
pub fn set_module(package: &mut PackageRef, label: &str) {
    if matches!(
        package.ecosystem,
        Ecosystem::Rhel(_) | Ecosystem::Rocky(_) | Ecosystem::Alma(_)
    ) {
        package.module_stream = module_stream(label);
    }
}

/// `nodejs:22:8100020261104150431:6d880403` gives `nodejs:22`.
pub(crate) fn module_stream(label: &str) -> Option<String> {
    let mut parts = label.split(':');
    let (name, stream) = (parts.next()?, parts.next()?);
    (valid_name(name) && valid_name(stream)).then(|| format!("{name}:{stream}"))
}

/// The source a purl's `upstream` qualifier names, as Syft writes it: the name
/// (`name@version` for some deb packages) or the source rpm's file name.
fn set_upstream_source(package: &mut PackageRef, upstream: &str) {
    match package.ecosystem {
        Ecosystem::Debian(_) | Ecosystem::Ubuntu(_) => {
            let name = upstream.split_once('@').map_or(upstream, |(name, _)| name);
            set_source(package, name, None);
        }
        Ecosystem::Alpine(_) => set_source(package, upstream, None),
        eco if is_rpm(eco) => {
            if upstream.strip_suffix(".rpm").is_none() {
                set_source(package, upstream, None);
            } else if let Some(name) = crate::rpm::source_name(upstream) {
                let release = crate::rpm::source_release(upstream);
                set_source(package, &name, release.as_deref());
            }
        }
        _ => {}
    }
}

/// The `--distro` value that names an ecosystem, for an error message.
fn distro_flag(e: Ecosystem) -> String {
    match e {
        Ecosystem::Fedora(v) => format!("fedora:{v}"),
        Ecosystem::Arch => "arch".to_owned(),
        Ecosystem::Debian(v) => format!("debian:{v}"),
        Ecosystem::Ubuntu(v) => {
            format!("ubuntu:{}.{:02}", v / 100, v % 100)
        }
        Ecosystem::Rocky(v) => format!("rocky:{v}"),
        Ecosystem::Alma(v) => format!("alma:{v}"),
        Ecosystem::Rhel(v) => format!("rhel:{}", Ecosystem::rhel_version(v)),
        Ecosystem::Alpine(v) => format!("alpine:{}.{}", v / 100, v % 100),
        Ecosystem::Gentoo => "gentoo".to_owned(),
        Ecosystem::Flatpak => "a Flatpak runtime".to_owned(),
        Ecosystem::Opensuse(0) => "opensuse:tumbleweed".to_owned(),
        Ecosystem::Opensuse(v) => format!("opensuse:{}.{}", v / 100, v % 100),
        Ecosystem::Go | Ecosystem::Crates => "a language ecosystem".to_owned(),
    }
}

/// Whether a purl of the ecosystem carries its epoch as a qualifier.
fn is_rpm(ecosystem: Ecosystem) -> bool {
    matches!(
        ecosystem,
        Ecosystem::Fedora(_)
            | Ecosystem::Rocky(_)
            | Ecosystem::Alma(_)
            | Ecosystem::Rhel(_)
            | Ecosystem::Opensuse(_)
    )
}

/// A Gentoo package as users write it: `category/name`, optionally followed by
/// `:slot` (`dev-lang/php:8.2`). Returns the name and the slot.
fn gentoo_name(text: &str) -> Result<(&str, Option<&str>), ResolveError> {
    let (name, slot) = match text.split_once(':') {
        Some((name, slot)) => (name, Some(slot)),
        None => (text, None),
    };
    let well_formed = name
        .split_once('/')
        .is_some_and(|(category, package)| valid_name(category) && valid_name(package))
        && slot.is_none_or(|s| valid_name(s) && !s.contains('@'));
    if !well_formed || name.contains('@') || name.matches('/').count() != 1 {
        return Err(bad(format!(
            "invalid Gentoo package {text:?}; use category/name or category/name:slot"
        )));
    }
    Ok((name, slot))
}

/// Builds a package from `name@version` for the given ecosystem.
///
/// # Errors
///
/// Fails when the name or version contains characters no package manager
/// would accept.
pub fn from_name_version(
    ecosystem: Ecosystem,
    name: &str,
    version: &str,
) -> Result<PackageRef, ResolveError> {
    let (name, slot) = if ecosystem == Ecosystem::Gentoo {
        gentoo_name(name)?
    } else {
        (name, None)
    };
    if ecosystem != Ecosystem::Gentoo && (!valid_name(name) || name.contains('@')) {
        return Err(bad(format!("invalid package name {name:?}")));
    }
    let ok = match ecosystem {
        Ecosystem::Debian(_) | Ecosystem::Ubuntu(_) => valid_deb_version(version),
        Ecosystem::Gentoo => amivuln_version::GentooVersion::is_valid(version),
        _ => valid_version(version),
    };
    if !ok {
        return Err(bad(format!("invalid version {version:?}")));
    }
    let mut package = make(ecosystem, name, version, None);
    package.slot = slot.map(str::to_owned);
    Ok(package)
}

fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        if b == b'%' {
            let hex = s.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(b);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Builds a package from a purl such as
/// `pkg:rpm/fedora/nginx@1.26.2-1.fc41?arch=x86_64&epoch=1` or
/// `pkg:alpm/arch/openssl@3.5.1-1`.
///
/// `expect` is the ecosystem the caller resolved on `--distro`; its release
/// fills in the purl, and a namespace that disagrees with it is an error.
///
/// # Errors
///
/// Fails on unsupported types or namespaces, a missing version, or a Fedora
/// purl when no release is known.
pub fn from_purl(purl: &str, expect: Option<Ecosystem>) -> Result<PackageRef, ResolveError> {
    let rest = purl
        .strip_prefix("pkg:")
        .ok_or_else(|| bad("a purl must start with pkg:"))?;
    let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
    let path = path.split_once('#').map_or(path, |(p, _)| p);
    let mut parts = path.splitn(3, '/');
    let (kind, namespace, name_version) = (
        parts.next().unwrap_or(""),
        parts.next().unwrap_or(""),
        parts.next().unwrap_or(""),
    );
    // The caller's ecosystem decides: its release fills in the purl, and a
    // namespace that disagrees is an error, never a silent reinterpretation.
    let ecosystem = match expect {
        Some(Ecosystem::Fedora(v)) if (kind, namespace) == ("rpm", "fedora") => {
            Ecosystem::Fedora(v)
        }
        Some(e @ Ecosystem::Arch) if (kind, namespace) == ("alpm", "arch") => e,
        Some(Ecosystem::Debian(v)) if (kind, namespace) == ("deb", "debian") => {
            Ecosystem::Debian(v)
        }
        Some(Ecosystem::Ubuntu(v)) if (kind, namespace) == ("deb", "ubuntu") => {
            Ecosystem::Ubuntu(v)
        }
        Some(Ecosystem::Rocky(v)) if (kind, namespace) == ("rpm", "rocky") => Ecosystem::Rocky(v),
        Some(Ecosystem::Alma(v)) if (kind, namespace) == ("rpm", "alma") => Ecosystem::Alma(v),
        Some(Ecosystem::Rhel(v)) if (kind, namespace) == ("rpm", "redhat") => Ecosystem::Rhel(v),
        Some(Ecosystem::Alpine(v)) if (kind, namespace) == ("apk", "alpine") => {
            Ecosystem::Alpine(v)
        }
        Some(Ecosystem::Opensuse(v)) if (kind, namespace) == ("rpm", "opensuse") => {
            Ecosystem::Opensuse(v)
        }
        Some(e @ Ecosystem::Gentoo) if (kind, namespace) == ("generic", "gentoo") => e,
        Some(e) => {
            return Err(bad(format!(
                "the purl {kind}/{namespace} does not match --distro {}; supported purls: pkg:rpm/fedora, pkg:alpm/arch, pkg:deb/debian, pkg:deb/ubuntu, pkg:apk/alpine, pkg:rpm/redhat, pkg:rpm/opensuse, pkg:generic/gentoo",
                distro_flag(e)
            )));
        }
        None => {
            return Err(bad(
                "a purl needs a --distro to fill in the release; for example --distro fedora:44",
            ));
        }
    };
    let (name, version) = name_version
        .rsplit_once('@')
        .ok_or_else(|| bad("the purl has no @version"))?;
    let name = percent_decode(name).ok_or_else(|| bad("bad percent-encoding in the name"))?;
    let mut version =
        percent_decode(version).ok_or_else(|| bad("bad percent-encoding in the version"))?;

    let mut arch = None;
    let mut slot = None;
    let mut upstream = None;
    let mut module = None;
    for kv in query.split('&').filter(|s| !s.is_empty()) {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        let v = percent_decode(v).ok_or_else(|| bad("bad percent-encoding in a qualifier"))?;
        match k {
            "arch" => arch = Some(v),
            "slot" if ecosystem == Ecosystem::Gentoo => slot = Some(v),
            "upstream" => upstream = Some(v),
            "modularitylabel" => module = Some(v),
            // Alpine and Arch versions have no epoch qualifier to read.
            "epoch"
                if (is_rpm(ecosystem)
                    || matches!(ecosystem, Ecosystem::Debian(_) | Ecosystem::Ubuntu(_)))
                    && !version.contains(':') =>
            {
                version = format!("{v}:{version}");
            }
            _ => {}
        }
    }
    if ecosystem == Ecosystem::Gentoo {
        gentoo_name(&name)?;
    } else if !valid_name(&name) || name.contains('@') {
        return Err(bad(format!("invalid package name {name:?}")));
    }
    let ok = match ecosystem {
        Ecosystem::Gentoo => amivuln_version::GentooVersion::is_valid(&version),
        Ecosystem::Debian(_)
        | Ecosystem::Ubuntu(_)
        | Ecosystem::Rocky(_)
        | Ecosystem::Alma(_)
        | Ecosystem::Rhel(_) => valid_deb_version(&version),
        _ => valid_version(&version),
    };
    if !ok {
        return Err(bad(format!("invalid version {version:?}")));
    }
    let mut package = make(ecosystem, &name, &version, arch);
    package.slot = slot;
    if let Some(upstream) = upstream {
        set_upstream_source(&mut package, &upstream);
    }
    if let Some(label) = module {
        set_module(&mut package, &label);
    }
    Ok(package)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_version_builds_user_input_packages() {
        let p = from_name_version(Ecosystem::Fedora(44), "nginx", "1:1.26.2-1.fc44").unwrap();
        assert_eq!(p.name, "nginx");
        assert_eq!(p.version.to_string(), "1:1.26.2-1.fc44");
        assert_eq!(p.provenance, Provenance::UserInput);
        assert!(matches!(p.version, Version::Rpm(_)));
        let a = from_name_version(Ecosystem::Arch, "openssl", "3.5.1-1").unwrap();
        assert!(matches!(a.version, Version::Pacman(_)));
    }

    #[test]
    fn gentoo_packages_are_category_name_with_an_optional_slot() {
        let p = from_name_version(Ecosystem::Gentoo, "dev-lang/php:8.2", "8.2.20-r1").unwrap();
        assert_eq!(p.name, "dev-lang/php");
        assert_eq!(p.slot.as_deref(), Some("8.2"));
        assert!(matches!(p.version, Version::Gentoo(_)));
        let plain = from_name_version(Ecosystem::Gentoo, "x11-libs/gtk+", "3.24.41").unwrap();
        assert_eq!(plain.slot, None);
        for bad in [
            "openssl",
            "a/b/c",
            "/x",
            "x/",
            "dev-libs/openssl:",
            "dev-libs/ope nssl",
        ] {
            assert!(
                from_name_version(Ecosystem::Gentoo, bad, "1.0").is_err(),
                "{bad}"
            );
        }
        // A version outside the ebuild grammar is refused, not compared as text.
        assert!(from_name_version(Ecosystem::Gentoo, "dev-libs/openssl", "3.0.x").is_err());
        let purl = from_purl(
            "pkg:generic/gentoo/dev-lang/php@8.2.20-r1?slot=8.2",
            Some(Ecosystem::Gentoo),
        )
        .unwrap();
        assert_eq!(
            (purl.name.as_str(), purl.slot.as_deref()),
            ("dev-lang/php", Some("8.2"))
        );
    }

    #[test]
    fn name_version_rejects_garbage() {
        assert!(from_name_version(Ecosystem::Arch, "", "1").is_err());
        assert!(from_name_version(Ecosystem::Arch, "a b", "1").is_err());
        assert!(from_name_version(Ecosystem::Arch, "a;rm", "1").is_err());
        assert!(from_name_version(Ecosystem::Arch, "a", "").is_err());
        assert!(from_name_version(Ecosystem::Arch, "a", "1 2").is_err());
        assert!(from_name_version(Ecosystem::Arch, "a\u{1b}", "1").is_err());
        assert!(from_name_version(Ecosystem::Arch, &"a".repeat(200), "1").is_err());
    }

    #[test]
    fn purl_fedora_with_epoch_and_arch() {
        let p = from_purl(
            "pkg:rpm/fedora/nginx@1.26.2-1.fc41?arch=x86_64&epoch=1",
            Some(Ecosystem::Fedora(41)),
        )
        .unwrap();
        assert_eq!(p.ecosystem, Ecosystem::Fedora(41));
        assert_eq!(p.version.to_string(), "1:1.26.2-1.fc41");
        assert_eq!(p.arch.as_deref(), Some("x86_64"));
    }

    #[test]
    fn purl_epoch_counts_on_every_rpm_distribution() {
        for (purl, eco) in [
            (
                "pkg:rpm/redhat/openssl@3.0.7-24.el9?epoch=1",
                Ecosystem::Rhel(9),
            ),
            (
                "pkg:rpm/rocky/openssl@3.0.7-24.el9?epoch=1",
                Ecosystem::Rocky(9),
            ),
            (
                "pkg:rpm/alma/openssl@3.0.7-24.el9?epoch=1",
                Ecosystem::Alma(9),
            ),
            (
                "pkg:rpm/opensuse/openssl@3.0.7-24.el9?epoch=1",
                Ecosystem::Opensuse(1506),
            ),
        ] {
            let p = from_purl(purl, Some(eco)).unwrap();
            assert_eq!(p.version.to_string(), "1:3.0.7-24.el9", "{purl}");
        }
    }

    #[test]
    fn purl_epoch_counts_on_deb_packages_too() {
        // Trivy keeps a deb epoch in the qualifier, Syft in the version.
        for purl in [
            "pkg:deb/debian/libcap2@2.66-4?epoch=1",
            "pkg:deb/debian/libcap2@1%3A2.66-4",
            "pkg:deb/debian/libcap2@1%3A2.66-4?epoch=1",
        ] {
            let p = from_purl(purl, Some(Ecosystem::Debian(12))).unwrap();
            assert_eq!(p.version.to_string(), "1:2.66-4", "{purl}");
        }
    }

    #[test]
    fn purl_module_label_names_the_stream() {
        let p = from_purl(
            "pkg:rpm/alma/nodejs@20.12.2-2.module_el8.9.0%2B1%2Ba?modularitylabel=nodejs%3A20%3A8090020240509091713%3A9edba152",
            Some(Ecosystem::Alma(8)),
        )
        .unwrap();
        assert_eq!(p.module_stream.as_deref(), Some("nodejs:20"));
    }

    #[test]
    fn purl_upstream_names_the_source_package() {
        let source = |purl: &str, eco| {
            let p = from_purl(purl, Some(eco)).unwrap();
            (p.source_name, p.source_vr)
        };
        let named = |name: &str| Some(name.to_owned());
        // Syft writes `name` or `name@version` for deb, `name` for apk and the
        // source rpm's file name for rpm.
        for purl in [
            "pkg:deb/debian/libssl3@3.0.11-1?upstream=openssl",
            "pkg:deb/debian/libssl3@3.0.11-1?upstream=openssl%403.0.11-1",
        ] {
            assert_eq!(
                source(purl, Ecosystem::Debian(12)),
                (named("openssl"), None)
            );
        }
        assert_eq!(
            source(
                "pkg:apk/alpine/libssl3@3.5.0-r0?upstream=openssl",
                Ecosystem::Alpine(322)
            ),
            (named("openssl"), None)
        );
        assert_eq!(
            source(
                "pkg:rpm/rocky/device-mapper@1.02.181-15.el8?epoch=8&upstream=lvm2-2.03.14-15.el8.src.rpm",
                Ecosystem::Rocky(8)
            ),
            (named("lvm2"), named("2.03.14-15.el8"))
        );
        assert_eq!(
            source(
                "pkg:rpm/rocky/openssl-libs@3.0.7-24.el9?epoch=1&upstream=openssl-3.0.7-24.el9.src.rpm",
                Ecosystem::Rocky(9)
            ),
            (named("openssl"), None)
        );
        // Nothing a package manager would accept: the source stays unknown.
        assert_eq!(
            source(
                "pkg:deb/debian/libssl3@3.0.11-1?upstream=a%20b",
                Ecosystem::Debian(12)
            ),
            (None, None)
        );
    }

    #[test]
    fn purl_arch_and_percent_encoding() {
        let p = from_purl(
            "pkg:alpm/arch/libstdc%2B%2B@14.2.1-1",
            Some(Ecosystem::Arch),
        )
        .unwrap();
        assert_eq!(p.name, "libstdc++");
        assert_eq!(p.ecosystem, Ecosystem::Arch);
    }

    #[test]
    fn purl_errors_are_actionable() {
        let e = from_purl("pkg:rpm/fedora/nginx@1.0-1", None)
            .unwrap_err()
            .to_string();
        assert!(e.contains("--distro"), "{e}");
        assert!(from_purl("pkg:deb/debian/nginx@1.0", Some(Ecosystem::Fedora(44))).is_err());
        assert!(from_purl("pkg:alpm/arch/openssl", Some(Ecosystem::Fedora(44))).is_err());
        assert!(from_purl("nginx", Some(Ecosystem::Arch)).is_err());
        assert!(from_purl("pkg:alpm/arch/a%zz@1", Some(Ecosystem::Arch)).is_err());
        // A Debian purl with a Debian distro resolves, and the release is taken
        // from the --distro value.
        let p = from_purl("pkg:deb/debian/nginx@1.0-1", Some(Ecosystem::Debian(12))).unwrap();
        assert_eq!(p.ecosystem, Ecosystem::Debian(12));
    }
}
