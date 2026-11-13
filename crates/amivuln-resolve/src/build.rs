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
        Ecosystem::Go | Ecosystem::Crates => {
            Version::Semver(amivuln_version::SemverVersion::default())
        }
    };
    PackageRef {
        ecosystem,
        name: name.to_owned(),
        source_name: None,
        version: parsed,
        arch,
        provenance: Provenance::UserInput,
    }
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
    if !valid_name(name) || name.contains('@') {
        return Err(bad(format!("invalid package name {name:?}")));
    }
    let ok = match ecosystem {
        Ecosystem::Debian(_) | Ecosystem::Ubuntu(_) => valid_deb_version(version),
        _ => valid_version(version),
    };
    if !ok {
        return Err(bad(format!("invalid version {version:?}")));
    }
    Ok(make(ecosystem, name, version, None))
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
        Some(e) => {
            return Err(bad(format!(
                "the purl {kind}/{namespace} does not match --distro {}; supported purls: pkg:rpm/fedora, pkg:alpm/arch, pkg:deb/debian, pkg:deb/ubuntu, pkg:apk/alpine, pkg:rpm/redhat, pkg:rpm/opensuse",
                match e {
                    Ecosystem::Fedora(v) => format!("fedora:{v}"),
                    Ecosystem::Arch => "arch".to_owned(),
                    Ecosystem::Debian(v) => format!("debian:{v}"),
                    Ecosystem::Ubuntu(v) => {
                        format!("ubuntu:{}.{:02}", v / 100, v % 100)
                    }
                    Ecosystem::Rocky(v) => format!("rocky:{v}"),
                    Ecosystem::Alma(v) => format!("alma:{v}"),
                    Ecosystem::Rhel(v) => format!("rhel:{v}"),
                    Ecosystem::Alpine(v) => format!("alpine:{}.{}", v / 100, v % 100),
                    Ecosystem::Opensuse(0) => "opensuse:tumbleweed".to_owned(),
                    Ecosystem::Opensuse(v) => format!("opensuse:{}.{}", v / 100, v % 100),
                    Ecosystem::Go | Ecosystem::Crates => "a language ecosystem".to_owned(),
                }
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
    for kv in query.split('&').filter(|s| !s.is_empty()) {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        let v = percent_decode(v).ok_or_else(|| bad("bad percent-encoding in a qualifier"))?;
        match k {
            "arch" => arch = Some(v),
            "epoch" if matches!(ecosystem, Ecosystem::Fedora(_)) && !version.contains(':') => {
                version = format!("{v}:{version}");
            }
            _ => {}
        }
    }
    if !valid_name(&name) || name.contains('@') {
        return Err(bad(format!("invalid package name {name:?}")));
    }
    let ok = match ecosystem {
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
    Ok(make(ecosystem, &name, &version, arch))
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
