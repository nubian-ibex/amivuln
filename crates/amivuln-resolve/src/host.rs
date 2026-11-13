// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Host identity from `/etc/os-release`.

use amivuln_core::Ecosystem;

/// What the host is, as far as amivuln supports it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HostInfo {
    /// Package ecosystem of the host.
    pub ecosystem: Ecosystem,
}

/// Parses the contents of an `os-release` file.
///
/// Returns `None` for unsupported distributions. Values may be quoted.
#[must_use]
pub fn parse_os_release(content: &str) -> Option<HostInfo> {
    let mut id = None;
    let mut version_id = None;
    for line in content.lines().take(200) {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim().trim_matches('"').trim_matches('\'');
        match key {
            "ID" => id = Some(value.to_owned()),
            "VERSION_ID" => version_id = Some(value.to_owned()),
            _ => {}
        }
    }
    let ecosystem = match id.as_deref()? {
        "fedora" => Ecosystem::Fedora(version_id?.parse().ok()?),
        "arch" => Ecosystem::Arch,
        // os-release says `debian` with VERSION_CODENAME in newer releases and
        // VERSION_ID as a number in others; a floating version is not possible.
        "debian" => Ecosystem::Debian(version_id?.parse().ok()?),
        // Rocky and AlmaLinux declare VERSION_ID as the major release.
        "rocky" => Ecosystem::Rocky(version_id?.parse().ok()?),
        // RHEL declares VERSION_ID as major.minor (9.4); the major decides.
        "rhel" => Ecosystem::Rhel(version_id?.split('.').next()?.parse().ok()?),
        "almalinux" => Ecosystem::Alma(version_id?.parse().ok()?),
        // Leap writes 15.6 (or 16.0); Tumbleweed has a date for VERSION_ID and
        // one rolling OSV ecosystem.
        "opensuse-leap" => {
            let vid = version_id?;
            let (major, minor) = vid.split_once('.')?;
            Ecosystem::Opensuse(major.parse::<u16>().ok()? * 100 + minor.parse::<u16>().ok()?)
        }
        "opensuse-tumbleweed" => Ecosystem::Opensuse(0),
        // Alpine writes 3.20.3; an edge or alpha image (3.23.0_alpha...) has no
        // OSV release.
        "alpine" => {
            let vid = version_id?;
            if vid.contains('_') {
                return None;
            }
            let mut parts = vid.split('.');
            let major: u16 = parts.next()?.parse().ok()?;
            let minor: u16 = parts.next()?.parse().ok()?;
            Ecosystem::Alpine(major * 100 + minor)
        }
        // Ubuntu LTS versions are "NN.04" or "NN.10"; interim releases have no
        // long-lived OSV ecosystem, so amivuln does not claim them.
        "ubuntu" => {
            let vid: Option<&String> = version_id.as_ref();
            let (maj, min) = vid?.split_once('.')?;
            let maj: u16 = maj.parse().ok()?;
            let min: u8 = min.parse().ok()?;
            if min != 4 && min != 10 {
                return None;
            }
            Ecosystem::Ubuntu(maj * 100 + u16::from(min))
        }
        _ => return None,
    };
    Some(HostInfo { ecosystem })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fedora_and_arch() {
        let f = "NAME=\"Fedora Linux\"\nID=fedora\nVERSION_ID=44\n";
        assert_eq!(
            parse_os_release(f).map(|h| h.ecosystem),
            Some(Ecosystem::Fedora(44))
        );
        let a = "NAME=\"Arch Linux\"\nID=arch\nBUILD_ID=rolling\n";
        assert_eq!(
            parse_os_release(a).map(|h| h.ecosystem),
            Some(Ecosystem::Arch)
        );
    }

    #[test]
    fn opensuse_leap_and_tumbleweed() {
        let leap = "NAME=\"openSUSE Leap\"\nID=\"opensuse-leap\"\nVERSION_ID=\"15.6\"\n";
        assert_eq!(
            parse_os_release(leap).map(|h| h.ecosystem),
            Some(Ecosystem::Opensuse(1506))
        );
        let tumbleweed = "ID=\"opensuse-tumbleweed\"\nVERSION_ID=\"20251107\"\n";
        assert_eq!(
            parse_os_release(tumbleweed).map(|h| h.ecosystem),
            Some(Ecosystem::Opensuse(0))
        );
        // A Leap without a minor version is not a release OSV knows.
        assert_eq!(parse_os_release("ID=opensuse-leap\nVERSION_ID=15\n"), None);
        // SUSE Linux Enterprise is a different product with its own data.
        assert_eq!(parse_os_release("ID=sles\nVERSION_ID=15.6\n"), None);
    }

    #[test]
    fn unsupported_or_malformed() {
        // Debian and Ubuntu are supported now.
        assert_eq!(
            parse_os_release("ID=debian\nVERSION_ID=12\n").map(|h| h.ecosystem),
            Some(Ecosystem::Debian(12))
        );
        assert_eq!(
            parse_os_release("ID=ubuntu\nVERSION_ID=24.04\n").map(|h| h.ecosystem),
            Some(Ecosystem::Ubuntu(2404))
        );
        assert_eq!(
            parse_os_release("ID=ubuntu\nVERSION_ID=25.10\n").map(|h| h.ecosystem),
            Some(Ecosystem::Ubuntu(2510))
        );
        assert_eq!(parse_os_release("ID=fedora\n"), None);
        assert_eq!(parse_os_release("ID=fedora\nVERSION_ID=rawhide\n"), None);
        assert_eq!(parse_os_release(""), None);
    }

    #[test]
    fn quoted_values() {
        let f = "ID=\"fedora\"\nVERSION_ID=\"43\"\n";
        assert_eq!(
            parse_os_release(f).map(|h| h.ecosystem),
            Some(Ecosystem::Fedora(43))
        );
    }
}
