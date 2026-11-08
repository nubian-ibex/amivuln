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
