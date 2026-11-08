// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Host identity from `/etc/os-release`.

use amivuln_core::Ecosystem;

/// What the host is, as far as amivuln supports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
        assert_eq!(parse_os_release("ID=debian\nVERSION_ID=12\n"), None);
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
