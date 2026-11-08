// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Classifying the user's target argument.

/// What kind of thing the user asked about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// A package URL (`pkg:...`).
    Purl(String),
    /// A file path.
    Path(String),
    /// A systemd unit (`.service`, `.socket`, `.timer`).
    Unit(String),
    /// `name@version`, answered without looking at the host.
    NameVersion(String, String),
    /// An installed package name.
    Name(String),
}

/// Applies the inference rules in order: purl, path, unit, `name@version`,
/// installed package name. `path_exists` decides whether a bare word is a file.
#[must_use]
pub fn parse_target(input: &str, path_exists: impl Fn(&str) -> bool) -> Target {
    if input.starts_with("pkg:") {
        return Target::Purl(input.to_owned());
    }
    if input.contains('/') || path_exists(input) {
        return Target::Path(input.to_owned());
    }
    if [".service", ".socket", ".timer"]
        .iter()
        .any(|s| input.ends_with(s))
    {
        return Target::Unit(input.to_owned());
    }
    if let Some((name, version)) = input.split_once('@') {
        return Target::NameVersion(name.to_owned(), version.to_owned());
    }
    Target::Name(input.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn none(_: &str) -> bool {
        false
    }

    #[test]
    fn rules_apply_in_order() {
        assert_eq!(
            parse_target("pkg:rpm/fedora/nginx@1.0", none),
            Target::Purl("pkg:rpm/fedora/nginx@1.0".into())
        );
        assert_eq!(
            parse_target("/usr/sbin/nginx", none),
            Target::Path("/usr/sbin/nginx".into())
        );
        assert_eq!(
            parse_target("./nginx", none),
            Target::Path("./nginx".into())
        );
        assert_eq!(
            parse_target("nginx.service", none),
            Target::Unit("nginx.service".into())
        );
        assert_eq!(
            parse_target("nginx@1.26.2", none),
            Target::NameVersion("nginx".into(), "1.26.2".into())
        );
        assert_eq!(parse_target("nginx", none), Target::Name("nginx".into()));
    }

    #[test]
    fn existing_file_wins_over_name() {
        assert_eq!(
            parse_target("nginx", |p| p == "nginx"),
            Target::Path("nginx".into())
        );
    }

    #[test]
    fn unit_beats_version_split() {
        assert_eq!(
            parse_target("user@1000.service", none),
            Target::Unit("user@1000.service".into())
        );
    }
}
