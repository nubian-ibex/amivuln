// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Installed package lookup through `rpm`.

use amivuln_core::{Ecosystem, PackageRef, ProcessRunner, Program, Provenance, Version};

use crate::{PackageResolver, ResolveError};

const QUERY_FORMAT: &str = "%{EPOCH}\t%{NAME}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\n";

/// Resolver backed by the rpm database.
#[derive(Debug)]
pub struct RpmResolver<'a, R> {
    runner: &'a R,
    ecosystem: Ecosystem,
}

impl<'a, R: ProcessRunner> RpmResolver<'a, R> {
    /// Creates a resolver that tags packages with `ecosystem`.
    pub fn new(runner: &'a R, ecosystem: Ecosystem) -> Self {
        Self { runner, ecosystem }
    }

    fn query(&self, flag: &str, subject: &str) -> Result<Vec<PackageRef>, ResolveError> {
        if subject.chars().any(char::is_control) {
            return Err(ResolveError::NotFound(subject.escape_default().to_string()));
        }
        let out = self
            .runner
            .run(Program::Rpm, &[flag, "--qf", QUERY_FORMAT, "--", subject])?;
        if !out.success {
            // rpm exits non-zero when nothing matches.
            return Err(ResolveError::NotFound(subject.to_owned()));
        }
        let text = String::from_utf8_lossy(&out.stdout);
        let mut pkgs = Vec::new();
        for line in text.lines().filter(|l| !l.is_empty()) {
            pkgs.push(parse_line(line, self.ecosystem)?);
        }
        if pkgs.is_empty() {
            return Err(ResolveError::NotFound(subject.to_owned()));
        }
        // Multilib: the same build installed for several architectures is one
        // package for vulnerability purposes.
        let mut seen: Vec<(String, String)> = Vec::new();
        pkgs.retain(|p| {
            let key = (p.name.clone(), p.version.to_string());
            let new = !seen.contains(&key);
            if new {
                seen.push(key);
            }
            new
        });
        Ok(pkgs)
    }

    fn single(subject: &str, mut pkgs: Vec<PackageRef>) -> Result<PackageRef, ResolveError> {
        if pkgs.len() == 1 {
            return pkgs
                .pop()
                .ok_or_else(|| ResolveError::NotFound(subject.to_owned()));
        }
        let list = pkgs
            .iter()
            .map(|p| format!("{}-{}", p.name, p.version))
            .collect::<Vec<_>>()
            .join(", ");
        Err(ResolveError::Ambiguous(subject.to_owned(), list))
    }
}

impl<R: ProcessRunner> PackageResolver for RpmResolver<'_, R> {
    fn owner_of(&self, path: &str) -> Result<PackageRef, ResolveError> {
        Self::single(path, self.query("-qf", path)?)
    }

    fn by_name(&self, name: &str) -> Result<PackageRef, ResolveError> {
        Self::single(name, self.query("-q", name)?)
    }

    fn list_all(&self) -> Result<Vec<PackageRef>, ResolveError> {
        let out = self
            .runner
            .run(Program::Rpm, &["-qa", "--qf", QUERY_FORMAT])?;
        if !out.success {
            return Err(ResolveError::Parse("rpm -qa failed".into()));
        }
        let text = String::from_utf8_lossy(&out.stdout);
        let mut pkgs = Vec::new();
        for line in text.lines().filter(|l| !l.is_empty()) {
            let p = parse_line(line, self.ecosystem)?;
            // gpg-pubkey pseudo packages carry no software.
            if p.name != "gpg-pubkey" {
                pkgs.push(p);
            }
        }
        pkgs.sort_by(|a, b| {
            a.name
                .cmp(&b.name)
                .then_with(|| a.version.to_string().cmp(&b.version.to_string()))
        });
        Ok(pkgs)
    }
}

/// Parses one tab-separated line produced with [`QUERY_FORMAT`].
fn parse_line(line: &str, ecosystem: Ecosystem) -> Result<PackageRef, ResolveError> {
    let bad = || ResolveError::Parse(line.chars().take(120).collect());
    let mut f = line.split('\t');
    let (epoch, name, version, release, arch, srpm) = (
        f.next().ok_or_else(bad)?,
        f.next().ok_or_else(bad)?,
        f.next().ok_or_else(bad)?,
        f.next().ok_or_else(bad)?,
        f.next().ok_or_else(bad)?,
        f.next().ok_or_else(bad)?,
    );
    if f.next().is_some() || name.is_empty() || version.is_empty() {
        return Err(bad());
    }
    let evr = if epoch == "(none)" || epoch.is_empty() {
        format!("{version}-{release}")
    } else {
        format!("{epoch}:{version}-{release}")
    };
    let parsed = evr.parse().unwrap_or_else(|never| match never {});
    Ok(PackageRef {
        ecosystem,
        name: name.to_owned(),
        source_name: source_name(srpm),
        version: Version::Rpm(parsed),
        arch: (arch != "(none)").then(|| arch.to_owned()),
        provenance: Provenance::PackageDb,
    })
}

/// `bash-5.3.9-3.fc44.src.rpm` gives `bash`.
fn source_name(srpm: &str) -> Option<String> {
    let base = srpm.strip_suffix(".src.rpm")?;
    let without_release = base.rsplit_once('-')?.0;
    let name = without_release.rsplit_once('-')?.0;
    (!name.is_empty()).then(|| name.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests_support::FakeRunner;

    const BASH: &str = "(none)\tbash\t5.3.9\t3.fc44\tx86_64\tbash-5.3.9-3.fc44.src.rpm\n";

    #[test]
    fn owner_of_parses_package() {
        let r = FakeRunner::ok(BASH);
        let p = RpmResolver::new(&r, Ecosystem::Fedora(44))
            .owner_of("/usr/bin/bash")
            .unwrap();
        assert_eq!(p.name, "bash");
        assert_eq!(p.source_name.as_deref(), Some("bash"));
        assert_eq!(p.version.to_string(), "5.3.9-3.fc44");
        assert_eq!(p.arch.as_deref(), Some("x86_64"));
        assert_eq!(p.provenance, Provenance::PackageDb);
        let calls = r.calls.borrow();
        assert_eq!(
            calls[0],
            ["-qf", "--qf", QUERY_FORMAT, "--", "/usr/bin/bash"]
        );
    }

    #[test]
    fn epoch_is_kept() {
        let r = FakeRunner::ok("1\tnginx\t1.26.2\t1.fc41\tx86_64\tnginx-1.26.2-1.fc41.src.rpm\n");
        let p = RpmResolver::new(&r, Ecosystem::Fedora(41))
            .by_name("nginx")
            .unwrap();
        assert_eq!(p.version.to_string(), "1:1.26.2-1.fc41");
    }

    #[test]
    fn several_installed_versions_are_ambiguous() {
        let r = FakeRunner::ok(
            "(none)\tkernel-core\t7.2.11\t200.fc44\tx86_64\tkernel-7.2.11-200.fc44.src.rpm\n\
             (none)\tkernel-core\t7.2.12\t200.fc44\tx86_64\tkernel-7.2.12-200.fc44.src.rpm\n",
        );
        let e = RpmResolver::new(&r, Ecosystem::Fedora(44))
            .by_name("kernel-core")
            .unwrap_err();
        assert!(
            matches!(e, ResolveError::Ambiguous(_, ref l) if l.contains("7.2.11") && l.contains("7.2.12"))
        );
    }

    #[test]
    fn multilib_by_name_is_one_package() {
        let r = FakeRunner::ok(
            "(none)\topenssl-libs\t3.5.9\t1.fc44\tx86_64\topenssl-3.5.9-1.fc44.src.rpm\n\
             (none)\topenssl-libs\t3.5.9\t1.fc44\ti686\topenssl-3.5.9-1.fc44.src.rpm\n",
        );
        let p = RpmResolver::new(&r, Ecosystem::Fedora(44))
            .by_name("openssl-libs")
            .unwrap();
        assert_eq!(p.name, "openssl-libs");
    }

    #[test]
    fn same_package_on_two_arches_owns_a_shared_file() {
        let r = FakeRunner::ok(
            "(none)\tfoo\t1\t1.fc44\tx86_64\tfoo-1-1.fc44.src.rpm\n(none)\tfoo\t1\t1.fc44\ti686\tfoo-1-1.fc44.src.rpm\n",
        );
        assert!(
            RpmResolver::new(&r, Ecosystem::Fedora(44))
                .owner_of("/usr/share/foo")
                .is_ok()
        );
    }

    #[test]
    fn not_found_and_garbage() {
        let r = FakeRunner::failing();
        assert!(matches!(
            RpmResolver::new(&r, Ecosystem::Fedora(44)).by_name("nope"),
            Err(ResolveError::NotFound(_))
        ));
        let r = FakeRunner::ok("garbage\n");
        assert!(matches!(
            RpmResolver::new(&r, Ecosystem::Fedora(44)).by_name("x"),
            Err(ResolveError::Parse(_))
        ));
    }

    #[test]
    fn control_characters_never_reach_rpm() {
        let r = FakeRunner::ok(BASH);
        assert!(
            RpmResolver::new(&r, Ecosystem::Fedora(44))
                .by_name("a\nb")
                .is_err()
        );
        assert!(r.calls.borrow().is_empty());
    }

    #[test]
    fn list_all_skips_pubkeys_and_sorts() {
        let r = FakeRunner::ok(
            "(none)\tzlib\t1\t1.fc44\tx86_64\tzlib-1-1.fc44.src.rpm\n\
             (none)\tgpg-pubkey\t1\t2\t(none)\t(none)\n\
             (none)\tbash\t5\t1.fc44\tx86_64\tbash-5-1.fc44.src.rpm\n",
        );
        let all = RpmResolver::new(&r, Ecosystem::Fedora(44))
            .list_all()
            .unwrap();
        let names: Vec<&str> = all.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["bash", "zlib"]);
        assert_eq!(r.calls.borrow()[0][0], "-qa");
    }

    #[test]
    fn source_name_cases() {
        assert_eq!(
            source_name("bash-5.3.9-3.fc44.src.rpm").as_deref(),
            Some("bash")
        );
        assert_eq!(
            source_name("python-foo-bar-1.0-2.fc44.src.rpm").as_deref(),
            Some("python-foo-bar")
        );
        assert_eq!(source_name("(none)"), None);
    }
}
