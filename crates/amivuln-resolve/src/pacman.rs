// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Installed package lookup through `pacman`.

use amivuln_core::{Ecosystem, PackageRef, ProcessRunner, Program, Provenance, Version};

use crate::{PackageResolver, ResolveError};

/// Resolver backed by the pacman local database.
#[derive(Debug)]
pub struct PacmanResolver<'a, R> {
    runner: &'a R,
}

impl<'a, R: ProcessRunner> PacmanResolver<'a, R> {
    /// Creates a resolver.
    pub fn new(runner: &'a R) -> Self {
        Self { runner }
    }

    fn run(&self, args: &[&str], subject: &str) -> Result<String, ResolveError> {
        if subject.chars().any(char::is_control) {
            return Err(ResolveError::NotFound(subject.escape_default().to_string()));
        }
        let out = self.runner.run(Program::Pacman, args)?;
        if !out.success {
            return Err(ResolveError::NotFound(subject.to_owned()));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }
}

impl<R: ProcessRunner> PackageResolver for PacmanResolver<'_, R> {
    fn owner_of(&self, path: &str) -> Result<PackageRef, ResolveError> {
        let text = self.run(&["-Qoq", "--", path], path)?;
        let mut names: Vec<&str> = text.lines().filter(|l| !l.is_empty()).collect();
        names.dedup();
        match names.as_slice() {
            [name] => self.by_name(name),
            [] => Err(ResolveError::NotFound(path.to_owned())),
            many => Err(ResolveError::Ambiguous(path.to_owned(), many.join(", "))),
        }
    }

    fn list_all(&self) -> Result<Vec<PackageRef>, ResolveError> {
        let text = self.run(&["-Q"], "installed packages")?;
        let mut pkgs = Vec::new();
        for line in text.lines().filter(|l| !l.is_empty()) {
            pkgs.push(parse_pair(line)?);
        }
        pkgs.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(pkgs)
    }

    fn by_name(&self, name: &str) -> Result<PackageRef, ResolveError> {
        let text = self.run(&["-Q", "--", name], name)?;
        let line = text
            .lines()
            .find(|l| !l.is_empty())
            .ok_or_else(|| ResolveError::NotFound(name.to_owned()))?;
        parse_pair(line)
    }
}

/// Parses one `name version` line from `pacman -Q`.
fn parse_pair(line: &str) -> Result<PackageRef, ResolveError> {
    let (pkg, version) = line
        .split_once(' ')
        .filter(|(p, v)| !p.is_empty() && !v.is_empty() && !v.contains(' '))
        .ok_or_else(|| ResolveError::Parse(line.chars().take(120).collect()))?;
    let parsed = version.parse().unwrap_or_else(|never| match never {});
    Ok(PackageRef {
        ecosystem: Ecosystem::Arch,
        name: pkg.to_owned(),
        source_name: None,
        version: Version::Pacman(parsed),
        arch: None,
        provenance: Provenance::PackageDb,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests_support::FakeRunner;

    #[test]
    fn by_name_parses_version() {
        let r = FakeRunner::ok("openssl 3.5.1-1\n");
        let p = PacmanResolver::new(&r).by_name("openssl").unwrap();
        assert_eq!(p.name, "openssl");
        assert_eq!(p.version.to_string(), "3.5.1-1");
        assert_eq!(p.ecosystem, Ecosystem::Arch);
        assert_eq!(r.calls.borrow()[0], ["-Q", "--", "openssl"]);
    }

    #[test]
    fn owner_of_resolves_in_two_steps() {
        let r = FakeRunner::sequence(&["bash\n", "bash 5.3.9-1\n"]);
        let p = PacmanResolver::new(&r).owner_of("/usr/bin/bash").unwrap();
        assert_eq!(p.name, "bash");
        let calls = r.calls.borrow();
        assert_eq!(calls[0], ["-Qoq", "--", "/usr/bin/bash"]);
        assert_eq!(calls[1], ["-Q", "--", "bash"]);
    }

    #[test]
    fn failures_and_garbage() {
        let r = FakeRunner::failing();
        assert!(matches!(
            PacmanResolver::new(&r).by_name("nope"),
            Err(ResolveError::NotFound(_))
        ));
        let r = FakeRunner::ok("justonetoken\n");
        assert!(matches!(
            PacmanResolver::new(&r).by_name("x"),
            Err(ResolveError::Parse(_))
        ));
        let r = FakeRunner::ok("a b c\n");
        assert!(matches!(
            PacmanResolver::new(&r).by_name("x"),
            Err(ResolveError::Parse(_))
        ));
    }

    #[test]
    fn list_all_parses_every_line() {
        let r = FakeRunner::ok("zlib 1.3-1\nbash 5.3-1\n");
        let all = PacmanResolver::new(&r).list_all().unwrap();
        assert_eq!(
            all.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(),
            ["bash", "zlib"]
        );
        assert_eq!(r.calls.borrow()[0], ["-Q"]);
    }

    #[test]
    fn multiple_owners_are_ambiguous() {
        let r = FakeRunner::ok("a\nb\n");
        assert!(matches!(
            PacmanResolver::new(&r).owner_of("/x"),
            Err(ResolveError::Ambiguous(..))
        ));
    }
}
