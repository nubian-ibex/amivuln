// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Turning user targets and `--all` into package references on this host.

use super::{
    ApkResolver, Cli, DpkgResolver, Duration, Ecosystem, PackageRef, PackageResolver,
    PacmanResolver, Path, ResolveError, RpmResolver, SystemRunner, Target, Unresolved,
    exe_for_unit, from_name_version, from_purl, language_packages, package_from_note, parse_target,
};

/// The package manager lookups for a host.
pub(super) enum Backend<'a> {
    Rpm(RpmResolver<'a, SystemRunner>),
    Pacman(PacmanResolver<'a, SystemRunner>),
    Dpkg(DpkgResolver),
    Apk(ApkResolver),
}

impl Backend<'_> {
    fn resolver(&self) -> &dyn PackageResolver {
        match self {
            Self::Rpm(r) => r,
            Self::Pacman(r) => r,
            Self::Dpkg(r) => r,
            Self::Apk(r) => r,
        }
    }
}

pub(crate) fn expand_targets(cli: &Cli, subcommand_targets: &[String]) -> Vec<String> {
    let mut v: Vec<String> = subcommand_targets.to_vec();
    v.extend(cli.global.package.iter().cloned());
    v.extend(cli.global.file.iter().map(|f| {
        if f.contains('/') {
            f.clone()
        } else {
            format!("./{f}")
        }
    }));
    v.extend(cli.global.purl.iter().cloned());
    v.extend(cli.global.pid.iter().map(|pid| pid_executable(*pid)));
    v
}

/// The path of a process's executable, from `/proc/PID/exe`. A process that
/// is gone, or not readable, or whose binary was replaced on disk
/// (`(deleted)`) keeps the `/proc` path, which then fails to resolve with a
/// message that names the process rather than checking the new file by
/// mistake: the running code is the old one.
pub(super) fn pid_executable(pid: u32) -> String {
    let link = format!("/proc/{pid}/exe");
    match std::fs::read_link(&link) {
        Ok(path) => {
            let path = path.display().to_string();
            if path.ends_with(" (deleted)") {
                link
            } else {
                path
            }
        }
        Err(_) => link,
    }
}

pub(super) fn resolve_one(
    input: &str,
    eco: Ecosystem,
    backend: &Backend<'_>,
    runner: &SystemRunner,
) -> Result<PackageRef, ResolveError> {
    let exists = |p: &str| Path::new(p).exists();
    match parse_target(input, exists) {
        // The purl itself carries no release, so the host's --distro fills it
        // in and must agree with the purl's namespace.
        Target::Purl(p) => from_purl(&p, Some(eco)),
        Target::NameVersion(n, v) => from_name_version(eco, &n, &v),
        Target::Path(p) => backend.resolver().owner_of(&p),
        Target::Name(n) => backend.resolver().by_name(&n),
        Target::Unit(u) => {
            let link = |p: &str| std::fs::read_link(p).ok().map(|l| l.display().to_string());
            let exe = exe_for_unit(runner, &link, &u)?;
            backend.resolver().owner_of(&exe.path)
        }
    }
}

/// Identifies a file: its owning package, else its package note, else the Go
/// modules or Rust crates it declares. Modules and crates are used only when
/// nothing else names the file, because a distribution backports fixes into
/// vendored code without changing versions.
pub(super) fn resolve_path(
    path: &str,
    eco: Ecosystem,
    backend: Option<&Backend<'_>>,
    probe: bool,
) -> Result<Vec<PackageRef>, ResolveError> {
    // `--pid` leaves the /proc path when the process cannot be followed.
    if path.starts_with("/proc/") && path.ends_with("/exe") {
        return Err(ResolveError::NotFound(format!(
            "{path} (the process is gone, unreadable, or its executable was replaced on disk)"
        )));
    }
    let owner = match backend {
        Some(b) => b.resolver().owner_of(path),
        None => Err(ResolveError::NotFound(path.to_owned())),
    };
    match owner {
        Ok(pkg) => return Ok(vec![pkg]),
        // Not owned (or the package manager is unavailable): look inside.
        // The package database may not exist here (`--distro` names another
        // system): look at the file itself.
        Err(ResolveError::NotFound(_) | ResolveError::Process(_) | ResolveError::Unreadable(_)) => {
        }
        Err(other) => return Err(other),
    }
    if let Ok(pkg) = package_from_note(eco, Path::new(path)) {
        return Ok(vec![pkg]);
    }
    let modules = language_packages(Path::new(path))?;
    if !modules.is_empty() {
        return Ok(modules);
    }
    // Last resort: version banners from a curated set of C products. The
    // upstream version is what was compiled in; the distribution may have
    // backported fixes without changing the banner, so every formatter
    // carries the low-confidence mark.
    let mut hits =
        amivuln_resolve::detect_string_hits(Path::new(path)).map_err(ResolveError::Parse)?;
    if probe {
        hits.extend(version_probe(Path::new(path))?);
        hits.sort();
        hits.dedup();
    }
    let mut out = Vec::new();
    for hit in hits {
        if let Ok(pkg) = from_name_version(eco, &hit.name, &hit.version) {
            let mut pkg = pkg;
            pkg.provenance = amivuln_core::Provenance::StringHeuristic;
            out.push(pkg);
        }
    }
    if !out.is_empty() {
        return Ok(out);
    }
    package_from_note(eco, Path::new(path)).map(|pkg| vec![pkg])
}

/// Runs `path --version` in the sandbox (opt-in `exec_version_probe`) and
/// reads the banners from what it prints. The user asked for the probe, so a
/// sandbox that cannot be enforced is an error, never a silent unconfined run.
pub(super) fn version_probe(path: &Path) -> Result<Vec<amivuln_resolve::StringHit>, ResolveError> {
    let out = amivuln_sandbox::probe(path, &["--version"], Duration::from_secs(2))
        .map_err(|e| ResolveError::Parse(format!("version probe of {}: {e}", path.display())))?;
    Ok(amivuln_resolve::detect_strings(&out.output))
}

/// The package that owns each path, or `None` when none does.
pub(crate) fn owners(
    eco: Ecosystem,
    paths: &[String],
) -> std::collections::BTreeMap<String, Option<String>> {
    let runner = SystemRunner::default();
    let backend = match eco {
        Ecosystem::Fedora(_) | Ecosystem::Rocky(_) | Ecosystem::Alma(_) | Ecosystem::Rhel(_) => {
            Backend::Rpm(RpmResolver::new(&runner, eco))
        }
        Ecosystem::Arch => Backend::Pacman(PacmanResolver::new(&runner)),
        Ecosystem::Debian(_) | Ecosystem::Ubuntu(_) => Backend::Dpkg(DpkgResolver::new(eco)),
        Ecosystem::Alpine(_) => Backend::Apk(ApkResolver::new(eco)),
        Ecosystem::Go | Ecosystem::Crates => {
            return paths.iter().map(|p| (p.clone(), None)).collect();
        }
    };
    // One call for all paths, so a database file is read once, not per path.
    paths
        .iter()
        .cloned()
        .zip(backend.resolver().owners_of(paths))
        .map(|(path, owner)| (path, owner.ok().map(|pkg| pkg.name)))
        .collect()
}

/// The running service units, for `amivuln services`.
pub(crate) fn running_services() -> Result<Vec<String>, ResolveError> {
    amivuln_resolve::list_running_services(&SystemRunner::default())
}

pub(crate) fn resolve_all(
    targets: &[String],
    all: bool,
    eco: Ecosystem,
    probe: bool,
) -> (Vec<(String, PackageRef)>, Vec<Unresolved>) {
    let runner = SystemRunner::default();
    let mut resolved: Vec<(String, PackageRef)> = Vec::new();
    let mut unresolved: Vec<Unresolved> = Vec::new();
    let backend = match eco {
        Ecosystem::Fedora(_) | Ecosystem::Rocky(_) | Ecosystem::Alma(_) | Ecosystem::Rhel(_) => {
            Some(Backend::Rpm(RpmResolver::new(&runner, eco)))
        }
        Ecosystem::Arch => Some(Backend::Pacman(PacmanResolver::new(&runner))),
        Ecosystem::Debian(_) | Ecosystem::Ubuntu(_) => Some(Backend::Dpkg(DpkgResolver::new(eco))),
        Ecosystem::Alpine(_) => Some(Backend::Apk(ApkResolver::new(eco))),
        // A host is never a language ecosystem.
        Ecosystem::Go | Ecosystem::Crates => None,
    };
    if all {
        match backend.as_ref().map(|b| b.resolver().list_all()) {
            Some(Ok(list)) => resolved.extend(list.into_iter().map(|p| (p.name.clone(), p))),
            Some(Err(e)) => unresolved.push(Unresolved {
                input: "--all".into(),
                reason: e.to_string(),
            }),
            // Language ecosystems have no host database.
            None => {}
        }
    }
    for t in targets {
        // A file is identified by its owner, else its own `.note.package`,
        // else the modules or crates it declares. Debian and Ubuntu have no
        // host package database, so they start at the note.
        if let Target::Path(p) = parse_target(t, |p| Path::new(p).exists()) {
            match resolve_path(&p, eco, backend.as_ref(), probe) {
                Ok(list) => resolved.extend(list.into_iter().map(|pkg| (t.clone(), pkg))),
                Err(e) => unresolved.push(Unresolved {
                    input: t.clone(),
                    reason: e.to_string(),
                }),
            }
            continue;
        }
        let resolved_one = match backend.as_ref() {
            Some(b) => resolve_one(t, eco, b, &runner),
            None => Err(ResolveError::NotFound(t.clone())),
        };
        match resolved_one {
            Ok(p) => resolved.push((t.clone(), p)),
            Err(e) => unresolved.push(Unresolved {
                input: t.clone(),
                reason: e.to_string(),
            }),
        }
    }
    (resolved, unresolved)
}
