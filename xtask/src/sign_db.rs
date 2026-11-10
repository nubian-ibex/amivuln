// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! `cargo xtask sign-db`: the nightly sign step.
//!
//! The reference minisign CLI reads the password from a terminal, which CI
//! cannot provide. This command uses the crates.io minisign library, so the
//! password arrives through `MINISIGN_PASSWORD` and nothing interactive runs.

use std::io::Write;
use std::path::PathBuf;

fn fail(err: &mut dyn Write, message: &str) -> std::process::ExitCode {
    let _ = writeln!(err, "error: {message}");
    std::process::ExitCode::FAILURE
}

/// Reads the flag/value pairs in order and returns the first value after each.
///
/// # Errors
///
/// Returns `Err` when a flag was skipped or when a matching value is missing.
fn find(args: &[String], flag: &str) -> Option<Result<String, String>> {
    args.iter().position(|name| name == flag).and_then(|at| {
        args.get(at + 1)
            .filter(|value| !value.starts_with("--"))
            .cloned()
            .map(Ok)
            .or_else(|| Some(Err(format!("{flag} holds no value"))))
    })
}

/// Runs `cargo xtask sign-db --key KEY --manifest MANIFEST --out SIG`.
pub(crate) fn run(args: &[String], err: &mut dyn Write) -> std::process::ExitCode {
    let password = match std::env::var("MINISIGN_PASSWORD")
        .ok()
        .filter(|value| !value.is_empty())
    {
        Some(value) if !value.is_empty() => value,
        _ => return fail(err, "the MINISIGN_PASSWORD environment variable is missing"),
    };
    let Some(Ok(key)) = find(args, "--key") else {
        return fail(err, "--key KEY is required");
    };
    let Some(Ok(manifest)) = find(args, "--manifest") else {
        return fail(err, "--manifest MANIFEST is required");
    };
    let Some(Ok(out)) = find(args, "--out") else {
        return fail(err, "--out SIG is required");
    };
    let key = PathBuf::from(key);
    let manifest = PathBuf::from(manifest);
    let out = PathBuf::from(out);
    let secret = match std::fs::read_to_string(&key) {
        Ok(s) => s,
        Err(e) => return fail(err, &format!("{}: {e}", key.display())),
    };
    let boxed = match minisign::SecretKeyBox::from_string(&secret) {
        Ok(boxed) => boxed,
        Err(e) => return fail(err, &format!("the secret key is not valid: {e}")),
    };
    let sk = match boxed.into_secret_key(Some(password)) {
        Ok(sk) => sk,
        Err(e) => return fail(err, &format!("the password check failed: {e}")),
    };
    let bytes = match std::fs::read(&manifest) {
        Ok(data) => data,
        Err(e) => return fail(err, &format!("{}: {e}", manifest.display())),
    };
    let sig_box = match minisign::sign(
        None,
        &sk,
        &bytes[..],
        Some("offline database manifest"),
        None,
    ) {
        Ok(sig_box) => sig_box,
        Err(e) => return fail(err, &format!("signing failed: {e}")),
    };
    if let Err(e) = std::fs::write(&out, sig_box.to_string()) {
        return fail(err, &format!("{}: {e}", out.display()));
    }
    let _ = writeln!(err, "signed {} -> {}", manifest.display(), out.display());
    std::process::ExitCode::SUCCESS
}
