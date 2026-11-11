// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Negative tests: the confined child cannot write, read outside its
//! allowance or reach the network, and a hung child is killed.

#![allow(clippy::expect_used)]

use std::path::Path;
use std::time::Duration;

use amivuln_sandbox::{SandboxError, probe, supported};

const SH: &str = "/bin/sh";
const WAIT: Duration = Duration::from_secs(5);

fn run(script: &str) -> String {
    let out = probe(Path::new(SH), &["-c", script], WAIT).expect("probe runs");
    String::from_utf8_lossy(&out.output).into_owned()
}

#[test]
fn allowed_commands_still_work() {
    if !supported() {
        return;
    }
    assert!(run("echo hello").contains("hello"));
}

#[test]
fn writes_are_denied() {
    if !supported() {
        return;
    }
    let target = std::env::temp_dir().join("amivuln-sandbox-write-test");
    let _ = std::fs::remove_file(&target);
    let script = format!(
        "if echo x > {} ; then echo WROTE; else echo DENIED; fi",
        target.display()
    );
    let out = run(&script);
    assert!(out.contains("DENIED"), "{out}");
    assert!(!target.exists());
}

#[test]
fn reads_outside_the_allowance_are_denied() {
    if !supported() {
        return;
    }
    let out = run("if read x < /etc/passwd; then echo READ; else echo DENIED; fi");
    assert!(out.contains("DENIED"), "{out}");
}

#[test]
fn the_network_is_denied() {
    if !supported() || !Path::new("/usr/bin/bash").exists() {
        return;
    }
    let out = probe(
        Path::new("/usr/bin/bash"),
        &[
            "-c",
            "if exec 3<>/dev/tcp/127.0.0.1/9; then echo OPEN; else echo DENIED; fi",
        ],
        WAIT,
    )
    .expect("probe runs");
    let text = String::from_utf8_lossy(&out.output);
    assert!(text.contains("DENIED"), "{text}");
    assert!(text.contains("not permitted"), "{text}");
}

#[test]
fn a_hung_child_is_killed() {
    if !supported() {
        return;
    }
    let r = probe(
        Path::new("/usr/bin/sleep"),
        &["30"],
        Duration::from_millis(300),
    );
    assert_eq!(r, Err(SandboxError::TimedOut));
}

#[test]
fn relative_paths_are_refused() {
    let r = probe(Path::new("sh"), &[], WAIT);
    assert!(matches!(r, Err(SandboxError::InvalidTarget(_))));
}
