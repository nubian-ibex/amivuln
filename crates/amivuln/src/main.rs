// SPDX-FileCopyrightText: 2026 amivuln contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! amivuln binary entry point.

#![forbid(unsafe_code)]

use std::io::Write;

use amivuln::app::{Env, run};

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args_os()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let env = Env::from_process();
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();
    let mut out = std::io::BufWriter::new(stdout.lock());
    let mut err = stderr.lock();
    let code = run(&args, &env, &mut out, &mut err);
    let _ = out.flush();
    // The exit codes are 0..=70, so the cast cannot truncate.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    std::process::ExitCode::from(code as u8)
}
