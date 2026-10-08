// SPDX-License-Identifier: GPL-3.0-or-later
//! A stand-in for `gh` and `git`, for the source tests.
//!
//! The tests copy this binary to a temporary directory under the name of the real tool and write
//! `<binary path>.behaviour` next to it. The behaviour file is a list of sections:
//!
//! ```text
//! [credential fill]      <- used when the arguments contain this text; `[]` matches always
//! exit=0
//! sleep_ms=0
//! echo_stdin=1           <- print the standard input first
//! stdout=password=x\n    <- `\n` is a newline
//! stderr=code\n         <- printed (and flushed) before the sleep, as `gh` prints its prompt
//! ```
//!
//! Every call appends the arguments, the standard input and the prompt-related environment to
//! `<binary path>.log`, so a test can check what puddle sent.
#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::expect_used,
    reason = "a command-line stand-in answers on standard output"
)]

use std::io::{Read, Write};

fn unescape(s: &str) -> String {
    s.replace("\\n", "\n")
}

fn main() {
    let exe = std::env::current_exe().expect("own path");
    let behaviour =
        std::fs::read_to_string(format!("{}.behaviour", exe.display())).unwrap_or_default();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let joined = args.join(" ");
    let mut stdin = String::new();
    let _ = std::io::stdin().read_to_string(&mut stdin);

    let mut log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(format!("{}.log", exe.display()))
        .expect("log");
    let env = |k: &str| std::env::var(k).unwrap_or_else(|_| "<unset>".to_owned());
    let _ = writeln!(
        log,
        "ARGS {joined}\nSTDIN {}\nENV GCM_INTERACTIVE={} GIT_TERMINAL_PROMPT={} GIT_ASKPASS={} GH_TOKEN={} GH_PROMPT_DISABLED={}",
        stdin.replace('\n', "\\n"),
        env("GCM_INTERACTIVE"),
        env("GIT_TERMINAL_PROMPT"),
        env("GIT_ASKPASS"),
        env("GH_TOKEN"),
        env("GH_PROMPT_DISABLED"),
    );

    let (mut exit, mut sleep_ms, mut echo) = (0, 0, false);
    let (mut stdout, mut stderr) = (String::new(), String::new());
    let mut active = false;
    for line in behaviour.lines() {
        if let Some(rest) = line.strip_prefix('[') {
            let needle = rest.trim_end_matches(']');
            active = needle.is_empty() || joined.contains(needle);
            if active {
                (exit, sleep_ms, echo) = (0, 0, false);
                (stdout, stderr) = (String::new(), String::new());
            }
        } else if active {
            match line.split_once('=') {
                Some(("exit", v)) => exit = v.parse().unwrap_or(1),
                Some(("sleep_ms", v)) => sleep_ms = v.parse().unwrap_or(0),
                Some(("echo_stdin", v)) => echo = v == "1",
                Some(("stdout", v)) => stdout = unescape(v),
                Some(("stderr", v)) => stderr = unescape(v),
                _ => {}
            }
        }
    }
    eprint!("{stderr}");
    let _ = std::io::stderr().flush();
    if sleep_ms > 0 {
        std::thread::sleep(std::time::Duration::from_millis(sleep_ms));
    }
    if echo {
        print!("{stdin}");
    }
    print!("{stdout}");
    let _ = std::io::stdout().flush();
    std::process::exit(exit);
}
