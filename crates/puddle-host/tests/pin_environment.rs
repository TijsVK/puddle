// SPDX-License-Identifier: GPL-3.0-or-later
//! Pinning the process environment, which must happen before the process has a second thread.
//! The test harness always has one, so this binary has none (`harness = false`) and runs each
//! case in a child process of itself.
#![expect(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::expect_used,
    reason = "a plain test program: it prints its result and exits with a status"
)]

use std::path::PathBuf;
use std::process::{Command, ExitCode};

use puddle_host::{HostError, Platform, SystemPlatform};
use puddle_runtime::RuntimeLayout;

fn layout() -> RuntimeLayout {
    let root = std::env::temp_dir().join("puddle-pin-environment-test");
    RuntimeLayout::new(root.join("runtime"), root.join("home")).expect("absolute folders")
}

/// The child: pins, then prints what the environment holds.
fn child(threads: bool) -> ExitCode {
    let _keep = threads
        .then(|| std::thread::spawn(|| std::thread::sleep(std::time::Duration::from_secs(5))));
    match SystemPlatform::new().pin_environment(&layout()) {
        Ok(()) => {
            for name in [
                "MSB_PATH",
                "MSB_HOME",
                "MSB_CONFIG_PATH",
                "MSB_BACKEND",
                "KEEP_ME",
            ] {
                println!(
                    "{name}={}",
                    std::env::var(name).unwrap_or_else(|_| "<unset>".into())
                );
            }
            ExitCode::SUCCESS
        }
        Err(HostError::EnvironmentTooLate) => {
            println!("too-late");
            ExitCode::from(3)
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn run_child(arg: &str) -> (std::process::ExitStatus, String) {
    let exe: PathBuf = std::env::current_exe().expect("own path");
    let out = Command::new(exe)
        .arg(arg)
        .env("MSB_BACKEND", "cloud")
        .env("MSB_PATH", "/user/msb")
        .env("KEEP_ME", "yes")
        .output()
        .expect("run the child");
    (
        out.status,
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

/// A case: its name as the test runner lists it, and the body.
type Case = (&'static str, fn());

fn pins_the_environment_before_any_thread() {
    let (status, out) = run_child("--child");
    assert!(status.success(), "{out}");
    let home = layout().home().display().to_string();
    assert!(out.contains("MSB_BACKEND=<unset>"), "{out}");
    assert!(out.contains("KEEP_ME=yes"), "{out}");
    assert!(out.contains(&format!("MSB_HOME={home}")), "{out}");
    assert!(!out.contains("/user/msb"), "{out}");
}

#[cfg(target_os = "linux")]
fn refuses_once_another_thread_runs() {
    let (status, out) = run_child("--child-threads");
    assert_eq!(status.code(), Some(3), "{out}");
    assert!(out.contains("too-late"), "{out}");
}

#[cfg(target_os = "linux")]
const CASES: &[Case] = &[
    (
        "pins_the_environment_before_any_thread",
        pins_the_environment_before_any_thread,
    ),
    (
        "refuses_once_another_thread_runs",
        refuses_once_another_thread_runs,
    ),
];

#[cfg(not(target_os = "linux"))]
const CASES: &[Case] = &[(
    "pins_the_environment_before_any_thread",
    pins_the_environment_before_any_thread,
)];

/// Speaks enough of the test runner protocol for `cargo test` and `nextest`: `--list` names the
/// cases (`name: test`), and the names given as arguments (with `--exact`) are the ones to run.
fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--child") => return child(false),
        Some("--child-threads") => return child(true),
        _ => {}
    }
    if args.iter().any(|a| a == "--list") {
        // `--ignored --list` asks for the ignored ones: there are none.
        if !args.iter().any(|a| a == "--ignored") {
            for (name, _) in CASES {
                println!("{name}: test");
            }
        }
        return ExitCode::SUCCESS;
    }
    let wanted: Vec<&String> = args.iter().filter(|a| !a.starts_with("--")).collect();
    for (name, body) in CASES {
        if wanted.is_empty() || wanted.iter().any(|w| name.contains(w.as_str())) {
            body();
            println!("test {name} ... ok");
        }
    }
    ExitCode::SUCCESS
}
