// SPDX-License-Identifier: GPL-3.0-or-later
//! The data-folder lock across real processes: a holder that is refused against, killed (the
//! stale lock a crash leaves) and ended cleanly. The test runs as a plain program
//! (`harness = false`) whose children are copies of itself that take the lock and wait.
#![expect(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::expect_used,
    clippy::panic,
    reason = "a plain test program: it prints its result and panics on a failed check"
)]

use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::process::{Child, Command, ExitCode, Stdio};

use puddle_fs::{DataLock, LockError};

/// The child: takes the lock on `dir`, says so, then waits until its stdin closes.
fn hold(dir: &Path) -> ExitCode {
    match DataLock::acquire(dir) {
        Ok(_lock) => {
            println!("locked");
            let mut sink = Vec::new();
            let _ = std::io::stdin().read_to_end(&mut sink);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

/// Starts a child holding `dir` and waits until it holds it.
fn spawn_holder(dir: &Path) -> Child {
    let mut child = Command::new(std::env::current_exe().expect("own path"))
        .arg("--hold")
        .arg(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("start the holder");
    let mut line = String::new();
    BufReader::new(child.stdout.as_mut().expect("piped stdout"))
        .read_line(&mut line)
        .expect("holder output");
    assert_eq!(line.trim(), "locked", "the holder did not get the lock");
    child
}

fn a_second_process_is_refused_and_told_who_holds_the_folder() {
    let dir = tempfile::tempdir().expect("temp dir");
    let mut holder = spawn_holder(dir.path());
    let err = DataLock::acquire(dir.path()).expect_err("must be refused");
    let LockError::Held { holder: pid, .. } = &err else {
        panic!("{err}");
    };
    assert_eq!(*pid, Some(holder.id()), "{err}");
    assert!(err.to_string().contains(&holder.id().to_string()), "{err}");
    holder.kill().expect("kill the holder");
    holder.wait().expect("reap the holder");
}

fn a_lock_left_by_a_killed_process_is_free_and_the_note_names_the_new_holder() {
    let dir = tempfile::tempdir().expect("temp dir");
    let mut holder = spawn_holder(dir.path());
    let dead = holder.id();
    // Killed, not asked to quit: the lock file and the note stay behind.
    holder.kill().expect("kill the holder");
    holder.wait().expect("reap the holder");
    assert!(dir.path().join("host.lock").is_file());
    assert!(dir.path().join("host.holder").is_file());

    let lock = DataLock::acquire(dir.path()).expect("a dead holder's lock is free");
    let note = std::fs::read_to_string(dir.path().join("host.holder")).expect("note");
    assert_eq!(note.trim(), std::process::id().to_string());
    assert_ne!(std::process::id(), dead);
    drop(lock);
}

fn a_process_that_exits_cleanly_frees_the_folder() {
    let dir = tempfile::tempdir().expect("temp dir");
    let mut holder = spawn_holder(dir.path());
    drop(holder.stdin.take());
    assert!(holder.wait().expect("reap the holder").success());
    drop(DataLock::acquire(dir.path()).expect("free after a clean exit"));
}

type Case = (&'static str, fn());

const CASES: &[Case] = &[
    (
        "a_second_process_is_refused_and_told_who_holds_the_folder",
        a_second_process_is_refused_and_told_who_holds_the_folder,
    ),
    (
        "a_lock_left_by_a_killed_process_is_free_and_the_note_names_the_new_holder",
        a_lock_left_by_a_killed_process_is_free_and_the_note_names_the_new_holder,
    ),
    (
        "a_process_that_exits_cleanly_frees_the_folder",
        a_process_that_exits_cleanly_frees_the_folder,
    ),
];

/// Speaks enough of the test runner protocol for `cargo test` and `nextest`: `--list` names the
/// cases (`name: test`), and the names given as arguments are the ones to run.
fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--hold") {
        return hold(Path::new(args.get(1).expect("the folder to hold")));
    }
    if args.iter().any(|a| a == "--list") {
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
