// SPDX-License-Identifier: GPL-3.0-or-later
//! Integration test: `puddle-agent merge-file` as the boot hook calls it.
#![cfg(unix)]
#![expect(
    clippy::unwrap_used,
    reason = "helpers outside #[test] fns, only in tests"
)]

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use puddle_types::{MergeEntry, MergeFormat, MergeSpec};

fn agent(args: &[&str], stdin: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_puddle-agent"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    child.wait_with_output().unwrap()
}

fn tmp() -> PathBuf {
    let p = std::env::temp_dir().join(format!("puddle-agent-merge-{}", std::process::id()));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

#[test]
fn apply_and_remove_print_one_word_and_keep_the_users_keys() {
    let dir = tmp();
    let state = dir.join("state");
    let file = dir.join("config.json");
    std::fs::write(&file, "{\"auths\": {}}\n").unwrap();
    let spec = serde_json::to_vec(
        &MergeSpec::new(
            MergeFormat::Json,
            vec![MergeEntry::json(
                &["proxies", "default"],
                &serde_json::json!({"httpProxy": "http://p"}),
            )],
        )
        .unwrap(),
    )
    .unwrap();
    let apply = [
        "merge-file",
        "apply",
        s(&state),
        "/c.json",
        s(&file),
        "0644",
    ];
    let out = agent(&apply, &spec);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"changed\n");
    assert_eq!(
        std::fs::read_to_string(&file).unwrap(),
        "{\"auths\": {}, \"proxies\": {\"default\":{\"httpProxy\":\"http://p\"}}}\n"
    );
    assert_eq!(agent(&apply, &spec).stdout, b"unchanged\n");
    let out = agent(
        &["merge-file", "remove", s(&state), "/c.json", s(&file)],
        b"",
    );
    assert_eq!(out.stdout, b"changed\n");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "{\"auths\": {}}\n");

    // A bad spec is an error (exit 1), bad usage exits 2.
    let out = agent(&apply, b"nope");
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("bad merge spec"));
    assert_eq!(agent(&["merge-file", "apply"], b"").status.code(), Some(2));
    std::fs::remove_dir_all(&dir).unwrap();
}
