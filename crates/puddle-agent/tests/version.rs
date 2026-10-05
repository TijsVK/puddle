// SPDX-License-Identifier: GPL-3.0-or-later
//! Integration test: the built agent binary reports its version.

use std::process::Command;

#[test]
fn prints_version_line() {
    let out = Command::new(env!("CARGO_BIN_EXE_puddle-agent"))
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(
        String::from_utf8(out.stdout).unwrap().trim_end(),
        format!("puddle-agent {}", puddle_types::VERSION)
    );
}
