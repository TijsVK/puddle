// SPDX-License-Identifier: GPL-3.0-or-later
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code: a panic is how a test fails"
)]
#![allow(dead_code, reason = "each test binary uses part of this")]
//! Shared by the source tests: fake `gh` and `git` executables.

use std::path::{Path, PathBuf};

pub(crate) const CANARY: &str = "CANARY-7f3a91";

/// A directory holding fake `gh` and `git`, each with its behaviour file.
pub(crate) struct Fakes {
    pub(crate) dir: tempfile::TempDir,
}

impl Fakes {
    pub(crate) fn new() -> Self {
        // Next to the fake binary, so a hard link works: on Linux a copy is written through a file
        // handle that a concurrently forking thread can inherit, and that makes the exec fail.
        let beside = Path::new(env!("CARGO_BIN_EXE_puddle-fake-tool"))
            .parent()
            .unwrap();
        Self {
            dir: tempfile::tempdir_in(beside).unwrap(),
        }
    }

    pub(crate) fn install(&self, tool: &str, behaviour: &str) -> PathBuf {
        let name = if cfg!(windows) {
            format!("{tool}.exe")
        } else {
            tool.to_owned()
        };
        let path = self.dir.path().join(name);
        let source = env!("CARGO_BIN_EXE_puddle-fake-tool");
        // A hard link avoids writing to an executable another test may be starting.
        if std::fs::hard_link(source, &path).is_err() {
            std::fs::copy(source, &path).unwrap();
        }
        std::fs::write(format!("{}.behaviour", path.display()), behaviour).unwrap();
        path
    }

    pub(crate) fn log(path: &Path) -> String {
        std::fs::read_to_string(format!("{}.log", path.display())).unwrap_or_default()
    }
}
