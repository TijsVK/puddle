// SPDX-License-Identifier: GPL-3.0-or-later
//! Housekeeping of msb's per-sandbox log files (`sandboxes/<name>/logs/`).

use std::path::Path;

/// Copies the files of `from` into `to`, best effort: a sandbox that never got a log directory
/// has nothing to keep, and a failed copy must not fail the removal it belongs to.
pub(crate) fn keep(from: &Path, to: &Path) {
    let Ok(entries) = std::fs::read_dir(from) else {
        return;
    };
    if std::fs::create_dir_all(to).is_err() {
        return;
    }
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        if path.is_file() {
            let _ = std::fs::copy(&path, to.join(entry.file_name()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("puddle-msb-logs-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn keep_copies_the_files_and_tolerates_a_missing_dir() {
        let d = dir("keep");
        let from = d.join("sb").join("logs");
        std::fs::create_dir_all(from.join("nested")).unwrap();
        std::fs::write(from.join("runtime.log"), b"vmm").unwrap();
        std::fs::write(from.join("kernel.log"), b"").unwrap();
        let to = d.join("kept").join("sb").join("logs");
        keep(&from, &to);
        assert_eq!(std::fs::read(to.join("runtime.log")).unwrap(), b"vmm");
        assert!(to.join("kernel.log").is_file());
        assert!(!to.join("nested").exists());
        let none = d.join("kept").join("never-booted");
        keep(&d.join("missing"), &none);
        assert!(!none.exists());
        std::fs::remove_dir_all(&d).unwrap();
    }
}
