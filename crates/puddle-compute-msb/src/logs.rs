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

/// Moves `runtime.log` in `logs` to `runtime.log.1` (replacing an older one) when it has grown
/// past `cap` bytes. msb rotates it itself on Linux and macOS but only appends on Windows. Call
/// it while the sandbox is down; best effort.
pub(crate) fn cap_runtime_log(logs: &Path, cap: u64) {
    let log = logs.join("runtime.log");
    if std::fs::metadata(&log).is_ok_and(|m| m.len() > cap) {
        let _ = std::fs::rename(&log, logs.join("runtime.log.1"));
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

    #[test]
    fn a_runtime_log_past_the_cap_moves_aside_and_replaces_the_older_one() {
        let d = dir("cap");
        std::fs::write(d.join("runtime.log"), b"0123456789").unwrap();
        std::fs::write(d.join("runtime.log.1"), b"older").unwrap();
        cap_runtime_log(&d, 10);
        assert_eq!(std::fs::read(d.join("runtime.log")).unwrap(), b"0123456789");
        cap_runtime_log(&d, 9);
        assert!(!d.join("runtime.log").exists());
        assert_eq!(
            std::fs::read(d.join("runtime.log.1")).unwrap(),
            b"0123456789"
        );
        cap_runtime_log(&d.join("missing"), 0);
        std::fs::remove_dir_all(&d).unwrap();
    }
}
