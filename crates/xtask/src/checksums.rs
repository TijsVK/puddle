// SPDX-License-Identifier: GPL-3.0-or-later
//! SHA-256 checksums: hashing files and checking them against a release's `checksums.sha256`.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::Read;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::error::{Result, XtaskError};

/// The lowercase hex SHA-256 of the file at `path`, read in chunks.
///
/// # Errors
///
/// [`XtaskError::Io`] when the file can't be read.
pub fn sha256_file(path: &Path) -> Result<String> {
    let context = || format!("hashing {}", path.display());
    let mut file = std::fs::File::open(path).map_err(|e| XtaskError::io(context(), e))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0_u8; 1 << 16];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| XtaskError::io(context(), e))?;
        let Some(chunk) = buf.get(..n).filter(|c| !c.is_empty()) else {
            break;
        };
        hasher.update(chunk);
    }
    Ok(hex(&hasher.finalize()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::with_capacity(64), |mut s, b| {
        let _ = write!(s, "{b:02x}"); // writing to a String can't fail
        s
    })
}

/// A parsed `checksums.sha256` (`sha256sum` format: `<64 hex>  <name>`, `*<name>` for binary
/// mode), keyed by file name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checksums {
    list: String,
    sums: BTreeMap<String, String>,
}

impl Checksums {
    /// Parses `text`; `list` names it in errors (e.g. `fork v0.7.7-puddle.1 checksums.sha256`).
    ///
    /// # Errors
    ///
    /// [`XtaskError::Parse`] for a malformed line or a file listed twice.
    pub fn parse(list: &str, text: &str) -> Result<Self> {
        let mut sums = BTreeMap::new();
        for (n, line) in text.lines().enumerate() {
            let line = line.trim_end_matches('\r');
            if line.trim().is_empty() {
                continue;
            }
            let bad = |why: &str| XtaskError::parse(list, format!("line {}: {why}", n + 1));
            let (sum, name) = line
                .split_once(char::is_whitespace)
                .ok_or_else(|| bad("no file name"))?;
            let name = name.trim_start();
            let name = name.strip_prefix('*').unwrap_or(name);
            if sum.len() != 64 || !sum.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(bad("not a SHA-256"));
            }
            if name.is_empty() {
                return Err(bad("no file name"));
            }
            if sums
                .insert(name.to_owned(), sum.to_ascii_lowercase())
                .is_some()
            {
                return Err(bad("file listed twice"));
            }
        }
        Ok(Self {
            list: list.to_owned(),
            sums,
        })
    }

    /// Checks that the file at `path` has the checksum listed for `name`; returns it.
    ///
    /// # Errors
    ///
    /// [`XtaskError::NotListed`], [`XtaskError::Checksum`], or [`XtaskError::Io`].
    pub fn verify(&self, name: &str, path: &Path) -> Result<String> {
        let expected = self.sums.get(name).ok_or_else(|| XtaskError::NotListed {
            file: name.to_owned(),
            list: self.list.clone(),
        })?;
        let actual = sha256_file(path)?;
        if &actual == expected {
            Ok(actual)
        } else {
            Err(XtaskError::Checksum {
                file: name.to_owned(),
                list: self.list.clone(),
                expected: expected.clone(),
                actual,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMPTY_SHA: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn temp_file(content: &[u8]) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "xtask-sum-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn hashes_files() {
        let empty = temp_file(b"");
        assert_eq!(sha256_file(&empty).unwrap(), EMPTY_SHA);
        let abc = temp_file(b"abc");
        assert_eq!(
            sha256_file(&abc).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        std::fs::remove_file(empty).unwrap();
        std::fs::remove_file(abc).unwrap();
        assert!(sha256_file(Path::new("/nonexistent/xtask/file")).is_err());
    }

    #[test]
    fn parses_sha256sum_output() {
        let upper = EMPTY_SHA.to_ascii_uppercase();
        let text = format!("{EMPTY_SHA}  a.exe\r\n\n{upper} *b.dll\n");
        let sums = Checksums::parse("list", &text).unwrap();
        assert_eq!(sums.sums.get("a.exe").map(String::as_str), Some(EMPTY_SHA));
        assert_eq!(sums.sums.get("b.dll").map(String::as_str), Some(EMPTY_SHA));
    }

    #[test]
    fn rejects_malformed_lists() {
        for bad in [
            "abc  a.exe",
            EMPTY_SHA,
            &format!("{EMPTY_SHA}  "),
            &format!("{}  a.exe", "g".repeat(64)),
            &format!("{EMPTY_SHA}  a.exe\n{EMPTY_SHA}  a.exe"),
        ] {
            assert!(Checksums::parse("list", bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn verifies_and_names_the_mismatch() {
        let file = temp_file(b"");
        let sums = Checksums::parse(
            "fork checksums",
            &format!("{EMPTY_SHA}  ok\n{}  bad\n", "0".repeat(64)),
        )
        .unwrap();
        assert_eq!(sums.verify("ok", &file).unwrap(), EMPTY_SHA);
        let err = sums.verify("bad", &file).unwrap_err().to_string();
        assert!(
            err.contains("bad") && err.contains("fork checksums") && err.contains(EMPTY_SHA),
            "{err}"
        );
        let err = sums.verify("missing", &file).unwrap_err().to_string();
        assert_eq!(err, "missing has no entry in fork checksums");
        std::fs::remove_file(file).unwrap();
    }
}
