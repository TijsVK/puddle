// SPDX-License-Identifier: GPL-3.0-or-later
//! `cargo xtask runtime`: the bundled runtime folder, built in a staging folder and moved into
//! place only when every check passed, so a half-built or unverified folder never exists at `out`.
//!
//! ```text
//! <out>/msb.exe               fork release asset, checksum verified, embedded version checked
//! <out>/libkrunfw.dll         upstream release asset, checksum verified
//! <out>/runtime.json          version, tags, SHA-256 of both binaries
//! <out>/licenses/             Apache-2.0, LGPL-2.1, GPL-2.0, NOTICE, THIRD-PARTY-{msb,puddle}
//! ```

use std::path::{Path, PathBuf};

use puddle_runtime::HostOs;
use serde::Serialize;

use crate::checksums::Checksums;
use crate::error::{Result, XtaskError};
use crate::inventory::Inventory;
use crate::notice;
use crate::source::{CHECKSUMS_ASSET, LIBKRUNFW_ASSET, MSB_ASSET, Origin, ReleaseSource};

/// The licence texts shipped with every runtime.
pub const LICENCE_TEXTS: [(&str, &str); 3] = [
    ("Apache-2.0.txt", include_str!("../licenses/Apache-2.0.txt")),
    ("LGPL-2.1.txt", include_str!("../licenses/LGPL-2.1.txt")),
    ("GPL-2.0.txt", include_str!("../licenses/GPL-2.0.txt")),
];

/// What `runtime.json` records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Manifest {
    /// The embedded msb version (the fork tag without `v`).
    pub version: String,
    /// The fork tag.
    pub fork_tag: String,
    /// Upstream's base tag.
    pub upstream_tag: String,
    /// SHA-256 of `msb.exe`.
    pub msb_sha256: String,
    /// SHA-256 of `libkrunfw.dll`.
    pub libkrunfw_sha256: String,
}

/// Builds the runtime folder at `out` for the msb version `expected` (exact embedded version),
/// with `puddle` as the inventory of puddle's own tree.
///
/// # Errors
///
/// Any failed check (checksum, version, missing licence entry, existing output) or fetch; `out`
/// is left untouched.
pub fn assemble(
    source: &dyn ReleaseSource,
    expected: &str,
    puddle: &Inventory,
    out: &Path,
) -> Result<Manifest> {
    if out.exists()
        && std::fs::read_dir(out)
            .map_err(|e| XtaskError::io(format!("reading {}", out.display()), e))?
            .next()
            .is_some()
    {
        return Err(XtaskError::OutputExists(out.to_path_buf()));
    }
    let staging = sibling(out, "partial");
    if staging.exists() {
        std::fs::remove_dir_all(&staging)
            .map_err(|e| XtaskError::io(format!("removing {}", staging.display()), e))?;
    }
    let result = build(source, expected, puddle, &staging);
    match result {
        Ok(manifest) => {
            if out.exists() {
                std::fs::remove_dir(out)
                    .map_err(|e| XtaskError::io(format!("removing empty {}", out.display()), e))?;
            }
            std::fs::rename(&staging, out).map_err(|e| {
                XtaskError::io(format!("moving {} into place", staging.display()), e)
            })?;
            Ok(manifest)
        }
        Err(e) => {
            let _ = std::fs::remove_dir_all(&staging); // best effort; the build error is what matters
            Err(e)
        }
    }
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".{suffix}"));
    path.with_file_name(name)
}

fn mkdir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path)
        .map_err(|e| XtaskError::io(format!("creating {}", path.display()), e))
}

fn write(path: &Path, content: impl AsRef<[u8]>) -> Result<()> {
    std::fs::write(path, content)
        .map_err(|e| XtaskError::io(format!("writing {}", path.display()), e))
}

fn fetch_verified(
    source: &dyn ReleaseSource,
    origin: Origin,
    asset: &str,
    dir: &Path,
    list_name: &str,
) -> Result<(PathBuf, String)> {
    mkdir(dir)?;
    let sums_path = source.fetch(origin, CHECKSUMS_ASSET, dir)?;
    let sums_text = std::fs::read_to_string(&sums_path)
        .map_err(|e| XtaskError::io(format!("reading {}", sums_path.display()), e))?;
    let sums = Checksums::parse(list_name, &sums_text)?;
    let file = source.fetch(origin, asset, dir)?;
    let sha = sums.verify(asset, &file)?;
    Ok((file, sha))
}

fn build(
    source: &dyn ReleaseSource,
    expected: &str,
    puddle: &Inventory,
    staging: &Path,
) -> Result<Manifest> {
    let facts = source.facts()?;
    let downloads = staging.join(".download");
    let (msb, msb_sha256) = fetch_verified(
        source,
        Origin::Fork,
        MSB_ASSET,
        &downloads.join("fork"),
        &format!("{} {} {CHECKSUMS_ASSET}", facts.fork_repo, facts.tag),
    )?;
    let found = puddle_runtime::read_embedded_version(&msb)
        .map_err(|reason| XtaskError::parse(MSB_ASSET, reason))?;
    if found.as_deref() != Some(expected) {
        return Err(XtaskError::Version {
            expected: expected.to_owned(),
            found: found.unwrap_or_else(|| "none".into()),
        });
    }
    let (fw, libkrunfw_sha256) = fetch_verified(
        source,
        Origin::Upstream,
        LIBKRUNFW_ASSET,
        &downloads.join("upstream"),
        &format!(
            "{} {} {CHECKSUMS_ASSET}",
            facts.upstream_repo, facts.upstream_tag
        ),
    )?;
    let msb_inventory = source.msb_inventory()?;
    msb_inventory.check()?;
    puddle.check()?;

    let rename = |from: &Path, name: &str| {
        let to = staging.join(name);
        std::fs::rename(from, &to)
            .map_err(|e| XtaskError::io(format!("moving {}", from.display()), e))
    };
    // The assets are the Windows release's, whatever OS runs xtask; a Linux runtime folder is
    // not built yet and would pick its row of the table here.
    let files = HostOs::Windows.runtime_files();
    rename(&msb, files.msb)?;
    rename(&fw, files.libkrunfw)?;
    std::fs::remove_dir_all(&downloads)
        .map_err(|e| XtaskError::io(format!("removing {}", downloads.display()), e))?;

    let licenses = staging.join("licenses");
    mkdir(&licenses)?;
    for (name, text) in LICENCE_TEXTS {
        write(&licenses.join(name), text)?;
    }
    write(&licenses.join("NOTICE.txt"), notice::render(&facts))?;
    write(
        &licenses.join("THIRD-PARTY-msb.txt"),
        msb_inventory.render(&format!(
            "The Rust crates statically linked into msb.exe ({} at {}), with their licences.",
            facts.fork_repo, facts.tag
        )),
    )?;
    write(
        &licenses.join("THIRD-PARTY-puddle.txt"),
        puddle.render("The Rust crates in puddle's own programs, with their licences."),
    )?;

    let manifest = Manifest {
        version: expected.to_owned(),
        fork_tag: facts.tag,
        upstream_tag: facts.upstream_tag,
        msb_sha256,
        libkrunfw_sha256,
    };
    let json = serde_json::to_string_pretty(&manifest)
        .map_err(|e| XtaskError::parse("runtime.json", e))?;
    write(&staging.join("runtime.json"), json + "\n")?;
    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn licence_texts_are_the_real_ones() {
        let [(_, apache), (_, lgpl), (_, gpl)] = LICENCE_TEXTS;
        assert!(apache.contains("Apache License") && apache.contains("Version 2.0, January 2004"));
        assert!(
            lgpl.contains("GNU LESSER GENERAL PUBLIC LICENSE")
                && lgpl.contains("Version 2.1, February 1999")
        );
        assert!(gpl.contains("GNU GENERAL PUBLIC LICENSE") && gpl.contains("Version 2, June 1991"));
    }

    #[test]
    fn staging_sits_beside_the_output() {
        assert_eq!(
            sibling(Path::new("/a/runtime"), "partial"),
            Path::new("/a/runtime.partial")
        );
    }
}
