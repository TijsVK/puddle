// SPDX-License-Identifier: GPL-3.0-or-later
//! `cargo xtask runtime` against a fixture release: the folder it builds, and every check that
//! must stop it (checksum, version, missing licence entry, existing output).
#![expect(
    clippy::unwrap_used,
    reason = "fixture helpers run outside #[test] but only in tests"
)]

use std::path::{Path, PathBuf};

use object::write::{Object, StandardSection};
use object::{Architecture, BinaryFormat, Endianness, SectionKind};
use puddle_runtime::{HostOs, RuntimeFiles};
use xtask::checksums::sha256_file;
use xtask::source::{CHECKSUMS_ASSET, Commit, Firmware, ForkFacts, LIBKRUNFW_ASSET, MSB_ASSET};

const VERSION: &str = "0.7.7-puddle.3";

/// The assembled folder is the Windows runtime, whatever OS runs the test.
const WIN: RuntimeFiles = HostOs::Windows.runtime_files();

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "xtask-runtime-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn fake_msb(version: &str) -> Vec<u8> {
    let mut obj = Object::new(BinaryFormat::Coff, Architecture::X86_64, Endianness::Little);
    let text = obj.section_id(StandardSection::Text);
    obj.append_section_data(text, &[0xc3], 1);
    let id = obj.add_section(Vec::new(), b".msbver".to_vec(), SectionKind::ReadOnlyData);
    obj.append_section_data(id, version.as_bytes(), 1);
    obj.write().unwrap()
}

fn tree(crates: &[(&str, &str)]) -> String {
    let lines: Vec<String> = crates.iter().map(|(n, v)| format!("{n} v{v}")).collect();
    format!("root v0.0.0 (/work/root)\n{}\n", lines.join("\n"))
}

fn about(licence: &str, crates: &[(&str, &str)]) -> String {
    let used_by: Vec<_> = crates
        .iter()
        .map(|(n, v)| serde_json::json!({"crate": {"name": n, "version": v, "repository": null}, "path": ""}))
        .collect();
    serde_json::json!({"licenses": [{"name": format!("{licence} licence"), "id": licence, "text": format!("{licence} TEXT with copyright"), "used_by": used_by}]}).to_string()
}

/// A complete fixture release in `<dir>/src`.
fn fixture(dir: &Path, embedded: &str) -> PathBuf {
    let src = dir.join("src");
    for sub in ["fork", "upstream"] {
        std::fs::create_dir_all(src.join(sub)).unwrap();
    }
    let msb = src.join("fork").join(MSB_ASSET);
    std::fs::write(&msb, fake_msb(embedded)).unwrap();
    std::fs::write(
        src.join("fork").join(CHECKSUMS_ASSET),
        format!("{}  {MSB_ASSET}\n", sha256_file(&msb).unwrap()),
    )
    .unwrap();
    let fw = src.join("upstream").join(LIBKRUNFW_ASSET);
    std::fs::write(&fw, b"firmware bytes").unwrap();
    std::fs::write(
        src.join("upstream").join(CHECKSUMS_ASSET),
        format!(
            "{}  agentd-x86_64\n{}  {LIBKRUNFW_ASSET}\n",
            "0".repeat(64),
            sha256_file(&fw).unwrap()
        ),
    )
    .unwrap();
    let facts = ForkFacts {
        fork_repo: "TijsVK/microsandbox".into(),
        upstream_repo: "superradcompany/microsandbox".into(),
        tag: format!("v{VERSION}"),
        upstream_tag: "v0.7.7".into(),
        commits: vec![Commit {
            sha: "c".repeat(40),
            subject: "fix(vsock): tail loss".into(),
        }],
        firmware: Firmware {
            libkrunfw_version: "5.6.1".into(),
            kernel_version: "6.12.109".into(),
            repo_url: "https://github.com/superradcompany/libkrunfw".into(),
            commit: "d".repeat(40),
        },
    };
    std::fs::write(
        src.join("facts.json"),
        serde_json::to_string(&facts).unwrap(),
    )
    .unwrap();
    let msb_crates = [("tokio", "1.0.0"), ("aws-lc-sys", "0.30.0")];
    std::fs::write(src.join("msb-tree.txt"), tree(&msb_crates)).unwrap();
    std::fs::write(src.join("msb-about.json"), about("MIT", &msb_crates)).unwrap();
    let puddle_crates = [("thiserror", "2.0.0")];
    std::fs::write(src.join("puddle-tree.txt"), tree(&puddle_crates)).unwrap();
    std::fs::write(
        src.join("puddle-about.json"),
        about("Apache-2.0", &puddle_crates),
    )
    .unwrap();
    src
}

fn run(src: &Path, out: &Path) -> xtask::Result<String> {
    xtask::run(
        [
            "runtime",
            "--tag",
            &format!("v{VERSION}"),
            "--from",
            src.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
            "--offline",
        ]
        .map(Into::into),
    )
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap()
}

#[test]
fn builds_the_runtime_folder_with_licences() {
    let dir = TempDir::new("ok");
    let src = fixture(&dir.0, VERSION);
    let out = dir.0.join("runtime");
    let msg = run(&src, &out).unwrap();
    assert!(msg.contains(VERSION), "{msg}");

    let mut names: Vec<String> = std::fs::read_dir(&out)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(names, [WIN.libkrunfw, "licenses", WIN.msb, "runtime.json"]);
    let mut licences: Vec<String> = std::fs::read_dir(out.join("licenses"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    licences.sort();
    assert_eq!(
        licences,
        [
            "Apache-2.0.txt",
            "GPL-2.0.txt",
            "LGPL-2.1.txt",
            "NOTICE.txt",
            "THIRD-PARTY-msb.txt",
            "THIRD-PARTY-puddle.txt"
        ]
    );

    assert_eq!(std::fs::read(out.join(WIN.msb)).unwrap(), fake_msb(VERSION));
    assert_eq!(
        puddle_runtime::read_embedded_version(&out.join(WIN.msb))
            .unwrap()
            .as_deref(),
        Some(VERSION)
    );
    let manifest: serde_json::Value =
        serde_json::from_str(&read(&out.join("runtime.json"))).unwrap();
    assert_eq!(manifest["version"], VERSION);
    assert_eq!(manifest["fork_tag"], format!("v{VERSION}"));
    assert_eq!(manifest["upstream_tag"], "v0.7.7");
    assert_eq!(
        manifest["msb_sha256"],
        sha256_file(&out.join(WIN.msb)).unwrap()
    );
    assert_eq!(
        manifest["libkrunfw_sha256"],
        sha256_file(&out.join(WIN.libkrunfw)).unwrap()
    );

    let notice = read(&out.join("licenses/NOTICE.txt"));
    assert!(notice.contains(&format!("{} fix(vsock): tail loss", "c".repeat(40))));
    assert!(notice.contains("Written offer"));
    let msb_notices = read(&out.join("licenses/THIRD-PARTY-msb.txt"));
    assert!(
        msb_notices.contains("aws-lc-sys 0.30.0")
            && msb_notices.contains("MIT TEXT with copyright")
    );
    let puddle_notices = read(&out.join("licenses/THIRD-PARTY-puddle.txt"));
    assert!(puddle_notices.contains("thiserror 2.0.0"));
    assert!(
        !dir.0.join("runtime.partial").exists(),
        "staging folder left behind"
    );
}

fn assert_fails_cleanly(dir: &TempDir, src: &Path, needle: &str) {
    let out = dir.0.join("runtime");
    let err = run(src, &out).unwrap_err().to_string();
    assert!(err.contains(needle), "expected {needle:?} in: {err}");
    assert!(!out.exists(), "a failed build left {}", out.display());
    assert!(
        !dir.0.join("runtime.partial").exists(),
        "staging folder left behind"
    );
}

#[test]
fn a_corrupted_msb_is_refused() {
    let dir = TempDir::new("corrupt");
    let src = fixture(&dir.0, VERSION);
    let mut bytes = std::fs::read(src.join("fork").join(MSB_ASSET)).unwrap();
    bytes.push(0);
    std::fs::write(src.join("fork").join(MSB_ASSET), bytes).unwrap();
    assert_fails_cleanly(&dir, &src, &format!("checksum mismatch for {MSB_ASSET}"));
}

#[test]
fn a_corrupted_firmware_is_refused() {
    let dir = TempDir::new("corruptfw");
    let src = fixture(&dir.0, VERSION);
    std::fs::write(src.join("upstream").join(LIBKRUNFW_ASSET), b"tampered").unwrap();
    assert_fails_cleanly(
        &dir,
        &src,
        &format!("checksum mismatch for {LIBKRUNFW_ASSET}"),
    );
}

#[test]
fn an_unlisted_asset_is_refused() {
    let dir = TempDir::new("unlisted");
    let src = fixture(&dir.0, VERSION);
    std::fs::write(src.join("fork").join(CHECKSUMS_ASSET), "").unwrap();
    assert_fails_cleanly(&dir, &src, &format!("{MSB_ASSET} has no entry in"));
}

#[test]
fn an_msb_of_another_version_is_refused_naming_both() {
    let dir = TempDir::new("version");
    let src = fixture(&dir.0, "0.7.7");
    assert_fails_cleanly(
        &dir,
        &src,
        &format!("downloaded msb is version 0.7.7, but the runtime folder is for {VERSION}"),
    );
}

#[test]
fn a_msb_dependency_without_licence_entry_fails() {
    let dir = TempDir::new("msblicence");
    let src = fixture(&dir.0, VERSION);
    std::fs::write(
        src.join("msb-about.json"),
        about("MIT", &[("tokio", "1.0.0")]),
    )
    .unwrap();
    assert_fails_cleanly(
        &dir,
        &src,
        "no licence entry in the msb notices for: aws-lc-sys 0.30.0",
    );
}

#[test]
fn a_puddle_dependency_without_licence_entry_fails() {
    let dir = TempDir::new("puddlelicence");
    let src = fixture(&dir.0, VERSION);
    std::fs::write(src.join("puddle-about.json"), about("MIT", &[])).unwrap();
    assert_fails_cleanly(
        &dir,
        &src,
        "no licence entry in the puddle notices for: thiserror 2.0.0",
    );
}

#[test]
fn an_existing_output_is_never_overwritten() {
    let dir = TempDir::new("exists");
    let src = fixture(&dir.0, VERSION);
    let out = dir.0.join("runtime");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(out.join("keep.txt"), "mine").unwrap();
    let err = run(&src, &out).unwrap_err().to_string();
    assert!(err.contains("exists and is not empty"), "{err}");
    assert_eq!(read(&out.join("keep.txt")), "mine");
}

#[test]
fn an_empty_output_folder_is_fine_and_a_stale_staging_folder_is_replaced() {
    let dir = TempDir::new("empty");
    let src = fixture(&dir.0, VERSION);
    let out = dir.0.join("runtime");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::create_dir_all(dir.0.join("runtime.partial/old")).unwrap();
    run(&src, &out).unwrap();
    assert!(out.join(WIN.msb).is_file());
    assert!(!out.join("old").exists());
}

#[test]
fn a_missing_part_is_an_io_error() {
    let dir = TempDir::new("missing");
    let src = fixture(&dir.0, VERSION);
    std::fs::remove_file(src.join("facts.json")).unwrap();
    assert_fails_cleanly(&dir, &src, "facts.json");
}
