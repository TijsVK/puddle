// SPDX-License-Identifier: GPL-3.0-or-later
//! Opening the bundled runtime: present, readable, exactly the pinned version.
#![expect(
    clippy::unwrap_used,
    reason = "fixture helpers run outside #[test] but only in tests"
)]

mod support;

use puddle_runtime::{
    BUILT_FOR, BundledRuntime, DevOverride, RuntimeError, RuntimeLayout, RuntimeVersion,
    VersionStatus,
};
use support::{TempDir, fake_msb};

fn layout_with(dir: &TempDir, msb: Option<&[u8]>) -> RuntimeLayout {
    let layout = RuntimeLayout::new(dir.path().join("runtime"), dir.path().join("home")).unwrap();
    std::fs::create_dir_all(layout.runtime_dir()).unwrap();
    if let Some(bytes) = msb {
        std::fs::write(layout.msb_path(), bytes).unwrap();
    }
    std::fs::write(layout.libkrunfw_path(), b"firmware").unwrap();
    layout
}

#[test]
fn the_pinned_version_opens() {
    let dir = TempDir::new("open");
    let layout = layout_with(&dir, Some(&fake_msb(Some(BUILT_FOR))));
    let rt = BundledRuntime::open(
        layout.clone(),
        &RuntimeVersion::built_for(),
        DevOverride::none(),
    )
    .unwrap();
    assert_eq!(rt.status(), &VersionStatus::Exact);
    assert_eq!(rt.layout(), &layout);
    assert_eq!(rt.command().get_program(), layout.msb_path().as_os_str());
}

#[test]
fn a_mismatch_is_refused_naming_both_versions() {
    let dir = TempDir::new("mismatch");
    let expected: RuntimeVersion = "0.7.7-puddle.2".parse().unwrap();
    for found in ["0.7.7", "0.7.7-puddle.1", "0.7.8-puddle.2"] {
        let layout = layout_with(&dir, Some(&fake_msb(Some(found))));
        let err = BundledRuntime::open(layout.clone(), &expected, DevOverride::none()).unwrap_err();
        assert_eq!(
            err,
            RuntimeError::Mismatch {
                path: layout.msb_path(),
                expected: "0.7.7-puddle.2".into(),
                found: found.into(),
            }
        );
        let msg = err.to_string();
        assert!(
            msg.contains(found) && msg.contains("0.7.7-puddle.2"),
            "{msg}"
        );
    }
}

#[test]
fn a_binary_without_version_is_refused() {
    let dir = TempDir::new("nover");
    let layout = layout_with(&dir, Some(&fake_msb(None)));
    let err = BundledRuntime::open(layout, &RuntimeVersion::built_for(), DevOverride::none())
        .unwrap_err();
    assert!(matches!(err, RuntimeError::NoVersion { ref expected, .. } if expected == BUILT_FOR));
    assert!(err.to_string().contains("no embedded version"));
}

#[test]
fn a_missing_or_unreadable_binary_is_refused() {
    let dir = TempDir::new("missing");
    let layout = layout_with(&dir, None);
    let err = BundledRuntime::open(
        layout.clone(),
        &RuntimeVersion::built_for(),
        DevOverride::none(),
    )
    .unwrap_err();
    assert_eq!(
        err,
        RuntimeError::Missing {
            path: layout.msb_path()
        }
    );
    assert!(err.to_string().contains("reinstall"));

    let layout = layout_with(&dir, Some(b"MZ not really a binary"));
    let err = BundledRuntime::open(layout, &RuntimeVersion::built_for(), DevOverride::none())
        .unwrap_err();
    assert!(matches!(err, RuntimeError::Unreadable { .. }), "{err:?}");
}

#[test]
fn a_directory_named_msb_is_missing_not_unreadable() {
    let dir = TempDir::new("dir");
    let layout = layout_with(&dir, None);
    std::fs::create_dir_all(layout.msb_path()).unwrap();
    let err = BundledRuntime::open(layout, &RuntimeVersion::built_for(), DevOverride::none())
        .unwrap_err();
    assert!(matches!(err, RuntimeError::Missing { .. }));
}

#[test]
fn the_dev_override_accepts_a_mismatch_only_when_compiled_in() {
    let dir = TempDir::new("override");
    let layout = layout_with(&dir, Some(&fake_msb(Some("0.9.0"))));
    let got = BundledRuntime::open(
        layout,
        &RuntimeVersion::built_for(),
        DevOverride::requested(),
    );
    if puddle_runtime::DEV_OVERRIDE_COMPILED {
        assert_eq!(
            got.unwrap().status(),
            &VersionStatus::Overridden {
                found: Some("0.9.0".into())
            }
        );
    } else {
        assert!(matches!(got, Err(RuntimeError::Mismatch { .. })));
    }
}

#[cfg(windows)]
#[test]
fn a_missing_firmware_library_is_refused_on_windows() {
    let dir = TempDir::new("nofw");
    let layout = layout_with(&dir, Some(&fake_msb(Some(BUILT_FOR))));
    std::fs::remove_file(layout.libkrunfw_path()).unwrap();
    let err = BundledRuntime::open(
        layout.clone(),
        &RuntimeVersion::built_for(),
        DevOverride::none(),
    )
    .unwrap_err();
    assert_eq!(
        err,
        RuntimeError::Missing {
            path: layout.libkrunfw_path()
        }
    );
}
