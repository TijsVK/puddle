// SPDX-License-Identifier: GPL-3.0-or-later
//! A user's own msb setup never leaks into puddle: their `MSB_*` variables are dropped and an
//! `msb` on `PATH` is never what runs (D-19, T-028 §1.3). nextest runs each test in its own
//! process, so changing the process environment here is safe.
#![expect(
    clippy::unwrap_used,
    reason = "fixture helpers run outside #[test] but only in tests"
)]

mod support;

use std::path::PathBuf;

use puddle_runtime::{
    BUILT_FOR, BundledRuntime, DEV_OVERRIDE_VAR, DevOverride, RuntimeEnv, RuntimeLayout,
    RuntimeVersion,
};
use support::{TempDir, fake_msb};

const USER_VARS: [(&str, &str); 7] = [
    ("MSB_PATH", "/user/bin/msb"),
    ("MSB_HOME", "/user/.microsandbox"),
    ("MSB_CONFIG_PATH", "/user/.microsandbox/config.json"),
    ("MSB_LIBKRUNFW_PATH", "/user/lib/libkrunfw.so"),
    ("MSB_AGENTD_PATH", "/user/lib/agentd"),
    ("MSB_BACKEND", "cloud"),
    ("MSB_API_URL", "https://example.invalid"),
];

#[expect(unsafe_code, reason = "tests change the process environment")]
fn set_env(name: &str, value: Option<&str>) {
    // SAFETY: nextest runs each test in its own process, and these tests start no threads.
    unsafe {
        match value {
            Some(v) => std::env::set_var(name, v),
            None => std::env::remove_var(name),
        }
    }
}

#[expect(unsafe_code, reason = "tests change the process environment")]
fn apply(env: &RuntimeEnv) {
    // SAFETY: as in `set_env`.
    unsafe { env.apply_to_process() };
}

#[test]
fn users_msb_variables_are_replaced_in_the_process() {
    let dir = TempDir::new("proc");
    let layout = RuntimeLayout::new(dir.path().join("runtime"), dir.path().join("home")).unwrap();
    std::fs::create_dir_all(layout.runtime_dir()).unwrap();
    std::fs::write(layout.msb_path(), fake_msb(Some(BUILT_FOR))).unwrap();
    std::fs::write(layout.libkrunfw_path(), b"firmware").unwrap();
    for (k, v) in USER_VARS {
        set_env(k, Some(v));
    }

    let rt = BundledRuntime::open(
        layout.clone(),
        &RuntimeVersion::built_for(),
        DevOverride::none(),
    )
    .unwrap();
    apply(&rt.env());

    let var = |k: &str| std::env::var_os(k).map(PathBuf::from);
    assert_eq!(var("MSB_PATH"), Some(layout.msb_path()));
    assert_eq!(var("MSB_HOME"), Some(layout.home().to_path_buf()));
    assert_eq!(var("MSB_CONFIG_PATH"), Some(layout.config_path()));
    for gone in [
        "MSB_LIBKRUNFW_PATH",
        "MSB_AGENTD_PATH",
        "MSB_BACKEND",
        "MSB_API_URL",
    ] {
        assert_eq!(std::env::var_os(gone), None, "{gone} survived");
    }
    // Idempotent: a second plan only replaces puddle's own three.
    let again = RuntimeEnv::plan(&layout, std::env::vars_os());
    let removed: Vec<_> = again
        .removed()
        .iter()
        .map(|n| n.to_str().unwrap())
        .collect();
    assert_eq!(removed, ["MSB_CONFIG_PATH", "MSB_HOME", "MSB_PATH"]);
}

#[test]
fn the_dev_override_variable_is_read_from_the_environment() {
    set_env(DEV_OVERRIDE_VAR, None);
    assert_eq!(DevOverride::from_env(), DevOverride::none());
    set_env(DEV_OVERRIDE_VAR, Some("yes"));
    assert_eq!(DevOverride::from_env(), DevOverride::none());
    set_env(DEV_OVERRIDE_VAR, Some("1"));
    assert_eq!(DevOverride::from_env(), DevOverride::requested());
}

/// Runs msb the way puddle does, with a user's `MSB_*` set and a fake `msb` first on `PATH`: only
/// the bundled one runs, and it sees puddle's variables, not the user's.
#[cfg(unix)]
#[test]
fn a_fake_msb_on_path_never_runs() {
    use std::ffi::OsString;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    let dir = TempDir::new("path");
    let layout = RuntimeLayout::new(dir.path().join("runtime"), dir.path().join("home")).unwrap();
    let user_bin = dir.path().join("user-bin");
    std::fs::create_dir_all(layout.runtime_dir()).unwrap();
    std::fs::create_dir_all(&user_bin).unwrap();
    let marker = dir.path().join("ran");
    let script = |who: &str| {
        format!(
            "#!/bin/sh\necho \"{who} MSB_PATH=$MSB_PATH MSB_HOME=$MSB_HOME LIBKRUNFW=${{MSB_LIBKRUNFW_PATH:-unset}} BACKEND=${{MSB_BACKEND:-unset}}\" >> '{}'\n",
            marker.display()
        )
    };
    for (path, who) in [
        (layout.msb_path(), "bundled"),
        (user_bin.join("msb"), "fake"),
    ] {
        std::fs::write(&path, script(who)).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    let mut user_env: Vec<(OsString, OsString)> = USER_VARS
        .iter()
        .map(|(k, v)| (OsString::from(k), OsString::from(v)))
        .collect();
    user_env.push(("PATH".into(), user_bin.clone().into_os_string()));
    let plan = RuntimeEnv::plan(&layout, user_env.clone());
    let mut cmd = Command::new(layout.msb_path());
    cmd.env_clear().envs(user_env);
    plan.apply_to(&mut cmd);
    assert!(cmd.status().unwrap().success());

    let log = std::fs::read_to_string(&marker).unwrap();
    assert_eq!(
        log.trim(),
        format!(
            "bundled MSB_PATH={} MSB_HOME={} LIBKRUNFW=unset BACKEND=unset",
            layout.msb_path().display(),
            layout.home().display()
        )
    );
}
