// SPDX-License-Identifier: GPL-3.0-or-later
//! The boot hook on real microVMs (K on Linux KVM, W on Windows WHP): the T-108 VM bar.
//!
//! Runs on the msb adapter (`puddle-compute-msb`, T-106) over the VM harness's private msb home
//! (T-102), with the static `puddle-agent` from `PUDDLE_AGENT_BIN` (built by
//! `ci/build-agent.sh`). The checks themselves only use the `Runtime` trait.
#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test helpers outside #[test] fns: a failed setup fails the test"
)]

use std::path::PathBuf;
use std::time::{Duration, Instant};

use puddle_boot::{
    BootError, BootFailure, BootHook, BootPlan, Gate, GatedSandbox, GitIdentity, with_boot_mounts,
    write_assets,
};
use puddle_compute::fake::FakeRuntime;
use puddle_compute::{ExecRequest, Runtime, Sandbox, SandboxSpec};
use puddle_compute_msb::{MsbConfig, MsbRuntime};
use puddle_guest_env::{ProxySettings, guest_proxy_config};
use puddle_types::{GuestEnv, GuestFile, GuestPath, ImageRef, SandboxName};
use puddle_vm_tests::Settings;

/// The adapter on the run's private msb home (T-102 harness), and the run's settings.
async fn runtime() -> (MsbRuntime, Settings) {
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .try_init();
    let settings = Settings::from_lookup(|var| std::env::var(var).ok()).expect("VM test settings");
    let pair = settings.prepare().expect("msb runtime pair");
    let home = settings.home();
    let config = MsbConfig::new(&home, pair.msb, pair.libkrunfw, home.join("guest-share"));
    (MsbRuntime::open(config).await.expect("open msb"), settings)
}

/// Where a test writes its boot assets: under the guest-share root, the only place mounts may
/// come from (T-020 C-7).
fn assets_dir(rt: &MsbRuntime, tag: &str) -> PathBuf {
    rt.config().guest_share.join(format!("t108-{tag}"))
}

/// A run-prefixed sandbox name.
fn sandbox_name(settings: &Settings, tag: &str) -> SandboxName {
    SandboxName::new(&format!("{}-t108-{tag}", settings.prefix)).unwrap()
}

/// The guest agent binary (T-111's static build, `ci/build-agent.sh`), copied into `dir` so the
/// mount source is under the guest-share root.
fn agent_binary(dir: &std::path::Path) -> PathBuf {
    let built = PathBuf::from(
        std::env::var_os("PUDDLE_AGENT_BIN")
            .expect("PUDDLE_AGENT_BIN: the static puddle-agent (ci/build-agent.sh)"),
    );
    let copy = dir.join("puddle-agent");
    std::fs::copy(&built, &copy).expect("copy the agent into the guest-share root");
    copy
}

async fn sh<S: Sandbox>(sb: &GatedSandbox<S>, script: &str) -> (i32, String) {
    let out = sb
        .exec(ExecRequest::sh(script).as_user("root"))
        .await
        .unwrap();
    (out.status.code, out.stdout_text().trim_end().to_owned())
}

/// Boots `image` with a CA file from a "provider", a git identity and the proxy env, and checks
/// every VM item of the T-108 bar, after create and again after stop + start.
async fn check_image(image: &str, tag: &str) {
    let (rt, settings) = runtime().await;
    let rt = &rt;
    let image = ImageRef::new(image).unwrap();
    let config = rt.pull_image(&image).await.unwrap();
    let mut env = GuestEnv::new();
    env.set("HTTPS_PROXY", "http://127.0.0.1:3128").unwrap();
    env.set("HTTP_PROXY", "http://127.0.0.1:3128").unwrap();
    let ca = GuestFile::new(
        GuestPath::new("/usr/local/share/ca-certificates/puddle/test-root.crt").unwrap(),
        include_bytes!("vm_test_root.pem").to_vec(),
    );
    let plan = BootPlan::builder(&config)
        .env(&env)
        .file(ca)
        .git_identity(GitIdentity::new("VM Test", "vm@example.org").unwrap())
        .build()
        .unwrap();
    let dir = assets_dir(rt, tag);
    let assets = write_assets(&dir).unwrap();
    let name = sandbox_name(&settings, tag);
    let spec = with_boot_mounts(
        SandboxSpec::new(name.clone(), image).with_env(&env),
        assets,
        Some(&agent_binary(&dir)),
    );
    let gate = Gate::new();
    let hook = BootHook::new();
    let sb = hook.create(rt, spec, &plan, &gate).await.unwrap();
    // alpine:3 ships the CA bundle without update-ca-certificates; the hook skips the step.
    let report = &sb.boot_report().stdout;
    assert!(
        report.contains("update-ca-certificates ran")
            || report.contains("update-ca-certificates skipped (not in this image)"),
        "{report}"
    );

    check_boot(&sb, &config, "create").await;
    sb.stop().await.unwrap();
    // After a restart the guest is back at default sysctls (T-028): the hook redoes them, and
    // skips the unchanged CA step.
    let again = hook.start(rt, &name, &plan, &gate).await.unwrap();
    assert!(
        again
            .boot_report()
            .stdout
            .contains("update-ca-certificates skipped")
    );
    check_boot(&again, &config, "restart").await;
    check_entrypoint(&again, &config).await;
    again.stop().await.unwrap();
    rt.remove(&name).await.unwrap();
}

/// The per-boot checks.
async fn check_boot<S: Sandbox>(
    sb: &GatedSandbox<S>,
    config: &puddle_compute::ImageConfig,
    boot: &str,
) {
    // inotify limits and the BPF lock.
    let (_, v) = sh(sb, "cat /proc/sys/fs/inotify/max_user_watches /proc/sys/fs/inotify/max_user_instances /proc/sys/kernel/unprivileged_bpf_disabled").await;
    assert_eq!(v, "524288\n1024\n1", "{boot}");
    // The image PATH is the suffix of a login shell's PATH (msb prepends /.msb/scripts).
    let image_path = config.env_var("PATH").unwrap_or("/usr/bin:/bin");
    let (_, path) = sh(sb, "sh -lc 'printf %s \"$PATH\"'").await;
    assert!(path.ends_with(image_path), "{boot}: {path}");
    // git settings through the include (checked with git where the image has it).
    let (code, fsync) = sh(
        sb,
        "command -v git >/dev/null && git config --system core.fsync",
    )
    .await;
    if code == 0 {
        assert_eq!(fsync, "committed");
        assert_eq!(sh(sb, "git config user.email").await.1, "vm@example.org");
    } else {
        assert!(
            sh(sb, "cat /etc/puddle/gitconfig")
                .await
                .1
                .contains("fsync = committed")
        );
    }
    // Machine settings, and no credential helper anywhere puddle writes.
    let (_, ms) = sh(sb, "cat /root/.vscode-server/data/Machine/settings.json").await;
    assert!(ms.contains("\"process\"") && ms.contains("\"remote.autoForwardPortsFallback\": 0"));
    let (code, _) = sh(
        sb,
        "grep -ril credential /etc/gitconfig /etc/puddle /root/.vscode-server/data/Machine",
    )
    .await;
    assert_eq!(code, 1, "{boot}: a credential setting was written");
    // The agent is back within 1 s after kill -9.
    let kill = "kill -9 $(awk '$2 == \"(puddle-agent)\" {print $1}' /proc/[0-9]*/stat 2>/dev/null)";
    assert_eq!(sh(sb, kill).await.0, 0, "{boot}");
    let start = Instant::now();
    while sh(sb, "grep -q ' 0100007F:0C38 ' /proc/net/tcp").await.0 != 0 {
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "{boot}: agent not back within 1 s"
        );
    }
}

/// `docker:dind`: the ENTRYPOINT is chained and dockerd runs with the proxy env. Images without
/// an ENTRYPOINT chain nothing.
async fn check_entrypoint<S: Sandbox>(sb: &GatedSandbox<S>, config: &puddle_compute::ImageConfig) {
    let (code, _) = sh(sb, "test -f /run/puddle/entrypoint.pid").await;
    if config.entrypoint.is_empty() {
        assert_eq!(code, 1, "chained without an ENTRYPOINT");
        return;
    }
    let start = Instant::now();
    loop {
        let (code, env) = sh(sb, "tr '\\0' '\\n' </proc/$(pidof dockerd)/environ").await;
        if code == 0 {
            assert!(env.contains("HTTPS_PROXY=http://127.0.0.1:3128"));
            break;
        }
        assert!(start.elapsed() < Duration::from_secs(30), "dockerd not up");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vm_boot_hook_debian_devcontainer() {
    Box::pin(check_image(FakeRuntime::DEBIAN, "deb")).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vm_boot_hook_alpine() {
    Box::pin(check_image(FakeRuntime::ALPINE, "alp")).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vm_boot_hook_docker_dind() {
    Box::pin(check_image(FakeRuntime::DIND, "dind")).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vm_image_without_sh_gives_a_clear_error() {
    let (rt, settings) = runtime().await;
    let image = ImageRef::new("gcr.io/distroless/static-debian12").unwrap();
    let config = rt.pull_image(&image).await.unwrap();
    let plan = BootPlan::builder(&config).no_agent().build().unwrap();
    let dir = assets_dir(&rt, "nosh");
    let assets = write_assets(&dir).unwrap();
    // The agent binary is the merge tool for the Machine settings, so it is always mounted.
    let spec = with_boot_mounts(
        SandboxSpec::new(sandbox_name(&settings, "nosh"), image),
        assets,
        Some(&agent_binary(&dir)),
    );
    let err = BootHook::new()
        .create(&rt, spec, &plan, &Gate::new())
        .await
        .unwrap_err();
    let BootError::Hook { failure, .. } = &err else {
        panic!("{err:?}")
    };
    assert!(matches!(**failure, BootFailure::NoShell { .. }), "{err}");
}

/// The Docker CLI config as `docker login` saves it: the file it read plus `auths` and
/// `credHelpers`, written whole with tab indents.
fn docker_login(config: &str) -> String {
    let mut v: serde_json::Value = serde_json::from_str(config).unwrap();
    v["auths"] = serde_json::json!({"registry.example.test": {"auth": "dXNlcjpwdWRkbGU="}});
    v["credHelpers"] = serde_json::json!({"gcr.io": "gcloud"});
    let two_spaces = serde_json::to_string_pretty(&v).unwrap();
    let lines: Vec<String> = two_spaces
        .lines()
        .map(|l| {
            let body = l.trim_start_matches(' ');
            "\t".repeat((l.len() - body.len()) / 2) + body
        })
        .collect();
    lines.join("\n")
}

async fn write_guest<S: Sandbox>(sb: &GatedSandbox<S>, path: &str, text: &str) {
    let out = sb
        .exec(
            ExecRequest::sh(format!("cat > {path}"))
                .as_user("root")
                .with_stdin(text.as_bytes().to_vec()),
        )
        .await
        .unwrap();
    assert_eq!(out.status.code, 0);
}

/// T-097: the Docker CLI config from `puddle-guest-env` is merged, so a `docker login` survives
/// restarts byte for byte; when the provider stops listing it only puddle's keys go; a file the
/// merge tool can't parse is left alone and the boot goes on. On Alpine (busybox ash runs the
/// hook; the static agent is the merge tool).
async fn check_merge() {
    const DOCKER: &str = "/root/.docker/config.json";
    let (rt, settings) = runtime().await;
    let rt = &rt;
    let image = ImageRef::new(FakeRuntime::ALPINE).unwrap();
    let config = rt.pull_image(&image).await.unwrap();
    let proxy = guest_proxy_config(&ProxySettings::default(), &config.env).unwrap();
    let docker = proxy
        .files
        .iter()
        .find(|f| f.path().as_str() == DOCKER)
        .cloned()
        .unwrap();
    let plan = |files: Vec<GuestFile>| {
        BootPlan::builder(&config)
            .env(&proxy.env)
            .files(files)
            .build()
            .unwrap()
    };
    let with = plan(vec![docker.clone()]);
    let without = plan(vec![]);
    let dir = assets_dir(rt, "merge");
    let assets = write_assets(&dir).unwrap();
    let name = sandbox_name(&settings, "merge");
    let spec = with_boot_mounts(
        SandboxSpec::new(name.clone(), image).with_env(&proxy.env),
        assets,
        Some(&agent_binary(&dir)),
    );
    let gate = Gate::new();
    let hook = BootHook::new();

    // Boot 1: puddle creates the file (0600: it will hold credentials).
    let sb = hook.create(rt, spec, &with, &gate).await.unwrap();
    let (_, created) = sh(&sb, &format!("cat {DOCKER}")).await;
    assert_eq!(
        format!("{created}\n").as_bytes(),
        docker.contents(),
        "boot 1"
    );
    assert_eq!(sh(&sb, &format!("stat -c %a {DOCKER}")).await.1, "600");
    let login = docker_login(&created);
    write_guest(&sb, DOCKER, &login).await;
    sb.stop().await.unwrap();

    // Boots 2 and 3: the login is still there, byte for byte, and so are puddle's proxies.
    for boot in [2, 3] {
        let sb = hook.start(rt, &name, &with, &gate).await.unwrap();
        let report = &sb.boot_report().stdout;
        assert!(!report.contains("left as it is"), "boot {boot}: {report}");
        assert_eq!(
            sh(&sb, &format!("cat {DOCKER}")).await.1,
            login,
            "boot {boot}"
        );
        sb.stop().await.unwrap();
    }

    // Boot 4: no provider lists the file: puddle's keys go, the login stays.
    let sb = hook.start(rt, &name, &without, &gate).await.unwrap();
    let (_, text) = sh(&sb, &format!("cat {DOCKER}")).await;
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert!(v.get("proxies").is_none(), "boot 4: {text}");
    assert_eq!(
        v["auths"]["registry.example.test"]["auth"],
        "dXNlcjpwdWRkbGU="
    );
    assert_eq!(v["credHelpers"]["gcr.io"], "gcloud");
    write_guest(&sb, DOCKER, "{ \"auths\": oops").await;
    sb.stop().await.unwrap();

    // Boot 5: a file that isn't JSON is left as it is; the boot goes on.
    let sb = hook.start(rt, &name, &with, &gate).await.unwrap();
    let report = &sb.boot_report().stdout;
    assert!(
        report.contains(&format!(
            "{DOCKER} left as it is: the file is not valid JSON"
        )),
        "boot 5: {report}"
    );
    assert_eq!(
        sh(&sb, &format!("cat {DOCKER}")).await.1,
        "{ \"auths\": oops"
    );
    sb.stop().await.unwrap();
    rt.remove(&name).await.unwrap();
}

/// T-125: VS Code's Machine settings are merged as JSONC, so the user's own settings, comments
/// and trailing commas survive restarts byte for byte; an invalid file is left as it is. On
/// Alpine, like [`check_merge`].
async fn check_machine_merge() {
    const MACHINE: &str = puddle_boot::MACHINE_SETTINGS_GUEST;
    const USER: &str = "// mine\n{\n    \"editor.fontSize\": 14, // big\n    \"github.gitAuthentication\": true,\n    \"remote.portsAttributes\": {\n        \"8080\": { \"label\": \"web\" },\n    },\n}\n";
    let (rt, settings) = runtime().await;
    let rt = &rt;
    let image = ImageRef::new(FakeRuntime::ALPINE).unwrap();
    let config = rt.pull_image(&image).await.unwrap();
    let plan = BootPlan::builder(&config).build().unwrap();
    let dir = assets_dir(rt, "machine");
    let assets = write_assets(&dir).unwrap();
    let name = sandbox_name(&settings, "machine");
    let spec = with_boot_mounts(
        SandboxSpec::new(name.clone(), image),
        assets,
        Some(&agent_binary(&dir)),
    );
    let gate = Gate::new();
    let hook = BootHook::new();

    // Boot 1: puddle creates the file; the user then edits it.
    let sb = hook.create(rt, spec, &plan, &gate).await.unwrap();
    let (_, created) = sh(&sb, &format!("cat {MACHINE}")).await;
    assert!(
        created.contains("\"remote.autoForwardPortsSource\": \"process\""),
        "{created}"
    );
    write_guest(&sb, MACHINE, USER).await;
    sb.stop().await.unwrap();

    // Boot 2: the user's keys and comments stay, puddle's arrive, the guard wins.
    let sb = hook.start(rt, &name, &plan, &gate).await.unwrap();
    let (_, merged) = sh(&sb, &format!("cat {MACHINE}")).await;
    assert!(
        merged.starts_with("// mine\n{\n    \"editor.fontSize\": 14, // big\n"),
        "{merged}"
    );
    assert!(
        merged.contains("\"8080\": { \"label\": \"web\" },"),
        "{merged}"
    );
    assert!(
        merged.contains("\"github.gitAuthentication\": false"),
        "{merged}"
    );
    assert!(
        merged.contains("\"remote.autoForwardPortsFallback\": 0"),
        "{merged}"
    );
    sb.stop().await.unwrap();

    // Boot 3: nothing changes, byte for byte.
    let sb = hook.start(rt, &name, &plan, &gate).await.unwrap();
    assert_eq!(sh(&sb, &format!("cat {MACHINE}")).await.1, merged, "boot 3");
    write_guest(&sb, MACHINE, "{ \"editor.fontSize\": oops").await;
    sb.stop().await.unwrap();

    // Boot 4: an invalid file is left as it is; the boot goes on.
    let sb = hook.start(rt, &name, &plan, &gate).await.unwrap();
    let report = &sb.boot_report().stdout;
    assert!(
        report.contains(&format!(
            "{MACHINE} left as it is: the file is not valid JSONC"
        )),
        "boot 4: {report}"
    );
    assert_eq!(
        sh(&sb, &format!("cat {MACHINE}")).await.1,
        "{ \"editor.fontSize\": oops"
    );
    sb.stop().await.unwrap();
    rt.remove(&name).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vm_merged_machine_settings_keep_the_users_jsonc_across_boots() {
    Box::pin(check_machine_merge()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vm_merged_docker_config_keeps_a_docker_login_across_boots() {
    Box::pin(check_merge()).await;
}
