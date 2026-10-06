// SPDX-License-Identifier: GPL-3.0-or-later
//! The boot hook on real microVMs (K on Linux KVM, W on Windows WHP): the T-108 VM bar.
//!
//! Runs on the msb adapter (`puddle-compute-msb`, T-106) over the VM harness's private msb home
//! (T-102), with the static `puddle-agent` from `PUDDLE_AGENT_BIN` (built by
//! `ci/build-agent.sh`). The checks themselves only use the `Runtime` trait.
#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
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
    let assets = write_assets(&assets_dir(&rt, "nosh")).unwrap();
    let spec = with_boot_mounts(
        SandboxSpec::new(sandbox_name(&settings, "nosh"), image),
        assets,
        None,
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
