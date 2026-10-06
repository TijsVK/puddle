// SPDX-License-Identifier: GPL-3.0-or-later
//! The real `guest/boot.sh`, run on the test host against a fake root with stubbed `sysctl`,
//! `update-ca-certificates` and `puddle-agent`, under every POSIX shell the host has (dash and
//! bash at least). The VM version of these checks is `tests/vm_boot.rs`.
#![cfg(unix)]
#![expect(
    clippy::unwrap_used,
    reason = "test helpers outside #[test] fns: a failed setup fails the test"
)]

mod common;

use std::os::unix::fs::PermissionsExt as _;
use std::time::Duration;

use common::{FakeRoot, alive, kill9, shells, show};
use puddle_boot::{
    BootHook, BootPlan, CA_DIR_GUEST, ENV_FILE_GUEST, GIT_CONFIG_GUEST, Gate, GateState,
    GitIdentity, MACHINE_SETTINGS_GUEST, PATH_FILE_GUEST, PLAN_HEADER,
};
use puddle_compute::ImageConfig;
use puddle_types::{GuestEnv, GuestFile, GuestPath};

const IMAGE_PATH: &str = "/usr/local/cargo/bin:/usr/local/bin:/usr/bin:/bin";

fn image(entrypoint: &[String], cmd: &[&str]) -> ImageConfig {
    ImageConfig {
        entrypoint: entrypoint.to_vec(),
        cmd: cmd.iter().map(|s| (*s).to_owned()).collect(),
        env: vec![("PATH".into(), IMAGE_PATH.into())],
        ..ImageConfig::default()
    }
}

fn env() -> GuestEnv {
    let mut env = GuestEnv::new();
    env.set("HTTPS_PROXY", "http://127.0.0.1:3128").unwrap();
    env.set("ODD", "it's $HOME `x` \\ \"q\"\nline2").unwrap();
    env
}

fn file(path: &str, contents: &[u8]) -> GuestFile {
    GuestFile::new(GuestPath::new(path).unwrap(), contents.to_vec())
}

const CA: &str = "/usr/local/share/ca-certificates/puddle/root.crt";

fn full_plan(ca: &str) -> BootPlan {
    BootPlan::builder(&image(&[], &["bash"]))
        .env(&env())
        .file(file(CA, ca.as_bytes()))
        .file(
            file("/etc/npmrc", b"proxy=http://127.0.0.1:3128\n")
                .with_mode(0o600)
                .unwrap(),
        )
        .git_identity(GitIdentity::new("Ada Lovelace", "ada@example.org").unwrap())
        .build()
        .unwrap()
}

fn count(calls: &[String], prefix: &str) -> usize {
    calls.iter().filter(|c| c.starts_with(prefix)).count()
}

/// Sources `files` in a fresh shell and prints `expr`.
fn source_and_print(fr: &FakeRoot, files: &[&str], expr: &str) -> String {
    let mut parts: Vec<String> = files
        .iter()
        .map(|f| format!(". '{}';", fr.path(f).display()))
        .collect();
    parts.push(format!("printf '%s' \"{expr}\""));
    let script = parts.join(" ");
    let out = std::process::Command::new(&fr.shell)
        .arg("-c")
        .arg(script)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .output()
        .unwrap();
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn boot_applies_every_step() {
    for sh in shells() {
        let fr = FakeRoot::new(&sh);
        let out = fr.run(&full_plan("CA-1\n"));
        assert!(out.status.success(), "{}: {}", sh.display(), show(&out));
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(stdout.ends_with("puddle-boot: ready\n"), "{stdout}");

        // Kernel settings, through sysctl, read back.
        assert_eq!(fr.read("/proc/sys/fs/inotify/max_user_instances"), "1024\n");
        assert_eq!(fr.read("/proc/sys/fs/inotify/max_user_watches"), "524288\n");
        assert_eq!(fr.read("/proc/sys/kernel/unprivileged_bpf_disabled"), "1\n");
        let calls = fr.calls();
        assert_eq!(count(&calls, "sysctl -w"), 3, "{calls:?}");

        // Files: contents and modes.
        assert_eq!(fr.read(CA), "CA-1\n");
        assert_eq!(fr.read("/etc/npmrc"), "proxy=http://127.0.0.1:3128\n");
        let mode = |p: &str| std::fs::metadata(fr.path(p)).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode("/etc/npmrc"), 0o600);
        assert_eq!(mode(ENV_FILE_GUEST), 0o644);
        assert!(fr.read(MACHINE_SETTINGS_GUEST).contains("\"process\""));

        // Login shells: the image PATH back, the env with odd values intact.
        assert_eq!(
            source_and_print(
                &fr,
                &["/etc/profile.d/01-puddle-env.sh", PATH_FILE_GUEST],
                "$PATH"
            ),
            IMAGE_PATH
        );
        assert_eq!(
            source_and_print(&fr, &[ENV_FILE_GUEST], "$ODD"),
            "it's $HOME `x` \\ \"q\"\nline2"
        );

        // git: one include, fsync and identity in puddle's file.
        assert_eq!(
            fr.read("/etc/gitconfig"),
            format!("[include]\n\tpath = {GIT_CONFIG_GUEST}\n")
        );
        let git = fr.read(GIT_CONFIG_GUEST);
        assert!(git.contains("fsync = committed") && git.contains("name = \"Ada Lovelace\""));

        // CA changed (first boot): update-ca-certificates ran once.
        assert_eq!(count(&calls, "update-ca-certificates"), 1);

        // Agent up under its supervisor; ready marker written.
        let agent = fr.agent_pids();
        assert_eq!(agent.len(), 1);
        assert!(alive(agent[0]));
        assert!(alive(fr.recorded_pid("supervisor.pid").unwrap()));
        assert_eq!(fr.read("/run/puddle/boot.done"), "boot-1\n");
        // No ENTRYPOINT declared (devcontainers image): nothing chained.
        assert!(fr.recorded_pid("entrypoint.pid").is_none());
    }
}

#[test]
fn second_boot_converges_and_skips_an_unchanged_ca() {
    for sh in shells() {
        let fr = FakeRoot::new(&sh);
        assert!(fr.run(&full_plan("CA-1\n")).status.success());
        let supervisor = fr.recorded_pid("supervisor.pid").unwrap();
        let out = fr.run(&full_plan("CA-1\n"));
        assert!(out.status.success(), "{}", show(&out));
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("update-ca-certificates skipped"),
            "{stdout}"
        );
        assert!(
            stdout.contains("agent supervisor already running"),
            "{stdout}"
        );
        assert_eq!(count(&fr.calls(), "update-ca-certificates"), 1);
        assert_eq!(fr.recorded_pid("supervisor.pid"), Some(supervisor));
        assert_eq!(fr.agent_pids().len(), 1, "agent started twice");
        assert_eq!(fr.read("/etc/gitconfig").matches("[include]").count(), 1);

        // A changed root: the step runs again.
        assert!(fr.run(&full_plan("CA-2\n")).status.success());
        assert_eq!(count(&fr.calls(), "update-ca-certificates"), 2);
    }
}

#[test]
fn after_a_restart_the_hook_redoes_the_sysctls_and_restarts_the_agent() {
    let fr = FakeRoot::new(&shells()[0]);
    assert!(fr.run(&full_plan("CA\n")).status.success());
    let old_supervisor = fr.recorded_pid("supervisor.pid").unwrap();
    // A reboot: new boot id, kernel settings back at defaults, processes gone.
    kill9(old_supervisor);
    for pid in fr.agent_pids() {
        kill9(pid);
    }
    std::fs::write(fr.path("/proc/sys/kernel/random/boot_id"), "boot-2\n").unwrap();
    std::fs::write(fr.path("/proc/sys/kernel/unprivileged_bpf_disabled"), "0\n").unwrap();
    std::fs::write(fr.path("/proc/net/tcp"), "  sl  local_address\n").unwrap();
    let out = fr.run(&full_plan("CA\n"));
    assert!(out.status.success(), "{}", show(&out));
    assert_eq!(fr.read("/proc/sys/kernel/unprivileged_bpf_disabled"), "1\n");
    assert_ne!(fr.recorded_pid("supervisor.pid"), Some(old_supervisor));
    assert_eq!(fr.agent_pids().len(), 2);
    assert_eq!(fr.read("/run/puddle/boot.done"), "boot-2\n");
}

#[test]
fn files_dropped_from_the_plan_are_removed_and_trigger_the_ca_step() {
    let fr = FakeRoot::new(&shells()[0]);
    assert!(fr.run(&full_plan("CA\n")).status.success());
    let without = BootPlan::builder(&image(&[], &["bash"])).build().unwrap();
    let out = fr.run(&without);
    assert!(out.status.success(), "{}", show(&out));
    assert!(!fr.path(CA).exists());
    assert!(!fr.path("/etc/npmrc").exists());
    assert_eq!(count(&fr.calls(), "update-ca-certificates"), 2);
    assert!(fr.path(ENV_FILE_GUEST).exists());
}

#[test]
fn every_byte_survives_the_plan() {
    let fr = FakeRoot::new(&shells()[0]);
    let all: Vec<u8> = (0..=255).cycle().take(4096).collect();
    let plan = BootPlan::builder(&ImageConfig::default())
        .no_agent()
        .file(file("/opt/blob.bin", &all))
        .file(file("/opt/with space/it's", b"-n %s\\"))
        .build()
        .unwrap();
    let out = fr.run(&plan);
    assert!(out.status.success(), "{}", show(&out));
    assert_eq!(std::fs::read(fr.path("/opt/blob.bin")).unwrap(), all);
    assert_eq!(
        std::fs::read(fr.path("/opt/with space/it's")).unwrap(),
        b"-n %s\\"
    );
}

#[test]
fn a_symlink_planted_at_a_file_path_is_replaced_not_followed() {
    let fr = FakeRoot::new(&shells()[0]);
    std::fs::create_dir_all(fr.path("/etc/profile.d")).unwrap();
    std::fs::write(fr.path("/etc/victim"), "keep").unwrap();
    std::os::unix::fs::symlink(fr.path("/etc/victim"), fr.path(ENV_FILE_GUEST)).unwrap();
    let plan = BootPlan::builder(&ImageConfig::default())
        .no_agent()
        .build()
        .unwrap();
    assert!(fr.run(&plan).status.success());
    assert_eq!(fr.read("/etc/victim"), "keep");
    assert!(!fr.path(ENV_FILE_GUEST).is_symlink());
}

#[test]
fn agent_is_back_within_a_second_after_kill_9() {
    let fr = FakeRoot::new(&shells()[0]);
    assert!(fr.run(&full_plan("CA\n")).status.success());
    let first = fr.agent_pids()[0];
    kill9(first);
    let back = FakeRoot::wait_for(Duration::from_secs(1), || {
        fr.agent_pids().len() == 2 && alive(fr.agent_pids()[1])
    });
    assert!(
        back.is_some(),
        "agent not restarted within 1 s: {:?}",
        fr.agent_pids()
    );
}

#[test]
fn entrypoint_is_chained_once_with_puddle_env_and_workdir() {
    for sh in shells() {
        let fr = FakeRoot::new(&sh);
        let entry = fr.path("/entry.sh");
        std::fs::write(
            &entry,
            "#!/bin/sh\nprintf '%s|%s|%s\\n' \"$HTTPS_PROXY\" \"$*\" \"$(pwd)\" >>\"$PUDDLE_ROOT/entry.out\"\nexec sleep 1000\n",
        )
        .unwrap();
        std::fs::set_permissions(&entry, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::create_dir_all(fr.path("/srv")).unwrap();
        let mut img = image(&[entry.display().to_string()], &["--flag"]);
        img.working_dir = Some("/srv".into());
        let plan = BootPlan::builder(&img).env(&env()).build().unwrap();
        // The supervisor's restarts don't matter here; the entrypoint's own PID does.
        let out = fr.run(&plan);
        assert!(out.status.success(), "{}", show(&out));
        let pid = fr.recorded_pid("entrypoint.pid").unwrap();
        let line = FakeRoot::wait_for(Duration::from_secs(5), || fr.path("/entry.out").exists());
        assert!(line.is_some());
        assert_eq!(
            fr.read("/entry.out"),
            format!(
                "http://127.0.0.1:3128|--flag|{}\n",
                fr.path("/srv").display()
            )
        );
        let out = fr.run(&plan);
        assert!(String::from_utf8_lossy(&out.stdout).contains("entrypoint already running"));
        assert_eq!(fr.recorded_pid("entrypoint.pid"), Some(pid));
        assert!(alive(pid));
    }
}

#[test]
fn boot_d_steps_run_in_name_order_and_a_failing_one_fails_the_boot() {
    let fr = FakeRoot::new(&shells()[0]);
    std::fs::create_dir_all(fr.path("/puddle/boot.d")).unwrap();
    for (name, n) in [("20-b.sh", 2), ("10-a.sh", 1)] {
        std::fs::write(
            fr.path(&format!("/puddle/boot.d/{name}")),
            format!("echo step{n} >>\"$PUDDLE_ROOT/steps\"\n"),
        )
        .unwrap();
    }
    let plan = BootPlan::builder(&ImageConfig::default())
        .no_agent()
        .build()
        .unwrap();
    assert!(fr.run(&plan).status.success());
    assert_eq!(fr.read("/steps"), "step1\nstep2\n");
    std::fs::write(
        fr.path("/puddle/boot.d/30-bad.sh"),
        "echo nope >&2; exit 4\n",
    )
    .unwrap();
    let out = fr.run(&plan);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("step 30-bad.sh failed: nope"), "{stderr}");
    assert!(!fr.path("/run/puddle/boot.done").exists());
}

#[test]
fn failures_exit_non_zero_with_the_reason_on_stderr() {
    let fr = FakeRoot::new(&shells()[0]);
    let plan = full_plan("CA\n");
    let rendered = plan.render();
    let err = |out: &std::process::Output| String::from_utf8_lossy(&out.stderr).into_owned();

    let truncated = &rendered[..rendered.len() / 2];
    let out = fr.run_raw(truncated, &[], true);
    assert_eq!(out.status.code(), Some(2), "{}", show(&out));
    assert!(err(&out).contains("truncated"));

    let out = fr.run_raw(b"# something else\npuddle_plan_end\n", &[], true);
    assert_eq!(out.status.code(), Some(2));
    assert!(err(&out).contains(PLAN_HEADER));

    std::fs::write(fr.path("/fail-update-ca"), "").unwrap();
    let out = fr.run(&plan);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        err(&out).starts_with(
            "puddle-boot: error: update-ca-certificates failed: boom: bad certificate"
        ),
        "{}",
        err(&out)
    );
    assert!(!fr.path("/run/puddle/boot.done").exists());
}

#[test]
fn a_missing_or_silent_agent_fails_the_boot() {
    let fr = FakeRoot::new(&shells()[0]);
    let missing = BootPlan::builder(&ImageConfig::default())
        .agent(puddle_boot::AgentConfig {
            binary: GuestPath::new("/puddle/none").unwrap(),
            port: 3128,
        })
        .build()
        .unwrap();
    let out = fr.run(&missing);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("/puddle/none is missing"));

    std::fs::write(
        fr.path("/puddle/mute"),
        "#!/bin/sh\necho $$ >>\"$PUDDLE_ROOT/agent.pids\"\necho mute agent here\nexec sleep 1000\n",
    )
    .unwrap();
    std::fs::set_permissions(
        fr.path("/puddle/mute"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let mute = BootPlan::builder(&ImageConfig::default())
        .agent(puddle_boot::AgentConfig {
            binary: GuestPath::new("/puddle/mute").unwrap(),
            port: 3999,
        })
        .build()
        .unwrap();
    let out = fr.run(&mute);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("not listening on 127.0.0.1:3999 after 10 s"),
        "{stderr}"
    );
    assert!(stderr.contains("mute agent here"), "{stderr}");
}

#[test]
fn without_sysctl_the_hook_writes_proc_sys_directly() {
    let fr = FakeRoot::new(&shells()[0]);
    let plan = BootPlan::builder(&ImageConfig::default())
        .no_agent()
        .build()
        .unwrap();
    let out = fr.run_raw(&plan.render(), &[], false);
    assert!(out.status.success(), "{}", show(&out));
    assert_eq!(count(&fr.calls(), "sysctl"), 0);
    assert_eq!(fr.read("/proc/sys/fs/inotify/max_user_watches"), "524288\n");
}

#[test]
fn no_credential_helper_is_ever_written() {
    let fr = FakeRoot::new(&shells()[0]);
    assert!(fr.run(&full_plan("CA\n")).status.success());
    let mut stack = vec![fr.path("/etc"), fr.path("/root")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let p = entry.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else {
                let text = std::fs::read_to_string(&p)
                    .unwrap_or_default()
                    .to_lowercase();
                assert!(!text.contains("credential"), "{}", p.display());
            }
        }
    }
}

#[test]
fn outside_a_test_root_the_hook_needs_root() {
    let is_root = std::process::Command::new("id")
        .arg("-u")
        .output()
        .is_ok_and(|o| o.stdout == b"0\n");
    if is_root {
        return; // Can't test the refusal as root; CI runs as a normal user.
    }
    let fr = FakeRoot::new(&shells()[0]);
    let mut cmd = fr.command(&[], true);
    cmd.env("PUDDLE_ROOT", "");
    let out = cmd.output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("must run as root"));
}

/// The whole path: plan rendered by Rust, run by the hook through the fake runtime's exec, gate
/// opened on success.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn boot_hook_through_the_fake_runtime_runs_the_real_script() {
    use puddle_compute::fake::{ExecContext, FakeRuntime};
    use puddle_compute::{ExecOutput, ExecRequest, FileMount, Runtime, SandboxSpec};
    use puddle_types::{ImageRef, SandboxName};
    use std::io::Write as _;

    let fr = std::sync::Arc::new(FakeRoot::new(&shells()[0]));
    let runner = fr.clone();
    let handler = move |_: &mut ExecContext<'_>, r: &ExecRequest| -> Option<ExecOutput> {
        if r.args.first().map(String::as_str) != Some("/puddle/boot.sh") {
            return None;
        }
        assert_eq!(r.user.as_deref(), Some("root"));
        assert_eq!(r.env.get("PUDDLE_ROOT"), Some(""));
        let mut child = runner.command(&r.args[1..], true).spawn().unwrap();
        child.stdin.take().unwrap().write_all(&r.stdin).unwrap();
        let out = child.wait_with_output().unwrap();
        Some(ExecOutput::new(
            out.status.code().unwrap_or(-1),
            out.stdout,
            out.stderr,
        ))
    };
    let rt = FakeRuntime::new();
    rt.on_exec(handler);
    let image = ImageRef::new(FakeRuntime::DEBIAN).unwrap();
    let config = rt.pull_image(&image).await.unwrap();
    let plan = BootPlan::builder(&config).env(&env()).build().unwrap();
    let mounts = puddle_boot::write_assets(&fr.path("/host-assets")).unwrap();
    assert!(mounts.iter().all(|m: &FileMount| m.host.exists()));
    let spec = puddle_boot::with_boot_mounts(
        SandboxSpec::new(SandboxName::new("real").unwrap(), image),
        mounts,
        Some(&fr.path("/puddle/puddle-agent")),
    );
    let gate = Gate::new();
    let sb = BootHook::new()
        .create(&rt, spec, &plan, &gate)
        .await
        .unwrap();
    assert_eq!(gate.state(), GateState::Ready);
    assert!(sb.boot_report().stdout.contains("puddle-boot: ready"));
    assert_eq!(fr.read("/proc/sys/kernel/unprivileged_bpf_disabled"), "1\n");
    assert!(fr.read(ENV_FILE_GUEST).contains("HTTPS_PROXY"));
    assert!(
        fr.read(MACHINE_SETTINGS_GUEST)
            .contains("autoForwardPortsFallback")
    );
    assert!(
        !fr.path(CA_DIR_GUEST).exists(),
        "no provider sent a CA file"
    );
    sb.stop().await.unwrap();
}
