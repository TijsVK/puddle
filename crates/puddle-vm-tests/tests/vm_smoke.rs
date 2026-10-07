// SPDX-License-Identifier: GPL-3.0-or-later
//! The VM smoke every VM tier runs first: one stock devcontainer sandbox boots through
//! the SDK and runs `true`. Runs only under `cargo nextest run --profile vm` (crate docs).

use std::time::{Duration, Instant};

use microsandbox::Sandbox;
use puddle_vm_tests::{DEBIAN_DEVCONTAINER, HarnessError, VmEnv, within};

/// Cold pull of the devcontainer image plus first boot: 7-12 s on `windows-2025`,
/// 60 s on a workstation's first pull. The job's own limit is 15 minutes.
const CREATE_BUDGET: Duration = Duration::from_secs(600);
const EXEC_BUDGET: Duration = Duration::from_secs(60);
const STOP_BUDGET: Duration = Duration::from_secs(60);

/// Wall-clock times of the smoke's steps, printed by the test.
struct Timings {
    create: Duration,
    exec: Duration,
}

async fn boot_and_exec_true(env: &VmEnv) -> Result<Timings, HarnessError> {
    let builder = env.sandbox("smoke", DEBIAN_DEVCONTAINER)?;
    // Boxed: the SDK's futures are large (clippy::large_futures).
    env.scope(Box::pin(async {
        let started = Instant::now();
        let sandbox = within("create", CREATE_BUDGET, builder.create()).await??;
        let create = started.elapsed();

        let started = Instant::now();
        let output = within(
            "exec true",
            EXEC_BUDGET,
            sandbox.exec("true", std::iter::empty::<&str>()),
        )
        .await??;
        let exec = started.elapsed();
        assert_eq!(output.status().code, 0, "stderr: {:?}", output.stderr());
        assert!(output.status().success);

        within("stop", STOP_BUDGET, sandbox.stop()).await??;
        within("remove", STOP_BUDGET, Sandbox::remove(sandbox.name())).await??;
        Ok(Timings { create, exec })
    }))
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vm_debian_devcontainer_boots_and_runs_true() {
    let env = VmEnv::from_env().await.expect("VM test environment");
    eprintln!(
        "run prefix {}, msb home {}, runtime {}",
        env.settings().prefix,
        env.settings().home().display(),
        env.runtime().msb.display()
    );
    let result = Box::pin(boot_and_exec_true(&env)).await;
    // Clean up whatever the run left, pass or fail; keep the home (msb logs) on failure.
    let cleaned = Box::pin(env.cleanup()).await;
    let timings = result.expect("boot and exec");
    eprintln!(
        "create (pull + boot) {} ms, exec true {} ms",
        timings.create.as_millis(),
        timings.exec.as_millis()
    );
    cleaned.expect("cleanup");
    env.remove_home().await.expect("remove the private home");
}
