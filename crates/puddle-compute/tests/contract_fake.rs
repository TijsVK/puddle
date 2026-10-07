// SPDX-License-Identifier: GPL-3.0-or-later
//! The contract suite against `FakeRuntime`: the fake must pass every case, with the upstream stale-directory bug
//! unfixed (msb 0.7.6) and fixed (the fork).
#![expect(
    clippy::unwrap_used,
    reason = "the env helper runs outside #[test] but only in tests"
)]

use puddle_compute::contract::{self, ContractEnv};
use puddle_compute::fake::{FakeConfig, FakeRuntime};
use puddle_types::ImageRef;

async fn env() -> ContractEnv<FakeRuntime> {
    ContractEnv::new(
        FakeRuntime::new(),
        ImageRef::new(FakeRuntime::DEBIAN).unwrap(),
    )
}

puddle_compute::contract_tests!(env);

#[test]
fn macro_runs_every_case() {
    assert_eq!(CONTRACT_CASES, contract::CASES);
}

#[tokio::test]
async fn run_all_passes_on_a_shared_fake() {
    let env = env().await;
    let report = contract::run_all(&env).await;
    assert!(report.all_passed(), "{:#?}", report.failed);
    assert_eq!(report.passed.len(), contract::CASES.len());
}

#[tokio::test]
async fn run_all_passes_with_the_stale_dir_fix() {
    let fixed = FakeRuntime::with_config(FakeConfig {
        stale_dir_fixed: true,
        ..FakeConfig::default()
    });
    let env = ContractEnv::new(fixed, ImageRef::new(FakeRuntime::DEBIAN).unwrap());
    let report = contract::run_all(&env).await;
    assert!(report.all_passed(), "{:#?}", report.failed);
}

#[tokio::test]
async fn cases_leave_nothing_behind() {
    use puddle_compute::Runtime;
    let env = env().await;
    assert!(contract::run_all(&env).await.all_passed());
    assert_eq!(env.runtime.list().await.unwrap(), []);
    assert_eq!(env.runtime.list_volumes().await.unwrap(), []);
    assert_eq!(
        env.runtime.stale_dirs().await.unwrap(),
        Vec::<String>::new()
    );
}

#[tokio::test]
async fn an_unknown_case_fails_cleanly() {
    let err = contract::run_case("no_such_case", &env().await)
        .await
        .unwrap_err();
    assert_eq!(err.case, "no_such_case");
}

#[tokio::test]
#[should_panic(expected = "contract case")]
async fn assert_case_panics_on_failure() {
    contract::assert_case("no_such_case", env().await).await;
}

/// The suite must not be vacuous: a runtime that deviates fails the matching cases.
async fn failing_cases(rt: FakeRuntime) -> Vec<String> {
    let env = ContractEnv::new(rt, ImageRef::new(FakeRuntime::DEBIAN).unwrap());
    let report = contract::run_all(&env).await;
    report.failed.into_iter().map(|f| f.case).collect()
}

#[tokio::test]
async fn the_suite_catches_lost_exit_codes() {
    use puddle_compute::ExecOutput;
    let rt = FakeRuntime::new();
    rt.on_exec(
        |_: &mut puddle_compute::fake::ExecContext<'_>, r: &puddle_compute::ExecRequest| {
            (r.program == "sh").then(|| ExecOutput::new(0, "", ""))
        },
    );
    let failed = failing_cases(rt).await;
    assert!(
        failed.contains(&"exec_exit_codes_are_exact".to_owned()),
        "{failed:?}"
    );
    assert!(
        failed.contains(&"signal_killed_exec_is_a_failure".to_owned()),
        "{failed:?}"
    );
}

#[tokio::test]
async fn the_suite_catches_a_writable_file_mount() {
    use puddle_compute::ExecOutput;
    let rt = FakeRuntime::new();
    rt.on_exec(
        |_: &mut puddle_compute::fake::ExecContext<'_>, r: &puddle_compute::ExecRequest| {
            (r.program == "tee" && r.args.iter().any(|a| a.starts_with("/puddle-ct/")))
                .then(|| ExecOutput::new(0, "", ""))
        },
    );
    let failed = failing_cases(rt).await;
    assert_eq!(failed, ["file_mount_is_read_only"]);
}

#[tokio::test]
async fn the_suite_catches_a_runtime_that_always_fails() {
    use puddle_compute::ComputeError;
    use puddle_compute::fake::{Fault, Op};
    let rt = FakeRuntime::new();
    rt.inject(
        Op::Create,
        Fault::always(ComputeError::Runtime {
            op: "create",
            message: "down".into(),
        }),
    );
    let failed = failing_cases(rt).await;
    assert!(failed.len() >= 20, "{failed:?}");
}
