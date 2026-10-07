// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared setup of the VM tests: the adapter on the VM harness's private msb home (T-102).
#![allow(
    dead_code,
    reason = "each test binary uses a different subset of the helpers"
)]
#![expect(clippy::expect_used, reason = "a failed setup fails the test")]

use puddle_compute_msb::{MsbConfig, MsbRuntime};
use puddle_vm_tests::Settings;

/// A throwaway public key (its private half was never kept): the SDK's SSH server refuses to
/// start without an authorized key.
pub(crate) const TEST_SSH_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOrqAVBGG1BD2K0dsi6Z6il4+PlI8R/egmhi8Ox00c0/ puddle-contract-test";

/// The harness settings (runtime pair, run prefix, private home) from the environment.
pub(crate) fn settings() -> Settings {
    Settings::from_lookup(|var| std::env::var(var).ok()).expect("VM test settings")
}

/// The adapter on the run's private msb home, with `<home>/guest-share` as the mount root. Its
/// warnings (a lost boot race, with msb's log tail) go to the test's stderr.
pub(crate) async fn runtime(settings: &Settings) -> MsbRuntime {
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .try_init();
    let pair = settings.prepare().expect("msb runtime pair");
    let home = settings.home();
    let config = MsbConfig::new(&home, pair.msb, pair.libkrunfw, home.join("guest-share"))
        .with_ssh_key(TEST_SSH_KEY)
        .with_runtime_log_level(settings.msb_log_level.clone());
    MsbRuntime::open(config).await.expect("open msb")
}
