// SPDX-License-Identifier: GPL-3.0-or-later
//! The runtime contract suite on real microVMs through the adapter (`run_all` green on tiers K
//! and W). One test per case; the binary's `vm_` name keeps them in the VM profile.
#![expect(clippy::expect_used, reason = "a failed setup fails the test")]

mod support;

use puddle_compute::contract::{CASES, ContractEnv};
use puddle_compute_msb::MsbRuntime;
use puddle_types::ImageRef;
use puddle_vm_tests::DEBIAN_DEVCONTAINER;

async fn env() -> ContractEnv<MsbRuntime> {
    let settings = support::settings();
    let rt = support::runtime(&settings).await;
    let host_dir = rt.config().guest_share.join("contract");
    let mut env = ContractEnv::new(rt, ImageRef::new(DEBIAN_DEVCONTAINER).expect("image"));
    // The run prefix, so the harness's cleanup also catches what a crashed case left.
    settings.prefix.as_str().clone_into(&mut env.prefix);
    env.host_dir = host_dir;
    env
}

puddle_compute::contract_tests!(env);

#[test]
fn vm_every_contract_case_runs_here() {
    assert_eq!(CONTRACT_CASES, CASES);
}
