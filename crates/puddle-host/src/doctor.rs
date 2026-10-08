// SPDX-License-Identifier: GPL-3.0-or-later
//! The system check the API serves: `puddle doctor`'s checks run against this machine and the
//! runtime folder the host was started with.

use std::sync::Arc;

use puddle_api::HostDoctor;
use puddle_doctor::{Options, SystemProbe, diagnose};
use puddle_runtime::{DevOverride, RuntimeLayout, RuntimeVersion};

/// A service that runs every check, with or without the test boot, on the real machine. Each run
/// opens the runtime afresh, so a fix made while puddle runs (a permission, a replaced file) shows
/// at the next run.
pub(crate) fn system_doctor(layout: &RuntimeLayout, expected: &RuntimeVersion) -> Arc<HostDoctor> {
    let dir = layout.runtime_dir().to_path_buf();
    let expected = *expected;
    Arc::new(HostDoctor::new(Arc::new(move |boot| {
        let probe = SystemProbe::new(dir.clone(), expected, DevOverride::from_env());
        let options = Options {
            boot,
            ..Options::default()
        };
        diagnose(&probe, &options, puddle_types::VERSION)
    })))
}
