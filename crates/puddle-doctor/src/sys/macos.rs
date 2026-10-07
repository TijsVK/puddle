// SPDX-License-Identifier: GPL-3.0-or-later
//! macOS probes. puddle doesn't run on macOS yet, so the hypervisor is
//! reported as unsupported and the report says so; Hypervisor.framework checks (Apple Silicon
//! only, the `com.apple.security.hypervisor` entitlement) come with that work.

use crate::facts::{HypervisorApi, HypervisorFacts};

pub(crate) fn hypervisor() -> HypervisorFacts {
    HypervisorFacts {
        api: HypervisorApi::Unsupported,
        firmware_virtualization: None,
        hypervisor_vendor: super::hypervisor_vendor(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_hypervisor_is_unsupported_for_now() {
        let facts = hypervisor();
        assert_eq!(facts.api, HypervisorApi::Unsupported);
        assert_eq!(facts.firmware_virtualization, None);
    }
}
