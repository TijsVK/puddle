// SPDX-License-Identifier: GPL-3.0-or-later
//! System managed: which hosts puddle allows because of the user's own setup (rules spec R-41).
//! Derived from the settings here and handed to the store, at start and after every settings
//! or consent change, so the allows follow the choices that justify them.

use puddle_settings::{Consent, ConsentKind, GlobalSettings, ServerChoice};
use puddle_store::{Store, SystemPlan, SystemReason};
use puddle_types::SandboxName;

use crate::error::ApiError;
use crate::routes::settings::load_global;
use crate::settings::SettingsRepo;

/// The System managed reasons for a setup.
///
/// - The browser editor's server is a global choice: Microsoft's server (only with the
///   consent granted) gives Microsoft's download and Marketplace hosts to every sandbox; the
///   bundled code-server gives Open VSX.
/// - `direct_ssh`: the sandboxes with direct SSH on, which get Microsoft's hosts for themselves
///   (desktop VS Code installs Microsoft's server and extensions there).
///
/// Nothing else is derived: a sandbox used with another tool gets no host for VS Code's sake.
#[must_use]
pub(crate) fn plan(global: &GlobalSettings, direct_ssh: &[SandboxName]) -> SystemPlan {
    let mut plan = SystemPlan::default();
    let consented = matches!(
        global.consents.get(ConsentKind::VsCodeServer),
        Consent::Granted { .. }
    );
    match global.vscode_server.server() {
        ServerChoice::Microsoft if consented => {
            plan.everywhere.insert(SystemReason::MicrosoftServer);
        }
        // Microsoft's server chosen without consent never runs: the API refuses the choice, so
        // a document that has it anyway allows nothing.
        ServerChoice::Microsoft => {}
        ServerChoice::CodeServer => {
            plan.everywhere.insert(SystemReason::CodeServer);
        }
    }
    for sandbox in direct_ssh {
        plan.sandboxes
            .entry(sandbox.clone())
            .or_default()
            .insert(SystemReason::DirectSsh);
    }
    plan
}

/// Derives the plan from the stored settings and hands it to the store. Blocking. Direct SSH is
/// not a setting yet, so no sandbox gets the `direct_ssh` hosts.
///
/// # Errors
/// The settings can't be read (the store keeps the reasons it had), or the store fails.
pub(crate) fn refresh(store: &Store, settings: &dyn SettingsRepo) -> Result<(), ApiError> {
    let global = load_global(settings)?;
    let closed = store.set_system_managed(&plan(&global.settings, &[]))?;
    if !closed.is_empty() {
        tracing::info!(
            closed = closed.len(),
            "System managed hosts decided waiting requests"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use puddle_settings::{TermsVersion, UnixMillis};

    use super::*;

    fn microsoft(consent: bool) -> GlobalSettings {
        let mut global = GlobalSettings::default();
        global.vscode_server.server = Some(ServerChoice::Microsoft);
        if consent {
            global.consents.set(
                ConsentKind::VsCodeServer,
                Consent::Granted {
                    at: UnixMillis(1),
                    terms_version: TermsVersion::new("t1").unwrap(),
                },
            );
        }
        global
    }

    #[test]
    fn r41_code_server_by_default_gives_open_vsx_only() {
        let plan = plan(&GlobalSettings::default(), &[]);
        assert_eq!(
            plan.everywhere.into_iter().collect::<Vec<_>>(),
            [SystemReason::CodeServer]
        );
        assert_eq!(plan.sandboxes.len(), 0);
    }

    #[test]
    fn r41_microsoft_server_needs_the_consent() {
        let with = plan(&microsoft(true), &[]);
        assert_eq!(
            with.everywhere.into_iter().collect::<Vec<_>>(),
            [SystemReason::MicrosoftServer]
        );
        assert_eq!(plan(&microsoft(false), &[]), SystemPlan::default());
    }

    #[test]
    fn r41_direct_ssh_gives_microsofts_hosts_to_that_sandbox_only() {
        let ssh = SandboxName::new("ssh").unwrap();
        let plan = plan(&GlobalSettings::default(), std::slice::from_ref(&ssh));
        assert_eq!(
            plan.sandboxes
                .get(&ssh)
                .map(|r| r.iter().copied().collect::<Vec<_>>()),
            Some(vec![SystemReason::DirectSsh])
        );
        assert!(!plan.everywhere.contains(&SystemReason::DirectSsh));
    }
}
