// SPDX-License-Identifier: GPL-3.0-or-later
//! System managed: which hosts puddle allows because of the user's own setup (rules spec R-41).
//! Derived from the settings here and handed to the store, at start and after every settings
//! or consent change, so the allows follow the choices that justify them.

use puddle_settings::{Consent, ConsentKind, GlobalSettings, ServerChoice};
use puddle_store::{SystemPlan, SystemReason};
use puddle_types::WorkspaceName;

use puddle_settings::resolve;

use crate::error::blocking;
use crate::routes::AppState;
use crate::routes::settings::{load_global, load_workspace};

/// The System managed reasons for a setup.
///
/// - The browser editor's server is a global choice: Microsoft's server (only with the
///   consent granted) gives Microsoft's download and Marketplace hosts to every workspace; the
///   bundled code-server gives Open VSX.
/// - `direct_ssh`: the workspaces with direct SSH on, which get Microsoft's hosts for themselves
///   (desktop VS Code installs Microsoft's server and extensions there).
///
/// Nothing else is derived: a workspace used with another tool gets no host for VS Code's sake.
#[must_use]
pub(crate) fn plan(global: &GlobalSettings, direct_ssh: &[WorkspaceName]) -> SystemPlan {
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
    for workspace in direct_ssh {
        plan.workspaces
            .entry(workspace.clone())
            .or_default()
            .insert(SystemReason::DirectSsh);
    }
    plan
}

/// Derives the plan from the stored settings and the workspaces, and hands it to the store. Run
/// at start and after every change that can move it: global or workspace settings, a consent, a
/// workspace made or deleted. Takes the settings lock itself, so call it after releasing it.
///
/// A failure is logged and leaves the store's reasons as they were. A workspace list that can't
/// be read counts as no workspace with direct SSH on (an allow is only ever dropped then).
pub(crate) async fn refresh(state: &AppState) {
    let names: Vec<WorkspaceName> = match state.workspaces.list().await {
        Ok(records) => records.into_iter().map(|w| w.name).collect(),
        Err(_) => Vec::new(),
    };
    let (store, settings) = (state.store.clone(), state.settings.clone());
    let _lock = state.settings_lock.lock().await;
    let result = blocking(move || {
        let repo = settings.as_ref();
        let global = load_global(repo)?;
        let direct: Vec<WorkspaceName> = names
            .into_iter()
            .filter(|name| {
                load_workspace(repo, name).is_ok_and(|own| {
                    resolve(&global.settings, Some(&own.settings))
                        .direct_ssh
                        .value
                })
            })
            .collect();
        Ok(store.set_system_managed(&plan(&global.settings, &direct))?)
    })
    .await;
    match result {
        Ok(closed) if !closed.is_empty() => {
            let count = closed.len();
            tracing::info!(count, "System managed hosts decided waiting requests");
        }
        Ok(_) => {}
        Err(err) => {
            tracing::warn!(error = ?err, "System managed hosts not derived; the stored ones stay");
        }
    }
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
        assert_eq!(plan.workspaces.len(), 0);
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
    fn r41_direct_ssh_gives_microsofts_hosts_to_that_workspace_only() {
        let ssh = WorkspaceName::new("ssh").unwrap();
        let plan = plan(&GlobalSettings::default(), std::slice::from_ref(&ssh));
        assert_eq!(
            plan.workspaces
                .get(&ssh)
                .map(|r| r.iter().copied().collect::<Vec<_>>()),
            Some(vec![SystemReason::DirectSsh])
        );
        assert!(!plan.everywhere.contains(&SystemReason::DirectSsh));
    }
}
