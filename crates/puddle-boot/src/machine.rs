// SPDX-License-Identifier: GPL-3.0-or-later
//! VS Code's Machine settings in the guest: how ports are forwarded (D-4, T-019) and the
//! accident guard that keeps desktop VS Code from handing its git credentials to the guest
//! (D-30 (c)).

use puddle_types::GuestFile;
use serde_json::json;

use crate::assets::guest_path;

/// Where the VS Code server reads Machine settings for the `root` user (T-003).
pub const MACHINE_SETTINGS_GUEST: &str = "/root/.vscode-server/data/Machine/settings.json";

/// The Machine settings file:
///
/// - `remote.autoForwardPortsSource: process` and `remote.autoForwardPortsFallback: 0`, so ports
///   are found from listening processes and VS Code never falls back to output scanning (D-4,
///   T-019 §2);
/// - the agent's proxy port is never auto-forwarded; other ports notify;
/// - `github.gitAuthentication: false` and `git.terminalAuthentication: false` (D-30 (c): an
///   accident guard only, desktop VS Code attach stays a trusted mode).
///
/// puddle owns the file: the boot hook rewrites it on every boot.
#[must_use]
pub fn machine_settings(agent_port: u16) -> GuestFile {
    let settings = json!({
        "remote.autoForwardPortsSource": "process",
        "remote.autoForwardPortsFallback": 0,
        "remote.otherPortsAttributes": { "onAutoForward": "notify" },
        "remote.portsAttributes": {
            agent_port.to_string(): { "onAutoForward": "ignore", "label": "puddle proxy" }
        },
        "github.gitAuthentication": false,
        "git.terminalAuthentication": false,
    });
    GuestFile::new(
        guest_path(MACHINE_SETTINGS_GUEST),
        format!("{settings:#}\n").into_bytes(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_forward_by_process_and_guard_git_auth() {
        let f = machine_settings(3128);
        assert_eq!(f.path().as_str(), MACHINE_SETTINGS_GUEST);
        assert_eq!(f.mode(), 0o644);
        let v: serde_json::Value = serde_json::from_slice(f.contents()).unwrap();
        assert_eq!(v["remote.autoForwardPortsSource"], "process");
        assert_eq!(v["remote.autoForwardPortsFallback"], 0);
        assert_eq!(
            v["remote.portsAttributes"]["3128"]["onAutoForward"],
            "ignore"
        );
        assert_eq!(v["remote.otherPortsAttributes"]["onAutoForward"], "notify");
        assert_eq!(v["github.gitAuthentication"], false);
        assert_eq!(v["git.terminalAuthentication"], false);
        assert!(f.contents().ends_with(b"}\n"));
    }

    #[test]
    fn settings_name_no_credential_helper() {
        let text = String::from_utf8(machine_settings(3128).contents().to_vec()).unwrap();
        assert!(!text.to_lowercase().contains("credential"));
    }
}
