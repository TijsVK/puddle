// SPDX-License-Identifier: GPL-3.0-or-later
//! VS Code's Machine settings in the guest: how ports are forwarded and the
//! accident guard that keeps desktop VS Code from handing its git credentials to the guest.

use puddle_types::{GuestFile, MergeEntry, MergeFormat, MergeSpec};
use serde_json::json;

use crate::assets::guest_path;

/// Where the VS Code server reads Machine settings for the `root` user.
pub const MACHINE_SETTINGS_GUEST: &str = "/root/.vscode-server/data/Machine/settings.json";

/// The Machine settings file, as a JSONC merge: puddle owns only these keys, so the
/// user's own Machine settings, comments and trailing commas survive every boot.
///
/// - `remote.autoForwardPortsSource: process` and `remote.autoForwardPortsFallback: 0`, so ports
///   are found from listening processes and VS Code never falls back to output scanning;
/// - the agent's proxy port is never auto-forwarded (`remote.portsAttributes.<port>`), other ports
///   notify (`remote.otherPortsAttributes.onAutoForward`); the user's own port entries stay;
/// - `github.gitAuthentication: false` and `git.terminalAuthentication: false` (an
///   accident guard only, desktop VS Code attach stays a trusted mode). Puddle sets them again
///   at every boot, so a user's own value for these two does not last.
///
/// # Panics
///
/// Never in practice: the keys are fixed and disjoint (the unit tests build the spec for several
/// ports).
#[must_use]
pub fn machine_settings(agent_port: u16) -> GuestFile {
    let entry = |key: &[&str], value: serde_json::Value| MergeEntry::json(key, &value);
    let port = agent_port.to_string();
    let spec = MergeSpec::new(
        MergeFormat::Jsonc,
        vec![
            entry(&["remote.autoForwardPortsSource"], json!("process")),
            entry(&["remote.autoForwardPortsFallback"], json!(0)),
            entry(
                &["remote.otherPortsAttributes", "onAutoForward"],
                json!("notify"),
            ),
            entry(
                &["remote.portsAttributes", &port],
                json!({ "onAutoForward": "ignore", "label": "puddle proxy" }),
            ),
            entry(&["github.gitAuthentication"], json!(false)),
            entry(&["git.terminalAuthentication"], json!(false)),
        ],
    );
    #[expect(
        clippy::expect_used,
        reason = "the keys are fixed and disjoint, the values are JSON: the unit tests build it for several ports"
    )]
    let spec = spec.expect("the Machine settings spec is valid");
    GuestFile::merged(guest_path(MACHINE_SETTINGS_GUEST), spec)
}

#[cfg(test)]
mod tests {
    use puddle_types::{ApplyKind, Merged};

    use super::*;

    #[test]
    fn settings_forward_by_process_and_guard_git_auth() {
        let f = machine_settings(3128);
        assert_eq!(f.path().as_str(), MACHINE_SETTINGS_GUEST);
        assert_eq!(f.mode(), 0o644);
        let ApplyKind::Merge(spec) = f.apply() else {
            panic!("the Machine settings are merged, not replaced")
        };
        assert_eq!(spec.format(), MergeFormat::Jsonc);
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
    fn puddle_owns_leaves_not_whole_port_tables() {
        let keys = machine_settings(3128);
        let ApplyKind::Merge(spec) = keys.apply() else {
            panic!()
        };
        let keys = spec.keys();
        // A user's own `remote.portsAttributes` entries and other ports' attributes are theirs.
        assert!(keys.contains(&vec![
            "remote.portsAttributes".to_owned(),
            "3128".to_owned()
        ]));
        assert!(!keys.contains(&vec!["remote.portsAttributes".to_owned()]));
        assert!(!keys.contains(&vec!["remote.otherPortsAttributes".to_owned()]));
        assert_eq!(keys.len(), 6);
    }

    #[test]
    fn any_agent_port_gives_a_valid_spec() {
        for port in [0, 1, 3128, u16::MAX] {
            let _ = machine_settings(port);
        }
    }

    #[test]
    fn the_users_own_machine_settings_survive_a_boot_and_the_guard_is_kept() {
        let user = "// mine\n{\n  \"editor.fontSize\": 14, // big\n  \"github.gitAuthentication\": true,\n  \"remote.portsAttributes\": { \"8080\": { \"label\": \"web\" }, },\n}\n";
        let f = machine_settings(3128);
        let ApplyKind::Merge(spec) = f.apply() else {
            panic!()
        };
        let Merged::Write(out) = spec.apply(Some(user.as_bytes()), &[]).unwrap() else {
            panic!("the file changes")
        };
        let out = String::from_utf8(out).unwrap();
        assert!(
            out.starts_with("// mine\n{\n  \"editor.fontSize\": 14, // big\n"),
            "{out}"
        );
        assert!(out.contains("\"8080\": { \"label\": \"web\" }"), "{out}");
        assert!(out.contains("\"3128\""), "{out}");
        // The guard wins over the user's own value, at every boot.
        assert!(out.contains("\"github.gitAuthentication\": false"), "{out}");
        assert_eq!(
            spec.apply(Some(out.as_bytes()), &spec.keys()).unwrap(),
            Merged::Unchanged
        );
    }

    #[test]
    fn settings_name_no_credential_helper() {
        let text = String::from_utf8(machine_settings(3128).contents().to_vec()).unwrap();
        assert!(!text.to_lowercase().contains("credential"));
    }
}
