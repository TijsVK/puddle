// SPDX-License-Identifier: GPL-3.0-or-later
//! Rule sets and System managed on the wire (rules spec §7).

use puddle_store as store;
use puddle_types::{RuleSetId, SandboxName};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::{Effect, PatternKind};

/// Why puddle allows a System managed host: a choice you made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SystemReason {
    /// You chose Microsoft's VS Code server for the browser editor.
    MicrosoftServer,
    /// The browser editor runs the bundled code-server.
    CodeServer,
    /// Direct SSH is on for the workspace.
    DirectSsh,
}

impl SystemReason {
    pub(crate) fn from_store(reason: store::SystemReason) -> Option<Self> {
        Some(match reason {
            store::SystemReason::MicrosoftServer => Self::MicrosoftServer,
            store::SystemReason::CodeServer => Self::CodeServer,
            store::SystemReason::DirectSsh => Self::DirectSsh,
            _ => return None,
        })
    }

    /// The reasons named in an audit record; a name this version doesn't know is left out.
    pub(crate) fn parse_all(names: &[String]) -> Vec<Self> {
        names
            .iter()
            .filter_map(|name| store::SystemReason::parse(name))
            .filter_map(Self::from_store)
            .collect()
    }
}

/// One host puddle allows because of your setup, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SystemManagedHost {
    /// `example.com`, or `*.example.com` for every name under it.
    pub pattern: String,
    /// What the host is for.
    pub note: String,
    /// Why it is allowed.
    pub reason: SystemReason,
    /// The reason in words.
    pub reason_text: String,
    /// The one sandbox it is allowed for; `null` for every sandbox.
    #[schema(required = true)]
    pub sandbox: Option<SandboxName>,
}

impl SystemManagedHost {
    pub(crate) fn from_store(host: store::SystemHost) -> Option<Self> {
        Some(Self {
            pattern: host.pattern.to_owned(),
            note: host.note.to_owned(),
            reason: SystemReason::from_store(host.reason)?,
            reason_text: host.reason.describe().to_owned(),
            sandbox: host.sandbox,
        })
    }
}

/// Who made a rule set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RuleSetKind {
    /// Ships with puddle, read-only, updated with puddle.
    BuiltIn,
    /// Made by you.
    User,
}

/// One sandbox's own switch for a set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RuleSetOverride {
    /// The sandbox.
    pub sandbox: SandboxName,
    /// On or off there.
    pub enabled: bool,
}

/// One entry of a rule set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RuleSetEntry {
    /// `example.com`, or `.example.com` for every name under it (a built-in entry is written
    /// `*.example.com`).
    pub pattern: String,
    /// Exact or suffix.
    pub pattern_kind: PatternKind,
    /// Allow or deny (built-in sets only allow).
    pub effect: Effect,
    /// What it is for (built-in sets); empty for your own entries.
    pub note: String,
    /// The entry's rule, for a set you made (delete or change it through `/api/rules`).
    #[schema(required = true)]
    pub rule_id: Option<i64>,
    /// Epoch ms from which the entry no longer counts; `null` is permanent.
    #[schema(required = true)]
    pub expires_at: Option<u64>,
}

/// A rule set: where it is on, and its entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RuleSetView {
    /// `builtin:<slug>` or `user:<id>`.
    pub id: String,
    /// Built-in or yours.
    pub kind: RuleSetKind,
    /// Name.
    pub name: String,
    /// What it is for.
    pub description: String,
    /// Whether it is on where nobody switched it: built-in sets ship off, your sets start on.
    pub default_on: bool,
    /// The switch for every sandbox; `null` follows `default_on`.
    #[schema(required = true)]
    pub global: Option<bool>,
    /// Sandboxes with a switch of their own.
    pub overrides: Vec<RuleSetOverride>,
    /// Its entries.
    pub entries: Vec<RuleSetEntry>,
    /// Built-in sets: epoch ms when a puddle update last changed the entries; `null` if never.
    #[schema(required = true)]
    pub changed_at: Option<u64>,
    /// Your sets: epoch ms it was made.
    #[schema(required = true)]
    pub created_at: Option<u64>,
}

impl RuleSetView {
    pub(crate) fn from_store(info: store::RuleSetInfo) -> Self {
        let store::RuleSetInfo {
            id,
            name,
            description,
            default_on,
            global,
            overrides,
            entries,
            changed_at,
            created_at,
        } = info;
        Self {
            kind: match id {
                RuleSetId::User(_) => RuleSetKind::User,
                _ => RuleSetKind::BuiltIn,
            },
            id: id.to_string(),
            name,
            description,
            default_on,
            global,
            overrides: overrides
                .into_iter()
                .map(|(sandbox, enabled)| RuleSetOverride { sandbox, enabled })
                .collect(),
            entries: entries.into_iter().map(RuleSetEntry::from_store).collect(),
            changed_at,
            created_at,
        }
    }
}

impl RuleSetEntry {
    fn from_store(entry: store::RuleSetEntryInfo) -> Self {
        let store::RuleSetEntryInfo {
            pattern,
            effect,
            note,
            rule_id,
            expires_at,
        } = entry;
        Self {
            pattern_kind: if pattern.starts_with('.') || pattern.starts_with("*.") {
                PatternKind::Suffix
            } else {
                PatternKind::Exact
            },
            pattern,
            effect: effect.into(),
            note,
            rule_id: rule_id.map(|id| id.0),
            expires_at,
        }
    }
}

/// Every rule set, and the System managed hosts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RuleSetList {
    /// Built-in sets first, then yours by name.
    pub sets: Vec<RuleSetView>,
    /// The hosts puddle allows because of your setup, each with its reason. Your own rules
    /// decide first: a deny of yours blocks one.
    pub system_managed: Vec<SystemManagedHost>,
}

/// A rule set to make.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NewRuleSetRequest {
    /// 1 to 64 characters, not used by another set.
    pub name: String,
    /// At most 500 characters.
    #[serde(default)]
    pub description: String,
}

/// A rule set's new name and description.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RuleSetUpdateRequest {
    /// 1 to 64 characters, not used by another set.
    pub name: String,
    /// At most 500 characters.
    #[serde(default)]
    pub description: String,
}

/// Switch a set on or off, for every sandbox or for one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RuleSetSwitchRequest {
    /// The sandbox whose own switch to set; left out or `null` for every sandbox.
    #[serde(default)]
    pub sandbox: Option<SandboxName>,
    /// On or off; `null` removes the switch, so the next level decides (the global switch, then
    /// the set's default).
    #[schema(required = true)]
    pub enabled: Option<bool>,
}

/// What a switch did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RuleSetSwitched {
    /// The set as it is now.
    pub set: RuleSetView,
    /// Open requests the set now decides, closed the same way.
    pub closed: Vec<i64>,
}
