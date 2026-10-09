// SPDX-License-Identifier: GPL-3.0-or-later
//! Effective values: a workspace's override over the global value over puddle's built-in default.

use puddle_types::{LocalCategory, MemoryMib};
use serde::Serialize;

use crate::{ClipboardRead, GlobalSettings, LocalToggles, ReconnectionGrace, WorkspaceSettings};

/// Which level a value came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// The workspace's own override.
    Workspace,
    /// The user's global setting.
    Global,
    /// puddle's built-in default.
    Default,
}

/// A value and where it came from, so the UI can show "inherited from global".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct Resolved<T> {
    /// The value in effect.
    pub value: T,
    /// The level that set it.
    pub source: Source,
}

/// The values one workspace runs with. Every field is set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct Effective {
    /// Guest memory.
    pub memory: Resolved<MemoryMib>,
    /// Local-destination toggles.
    pub local_toggles: EffectiveToggles,
    /// Whether wildcard allows reach local addresses.
    pub wildcards_reach_local: Resolved<bool>,
    /// Browser VS Code's reconnection grace.
    pub reconnection_grace: Resolved<ReconnectionGrace>,
    /// Zoom hotkeys in workspace windows.
    pub zoom_hotkeys: Resolved<bool>,
    /// Programmatic clipboard reads in workspace windows.
    pub clipboard_read: Resolved<ClipboardRead>,
    /// Whether puddle opens an SSH endpoint and an ssh config entry for the workspace.
    pub direct_ssh: Resolved<bool>,
    /// Whether logins made inside the workspace are captured (the real tokens stay on the host).
    pub capture_logins: Resolved<bool>,
}

/// The local-destination toggles in effect for one workspace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct EffectiveToggles {
    /// Host loopback.
    pub loopback: Resolved<bool>,
    /// Private networks.
    pub private: Resolved<bool>,
    /// Link-local addresses.
    pub link_local: Resolved<bool>,
    /// Cloud metadata endpoints.
    pub metadata: Resolved<bool>,
    /// Other special-purpose ranges.
    pub special: Resolved<bool>,
}

impl EffectiveToggles {
    /// The toggle in effect for `category`.
    ///
    /// ```
    /// use puddle_settings::Effective;
    /// use puddle_types::LocalCategory;
    /// assert!(!Effective::DEFAULTS.local_toggles.get(LocalCategory::Metadata).value);
    /// ```
    #[must_use]
    pub fn get(&self, category: LocalCategory) -> Resolved<bool> {
        match category {
            LocalCategory::Loopback => self.loopback,
            LocalCategory::Private => self.private,
            LocalCategory::LinkLocal => self.link_local,
            LocalCategory::Metadata => self.metadata,
            LocalCategory::Special => self.special,
            // Fails closed: a category without a toggle here is off.
            _ => default(false),
        }
    }
}

impl Effective {
    /// puddle's built-in defaults: 8 GiB, every local toggle off, wildcards don't reach
    /// local addresses, 300 s grace, zoom hotkeys on, clipboard reads
    /// ask.
    pub const DEFAULTS: Effective = Effective {
        memory: default(MemoryMib::DEFAULT),
        local_toggles: EffectiveToggles {
            loopback: default(false),
            private: default(false),
            link_local: default(false),
            metadata: default(false),
            special: default(false),
        },
        wildcards_reach_local: default(false),
        reconnection_grace: default(ReconnectionGrace::DEFAULT),
        zoom_hotkeys: default(true),
        clipboard_read: default(ClipboardRead::Ask),
        direct_ssh: default(false),
        capture_logins: default(true),
    };
}

const fn default<T: Copy>(value: T) -> Resolved<T> {
    Resolved {
        value,
        source: Source::Default,
    }
}

fn pick<T: Copy>(workspace: Option<T>, global: Option<T>, builtin: Resolved<T>) -> Resolved<T> {
    match (workspace, global) {
        (Some(value), _) => Resolved {
            value,
            source: Source::Workspace,
        },
        (None, Some(value)) => Resolved {
            value,
            source: Source::Global,
        },
        (None, None) => builtin,
    }
}

/// The settings `workspace` runs with: its override if set, else the global value if set, else
/// puddle's default ([`Effective::DEFAULTS`]). `None` resolves a workspace that has no settings
/// document (yet), i.e. the global values.
///
/// ```
/// use puddle_settings::{GlobalSettings, WorkspaceSettings, Source, resolve};
///
/// let mut global = GlobalSettings::default();
/// global.workspace_defaults.local_toggles.private = Some(true);
/// let mut workspace = WorkspaceSettings::default();
/// workspace.overrides.local_toggles.private = Some(false);
///
/// let e = resolve(&global, Some(&workspace));
/// assert!(!e.local_toggles.private.value);
/// assert_eq!(e.local_toggles.private.source, Source::Workspace);
/// assert_eq!(e.local_toggles.loopback.source, Source::Default);
/// ```
#[must_use]
pub fn resolve(global: &GlobalSettings, workspace: Option<&WorkspaceSettings>) -> Effective {
    let g = &global.workspace_defaults;
    let none = crate::WorkspaceLayer::default();
    let s = workspace.map_or(&none, |s| &s.overrides);
    let d = Effective::DEFAULTS;
    // Destructured so a new layer field doesn't compile until it is resolved here.
    let crate::WorkspaceLayer {
        memory,
        local_toggles,
        wildcards_reach_local,
        reconnection_grace,
        zoom_hotkeys,
        clipboard_read,
        direct_ssh,
        capture_logins,
        extra: _,
    } = s;
    let LocalToggles {
        loopback,
        private,
        link_local,
        metadata,
        special,
        extra: _,
    } = local_toggles;
    Effective {
        memory: pick(*memory, g.memory, d.memory),
        local_toggles: EffectiveToggles {
            loopback: pick(
                *loopback,
                g.local_toggles.loopback,
                d.local_toggles.loopback,
            ),
            private: pick(*private, g.local_toggles.private, d.local_toggles.private),
            link_local: pick(
                *link_local,
                g.local_toggles.link_local,
                d.local_toggles.link_local,
            ),
            metadata: pick(
                *metadata,
                g.local_toggles.metadata,
                d.local_toggles.metadata,
            ),
            special: pick(*special, g.local_toggles.special, d.local_toggles.special),
        },
        wildcards_reach_local: pick(
            *wildcards_reach_local,
            g.wildcards_reach_local,
            d.wildcards_reach_local,
        ),
        reconnection_grace: pick(
            *reconnection_grace,
            g.reconnection_grace,
            d.reconnection_grace,
        ),
        zoom_hotkeys: pick(*zoom_hotkeys, g.zoom_hotkeys, d.zoom_hotkeys),
        clipboard_read: pick(*clipboard_read, g.clipboard_read, d.clipboard_read),
        direct_ssh: pick(*direct_ssh, g.direct_ssh, d.direct_ssh),
        capture_logins: pick(*capture_logins, g.capture_logins, d.capture_logins),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_ssh_follows_the_override_then_the_global_default() {
        let mut g = GlobalSettings::default();
        let mut s = WorkspaceSettings::default();
        g.workspace_defaults.direct_ssh = Some(true);
        let e = resolve(&g, Some(&s));
        assert!(e.direct_ssh.value);
        assert_eq!(e.direct_ssh.source, Source::Global);
        s.overrides.direct_ssh = Some(false);
        let e = resolve(&g, Some(&s));
        assert!(!e.direct_ssh.value);
        assert_eq!(e.direct_ssh.source, Source::Workspace);
    }

    #[test]
    fn login_capture_is_on_until_someone_turns_it_off() {
        let mut g = GlobalSettings::default();
        let mut s = WorkspaceSettings::default();
        let e = resolve(&g, Some(&s));
        assert!(e.capture_logins.value);
        assert_eq!(e.capture_logins.source, Source::Default);
        g.workspace_defaults.capture_logins = Some(false);
        let e = resolve(&g, Some(&s));
        assert!(!e.capture_logins.value);
        assert_eq!(e.capture_logins.source, Source::Global);
        s.overrides.capture_logins = Some(true);
        let e = resolve(&g, Some(&s));
        assert!(e.capture_logins.value);
        assert_eq!(e.capture_logins.source, Source::Workspace);
    }

    #[test]
    fn nothing_set_gives_the_built_in_defaults() {
        let e = resolve(&GlobalSettings::default(), None);
        assert_eq!(e, Effective::DEFAULTS);
        assert_eq!(e.memory.value, MemoryMib::DEFAULT);
        assert!(!e.local_toggles.metadata.value);
        assert!(!e.wildcards_reach_local.value);
        assert!(
            !e.direct_ssh.value,
            "direct SSH is off until someone turns it on"
        );
        assert_eq!(e.reconnection_grace.value.secs(), 300);
        assert!(e.zoom_hotkeys.value);
        assert_eq!(e.clipboard_read.value, ClipboardRead::Ask);
        assert_eq!(
            resolve(
                &GlobalSettings::default(),
                Some(&WorkspaceSettings::default())
            ),
            Effective::DEFAULTS
        );
    }

    #[test]
    fn effective_values_serialise_with_their_source() {
        let mut g = GlobalSettings::default();
        g.workspace_defaults.zoom_hotkeys = Some(false);
        let v = serde_json::to_value(resolve(&g, None)).unwrap();
        assert_eq!(
            v["zoom_hotkeys"],
            serde_json::json!({"value": false, "source": "global"})
        );
        assert_eq!(v["memory"]["source"], "default");
        assert_eq!(v["local_toggles"]["private"]["value"], false);
    }

    #[test]
    fn toggles_resolve_per_category_under_their_keys() {
        for category in LocalCategory::ALL {
            let mut g = GlobalSettings::default();
            let mut s = WorkspaceSettings::default();
            // The global default turns it on; the workspace turns it off again.
            let doc = serde_json::json!({ category.key(): true });
            g.workspace_defaults.local_toggles = serde_json::from_value(doc).unwrap();
            assert_eq!(
                resolve(&g, Some(&s)).local_toggles.get(category),
                Resolved {
                    value: true,
                    source: Source::Global
                }
            );
            let doc = serde_json::json!({ category.key(): false });
            s.overrides.local_toggles = serde_json::from_value(doc).unwrap();
            let e = resolve(&g, Some(&s));
            assert_eq!(
                e.local_toggles.get(category),
                Resolved {
                    value: false,
                    source: Source::Workspace
                }
            );
            let v = serde_json::to_value(e).unwrap();
            assert_eq!(v["local_toggles"][category.key()]["source"], "workspace");
            for other in LocalCategory::ALL.into_iter().filter(|o| *o != category) {
                assert_eq!(e.local_toggles.get(other).source, Source::Default);
            }
        }
    }
}
