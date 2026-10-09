// SPDX-License-Identifier: GPL-3.0-or-later
//! Events puddle reports to the user (API/SSE, tray, logs), and the sink they go into.

use std::fmt;
use std::sync::{Mutex, PoisonError};

use serde::{Deserialize, Serialize};

use crate::WorkspaceName;

/// A workspace's state: its sandbox's state as the runtime reports it (msb's states, one for one).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum WorkspaceStatus {
    /// Created but not started.
    Created,
    /// A start was accepted; not running yet.
    Starting,
    /// Running: exec and SSH work.
    Running,
    /// Shutting down gracefully.
    Draining,
    /// Paused.
    Paused,
    /// Stopped by an explicit stop.
    Stopped,
    /// Ended without an explicit stop: the VM died, or its owning handle was dropped.
    Crashed,
    /// The workspace is listed but its volume is gone, so it cannot start: restore the volume
    /// and start it again, or delete the workspace.
    VolumeMissing,
}

impl WorkspaceStatus {
    /// The `snake_case` name used on the wire and in messages.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Draining => "draining",
            Self::Paused => "paused",
            Self::Stopped => "stopped",
            Self::Crashed => "crashed",
            Self::VolumeMissing => "volume_missing",
        }
    }

    /// Whether the workspace has no VM (it can be started or removed).
    #[must_use]
    pub fn is_down(self) -> bool {
        matches!(
            self,
            Self::Created | Self::Stopped | Self::Crashed | Self::VolumeMissing
        )
    }
}

impl fmt::Display for WorkspaceStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Longest process name kept in [`Event::OomKill`] (the kernel's `TASK_COMM_LEN` is 16).
const MAX_PROCESS_NAME_CHARS: usize = 64;

/// Something the user should hear about. Serialised as one internally tagged enum
/// (`{"type":"oom_kill",...}`, ADR 0002).
///
/// Most events are about one workspace and carry a `workspace` field; global ones (crash report
/// waiting, consent needed, network change, ...) carry none, and [`Event::workspace`] returns
/// `None` for them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[non_exhaustive]
pub enum Event {
    /// A workspace changed state.
    StatusChanged {
        /// The workspace.
        workspace: WorkspaceName,
        /// Its new state.
        status: WorkspaceStatus,
    },
    /// The guest kernel's OOM killer ended a process (reported by the guest agent).
    ///
    /// `pid` and `process` come from the guest and are untrusted: build this variant with
    /// [`Event::oom_kill`], which bounds and cleans the name, and escape it when rendering.
    OomKill {
        /// The workspace whose guest killed the process.
        workspace: WorkspaceName,
        /// The killed process's id inside the guest.
        pid: u32,
        /// The killed process's name (`comm`), cleaned by [`Event::oom_kill`].
        process: String,
    },
    /// A workspace operation (create, start, stop, reclaim, delete) moved on. An operation ends
    /// with one event whose step is [`WorkspaceStep::Done`] or [`WorkspaceStep::Failed`].
    WorkspaceProgress {
        /// The workspace's workspace.
        workspace: WorkspaceName,
        /// What it is doing now.
        step: WorkspaceStep,
        /// More about the step, or why it failed; `null` when there is nothing to add. It can
        /// quote tool output: escape it when rendering.
        #[serde(default)]
        #[cfg_attr(feature = "openapi", schema(required = true))]
        detail: Option<String>,
    },
    /// A new open pending request (a workspace asked for a host:port no rule decides).
    PendingOpened {
        /// The request, as `GET /api/pending` shows it.
        request: PendingSummary,
    },
    /// An open pending request was seen again.
    PendingUpdated {
        /// The workspace.
        workspace: WorkspaceName,
        /// The pending request's id.
        id: i64,
        /// Requests the row stands for now.
        attempts: u64,
        /// Epoch ms of the latest one.
        last_seen: u64,
    },
    /// A pending request is no longer open: decided by a user or by a rule, or expired.
    PendingClosed {
        /// The workspace.
        workspace: WorkspaceName,
        /// The pending request's id.
        id: i64,
        /// How it ended.
        state: PendingEnd,
        /// The rule that decided it; `null` for an expiry.
        #[serde(default)]
        #[cfg_attr(feature = "openapi", schema(required = true))]
        rule_id: Option<i64>,
    },
    /// A workspace's "requests held back" state (R-13) changed. Sent when suppression starts or
    /// ends, and at most twice a second while its count grows.
    SuppressionChanged {
        /// The workspace.
        workspace: WorkspaceName,
        /// Whether suppression is on.
        active: bool,
        /// Requests held back in this episode so far.
        count: u64,
    },
    /// Rules were created, changed, deleted or expired. Global: every subscriber gets it.
    RulesChanged {},
    /// The list of identities, their order, the default or an identity's author or credentials
    /// changed. Carries no data: refetch `GET /api/identities`.
    IdentitiesChanged {},
    /// A workspace's identities, repository table or "only listed" switches changed (also when an
    /// identity it has changed). Refetch `GET /api/workspaces/{id}/git`.
    WorkspaceGitChanged {
        /// The workspace.
        workspace: WorkspaceName,
    },
    /// The global environment (variables and secrets every workspace gets) changed. Carries no
    /// data: refetch `GET /api/env`, and a workspace's page refetches its own list too.
    GlobalEnvChanged {},
    /// A workspace's own environment changed. Refetch `GET /api/workspaces/{id}/env`. Never carries
    /// a value.
    WorkspaceEnvChanged {
        /// The workspace.
        workspace: WorkspaceName,
    },
    /// A workspace asked for a credential and the source of it cannot supply one (not signed in,
    /// or the sign-in ran out). The user signs in from puddle; a request never opens a sign-in
    /// window. Global: every subscriber gets it. Names only, never a value.
    CredentialSignInNeeded {
        /// The Git host the workspace was talking to.
        host: String,
        /// The source, as one line of names (`gh account me on github.com`).
        source: String,
    },
    /// A push or a fetch was refused because the workspace's repository table does not allow it.
    /// `host`, `owner` and `repo` are the table's spelling of the repository (lower-case, no
    /// `.git`), so the notice can add the row as it is.
    GitAccessDenied {
        /// The workspace that tried.
        workspace: WorkspaceName,
        /// The Git host.
        host: String,
        /// The user or organisation.
        owner: String,
        /// `repo`, or `project/repo` on Azure DevOps.
        repo: String,
        /// What was refused.
        access: GitAccess,
    },
    /// New audit records were committed. `id` is the newest record's id, so a client that holds
    /// everything up to `after` reads on with `GET /api/audit?after=`. One event per commit,
    /// not per record. Global: every subscriber gets it.
    AuditAppended {
        /// The newest audit record's id.
        id: i64,
    },
    /// The network or the system's proxy settings changed (after a quiet period), so what
    /// `GET /api/network-health` showed may be out of date. Global: every subscriber gets it.
    NetworkChanged {
        /// The network epoch that began; it only grows while puddle runs.
        epoch: u64,
    },
}

/// An open pending request as [`Event::PendingOpened`] carries it. `host` comes from the guest
/// (already normalised by the proxy): escape it when rendering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct PendingSummary {
    /// The pending request's id.
    pub id: i64,
    /// The workspace that asked.
    pub workspace: WorkspaceName,
    /// The requested host, normalised.
    pub host: String,
    /// The host's registrable domain (`example.co.uk` for `api.example.co.uk`; the IP literal
    /// itself), the key the inbox groups rows by.
    pub registrable_domain: String,
    /// The requested port.
    pub port: u16,
    /// Epoch ms of the first request.
    pub first_seen: u64,
    /// Epoch ms of the latest one.
    pub last_seen: u64,
    /// Requests the row stands for.
    pub attempts: u64,
}

/// What a workspace's repository table refused, as [`Event::GitAccessDenied`] reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum GitAccess {
    /// A push (`git-receive-pack`).
    Push,
    /// A fetch or clone (`git-upload-pack`).
    Pull,
}

/// How a pending request ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum PendingEnd {
    /// Allowed by a rule.
    Allowed,
    /// Denied by a rule.
    Denied,
    /// Expired without a decision.
    Expired,
}

/// Where a long workspace operation is, as [`Event::WorkspaceProgress`] reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum WorkspaceStep {
    /// Creating the workspace's disk volume.
    PreparingVolume,
    /// Pulling the workspace's image.
    PullingImage,
    /// Cloning the repository.
    Cloning,
    /// Booting the workspace's virtual machine.
    Starting,
    /// Bringing the checkouts in line with the volume after a boot.
    Syncing,
    /// Looking for work that is not on a remote.
    Checking,
    /// Giving freed disk space back to the host.
    Reclaiming,
    /// Shutting the virtual machine down.
    Stopping,
    /// Removing the volume and the workspace.
    Removing,
    /// The operation finished.
    Done,
    /// The operation failed; `detail` says why.
    Failed,
}

impl Event {
    /// An [`Event::OomKill`], with `process` cut to 64 characters and control characters
    /// replaced by `?`, since it comes from the guest.
    ///
    /// ```
    /// use puddle_types::{Event, WorkspaceName};
    /// let e = Event::oom_kill(WorkspaceName::new("a").unwrap(), 42, "node\u{1b}[2J");
    /// assert!(matches!(e, Event::OomKill { ref process, .. } if process == "node?[2J"));
    /// ```
    #[must_use]
    pub fn oom_kill(workspace: WorkspaceName, pid: u32, process: &str) -> Self {
        let process = process
            .chars()
            .take(MAX_PROCESS_NAME_CHARS)
            .map(|c| if c.is_control() { '?' } else { c })
            .collect();
        Self::OomKill {
            workspace,
            pid,
            process,
        }
    }

    /// The workspace this event is about, or `None` for a global event.
    ///
    /// ```
    /// use puddle_types::{Event, WorkspaceName};
    /// let a = WorkspaceName::new("a").unwrap();
    /// assert_eq!(Event::oom_kill(a.clone(), 1, "x").workspace(), Some(&a));
    /// ```
    #[must_use]
    pub fn workspace(&self) -> Option<&WorkspaceName> {
        match self {
            Self::StatusChanged { workspace, .. }
            | Self::OomKill { workspace, .. }
            | Self::WorkspaceProgress { workspace, .. }
            | Self::PendingUpdated { workspace, .. }
            | Self::PendingClosed { workspace, .. }
            | Self::SuppressionChanged { workspace, .. }
            | Self::GitAccessDenied { workspace, .. }
            | Self::WorkspaceGitChanged { workspace }
            | Self::WorkspaceEnvChanged { workspace } => Some(workspace),
            Self::PendingOpened { request } => Some(&request.workspace),
            Self::RulesChanged {}
            | Self::IdentitiesChanged {}
            | Self::GlobalEnvChanged {}
            | Self::CredentialSignInNeeded { .. }
            | Self::AuditAppended { .. }
            | Self::NetworkChanged { .. } => None,
        }
    }
}

/// Where events go. Implementations must not block: queue or drop, never wait on a consumer.
pub trait EventSink: Send + Sync {
    /// Hands over one event.
    fn emit(&self, event: Event);
}

/// A sink that drops every event.
#[derive(Debug, Clone, Copy, Default)]
pub struct NullSink;

impl EventSink for NullSink {
    fn emit(&self, _event: Event) {}
}

/// A sink that keeps every event in memory, for tests.
///
/// ```
/// use puddle_types::{CollectingSink, Event, EventSink, WorkspaceName};
/// let sink = CollectingSink::default();
/// sink.emit(Event::oom_kill(WorkspaceName::new("a").unwrap(), 1, "x"));
/// assert_eq!(sink.take().len(), 1);
/// assert!(sink.take().is_empty());
/// ```
#[derive(Debug, Default)]
pub struct CollectingSink {
    events: Mutex<Vec<Event>>,
}

impl CollectingSink {
    /// The events so far, leaving them in place.
    #[must_use]
    pub fn events(&self) -> Vec<Event> {
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The events so far, emptying the sink.
    #[must_use]
    pub fn take(&self) -> Vec<Event> {
        std::mem::take(&mut *self.events.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

impl EventSink for CollectingSink {
    fn emit(&self, event: Event) {
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(event);
    }
}

impl<T: EventSink + ?Sized> EventSink for std::sync::Arc<T> {
    fn emit(&self, event: Event) {
        (**self).emit(event);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    fn name() -> WorkspaceName {
        WorkspaceName::new("box").unwrap()
    }

    #[test]
    fn status_names_and_down_states() {
        let all = [
            (WorkspaceStatus::Created, "created", true),
            (WorkspaceStatus::Starting, "starting", false),
            (WorkspaceStatus::Running, "running", false),
            (WorkspaceStatus::Draining, "draining", false),
            (WorkspaceStatus::Paused, "paused", false),
            (WorkspaceStatus::Stopped, "stopped", true),
            (WorkspaceStatus::Crashed, "crashed", true),
            (WorkspaceStatus::VolumeMissing, "volume_missing", true),
        ];
        for (status, text, down) in all {
            assert_eq!(status.to_string(), text);
            assert_eq!(status.is_down(), down, "{status}");
            assert_eq!(
                serde_json::to_string(&status).unwrap(),
                format!("\"{text}\"")
            );
        }
    }

    #[test]
    fn oom_kill_bounds_and_cleans_the_guest_supplied_name() {
        let long = "a".repeat(1000);
        let Event::OomKill { process, pid, .. } = Event::oom_kill(name(), 7, &long) else {
            panic!("wrong variant");
        };
        assert_eq!(process.len(), MAX_PROCESS_NAME_CHARS);
        assert_eq!(pid, 7);
        let Event::OomKill { process, .. } = Event::oom_kill(name(), 7, "a\nb\0c") else {
            panic!("wrong variant");
        };
        assert_eq!(process, "a?b?c");
    }

    #[test]
    fn events_are_internally_tagged_snake_case() {
        let e = Event::oom_kill(name(), 42, "node");
        assert_eq!(
            serde_json::to_string(&e).unwrap(),
            r#"{"type":"oom_kill","workspace":"box","pid":42,"process":"node"}"#
        );
        let s = Event::StatusChanged {
            workspace: name(),
            status: WorkspaceStatus::Crashed,
        };
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(
            json,
            r#"{"type":"status_changed","workspace":"box","status":"crashed"}"#
        );
        assert_eq!(serde_json::from_str::<Event>(&json).unwrap(), s);
        assert_eq!(s.workspace(), Some(&name()));
        assert_eq!(e.workspace(), Some(&name()));
    }

    #[test]
    fn workspace_progress_is_per_workspace_and_always_carries_detail() {
        let steps = [
            (WorkspaceStep::PreparingVolume, "preparing_volume"),
            (WorkspaceStep::PullingImage, "pulling_image"),
            (WorkspaceStep::Cloning, "cloning"),
            (WorkspaceStep::Starting, "starting"),
            (WorkspaceStep::Syncing, "syncing"),
            (WorkspaceStep::Checking, "checking"),
            (WorkspaceStep::Reclaiming, "reclaiming"),
            (WorkspaceStep::Stopping, "stopping"),
            (WorkspaceStep::Removing, "removing"),
            (WorkspaceStep::Done, "done"),
            (WorkspaceStep::Failed, "failed"),
        ];
        for (step, text) in steps {
            let e = Event::WorkspaceProgress {
                workspace: name(),
                step,
                detail: None,
            };
            let json = serde_json::to_string(&e).unwrap();
            assert_eq!(
                json,
                format!(
                    r#"{{"type":"workspace_progress","workspace":"box","step":"{text}","detail":null}}"#
                )
            );
            assert_eq!(serde_json::from_str::<Event>(&json).unwrap(), e);
            assert_eq!(e.workspace(), Some(&name()));
        }
        let with_detail: Event = serde_json::from_str(
            r#"{"type":"workspace_progress","workspace":"box","step":"failed","detail":"disk full"}"#,
        )
        .unwrap();
        assert!(matches!(
            with_detail,
            Event::WorkspaceProgress { detail: Some(ref d), .. } if d == "disk full"
        ));
    }

    #[test]
    fn global_events_have_no_workspace_and_round_trip_without_one() {
        let g = Event::RulesChanged {};
        assert_eq!(g.workspace(), None);
        let json = serde_json::to_string(&g).unwrap();
        assert_eq!(json, r#"{"type":"rules_changed"}"#);
        assert_eq!(serde_json::from_str::<Event>(&json).unwrap(), g);
        let sink = CollectingSink::default();
        sink.emit(g.clone());
        assert_eq!(sink.take(), [g]);
    }

    #[test]
    fn pending_rule_and_audit_events_have_fixed_shapes() {
        let request = PendingSummary {
            id: 7,
            workspace: name(),
            host: "www.example.com".into(),
            registrable_domain: "example.com".into(),
            port: 443,
            first_seen: 1,
            last_seen: 2,
            attempts: 3,
        };
        for (event, json, workspace) in [
            (
                Event::PendingOpened { request },
                r#"{"type":"pending_opened","request":{"id":7,"workspace":"box","host":"www.example.com","registrable_domain":"example.com","port":443,"first_seen":1,"last_seen":2,"attempts":3}}"#,
                Some(name()),
            ),
            (
                Event::PendingUpdated {
                    workspace: name(),
                    id: 7,
                    attempts: 4,
                    last_seen: 9,
                },
                r#"{"type":"pending_updated","workspace":"box","id":7,"attempts":4,"last_seen":9}"#,
                Some(name()),
            ),
            (
                Event::PendingClosed {
                    workspace: name(),
                    id: 7,
                    state: PendingEnd::Allowed,
                    rule_id: Some(2),
                },
                r#"{"type":"pending_closed","workspace":"box","id":7,"state":"allowed","rule_id":2}"#,
                Some(name()),
            ),
            (
                Event::PendingClosed {
                    workspace: name(),
                    id: 8,
                    state: PendingEnd::Expired,
                    rule_id: None,
                },
                r#"{"type":"pending_closed","workspace":"box","id":8,"state":"expired","rule_id":null}"#,
                Some(name()),
            ),
            (
                Event::SuppressionChanged {
                    workspace: name(),
                    active: true,
                    count: 12,
                },
                r#"{"type":"suppression_changed","workspace":"box","active":true,"count":12}"#,
                Some(name()),
            ),
            (Event::RulesChanged {}, r#"{"type":"rules_changed"}"#, None),
            (
                Event::IdentitiesChanged {},
                r#"{"type":"identities_changed"}"#,
                None,
            ),
            (
                Event::WorkspaceGitChanged {
                    workspace: WorkspaceName::new("box").unwrap(),
                },
                r#"{"type":"workspace_git_changed","workspace":"box"}"#,
                Some(WorkspaceName::new("box").unwrap()),
            ),
            (
                Event::GlobalEnvChanged {},
                r#"{"type":"global_env_changed"}"#,
                None,
            ),
            (
                Event::WorkspaceEnvChanged {
                    workspace: WorkspaceName::new("box").unwrap(),
                },
                r#"{"type":"workspace_env_changed","workspace":"box"}"#,
                Some(WorkspaceName::new("box").unwrap()),
            ),
            (
                Event::AuditAppended { id: 99 },
                r#"{"type":"audit_appended","id":99}"#,
                None,
            ),
            (
                Event::NetworkChanged { epoch: 4 },
                r#"{"type":"network_changed","epoch":4}"#,
                None,
            ),
        ] {
            assert_eq!(serde_json::to_string(&event).unwrap(), json);
            assert_eq!(serde_json::from_str::<Event>(json).unwrap(), event);
            assert_eq!(event.workspace(), workspace.as_ref());
        }
        // `rule_id` may be left out by an older sender.
        let closed: Event = serde_json::from_str(
            r#"{"type":"pending_closed","workspace":"box","id":1,"state":"denied"}"#,
        )
        .unwrap();
        assert!(matches!(closed, Event::PendingClosed { rule_id: None, .. }));
    }

    #[test]
    fn credential_and_git_access_events_have_fixed_shapes() {
        for (event, json, workspace) in [
            (
                Event::CredentialSignInNeeded {
                    host: "github.com".into(),
                    source: "gh account me on github.com".into(),
                },
                r#"{"type":"credential_sign_in_needed","host":"github.com","source":"gh account me on github.com"}"#,
                None,
            ),
            (
                Event::GitAccessDenied {
                    workspace: name(),
                    host: "github.com".into(),
                    owner: "acme".into(),
                    repo: "web-shop".into(),
                    access: GitAccess::Pull,
                },
                r#"{"type":"git_access_denied","workspace":"box","host":"github.com","owner":"acme","repo":"web-shop","access":"pull"}"#,
                Some(name()),
            ),
            (
                Event::GitAccessDenied {
                    workspace: name(),
                    host: "dev.azure.com".into(),
                    owner: "acme".into(),
                    repo: "proj/web".into(),
                    access: GitAccess::Push,
                },
                r#"{"type":"git_access_denied","workspace":"box","host":"dev.azure.com","owner":"acme","repo":"proj/web","access":"push"}"#,
                Some(name()),
            ),
        ] {
            assert_eq!(serde_json::to_string(&event).unwrap(), json);
            assert_eq!(serde_json::from_str::<Event>(json).unwrap(), event);
            assert_eq!(event.workspace(), workspace.as_ref());
        }
    }

    #[test]
    fn per_workspace_json_is_unchanged_by_global_events() {
        // Events are not persisted today, but SSE clients parse them: the wire shape of
        // existing variants must stay exactly as it was (ADR 0002).
        for (json, want) in [
            (
                r#"{"type":"status_changed","workspace":"box","status":"running"}"#,
                Event::StatusChanged {
                    workspace: name(),
                    status: WorkspaceStatus::Running,
                },
            ),
            (
                r#"{"type":"oom_kill","workspace":"box","pid":1,"process":"x"}"#,
                Event::oom_kill(name(), 1, "x"),
            ),
        ] {
            let got: Event = serde_json::from_str(json).unwrap();
            assert_eq!(got, want);
            assert_eq!(got.workspace(), Some(&name()));
            assert_eq!(serde_json::to_string(&got).unwrap(), json);
        }
        assert!(
            serde_json::from_str::<Event>(r#"{"type":"oom_kill","pid":1,"process":"x"}"#).is_err()
        );
    }

    #[cfg(feature = "openapi")]
    #[test]
    fn openapi_schema_is_the_tagged_union() {
        use utoipa::PartialSchema;
        let schema = serde_json::to_value(Event::schema()).unwrap();
        let variants = schema["oneOf"].as_array().unwrap();
        let tags: Vec<&str> = variants
            .iter()
            .map(|v| v["properties"]["type"]["enum"][0].as_str().unwrap())
            .collect();
        assert_eq!(
            tags,
            [
                "status_changed",
                "oom_kill",
                "workspace_progress",
                "pending_opened",
                "pending_updated",
                "pending_closed",
                "suppression_changed",
                "rules_changed",
                "identities_changed",
                "workspace_git_changed",
                "global_env_changed",
                "workspace_env_changed",
                "credential_sign_in_needed",
                "git_access_denied",
                "audit_appended",
                "network_changed"
            ]
        );
        for v in variants {
            let required = v["required"].as_array().unwrap();
            assert!(required.iter().any(|r| r == "type"), "{v}");
        }
        let progress = &variants[2];
        assert!(
            progress["required"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r == "detail"),
            "detail is always present, null when empty: {progress}"
        );
        let global = &variants[7];
        assert!(global["properties"].get("workspace").is_none());
        assert_eq!(
            variants[0]["properties"]["workspace"]["$ref"],
            "#/components/schemas/WorkspaceName"
        );
        let status = serde_json::to_value(WorkspaceStatus::schema()).unwrap();
        assert_eq!(status["enum"].as_array().unwrap().len(), 8);
    }

    #[test]
    fn sinks_collect_or_drop() {
        let sink = Arc::new(CollectingSink::default());
        let as_dyn: Arc<dyn EventSink> = sink.clone();
        as_dyn.emit(Event::oom_kill(name(), 1, "x"));
        sink.emit(Event::oom_kill(name(), 2, "y"));
        assert_eq!(sink.events().len(), 2);
        assert_eq!(sink.take().len(), 2);
        assert_eq!(sink.events(), []);
        NullSink.emit(Event::oom_kill(name(), 3, "z"));
    }
}
