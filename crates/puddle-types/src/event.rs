// SPDX-License-Identifier: GPL-3.0-or-later
//! Events puddle reports to the user (API/SSE, tray, logs), and the sink they go into.

use std::fmt;
use std::sync::{Mutex, PoisonError};

use serde::{Deserialize, Serialize};

use crate::SandboxName;

/// A sandbox's state as the runtime reports it (msb's states, one for one).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum SandboxStatus {
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
}

impl SandboxStatus {
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
        }
    }

    /// Whether the sandbox has no VM (it can be started or removed).
    #[must_use]
    pub fn is_down(self) -> bool {
        matches!(self, Self::Created | Self::Stopped | Self::Crashed)
    }
}

impl fmt::Display for SandboxStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Longest process name kept in [`Event::OomKill`] (the kernel's `TASK_COMM_LEN` is 16).
const MAX_PROCESS_NAME_CHARS: usize = 64;

/// Something the user should hear about. Serialised as one internally tagged enum
/// (`{"type":"oom_kill",...}`, ADR 0002).
///
/// Most events are about one sandbox and carry a `sandbox` field; global ones (crash report
/// waiting, consent needed, network change, ...) carry none, and [`Event::sandbox`] returns
/// `None` for them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[non_exhaustive]
pub enum Event {
    /// A sandbox changed state.
    StatusChanged {
        /// The sandbox.
        sandbox: SandboxName,
        /// Its new state.
        status: SandboxStatus,
    },
    /// The guest kernel's OOM killer ended a process (reported by the guest agent).
    ///
    /// `pid` and `process` come from the guest and are untrusted: build this variant with
    /// [`Event::oom_kill`], which bounds and cleans the name, and escape it when rendering.
    OomKill {
        /// The sandbox whose guest killed the process.
        sandbox: SandboxName,
        /// The killed process's id inside the guest.
        pid: u32,
        /// The killed process's name (`comm`), cleaned by [`Event::oom_kill`].
        process: String,
    },
    /// A workspace operation (create, start, stop, reclaim, delete) moved on. An operation ends
    /// with one event whose step is [`WorkspaceStep::Done`] or [`WorkspaceStep::Failed`].
    WorkspaceProgress {
        /// The workspace's sandbox.
        sandbox: SandboxName,
        /// What it is doing now.
        step: WorkspaceStep,
        /// More about the step, or why it failed; `null` when there is nothing to add. It can
        /// quote tool output: escape it when rendering.
        #[serde(default)]
        #[cfg_attr(feature = "openapi", schema(required = true))]
        detail: Option<String>,
    },
    /// A global event, standing in for the real ones until the first lands.
    #[cfg(test)]
    TestGlobal,
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
    /// Removing the volume and the sandbox.
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
    /// use puddle_types::{Event, SandboxName};
    /// let e = Event::oom_kill(SandboxName::new("a").unwrap(), 42, "node\u{1b}[2J");
    /// assert!(matches!(e, Event::OomKill { ref process, .. } if process == "node?[2J"));
    /// ```
    #[must_use]
    pub fn oom_kill(sandbox: SandboxName, pid: u32, process: &str) -> Self {
        let process = process
            .chars()
            .take(MAX_PROCESS_NAME_CHARS)
            .map(|c| if c.is_control() { '?' } else { c })
            .collect();
        Self::OomKill {
            sandbox,
            pid,
            process,
        }
    }

    /// The sandbox this event is about, or `None` for a global event.
    ///
    /// ```
    /// use puddle_types::{Event, SandboxName};
    /// let a = SandboxName::new("a").unwrap();
    /// assert_eq!(Event::oom_kill(a.clone(), 1, "x").sandbox(), Some(&a));
    /// ```
    #[must_use]
    pub fn sandbox(&self) -> Option<&SandboxName> {
        match self {
            Self::StatusChanged { sandbox, .. }
            | Self::OomKill { sandbox, .. }
            | Self::WorkspaceProgress { sandbox, .. } => Some(sandbox),
            #[cfg(test)]
            Self::TestGlobal => None,
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
/// use puddle_types::{CollectingSink, Event, EventSink, SandboxName};
/// let sink = CollectingSink::default();
/// sink.emit(Event::oom_kill(SandboxName::new("a").unwrap(), 1, "x"));
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

    fn name() -> SandboxName {
        SandboxName::new("box").unwrap()
    }

    #[test]
    fn status_names_and_down_states() {
        let all = [
            (SandboxStatus::Created, "created", true),
            (SandboxStatus::Starting, "starting", false),
            (SandboxStatus::Running, "running", false),
            (SandboxStatus::Draining, "draining", false),
            (SandboxStatus::Paused, "paused", false),
            (SandboxStatus::Stopped, "stopped", true),
            (SandboxStatus::Crashed, "crashed", true),
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
            r#"{"type":"oom_kill","sandbox":"box","pid":42,"process":"node"}"#
        );
        let s = Event::StatusChanged {
            sandbox: name(),
            status: SandboxStatus::Crashed,
        };
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(
            json,
            r#"{"type":"status_changed","sandbox":"box","status":"crashed"}"#
        );
        assert_eq!(serde_json::from_str::<Event>(&json).unwrap(), s);
        assert_eq!(s.sandbox(), Some(&name()));
        assert_eq!(e.sandbox(), Some(&name()));
    }

    #[test]
    fn workspace_progress_is_per_sandbox_and_always_carries_detail() {
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
                sandbox: name(),
                step,
                detail: None,
            };
            let json = serde_json::to_string(&e).unwrap();
            assert_eq!(
                json,
                format!(
                    r#"{{"type":"workspace_progress","sandbox":"box","step":"{text}","detail":null}}"#
                )
            );
            assert_eq!(serde_json::from_str::<Event>(&json).unwrap(), e);
            assert_eq!(e.sandbox(), Some(&name()));
        }
        let with_detail: Event = serde_json::from_str(
            r#"{"type":"workspace_progress","sandbox":"box","step":"failed","detail":"disk full"}"#,
        )
        .unwrap();
        assert!(matches!(
            with_detail,
            Event::WorkspaceProgress { detail: Some(ref d), .. } if d == "disk full"
        ));
    }

    #[test]
    fn global_events_have_no_sandbox_and_round_trip_without_one() {
        let g = Event::TestGlobal;
        assert_eq!(g.sandbox(), None);
        let json = serde_json::to_string(&g).unwrap();
        assert_eq!(json, r#"{"type":"test_global"}"#);
        assert_eq!(serde_json::from_str::<Event>(&json).unwrap(), g);
        let sink = CollectingSink::default();
        sink.emit(g.clone());
        assert_eq!(sink.take(), [g]);
    }

    #[test]
    fn per_sandbox_json_is_unchanged_by_global_events() {
        // Events are not persisted today, but SSE clients parse them: the wire shape of
        // existing variants must stay exactly as it was (ADR 0002).
        for (json, want) in [
            (
                r#"{"type":"status_changed","sandbox":"box","status":"running"}"#,
                Event::StatusChanged {
                    sandbox: name(),
                    status: SandboxStatus::Running,
                },
            ),
            (
                r#"{"type":"oom_kill","sandbox":"box","pid":1,"process":"x"}"#,
                Event::oom_kill(name(), 1, "x"),
            ),
        ] {
            let got: Event = serde_json::from_str(json).unwrap();
            assert_eq!(got, want);
            assert_eq!(got.sandbox(), Some(&name()));
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
                "test_global"
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
        let global = &variants[3];
        assert!(global["properties"].get("sandbox").is_none());
        assert_eq!(
            variants[0]["properties"]["sandbox"]["$ref"],
            "#/components/schemas/SandboxName"
        );
        let status = serde_json::to_value(SandboxStatus::schema()).unwrap();
        assert_eq!(status["enum"].as_array().unwrap().len(), 7);
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
