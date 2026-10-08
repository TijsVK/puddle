// SPDX-License-Identifier: GPL-3.0-or-later
//! The scenario file: what the fixture holds at start, and the named scripts a test can run.
//!
//! Everything a scenario names is applied through the same store calls the proxy and the API
//! use, so the data has the shape real data has (ids, audit records, suppression, rate limits).
//! Fields are all optional; an unknown field is an error, so a typo in a scenario file fails at
//! start instead of seeding nothing.

use std::collections::BTreeMap;

use puddle_api::wire::NetworkHealth;
use puddle_types::Event;
use serde::{Deserialize, Serialize};

/// 2026-10-07T12:00:00Z. The fixture's clock starts here unless the scenario says otherwise; a
/// test installs the browser's fake clock at the same instant so relative times agree.
pub const DEFAULT_NOW_MS: u64 = 1_791_374_400_000;

const fn default_port() -> u16 {
    443
}

const fn one() -> u64 {
    1
}

/// A scenario: the state the fixture starts in and the scripts it can run.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    /// A name for logs and `GET /control/state`.
    #[serde(default)]
    pub name: String,
    /// Epoch ms the clock starts at; [`DEFAULT_NOW_MS`] when left out.
    #[serde(default)]
    pub now_ms: Option<u64>,
    /// Rules, created first and in this order.
    #[serde(default)]
    pub rules: Vec<RuleSeed>,
    /// Requests workspaces made, decided in this order (a matching rule decides, else a pending
    /// row opens), each leaving its `connection` audit record.
    #[serde(default)]
    pub requests: Vec<RequestSeed>,
    /// Extra `connection` audit records (allowed traffic, blocks) that open nothing.
    #[serde(default)]
    pub connections: Vec<ConnectionSeed>,
    /// Workspaces that exist at start, with the state they are in.
    #[serde(default)]
    pub workspaces: Vec<WorkspaceSeed>,
    /// How long the fake workspace service pauses between the steps of an operation (create,
    /// start, ...), in ms. Zero (the default) runs them back to back; tests that need to look
    /// at the busy state use the `hold_workspaces` step instead.
    #[serde(default)]
    pub workspace_step_delay_ms: u64,
    /// Settings documents kept as given.
    #[serde(default)]
    pub settings: SettingsSeed,
    /// What `GET /api/network-health` reports at start; a direct machine with no company roots
    /// when left out. `generated_at` is replaced by the clock on every request.
    #[serde(default)]
    pub network_health: Option<NetworkHealth>,
    /// Named lists of steps; run one with `POST /control/script/{name}`.
    #[serde(default)]
    pub scripts: BTreeMap<String, Vec<Step>>,
}

impl Scenario {
    /// The clock's start.
    #[must_use]
    pub fn start_ms(&self) -> u64 {
        self.now_ms.unwrap_or(DEFAULT_NOW_MS)
    }
}

/// A rule to create.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSeed {
    /// `allow` or `deny`.
    pub effect: EffectSeed,
    /// `host`, `.suffix.example.com` or `*.suffix.example.com`.
    pub pattern: String,
    /// The one workspace it applies to; left out is every workspace.
    #[serde(default)]
    pub workspace: Option<String>,
    /// Created this long before now (ms).
    #[serde(default)]
    pub ago_ms: u64,
    /// Expires this long after it was created (ms); left out is permanent.
    #[serde(default)]
    pub expires_in_ms: Option<u64>,
}

/// Allow or deny.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectSeed {
    /// Let through.
    Allow,
    /// Refuse.
    Deny,
}

/// A workspace that exists at start.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceSeed {
    /// The name (also the id).
    pub name: String,
    /// The repository, an `https://` URL.
    pub repo_url: String,
    /// The image; the default image when left out.
    #[serde(default)]
    pub image: Option<String>,
    /// Memory in MiB; the default when left out.
    #[serde(default)]
    pub memory_mib: Option<u32>,
    /// Its state; `stopped` when left out.
    #[serde(default)]
    pub status: StatusSeed,
    /// Created this long before now (ms).
    #[serde(default)]
    pub ago_ms: u64,
    /// What the disk holds, in MiB.
    #[serde(default)]
    pub disk_used_mib: Option<u64>,
    /// What deleting it would lose; nothing when left out.
    #[serde(default)]
    pub unsaved: UnsavedSeed,
}

/// A workspace's state at start.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StatusSeed {
    /// Created, never started.
    Created,
    /// Running.
    Running,
    /// Stopped.
    #[default]
    Stopped,
    /// Ended without a stop.
    Crashed,
}

/// What the delete check finds in a workspace.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsavedSeed {
    /// Per checkout.
    #[serde(default)]
    pub repos: Vec<RepoSeed>,
    /// Data outside any checkout.
    #[serde(default)]
    pub other: Vec<String>,
    /// What the check could not read.
    #[serde(default)]
    pub errors: Vec<String>,
}

/// One checkout's findings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepoSeed {
    /// The directory.
    pub dir: String,
    /// `git status --porcelain` lines.
    #[serde(default)]
    pub uncommitted: Vec<String>,
    /// `<hash> <subject>` lines.
    #[serde(default)]
    pub unpushed: Vec<String>,
    /// `git stash list` lines.
    #[serde(default)]
    pub stashes: Vec<String>,
}

/// A long workspace operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceOperationSeed {
    /// Create.
    Create,
    /// Start.
    Start,
    /// Stop.
    Stop,
    /// Reclaim space.
    Reclaim,
    /// Delete.
    Delete,
}

/// A workspace asking for `host:port`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestSeed {
    /// The workspace's name.
    pub workspace: String,
    /// The host asked for.
    pub host: String,
    /// The port; 443 when left out.
    #[serde(default = "default_port")]
    pub port: u16,
    /// How many times it asked (the pending row counts attempts); 1 when left out.
    #[serde(default = "one")]
    pub repeat: u64,
    /// First asked this long before now (ms).
    #[serde(default)]
    pub ago_ms: u64,
}

/// One `connection` audit record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionSeed {
    /// The workspace's name.
    pub workspace: String,
    /// The host.
    pub host: String,
    /// The port; 443 when left out.
    #[serde(default = "default_port")]
    pub port: u16,
    /// What happened.
    pub decision: DecisionSeed,
    /// Why, as the audit log's `reason` code: `rule` (default for allow and deny), `no_rule`
    /// (default for pending), `puddle_endpoint`, `ssh_unsupported` or `local_address` (default
    /// for blocked).
    #[serde(default)]
    pub reason: Option<String>,
    /// Bytes from the workspace.
    #[serde(default)]
    pub bytes_up: u64,
    /// Bytes to the workspace.
    #[serde(default)]
    pub bytes_down: u64,
    /// Recorded this long before now (ms).
    #[serde(default)]
    pub ago_ms: u64,
}

/// The audit log's connection decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionSeed {
    /// Let through.
    Allow,
    /// Refused by a deny rule.
    Deny,
    /// Refused while waiting for the user.
    Pending,
    /// Refused whatever the rules say.
    Blocked,
}

/// Settings documents, as the API stores them.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettingsSeed {
    /// The global document.
    #[serde(default)]
    pub global: Option<serde_json::Value>,
    /// Per-workspace documents by name.
    #[serde(default)]
    pub workspaces: BTreeMap<String, serde_json::Value>,
}

/// One thing a script (or `POST /control/step`) does. `{"do": "<name>", ...}` in JSON.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "do", rename_all = "snake_case")]
pub enum Step {
    /// Puts an event on the SSE stream, as a component of puddle would. `event` is the wire
    /// form: `{"type": "oom_kill", ...}`. New `Event` variants need no change here.
    Emit {
        /// The event.
        event: Event,
    },
    /// Moves the clock forward and sweeps what expired, as the sweeper would.
    Advance {
        /// Milliseconds.
        ms: u64,
    },
    /// Waits in real time, so a script can pace events for a page that is open.
    Wait {
        /// Milliseconds.
        ms: u64,
    },
    /// A workspace asks for a host.
    Request(RequestSeed),
    /// `count` workspaces-worth of requests to `n0.<domain>` .. `n<count-1>.<domain>`.
    Bulk {
        /// The workspace's name.
        workspace: String,
        /// How many hosts.
        count: u64,
        /// The shared domain; `bulk.example.org` when left out.
        #[serde(default)]
        domain: Option<String>,
    },
    /// `count` requests spread over workspaces `bulk-0`..`bulk-9` and domains `d0`..`d49` of
    /// `example.org` (the inbox's speed bar).
    Spread {
        /// How many requests.
        count: u64,
    },
    /// `count` connection records over the last 7 days, oldest first, across workspaces
    /// `bulk-0`..`bulk-9`, hosts `h<n>.d<m>.example.org` and the four decisions (the activity
    /// screen's speed bar).
    History {
        /// How many records.
        count: u64,
    },
    /// Holds every workspace operation before its next step, so the busy state stays put.
    HoldWorkspaces,
    /// Lets held workspace operations go on.
    ReleaseWorkspaces,
    /// Makes the next operation of this kind fail after its steps (once).
    FailWorkspace {
        /// Which operation.
        operation: WorkspaceOperationSeed,
        /// The reason the failed event carries.
        reason: String,
    },
    /// Replaces the network-health report and sends `network_changed` with its epoch, as a
    /// network or proxy change would.
    NetworkHealth(Box<NetworkHealth>),
    /// Creates a rule.
    Rule(RuleSeed),
    /// Writes a connection audit record.
    Connection(ConnectionSeed),
}
