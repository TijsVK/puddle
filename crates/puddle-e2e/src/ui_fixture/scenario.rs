// SPDX-License-Identifier: GPL-3.0-or-later
//! The scenario file: what the fixture holds at start, and the named scripts a test can run.
//!
//! Everything a scenario names is applied through the same store calls the proxy and the API
//! use, so the data has the shape real data has (ids, audit records, suppression, rate limits).
//! Fields are all optional; an unknown field is an error, so a typo in a scenario file fails at
//! start instead of seeding nothing.

use std::collections::BTreeMap;

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
    /// Settings documents kept as given.
    #[serde(default)]
    pub settings: SettingsSeed,
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
    pub sandbox: Option<String>,
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

/// A workspace asking for `host:port`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestSeed {
    /// The workspace's name.
    pub sandbox: String,
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
    pub sandbox: String,
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
    pub sandboxes: BTreeMap<String, serde_json::Value>,
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
        sandbox: String,
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
    /// Creates a rule.
    Rule(RuleSeed),
    /// Writes a connection audit record.
    Connection(ConnectionSeed),
}
