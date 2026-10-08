// SPDX-License-Identifier: GPL-3.0-or-later
//! The first-run flow's state on the wire: whether it has been through, and what it shows about
//! the development certificate.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// What puddle knows about a development certificate on this computer (the ASP.NET one that
/// `dotnet dev-certs` makes), for the one line the certificates step shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DevCertificate {
    /// puddle does not look for one yet.
    NotChecked,
    /// Windows already trusts one, so puddle uses it in every workspace with no dialog.
    ReusingExisting,
}

/// Where the first-run flow stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct FirstRun {
    /// The flow has been finished or skipped, so the app opens on its start screen.
    pub completed: bool,
    /// Epoch ms of that; `null` while it still has to run.
    #[schema(required = true)]
    pub completed_at: Option<u64>,
    /// What the certificates step says about a development certificate.
    pub dev_certificate: DevCertificate,
}

/// Marks the first-run flow finished, or open again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct FirstRunRequest {
    /// `true` records that the flow was finished or skipped (the time of the first such call is
    /// kept); `false` makes it run again at the next start.
    pub completed: bool,
}
