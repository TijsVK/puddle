// SPDX-License-Identifier: GPL-3.0-or-later
//! Azure DevOps: the repositories of one organisation (`GET /{org}/_apis/git/repositories`, one
//! call for the whole organisation).
//!
//! A personal access token covers one organisation and cannot ask who it belongs to, and the
//! calls that list a person's organisations answer only to a Microsoft Entra sign-in. So a list is
//! read for an organisation the credential names, and a credential that names none says so.

use std::fmt::Write as _;
use std::sync::Arc;

use puddle_secrets::Secret;
use serde::Deserialize;

use crate::api::{ApiRequest, Authorization};
use crate::exchange::Exchange;
use crate::model::{Listed, Note, NoteKind, Problem, Repository, Role, Visibility};

/// The host of Azure DevOps Services; its API is on the same host.
pub(crate) const HOST: &str = "dev.azure.com";
/// The most repositories one organisation's list keeps.
const MAX_REPOS: usize = 5000;

/// A personal access token goes as Basic, an Entra access token (a JWT, what Git Credential
/// Manager signs in with) as Bearer.
pub(crate) fn authorization(token: Arc<Secret>) -> Authorization {
    if looks_like_jwt(token.expose()) {
        Authorization::Bearer(token)
    } else {
        Authorization::BasicPassword(token)
    }
}

/// Three base64url parts, the first a JSON header (`eyJ...`).
fn looks_like_jwt(token: &str) -> bool {
    let parts: Vec<&str> = token.split('.').collect();
    parts.len() == 3
        && parts.first().is_some_and(|head| head.starts_with("eyJ"))
        && parts.iter().all(|part| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '='))
        })
}

/// One path segment, with everything but the unreserved characters escaped.
fn segment(text: &str) -> String {
    text.bytes().fold(String::new(), |mut out, byte| {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            // Writing to a `String` cannot fail.
            let _ = write!(out, "%{byte:02X}");
        }
        out
    })
}

#[derive(Deserialize)]
struct ListJson {
    value: Vec<RepoJson>,
}

#[derive(Deserialize)]
struct RepoJson {
    name: String,
    project: Option<ProjectJson>,
    #[serde(rename = "isDisabled")]
    is_disabled: Option<bool>,
    #[serde(rename = "isFork")]
    is_fork: Option<bool>,
}

#[derive(Deserialize)]
struct ProjectJson {
    name: String,
    visibility: Option<String>,
}

/// Every repository of `organisation` the token can see, in the host's order.
pub(crate) async fn list(
    exchange: &Exchange<'_>,
    organisation: &str,
    authorization: &Authorization,
) -> Result<Listed, Problem> {
    let reply = exchange
        .get(ApiRequest {
            host: HOST.to_owned(),
            path: format!(
                "/{}/_apis/git/repositories?api-version=7.1",
                segment(organisation)
            ),
            accept: "application/json",
            headers: &[],
            authorization: authorization.clone(),
        })
        .await?;
    let list: ListJson = serde_json::from_slice(&reply.body).map_err(|_| {
        Problem::bad_answer("the list of repositories is not what Azure DevOps documents")
    })?;
    let mut notes = Vec::new();
    if list.value.len() > MAX_REPOS {
        notes.push(Note::new(
            NoteKind::Truncated,
            format!("puddle reads the first {MAX_REPOS} repositories; there are more"),
        ));
    }
    let repos = list
        .value
        .into_iter()
        .take(MAX_REPOS)
        .map(|row| repository(row, organisation))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Listed {
        repos,
        notes,
        spent_until: None,
    })
}

fn repository(row: RepoJson, organisation: &str) -> Result<Repository, Problem> {
    let project = row
        .project
        .ok_or_else(|| Problem::bad_answer("a repository with no project"))?;
    let visibility = match project.visibility.as_deref() {
        Some("public") => Visibility::Public,
        Some("private") => Visibility::Private,
        _ => Visibility::Unknown,
    };
    Ok(Repository {
        host: HOST.to_owned(),
        owner: organisation.to_owned(),
        full_name: format!("{organisation}/{}/{}", project.name, row.name),
        url: format!(
            "https://{HOST}/{}/{}/_git/{}",
            segment(organisation),
            segment(&project.name),
            segment(&row.name)
        ),
        project: Some(project.name),
        name: row.name,
        visibility,
        role: Role::Unknown,
        archived: row.is_disabled == Some(true),
        fork: row.is_fork == Some(true),
    })
}
