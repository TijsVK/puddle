// SPDX-License-Identifier: GPL-3.0-or-later
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code: a panic is how a test fails"
)]
//! The listing commands, against fake tools that also print a token-shaped canary.

mod common;

use common::{CANARY, Fakes};
use puddle_secrets::{Listing, SourceError, Tool, ToolPaths, discover};

fn gh_json() -> String {
    format!(
        r#"{{"hosts":{{"github.com":[{{"login":"me","active":true,"state":"success","token":"{CANARY}"}},{{"login":"work","active":false,"state":"error"}}]}}}}"#
    )
}

#[tokio::test]
async fn discovery_runs_only_the_fixed_listings_and_keeps_names() {
    let fakes = Fakes::new();
    // `gh auth status` exits 1 when one account is broken but still prints the JSON.
    let gh = fakes.install(
        "gh",
        &format!("[auth status --json hosts]\nexit=1\nstdout={}\n", gh_json()),
    );
    let git = fakes.install(
        "git",
        &format!(
            "[github list]\nstdout=me\\ntoken {CANARY}\\n\n\
             [azure-repos list]\nstdout=acme:\\n  (global) -> me@example.com\\n  password={CANARY}\\n\n"
        ),
    );
    let found = discover(&ToolPaths::new(Some(gh.clone()), Some(git.clone()))).await;
    assert!(found.problems.is_empty(), "{:?}", found.problems);
    let rows: Vec<_> = found
        .accounts
        .iter()
        .map(|a| {
            (
                a.via,
                a.host.as_str(),
                a.account.as_str(),
                a.org.as_ref().map(puddle_secrets::OrgName::as_str),
                a.signed_in,
            )
        })
        .collect();
    assert_eq!(
        rows,
        [
            (Listing::GhAuthStatus, "github.com", "me", None, true),
            (Listing::GhAuthStatus, "github.com", "work", None, false),
            (Listing::GcmGithub, "github.com", "me", None, true),
            (
                Listing::GcmAzureRepos,
                "dev.azure.com",
                "me@example.com",
                Some("acme"),
                true
            ),
        ]
    );
    assert!(!format!("{found:?}").contains(CANARY));

    let gh_log = Fakes::log(&gh);
    assert_eq!(gh_log.matches("ARGS ").count(), 1);
    assert!(
        gh_log.contains("ARGS auth status --json hosts\n"),
        "{gh_log}"
    );
    let git_log = Fakes::log(&git);
    assert!(
        git_log.contains("ARGS credential-manager github list\n"),
        "{git_log}"
    );
    assert!(
        git_log.contains("ARGS credential-manager azure-repos list\n"),
        "{git_log}"
    );
    assert_eq!(git_log.matches("ARGS ").count(), 2);
}

#[tokio::test]
async fn a_missing_tool_or_a_logged_out_cli_is_a_problem_not_a_failure() {
    let fakes = Fakes::new();
    let gh = fakes.install("gh", "[]\nexit=1\n");
    let found = discover(&ToolPaths::new(Some(gh), None)).await;
    assert!(found.accounts.is_empty());
    assert!(
        found
            .problems
            .contains(&(Listing::GhAuthStatus, SourceError::NotSignedIn))
    );
    assert!(
        found
            .problems
            .contains(&(Listing::GcmGithub, SourceError::ToolMissing(Tool::Git)))
    );
    assert!(
        found
            .problems
            .contains(&(Listing::GcmAzureRepos, SourceError::ToolMissing(Tool::Git)))
    );
}
