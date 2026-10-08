// SPDX-License-Identifier: GPL-3.0-or-later
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code: a panic is how a test fails"
)]
//! Signing in on the user's click, against fake `gh` and `git`.

mod common;

use std::path::Path;
use std::time::Duration;

use common::{CANARY, Fakes};
use puddle_secrets::{
    AccountName, HostName, OrgName, SignInError, SignInStart, SignIns, SourceError, SourceSpec,
    StoredId, TokenScope, Tool, ToolPaths, UrlPath,
};

fn gh_spec() -> SourceSpec {
    SourceSpec::Gh {
        host: HostName::new("github.com").unwrap(),
        account: AccountName::new("me").unwrap(),
    }
}

fn git_spec() -> SourceSpec {
    SourceSpec::GitCredential {
        host: HostName::new("dev.azure.com").unwrap(),
        path: UrlPath::new("acme").unwrap(),
        username: None,
    }
}

const GH_PROMPT: &str = "! First copy your one-time code: ABCD-1234\\nOpen this URL to continue in your web browser: https://github.com/login/device\\n";

async fn wait_for(log: &Path, needle: &str) -> String {
    for _ in 0..100 {
        let text = Fakes::log(log);
        if text.contains(needle) {
            return text;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Fakes::log(log)
}

#[tokio::test]
async fn gh_sign_in_hands_back_the_code_and_address_and_runs_nothing_else() {
    let fakes = Fakes::new();
    let gh = fakes.install(
        "gh",
        &format!("[auth login]\nstderr={GH_PROMPT}sleep_ms=3000\n"),
    );
    let signin = SignIns::new(ToolPaths::new(Some(gh.clone()), None));
    let start = signin.begin(&gh_spec()).await.unwrap();
    assert_eq!(
        start,
        SignInStart {
            code: Some("ABCD-1234".into()),
            url: Some("https://github.com/login/device".into()),
        }
    );
    let log = Fakes::log(&gh);
    assert!(
        log.contains("ARGS auth login --hostname github.com --web\n"),
        "{log}"
    );
    assert!(log.contains("GH_TOKEN=<unset>"), "{log}");

    // A second click while it is open shows the same code and starts nothing.
    assert_eq!(signin.begin(&gh_spec()).await.unwrap(), start);
    assert_eq!(Fakes::log(&gh).matches("ARGS ").count(), 1);
}

#[tokio::test]
async fn an_open_sign_in_ends_with_its_window_and_can_be_started_again() {
    let fakes = Fakes::new();
    let gh = fakes.install(
        "gh",
        &format!("[auth login]\nstderr={GH_PROMPT}sleep_ms=5000\n"),
    );
    let signin = SignIns::new(ToolPaths::new(Some(gh.clone()), None))
        .with_window(Duration::from_millis(300));
    signin.begin(&gh_spec()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(900)).await;
    signin.begin(&gh_spec()).await.unwrap();
    assert_eq!(Fakes::log(&gh).matches("ARGS ").count(), 2);
}

#[tokio::test]
async fn gh_that_shows_no_usable_code_is_reported_not_guessed() {
    let fakes = Fakes::new();
    let quiet = fakes.install("gh", "[auth login]\nexit=1\n");
    let err = SignIns::new(ToolPaths::new(Some(quiet), None))
        .begin(&gh_spec())
        .await
        .unwrap_err();
    assert_eq!(err, SignInError::NoPrompt(Tool::Gh));

    // An address on another host is not shown to the user.
    let fakes = Fakes::new();
    let elsewhere = fakes.install(
        "gh",
        "[auth login]\nstderr=! First copy your one-time code: ABCD-1234\\nOpen this URL to continue in your web browser: https://evil.example/login\\n\n",
    );
    let err = SignIns::new(ToolPaths::new(Some(elsewhere), None))
        .begin(&gh_spec())
        .await
        .unwrap_err();
    assert_eq!(err, SignInError::NoPrompt(Tool::Gh));
}

#[tokio::test]
async fn a_missing_tool_and_a_pasted_token_have_their_own_answers() {
    let none = SignIns::new(ToolPaths::new(None, None));
    assert_eq!(
        none.begin(&gh_spec()).await.unwrap_err(),
        SignInError::Source(SourceError::ToolMissing(Tool::Gh))
    );
    assert_eq!(
        none.begin(&git_spec()).await.unwrap_err(),
        SignInError::Source(SourceError::ToolMissing(Tool::Git))
    );
    let stored = SourceSpec::Stored {
        id: StoredId::new("abc").unwrap(),
        scope: TokenScope {
            host: HostName::new("dev.azure.com").unwrap(),
            org: Some(OrgName::new("acme").unwrap()),
        },
    };
    assert_eq!(
        none.begin(&stored).await.unwrap_err(),
        SignInError::NothingToSignIn
    );
}

#[tokio::test]
async fn git_sign_in_lets_the_helper_open_its_window_then_keeps_the_answer() {
    let fakes = Fakes::new();
    let git = fakes.install(
        "git",
        &format!(
            "[credential fill]\nstdout=protocol=https\\nhost=dev.azure.com\\npath=acme\\nusername=me\\npassword={CANARY}\\n\n\
             [credential approve]\nexit=0\n"
        ),
    );
    let signin = SignIns::new(ToolPaths::new(None, Some(git.clone())));
    assert_eq!(
        signin.begin(&git_spec()).await.unwrap(),
        SignInStart::default()
    );
    let log = wait_for(&git, "ARGS credential approve").await;
    // The fill may open a window; the approve may not, and it carries the answer.
    let fill = log.split("ARGS credential approve").next().unwrap();
    assert!(
        fill.contains("credential.useHttpPath=true credential fill"),
        "{log}"
    );
    assert!(fill.contains("GCM_INTERACTIVE=true"), "{log}");
    let approve = log.split("ARGS credential approve").nth(1).unwrap();
    assert!(approve.contains("GCM_INTERACTIVE=never"), "{log}");
    assert!(approve.contains(&format!("password={CANARY}")), "{log}");
}

#[tokio::test]
async fn git_sign_in_does_not_keep_an_answer_for_another_target() {
    let fakes = Fakes::new();
    let git = fakes.install(
        "git",
        "[credential fill]\nstdout=protocol=https\\nhost=github.com\\npath=other\\nusername=me\\npassword=x\\n\n",
    );
    let signin = SignIns::new(ToolPaths::new(None, Some(git.clone())));
    signin.begin(&git_spec()).await.unwrap();
    let log = wait_for(&git, "ARGS credential approve").await;
    assert!(log.contains("credential fill"), "{log}");
    assert!(!log.contains("credential approve"), "{log}");
}
