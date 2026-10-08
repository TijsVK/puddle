// SPDX-License-Identifier: GPL-3.0-or-later
//! What the identities screens ask the host about credentials, over real HTTP: the accounts found,
//! checking a credential, a pasted token (write-only) and signing in.

use std::sync::Arc;

use puddle_api::{HostCredentials, NoCredentials};
use puddle_secrets::{
    AccountName, DiscoveredAccount, Discovery, HostName, Listing, MemoryStore, OrgName,
    SignInStart, SourceError, SourceSpec, Tool, ToolPaths,
};
use serde_json::{Value, json};

use crate::common::{start, start_with_credentials};

const CANARY: &str = "CANARY-5d1c0e";

fn gh() -> Value {
    json!({"kind": "gh", "host": "github.com", "account": "me"})
}

fn gh_spec() -> SourceSpec {
    SourceSpec::Gh {
        host: HostName::new("github.com").unwrap(),
        account: AccountName::new("me").unwrap(),
    }
}

#[tokio::test]
async fn the_accounts_found_come_back_as_names_with_the_listings_that_failed() {
    let api = start().await;
    let empty = api.get("/api/credentials/found").await;
    assert_eq!(empty.status, 200);
    assert_eq!(empty.json(), json!({"accounts": [], "problems": []}));

    api.credentials.set_found(Discovery {
        accounts: vec![
            DiscoveredAccount {
                via: Listing::GhAuthStatus,
                host: HostName::new("github.com").unwrap(),
                account: AccountName::new("me").unwrap(),
                org: None,
                signed_in: true,
            },
            DiscoveredAccount {
                via: Listing::GcmAzureRepos,
                host: HostName::new("dev.azure.com").unwrap(),
                account: AccountName::new("me@example.com").unwrap(),
                org: Some(OrgName::new("acme").unwrap()),
                signed_in: false,
            },
        ],
        problems: vec![(Listing::GcmGithub, SourceError::ToolMissing(Tool::Git))],
    });
    let found = api.get("/api/credentials/found").await.json();
    assert_eq!(
        found,
        json!({
            "accounts": [
                {"via": "gh", "host": "github.com", "account": "me", "org": null, "signed_in": true},
                {"via": "gcm_azure_repos", "host": "dev.azure.com", "account": "me@example.com",
                 "org": "acme", "signed_in": false}
            ],
            "problems": [{"via": "gcm_github", "message": "git is not installed or not on PATH"}]
        })
    );
}

#[tokio::test]
async fn checking_a_credential_says_whether_it_reads_and_never_shows_a_value() {
    let api = start().await;
    let ok = api
        .send(
            "POST",
            "/api/credentials/check",
            Some(&json!({"source": gh()})),
        )
        .await;
    assert_eq!(ok.status, 200, "{}", ok.body);
    assert_eq!(
        ok.json(),
        json!({"readable": true, "problem": null, "needs_sign_in": false})
    );

    api.credentials
        .set_unreadable(gh_spec(), Some(SourceError::NotSignedIn));
    let bad = api
        .send(
            "POST",
            "/api/credentials/check",
            Some(&json!({"source": gh()})),
        )
        .await
        .json();
    assert_eq!(bad["readable"], false);
    assert_eq!(bad["needs_sign_in"], true);
    assert_eq!(bad["problem"], "not signed in, or the sign-in has expired");

    // A source that is not on the closed list is refused before anything runs.
    let command = api
        .send(
            "POST",
            "/api/credentials/check",
            Some(&json!({"source": {"kind": "command", "command": "curl evil"}})),
        )
        .await;
    assert!(
        command.status == 400 || command.status == 422,
        "{}",
        command.body
    );
}

#[tokio::test]
async fn a_pasted_token_is_kept_by_id_never_read_back_and_can_be_removed() {
    let api = start().await;
    let made = api
        .send(
            "POST",
            "/api/credentials/stored",
            Some(&json!({"host": "dev.azure.com", "org": "Acme", "token": CANARY})),
        )
        .await;
    assert_eq!(made.status, 201, "{}", made.body);
    assert!(
        !made.body.contains(CANARY),
        "the answer must not echo the token"
    );
    let source = &made.json()["source"];
    assert_eq!(source["kind"], "stored");
    assert_eq!(source["host"], "dev.azure.com");
    assert_eq!(source["org"], "Acme");
    let id = source["id"].as_str().unwrap().to_owned();
    assert!(id.starts_with("tok-"), "{id}");
    assert_eq!(api.credentials.tokens(), std::slice::from_ref(&id));

    for _ in 0..2 {
        let gone = api
            .send("DELETE", &format!("/api/credentials/stored/{id}"), None)
            .await;
        assert_eq!(gone.status, 204, "{}", gone.body);
    }
    assert_eq!(api.credentials.tokens().len(), 0);
}

#[tokio::test]
async fn a_token_a_host_or_an_id_that_cannot_be_used_is_refused() {
    let api = start().await;
    for body in [
        json!({"host": "github.com", "token": "two words"}),
        json!({"host": "github.com", "token": ""}),
        json!({"host": "not a host", "token": CANARY}),
        json!({"host": "dev.azure.com", "org": "bad org!", "token": CANARY}),
    ] {
        let reply = api
            .send("POST", "/api/credentials/stored", Some(&body))
            .await;
        assert_eq!(reply.status, 422, "{body}: {}", reply.body);
        assert!(!reply.body.contains(CANARY));
    }
    let extra = api
        .send(
            "POST",
            "/api/credentials/stored",
            Some(&json!({"host": "github.com", "token": CANARY, "label": "x"})),
        )
        .await;
    assert!(extra.status == 400 || extra.status == 422);
    let bad_id = api
        .send("DELETE", "/api/credentials/stored/a%20b", None)
        .await;
    assert_eq!(bad_id.status, 422, "{}", bad_id.body);
    assert_eq!(api.credentials.tokens().len(), 0);
}

#[tokio::test]
async fn signing_in_shows_the_code_and_makes_the_credential_readable() {
    let api = start().await;
    api.credentials.set_sign_in(SignInStart {
        code: Some("ABCD-1234".into()),
        url: Some("https://github.com/login/device".into()),
    });
    api.credentials
        .set_unreadable(gh_spec(), Some(SourceError::NotSignedIn));
    let started = api
        .send(
            "POST",
            "/api/credentials/sign-in",
            Some(&json!({"source": gh()})),
        )
        .await;
    assert_eq!(started.status, 200, "{}", started.body);
    assert_eq!(
        started.json(),
        json!({"code": "ABCD-1234", "url": "https://github.com/login/device"})
    );
    assert_eq!(api.credentials.sign_ins(), [gh_spec()]);
    let after = api
        .send(
            "POST",
            "/api/credentials/check",
            Some(&json!({"source": gh()})),
        )
        .await
        .json();
    assert_eq!(after["readable"], true);

    let stored = json!({"kind": "stored", "id": "tok-1", "host": "github.com", "org": null});
    let refused = api
        .send(
            "POST",
            "/api/credentials/sign-in",
            Some(&json!({"source": stored})),
        )
        .await;
    assert_eq!((refused.status, refused.error().as_str()), (422, "invalid"));
}

#[tokio::test]
async fn without_a_credentials_service_every_call_says_so() {
    let api = start_with_credentials(Arc::new(NoCredentials)).await;
    let body = json!({"source": gh()});
    for (method, path, payload) in [
        ("GET", "/api/credentials/found", None),
        ("POST", "/api/credentials/check", Some(&body)),
        ("POST", "/api/credentials/sign-in", Some(&body)),
        (
            "POST",
            "/api/credentials/stored",
            Some(&json!({"host": "github.com", "token": CANARY})),
        ),
        ("DELETE", "/api/credentials/stored/abc", None),
    ] {
        let reply = api.send(method, path, payload).await;
        assert_eq!(
            (reply.status, reply.error().as_str()),
            (503, "unavailable"),
            "{method} {path}"
        );
    }
}

#[tokio::test]
async fn the_real_service_keeps_a_pasted_token_in_its_store_and_reads_it_back_for_a_check() {
    let store = Arc::new(MemoryStore::new());
    let real = HostCredentials::new(ToolPaths::new(None, None), store.clone());
    let api = start_with_credentials(Arc::new(real)).await;

    let made = api
        .send(
            "POST",
            "/api/credentials/stored",
            Some(&json!({"host": "github.com", "token": format!("  {CANARY}  ")})),
        )
        .await;
    assert_eq!(made.status, 201, "{}", made.body);
    assert!(!made.body.contains(CANARY));
    let source = made.json()["source"].clone();
    let check = || async {
        api.send(
            "POST",
            "/api/credentials/check",
            Some(&json!({"source": source})),
        )
        .await
        .json()
    };
    assert_eq!(check().await["readable"], true);

    // Signing in to a pasted token, or with a tool that is not installed, is refused in words.
    let stored_in = api
        .send(
            "POST",
            "/api/credentials/sign-in",
            Some(&json!({"source": source})),
        )
        .await;
    assert_eq!(stored_in.status, 422);
    let no_gh = api
        .send(
            "POST",
            "/api/credentials/sign-in",
            Some(&json!({"source": gh()})),
        )
        .await;
    assert_eq!(no_gh.status, 503);
    assert!(
        no_gh.body.contains("gh is not installed or not on PATH"),
        "{}",
        no_gh.body
    );

    let id = source["id"].as_str().unwrap();
    let gone = api
        .send("DELETE", &format!("/api/credentials/stored/{id}"), None)
        .await;
    assert_eq!(gone.status, 204);
    let after = check().await;
    assert_eq!(after["readable"], false);
    assert_eq!(after["needs_sign_in"], true);

    // No tools: every listing reports why, and nothing is found.
    let found = api.get("/api/credentials/found").await.json();
    assert_eq!(found["accounts"], json!([]));
    assert_eq!(found["problems"].as_array().unwrap().len(), 3);

    // A broken store is a 503 for both the write and the removal.
    store.break_it();
    let broken = api
        .send(
            "POST",
            "/api/credentials/stored",
            Some(&json!({"host": "github.com", "token": CANARY})),
        )
        .await;
    assert_eq!(broken.status, 503, "{}", broken.body);
    let broken_delete = api
        .send("DELETE", &format!("/api/credentials/stored/{id}"), None)
        .await;
    assert_eq!(broken_delete.status, 503);
}
