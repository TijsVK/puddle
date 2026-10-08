// SPDX-License-Identifier: GPL-3.0-or-later
//! Identities and a workspace's Git settings through the store's public API.
#![expect(
    clippy::unwrap_used,
    reason = "test helpers outside #[test] functions fail the test by panicking"
)]

use std::collections::BTreeSet;
use std::sync::Arc;

use puddle_secrets::{AccountName, HostName, SourceSpec};
use puddle_store::{
    Author, CollisionWhat, Coverage, CredentialBinding, CredentialChoice, IdentityDraft,
    IdentityId, Limits, ManualClock, Owner, RepoRef, Store, StoreError,
};
use puddle_types::{CollectingSink, Event, WorkspaceName};

fn fixture() -> (Arc<CollectingSink>, Store) {
    let clock = Arc::new(ManualClock::new(1_800_000_000_000));
    let sink = Arc::new(CollectingSink::default());
    let store = Store::open_in_memory(clock, Limits::default())
        .unwrap()
        .with_events(sink.clone());
    (sink, store)
}

fn ws(name: &str) -> WorkspaceName {
    WorkspaceName::new(name).unwrap()
}

fn draft(label: &str, host: &str, owners: &[&str], rest: bool) -> IdentityDraft {
    let owners: BTreeSet<Owner> = owners.iter().map(|o| Owner::new(o).unwrap()).collect();
    let host = HostName::new(host).unwrap();
    let source = SourceSpec::Gh {
        host: host.clone(),
        account: AccountName::new("me").unwrap(),
    };
    IdentityDraft {
        label: label.to_owned(),
        author: Author::new(label, &format!("{}@example.com", label.to_lowercase())).unwrap(),
        credentials: vec![
            CredentialBinding::new(&host, source, Coverage::new(owners, rest).unwrap()).unwrap(),
        ],
    }
}

fn make(store: &Store, label: &str, owners: &[&str], rest: bool) -> IdentityId {
    store
        .create_identity(draft(label, "github.com", owners, rest))
        .unwrap()
        .id
}

#[test]
fn identities_keep_order_default_and_only_references() {
    let (sink, store) = fixture();
    assert!(store.default_identity().unwrap().is_none());
    let work = make(&store, "Work", &["acme"], false);
    let personal = make(&store, "Personal", &[], true);
    // The first one made is the default; labels are unique whatever the case.
    assert_eq!(store.default_identity().unwrap().unwrap().id, work);
    assert!(matches!(
        store.create_identity(draft("work", "github.com", &["x"], false)),
        Err(StoreError::IdentityLabelTaken(_))
    ));
    assert!(sink.take().contains(&Event::IdentitiesChanged {}));

    store.set_default_identity(personal).unwrap();
    let list = store.identities().unwrap();
    assert_eq!(
        list.iter()
            .map(|i| (i.label.as_str(), i.is_default))
            .collect::<Vec<_>>(),
        [("Work", false), ("Personal", true)]
    );
    let order = store.reorder_identities(&[personal, work]).unwrap();
    assert_eq!(order[0].id, personal);
    assert!(store.reorder_identities(&[personal]).is_err());
    assert!(store.reorder_identities(&[personal, personal]).is_err());

    // Deleting the default hands it to the first in the order.
    store.delete_identity(personal).unwrap();
    assert_eq!(store.default_identity().unwrap().unwrap().id, work);
    assert!(matches!(
        store.identity(personal),
        Err(StoreError::UnknownIdentity(_))
    ));
}

#[test]
fn a_collision_on_one_workspace_is_refused_naming_both() {
    let (sink, store) = fixture();
    let work = make(&store, "Work", &["acme", "acme-labs"], false);
    let clash = make(&store, "Clash", &["ACME"], false);
    let rest = make(&store, "Personal", &[], true);
    let w = ws("shop");
    store.attach_identity(&w, work, None).unwrap();
    let _ = sink.take();
    let Err(StoreError::IdentityCollision(c)) = store.attach_identity(&w, clash, None) else {
        panic!("expected a collision");
    };
    assert_eq!(
        c.to_string(),
        "Work and Clash both cover github.com/acme; narrow one"
    );
    assert_eq!(c.what, CollisionWhat::Owner(Owner::new("acme").unwrap()));
    assert!(sink.take().is_empty(), "a refused change emits nothing");
    // An exact owner and the rest of the host live together; the same identity twice does not.
    let git = store.attach_identity(&w, rest, Some(0)).unwrap();
    assert_eq!(
        git.identities.iter().map(|i| i.id).collect::<Vec<_>>(),
        [rest, work]
    );
    assert!(matches!(
        store.attach_identity(&w, rest, None),
        Err(StoreError::IdentityAttached { .. })
    ));
    // Another workspace may hold the clashing one.
    store.attach_identity(&ws("blog"), clash, None).unwrap();
    // The whole list is checked as a list.
    assert!(matches!(
        store.set_workspace_identities(&w, &[work, clash]),
        Err(StoreError::IdentityCollision(_))
    ));
    assert_eq!(
        store.workspace_git(&w).unwrap().identities.len(),
        2,
        "unchanged"
    );
}

#[test]
fn changing_coverage_is_refused_where_it_would_collide() {
    let (_, store) = fixture();
    let work = make(&store, "Work", &["acme"], false);
    let other = make(&store, "Other", &["other"], false);
    let w = ws("shop");
    store.set_workspace_identities(&w, &[work, other]).unwrap();
    let widened = draft("Other", "github.com", &["other", "acme"], false);
    let Err(StoreError::IdentityCollision(c)) = store.update_identity(other, widened) else {
        panic!("expected a collision");
    };
    assert_eq!(
        c.to_string(),
        "Work and Other both cover github.com/acme; narrow one"
    );
    assert_eq!(
        store.identity(other).unwrap().credentials[0]
            .covers
            .owners
            .len(),
        1
    );
    // The same widening is fine while no workspace holds both.
    store.detach_identity(&w, work).unwrap();
    let widened = draft("Renamed", "github.com", &["other", "acme"], false);
    assert_eq!(
        store.update_identity(other, widened).unwrap().label,
        "Renamed"
    );
}

#[test]
fn a_request_gets_the_exact_owner_then_the_rest_and_events_follow() {
    let (sink, store) = fixture();
    let work = make(&store, "Work", &["acme"], false);
    let rest = make(&store, "Personal", &[], true);
    let w = ws("shop");
    store.set_workspace_identities(&w, &[rest, work]).unwrap();
    assert_eq!(
        sink.take()
            .into_iter()
            .filter(|e| matches!(e, Event::WorkspaceGitChanged { .. }))
            .count(),
        1
    );
    let git = store.workspace_git(&w).unwrap();
    let who = |owner: &str| match git.credential_for("github.com", owner) {
        CredentialChoice::Covered {
            identity, exact, ..
        } => Some((identity.label.clone(), exact)),
        _ => None,
    };
    assert_eq!(who("Acme"), Some(("Work".into(), true)));
    assert_eq!(who("someone"), Some(("Personal".into(), false)));
    assert!(matches!(
        git.credential_for("gitlab.com", "acme"),
        CredentialChoice::Uncovered
    ));
    // Deleting an identity takes it off the workspace and tells that workspace.
    let _ = sink.take();
    assert_eq!(store.delete_identity(work).unwrap(), vec![w.clone()]);
    assert_eq!(store.workspace_git(&w).unwrap().identities.len(), 1);
    assert!(
        sink.take()
            .contains(&Event::WorkspaceGitChanged { workspace: w })
    );
}

#[test]
fn the_repository_table_and_the_two_switches() {
    let (sink, store) = fixture();
    let w = ws("shop");
    let fresh = store.workspace_git(&w).unwrap();
    assert!(fresh.only_push_listed && !fresh.only_pull_listed && fresh.repos.is_empty());
    let web = RepoRef::new("GitHub.com", "Acme", "web.git").unwrap();
    let entry = store.add_repo(&w, &web, true, true).unwrap();
    assert_eq!(entry.repo.to_string(), "github.com/acme/web");
    assert!(matches!(
        store.add_repo(&w, &web, true, true),
        Err(StoreError::RepoListed(_))
    ));
    let docs = RepoRef::new("github.com", "acme", "docs").unwrap();
    let docs_row = store.add_repo(&w, &docs, true, false).unwrap();
    let git = store.workspace_git(&w).unwrap();
    assert!(git.allows_push(&web) && !git.allows_push(&docs));
    assert!(
        git.allows_pull(&docs),
        "pull is open until its switch is on"
    );
    store.set_git_switches(&w, None, Some(true)).unwrap();
    store
        .set_repo_toggles(&w, docs_row.id, false, true)
        .unwrap();
    let git = store.workspace_git(&w).unwrap();
    assert!(git.only_push_listed && git.only_pull_listed);
    assert!(git.allows_push(&docs) && !git.allows_pull(&docs) && git.allows_pull(&web));
    let other = RepoRef::new("github.com", "me", "x").unwrap();
    assert!(!git.allows_push(&other) && !git.allows_pull(&other));
    store.set_git_switches(&w, Some(false), None).unwrap();
    assert!(store.workspace_git(&w).unwrap().allows_push(&other));
    // Rows belong to their workspace.
    assert!(matches!(
        store.set_repo_toggles(&ws("blog"), docs_row.id, true, true),
        Err(StoreError::UnknownRepo(_))
    ));
    assert!(store.remove_repo(&ws("blog"), docs_row.id).is_err());
    store.remove_repo(&w, docs_row.id).unwrap();
    assert_eq!(store.workspace_git(&w).unwrap().repos.len(), 1);
    assert!(
        sink.take()
            .contains(&Event::WorkspaceGitChanged { workspace: w })
    );
}

#[test]
fn deleting_a_workspace_clears_its_git_settings_but_keeps_the_identities() {
    let (sink, store) = fixture();
    let a = make(&store, "Work", &["acme"], false);
    let w = ws("shop");
    store.attach_identity(&w, a, None).unwrap();
    store
        .add_repo(
            &w,
            &RepoRef::new("github.com", "acme", "web").unwrap(),
            true,
            true,
        )
        .unwrap();
    store.set_git_switches(&w, Some(false), Some(true)).unwrap();
    let _ = sink.take();
    store.delete_workspace(&w).unwrap();
    assert!(sink.take().contains(&Event::WorkspaceGitChanged {
        workspace: w.clone()
    }));
    let git = store.workspace_git(&w).unwrap();
    assert!(git.identities.is_empty() && git.repos.is_empty());
    assert!(git.only_push_listed && !git.only_pull_listed);
    assert_eq!(store.identities().unwrap().len(), 1);
}

#[test]
fn the_database_holds_references_never_a_value() {
    let (_, store) = fixture();
    let host = HostName::new("github.com").unwrap();
    let source = SourceSpec::Stored {
        id: puddle_secrets::StoredId::new("tok1").unwrap(),
        scope: puddle_secrets::TokenScope {
            host: host.clone(),
            org: None,
        },
    };
    let binding =
        CredentialBinding::new(&host, source, Coverage::new(BTreeSet::new(), true).unwrap())
            .unwrap();
    let id = store
        .create_identity(IdentityDraft {
            label: "Pasted".into(),
            author: Author::new("Me", "me@example.com").unwrap(),
            credentials: vec![binding],
        })
        .unwrap()
        .id;
    let json = serde_json::to_string(&store.identity(id).unwrap().credentials).unwrap();
    assert!(
        json.contains(r#""kind":"stored""#) && json.contains("tok1"),
        "{json}"
    );
    assert!(
        !json.contains("secret") && !json.contains("password"),
        "{json}"
    );
}

fn repo(host: &str, owner: &str, name: &str) -> RepoRef {
    RepoRef::new(host, owner, name).unwrap()
}

#[test]
fn a_new_workspace_gets_the_identity_that_covers_its_repository_and_the_repository_itself() {
    let (_sink, store) = fixture();
    let _personal = make(&store, "Personal", &[], true);
    let work = make(&store, "Work", &["acme"], false);

    store
        .start_workspace_git(&ws("shop"), &repo("github.com", "acme", "shop"))
        .unwrap();
    let git = store.workspace_git(&ws("shop")).unwrap();
    // The exact owner beats "the rest of github.com", which is the default.
    assert_eq!(
        git.identities.iter().map(|i| i.id).collect::<Vec<_>>(),
        [work]
    );
    assert_eq!(git.repos.len(), 1);
    assert_eq!((git.repos[0].pull, git.repos[0].push), (true, true));
    assert_eq!(git.repos[0].repo, repo("github.com", "acme", "shop"));
    assert!(git.only_push_listed && !git.only_pull_listed);
}

#[test]
fn a_repository_nobody_covers_gets_the_default_and_none_when_there_is_none() {
    let (_sink, store) = fixture();
    store
        .start_workspace_git(&ws("lonely"), &repo("github.com", "me", "x"))
        .unwrap();
    let none = store.workspace_git(&ws("lonely")).unwrap();
    assert_eq!(none.identities.len(), 0);
    assert_eq!(none.repos.len(), 1);

    // Work covers only acme on github.com; the default (first made) covers another host.
    let default = store
        .create_identity(draft("Default", "dev.azure.com", &["contoso"], false))
        .unwrap()
        .id;
    let _work = make(&store, "Work", &["acme"], false);
    store
        .start_workspace_git(&ws("elsewhere"), &repo("github.com", "me", "x"))
        .unwrap();
    let git = store.workspace_git(&ws("elsewhere")).unwrap();
    assert_eq!(
        git.identities.iter().map(|i| i.id).collect::<Vec<_>>(),
        [default]
    );
}

#[test]
fn two_identities_that_cover_a_repository_equally_give_the_first_in_your_order() {
    let (_sink, store) = fixture();
    // Collisions are refused per workspace, not globally, so two identities may both cover the
    // rest of github.com; a new workspace gets the first of them in your order.
    let a = make(&store, "A", &[], true);
    let b = make(&store, "B", &[], true);
    store
        .start_workspace_git(&ws("both"), &repo("github.com", "x", "y"))
        .unwrap();
    let ids: Vec<_> = store
        .workspace_git(&ws("both"))
        .unwrap()
        .identities
        .iter()
        .map(|i| i.id)
        .collect();
    assert_eq!(ids, [a]);
    assert_ne!(a, b);
}
