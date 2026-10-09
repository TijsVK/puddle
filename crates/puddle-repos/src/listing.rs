// SPDX-License-Identifier: GPL-3.0-or-later
//! One list out of every credential's: repositories reached by more than one identity appear
//! once with all of them, filtered by what the user typed and cut to a page. The Identities tab
//! and the create form both read this, so they agree on order and spelling.

use std::collections::HashMap;

use puddle_store::IdentityId;

use crate::model::{Repository, SourceList};

/// What to show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    /// Words that must all appear in the repository's full name, whatever the case; empty for
    /// everything.
    pub text: String,
    /// Only repositories this identity reaches.
    pub only: Option<IdentityId>,
    /// Repositories to skip.
    pub offset: usize,
    /// Repositories to return.
    pub limit: usize,
}

/// A repository with the identities that reach it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    /// The repository, as the first list that had it spells it.
    pub repository: Repository,
    /// The identities whose credentials list it, in the order of their lists.
    pub identities: Vec<IdentityId>,
}

/// A page of repositories.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    /// How many repositories match, before the page is cut.
    pub total: usize,
    /// The page, by full name.
    pub repos: Vec<Found>,
}

/// The repositories of `lists` that match `query`, one entry each, by full name.
#[must_use]
pub fn page(lists: &[SourceList], query: &Query) -> Page {
    let mut index: HashMap<String, usize> = HashMap::new();
    let mut found: Vec<Found> = Vec::new();
    for list in lists {
        for repository in list.repos.iter() {
            if let Some(&at) = index.get(&repository.key()) {
                if let Some(entry) = found.get_mut(at)
                    && !entry.identities.contains(&list.identity)
                {
                    entry.identities.push(list.identity);
                }
            } else {
                index.insert(repository.key(), found.len());
                found.push(Found {
                    repository: repository.clone(),
                    identities: vec![list.identity],
                });
            }
        }
    }
    let words: Vec<String> = query
        .text
        .split_whitespace()
        .map(str::to_lowercase)
        .collect();
    found.retain(|f| {
        let name = f.repository.full_name.to_lowercase();
        query.only.is_none_or(|id| f.identities.contains(&id))
            && words.iter().all(|word| name.contains(word.as_str()))
    });
    found.sort_by_cached_key(|f| {
        (
            f.repository.full_name.to_lowercase(),
            f.repository.host.clone(),
        )
    });
    Page {
        total: found.len(),
        repos: found
            .into_iter()
            .skip(query.offset)
            .take(query.limit)
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::model::{ListState, Role, Visibility};

    fn repo(host: &str, full_name: &str) -> Repository {
        let (owner, name) = full_name.split_once('/').unwrap();
        Repository {
            host: host.to_owned(),
            owner: owner.to_owned(),
            project: None,
            name: name.to_owned(),
            full_name: full_name.to_owned(),
            url: format!("https://{host}/{full_name}"),
            visibility: Visibility::Private,
            role: Role::Write,
            archived: false,
            fork: false,
        }
    }

    fn list(identity: i64, repos: Vec<Repository>) -> SourceList {
        SourceList {
            identity: IdentityId(identity),
            credential: 0,
            host: "github.com".to_owned(),
            organisation: None,
            state: ListState::Ok,
            refreshed_at: Some(1),
            retry_at: None,
            problem: None,
            notes: Vec::new(),
            repos: Arc::from(repos),
        }
    }

    fn query(text: &str, only: Option<i64>, offset: usize, limit: usize) -> Query {
        Query {
            text: text.to_owned(),
            only: only.map(IdentityId),
            offset,
            limit,
        }
    }

    fn names(page: &Page) -> Vec<&str> {
        page.repos
            .iter()
            .map(|f| f.repository.full_name.as_str())
            .collect()
    }

    fn lists() -> Vec<SourceList> {
        vec![
            list(
                1,
                vec![
                    repo("github.com", "acme/web"),
                    repo("github.com", "Acme/api"),
                ],
            ),
            list(
                2,
                vec![
                    repo("github.com", "ACME/Web"),
                    repo("github.com", "me/notes"),
                ],
            ),
        ]
    }

    #[test]
    fn a_repository_two_identities_reach_appears_once_with_both_and_the_list_is_by_name() {
        let page = page(&lists(), &query("", None, 0, 50));
        assert_eq!(page.total, 3);
        assert_eq!(names(&page), ["Acme/api", "acme/web", "me/notes"]);
        // The first list's spelling stays, and every identity that lists it is named.
        assert_eq!(page.repos[1].identities, [IdentityId(1), IdentityId(2)]);
        assert_eq!(page.repos[2].identities, [IdentityId(2)]);
    }

    #[test]
    fn the_same_identity_twice_is_named_once() {
        let page = page(
            &[
                list(1, vec![repo("github.com", "a/b")]),
                list(1, vec![repo("github.com", "A/B")]),
            ],
            &query("", None, 0, 50),
        );
        assert_eq!(page.repos.len(), 1);
        assert_eq!(page.repos[0].identities, [IdentityId(1)]);
    }

    #[test]
    fn every_word_must_appear_in_the_full_name_whatever_the_case() {
        let all = lists();
        assert_eq!(
            names(&page(&all, &query("ACME", None, 0, 50))),
            ["Acme/api", "acme/web"]
        );
        assert_eq!(
            names(&page(&all, &query("  acme   WEB ", None, 0, 50))),
            ["acme/web"]
        );
        assert_eq!(page(&all, &query("nothing here", None, 0, 50)).total, 0);
    }

    #[test]
    fn one_identity_sees_what_it_reaches_with_all_who_reach_it() {
        let all = lists();
        let mine = page(&all, &query("", Some(2), 0, 50));
        assert_eq!(names(&mine), ["acme/web", "me/notes"]);
        assert_eq!(mine.repos[0].identities, [IdentityId(1), IdentityId(2)]);
        assert_eq!(page(&all, &query("", Some(9), 0, 50)).total, 0);
    }

    #[test]
    fn a_page_is_cut_after_the_total_is_counted() {
        let all = lists();
        let second = page(&all, &query("", None, 1, 1));
        assert_eq!(second.total, 3);
        assert_eq!(names(&second), ["acme/web"]);
        assert_eq!(page(&all, &query("", None, 5, 10)).repos, []);
    }

    #[test]
    fn two_hosts_with_one_name_stay_apart_and_sort_by_host() {
        let page = page(
            &[list(
                1,
                vec![repo("b.example", "a/x"), repo("a.example", "a/x")],
            )],
            &query("", None, 0, 50),
        );
        let hosts: Vec<&str> = page
            .repos
            .iter()
            .map(|f| f.repository.host.as_str())
            .collect();
        assert_eq!(hosts, ["a.example", "b.example"]);
    }
}
