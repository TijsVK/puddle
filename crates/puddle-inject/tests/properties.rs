// SPDX-License-Identifier: GPL-3.0-or-later
//! Properties of the injector over generated requests: whatever the path, method, query and
//! headers, a request never carries a credential that is not the one the owner in its path is
//! covered by; never one of another workspace's; never when the workspace sent its own
//! `Authorization`; never for a push the table does not list; and no refusal shows a token.
#![expect(
    clippy::unwrap_used,
    reason = "helpers outside #[test] functions fail the test by panicking"
)]
mod support;

use std::sync::OnceLock;

use proptest::prelude::*;
use puddle_inject::testing::World;
use puddle_proxy::InjectDecision;
use support::{Ask as _, basic};

/// Tokens that are each other's near misses: the names that are covered, case and encoding
/// variants of them, separators, dot segments, service words.
const PIECES: &[&str] = &[
    "alpha",
    "Alpha",
    "ALPHA",
    "%61lpha",
    "beta",
    "acme",
    "web",
    "Web.git",
    "web.git",
    "other",
    "someone",
    "contoso",
    "fabrikam",
    "proj",
    "_git",
    "_GIT",
    "info",
    "refs",
    "info/refs",
    "git-upload-pack",
    "git-receive-pack",
    "info/lfs",
    "objects",
    "batch",
    "locks",
    "..",
    ".",
    "",
    "%2e%2e",
    "%2F",
    "%2f",
    "%5c",
    "\\",
    "%00",
    "a;b",
    "x y",
    "%20",
    "DefaultCollection",
];

const HOSTS: &[&str] = &[
    "github.com",
    "dev.azure.com",
    "contoso.visualstudio.com",
    "fabrikam.visualstudio.com",
    "evil.example",
];

const QUERIES: &[Option<&str>] = &[
    None,
    Some(""),
    Some("service=git-upload-pack"),
    Some("service=git-receive-pack"),
    Some("service=git%2Dreceive%2Dpack"),
    Some("SERVICE=git-receive-pack"),
    Some("service=git-upload-pack&service=git-receive-pack"),
    Some("x=1"),
];

const ALPHA: &str = "CANARY-ALPHA";
const BETA: &str = "CANARY-BETA";
const REST: &str = "CANARY-REST";
const CONTOSO: &str = "CANARY-CONTOSO";
const FABRIKAM: &str = "CANARY-FABRIKAM";
const OTHER_ALPHA: &str = "CANARY-OTHER-ALPHA";
const OTHER_ADO: &str = "CANARY-OTHER-ADO";

/// The tokens of the first workspace's identities and of the second one's.
const MINE: &[&str] = &[ALPHA, BETA, REST, CONTOSO, FABRIKAM];
const THEIRS: &[&str] = &[OTHER_ALPHA, OTHER_ADO];

struct Worlds {
    /// One per combination of the two switches.
    mine: Vec<(World, bool, bool)>,
    theirs: World,
}

fn worlds() -> &'static Worlds {
    static WORLDS: OnceLock<Worlds> = OnceLock::new();
    WORLDS.get_or_init(|| {
        let mut mine = Vec::new();
        for (push_listed, pull_listed) in
            [(true, false), (true, true), (false, false), (false, true)]
        {
            let w = World::new();
            w.identity("Alpha", "github.com", &["alpha"], false, ALPHA);
            w.identity("Beta", "github.com", &["beta"], false, BETA);
            w.identity("Rest", "github.com", &[], true, REST);
            w.identity("Contoso", "dev.azure.com", &["contoso"], false, CONTOSO);
            w.identity("Fabrikam", "dev.azure.com", &["fabrikam"], false, FABRIKAM);
            w.list("github.com/acme/web", true, true);
            w.switches(push_listed, pull_listed);
            mine.push((w, push_listed, pull_listed));
        }
        let theirs = World::new();
        theirs.identity("Alpha", "github.com", &["alpha"], false, OTHER_ALPHA);
        theirs.identity("Ado", "dev.azure.com", &["contoso"], false, OTHER_ADO);
        theirs.switches(false, false);
        Worlds { mine, theirs }
    })
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
}

#[derive(Debug, Clone)]
struct Case {
    world: usize,
    host: &'static str,
    method: &'static str,
    path: String,
    query: Option<&'static str>,
    own_header: bool,
    body: Option<&'static str>,
}

fn case() -> impl Strategy<Value = Case> {
    let piece = prop_oneof![
        3 => proptest::sample::select(PIECES).prop_map(str::to_owned),
        1 => "[a-zA-Z0-9%.;\\\\-]{0,5}",
    ];
    let path = prop::collection::vec(piece, 0..8).prop_map(|parts| format!("/{}", parts.join("/")));
    // Mostly real service shapes, so the interesting branches are reached often.
    let shaped = (
        proptest::sample::select(PIECES),
        proptest::sample::select(PIECES),
        proptest::sample::select(
            &[
                "info/refs",
                "git-upload-pack",
                "git-receive-pack",
                "info/lfs/objects/batch",
            ][..],
        ),
    )
        .prop_map(|(a, b, tail)| format!("/{a}/{b}/{tail}"));
    let clean = (
        proptest::sample::select(
            &["alpha", "Alpha", "beta", "acme", "someone", "contoso", "x"][..],
        ),
        proptest::sample::select(&["web", "Web.git", "other.git", "web.git"][..]),
        proptest::sample::select(
            &[
                "info/refs",
                "git-upload-pack",
                "git-receive-pack",
                "info/lfs/objects/batch",
            ][..],
        ),
    )
        .prop_map(|(a, b, tail)| format!("/{a}/{b}/{tail}"));
    let ado = (
        proptest::sample::select(&["contoso", "fabrikam", "CONTOSO", "x"][..]),
        proptest::sample::select(&["info/refs", "git-upload-pack", "git-receive-pack"][..]),
    )
        .prop_map(|(org, tail)| format!("/{org}/proj/_git/repo/{tail}"));
    let vs = (
        proptest::sample::select(&["proj", "Proj", "DefaultCollection/proj"][..]),
        proptest::sample::select(&["info/refs", "git-upload-pack", "git-receive-pack"][..]),
    )
        .prop_map(|(project, tail)| format!("/{project}/_git/repo/{tail}"));
    let place = prop_oneof![
        2 => (Just("github.com"), path.clone()),
        2 => (Just("github.com"), shaped),
        6 => (Just("github.com"), clean.clone()),
        1 => (Just("evil.example"), clean),
        3 => (Just("dev.azure.com"), ado),
        2 => (proptest::sample::select(&["contoso.visualstudio.com", "fabrikam.visualstudio.com"][..]), vs),
        1 => (proptest::sample::select(HOSTS), path),
    ];
    (
        0..4_usize,
        place,
        prop_oneof![5 => Just("GET"), 3 => Just("POST"), 1 => Just("PUT"), 1 => Just("HEAD"), 1 => Just("DELETE")],
        proptest::sample::select(QUERIES),
        prop_oneof![1 => Just(true), 4 => Just(false)],
        proptest::sample::select(
            &[
                None,
                Some(r#"{"operation":"upload"}"#),
                Some(r#"{"operation":"download"}"#),
            ][..],
        ),
    )
        .prop_map(
            |(world, (host, path), method, query, own_header, body)| Case {
                world,
                host,
                method,
                path,
                query,
                own_header,
                body,
            },
        )
}

/// The identity token a request on `host` for `owner` is covered by, by a plain reading.
fn covered_by(host: &str, owner: &str) -> Option<&'static str> {
    let owner = owner.to_ascii_lowercase();
    match host {
        "github.com" => Some(match owner.as_str() {
            "alpha" => ALPHA,
            "beta" => BETA,
            _ => REST,
        }),
        "dev.azure.com" | "contoso.visualstudio.com" | "fabrikam.visualstudio.com" => {
            match owner.as_str() {
                "contoso" => Some(CONTOSO),
                "fabrikam" => Some(FABRIKAM),
                _ => None,
            }
        }
        _ => None,
    }
}

/// Whether `path` is plain enough that a plain reading is the reading: the bytes a path segment
/// may carry raw and single slashes, no dot segment.
fn plain(path: &str) -> bool {
    // A space is spelled one way, `%20`.
    if path.contains(' ') {
        return false;
    }
    let path = path.replace("%20", " ");
    path.starts_with('/')
        && path
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || " ._~-!$&'()*+,:=@/".contains(c))
        && !path.contains("//")
        && !path.ends_with('/')
        && path.split('/').skip(1).all(|s| s != "." && s != "..")
}

/// The owner a plain path names on `host`, by a plain reading.
fn plain_owner(host: &str, path: &str) -> Option<String> {
    let segments: Vec<&str> = path.split('/').skip(1).collect();
    match host {
        "contoso.visualstudio.com" => Some("contoso".to_owned()),
        "fabrikam.visualstudio.com" => Some("fabrikam".to_owned()),
        _ => segments.first().map(|s| (*s).to_owned()),
    }
}

/// Which of `tokens` the injected value carries (as a GitHub-style Basic, an Azure DevOps Basic
/// or a Bearer).
fn carried(decision: &InjectDecision, tokens: &[&'static str]) -> Vec<&'static str> {
    let InjectDecision::Inject(injection) = decision else {
        return Vec::new();
    };
    tokens
        .iter()
        .copied()
        .filter(|token| {
            [
                basic("x-access-token", token),
                basic("", token),
                format!("Bearer {token}"),
            ]
            .iter()
            .any(|value| injection.headers().iter().any(|h| h.value_is(value)))
        })
        .collect()
}

fn is_push_by_plain_reading(case: &Case) -> bool {
    let path = case.path.to_ascii_lowercase();
    path.ends_with("/git-receive-pack")
        || (path.ends_with("/info/refs")
            && case
                .query
                .is_some_and(|q| q.eq_ignore_ascii_case("service=git-receive-pack")))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn no_request_ever_carries_another_identitys_credential(case in case()) {
        let worlds = worlds();
        let (world, push_listed, _pull_listed) = &worlds.mine[case.world];
        let target = match case.query {
            Some(query) => format!("{}?{query}", case.path),
            None => case.path.clone(),
        };
        let headers: &[&str] = if case.own_header { &["authorization: Bearer mine"] } else { &[] };
        let rt = runtime();
        let decision = rt.block_on(world.decide_with(
            case.host,
            case.method,
            &target,
            headers,
            case.body.map(str::as_bytes),
        ));

        // 1. Never a token of the other workspace, never two tokens, never a secret in a message.
        prop_assert!(carried(&decision, THEIRS).is_empty(), "{case:?}");
        let mine = carried(&decision, MINE);
        prop_assert!(mine.len() <= 1, "{case:?}: {mine:?}");
        let shown = format!("{decision:?}");
        prop_assert!(!shown.contains("CANARY"), "{case:?}: {shown}");

        // 2. The workspace's own header is never replaced: no injection.
        if case.own_header {
            prop_assert!(
                matches!(
                    decision,
                    InjectDecision::PassThrough | InjectDecision::Refuse(_)
                ),
                "{case:?}: {decision:?}"
            );
        }

        // 3. An injected credential is the covering identity's, on a plain path, for a git service.
        if let InjectDecision::Inject(_) = &decision {
            prop_assert!(plain(&case.path), "a path that is not plain was injected: {case:?}");
            let lower = case.path.to_ascii_lowercase();
            prop_assert!(
                ["info/refs", "git-upload-pack", "git-receive-pack", "info/lfs"]
                    .iter()
                    .any(|m| lower.contains(m)),
                "{case:?}"
            );
            let owner = plain_owner(case.host, &case.path).unwrap();
            prop_assert_eq!(mine.first().copied(), covered_by(case.host, &owner), "{:?}", case);

            // 4. A push goes only to a repository the table lists with Push on, when it asks.
            if *push_listed && case.host == "github.com" && is_push_by_plain_reading(&case) {
                let segments: Vec<String> = case.path.split('/').skip(1).map(str::to_ascii_lowercase).collect();
                let repo = segments.get(1).map(|s| s.strip_suffix(".git").unwrap_or(s).to_owned());
                prop_assert_eq!(
                    (segments.first().map(String::as_str), repo.as_deref()),
                    (Some("acme"), Some("web")),
                    "{:?}", case
                );
            }
        }

        // 5. A workspace without these identities never gets them: the other workspace's world
        // answers the same request with its own tokens or none.
        let other = rt.block_on(worlds.theirs.decide_with(
            case.host,
            case.method,
            &target,
            headers,
            case.body.map(str::as_bytes),
        ));
        prop_assert!(carried(&other, MINE).is_empty(), "{case:?}");
        let shown = format!("{other:?}");
        prop_assert!(!shown.contains("CANARY-ALPHA"), "{}", shown);
    }
}

/// The property above means something only if the generator reaches every kind of answer.
#[test]
fn the_generated_requests_reach_every_kind_of_answer() {
    use proptest::strategy::{Strategy as _, ValueTree as _};
    use proptest::test_runner::TestRunner;

    let worlds = worlds();
    let rt = runtime();
    let mut runner = TestRunner::deterministic();
    let strategy = case();
    let (mut injected, mut refused, mut passed) = (0, 0, 0);
    let mut codes = std::collections::BTreeSet::new();
    for _ in 0..2000 {
        let case = strategy.new_tree(&mut runner).unwrap().current();
        let (world, _, _) = &worlds.mine[case.world];
        let target = match case.query {
            Some(query) => format!("{}?{query}", case.path),
            None => case.path.clone(),
        };
        let headers: &[&str] = if case.own_header {
            &["authorization: Bearer mine"]
        } else {
            &[]
        };
        match rt.block_on(world.decide_with(
            case.host,
            case.method,
            &target,
            headers,
            case.body.map(str::as_bytes),
        )) {
            InjectDecision::Inject(_) => injected += 1,
            InjectDecision::Refuse(refusal) => {
                refused += 1;
                codes.insert(refusal.code());
            }
            _ => passed += 1,
        }
    }
    assert!(injected > 300, "injected {injected}");
    assert!(passed > 100, "passed {passed}");
    assert!(refused > 100, "refused {refused}");
    for code in ["bad_git_path", "push_denied", "pull_denied"] {
        assert!(codes.contains(code), "{codes:?}");
    }
}
