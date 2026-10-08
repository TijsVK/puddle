// SPDX-License-Identifier: GPL-3.0-or-later
//! A `401` from the real server is replaced by the injector's own answer when the injector chose
//! the request's credential (it added one, or had none to add), and only then: any other `401`
//! is the server's answer like every other. Both HTTP versions.
#![expect(
    clippy::unwrap_used,
    reason = "helpers outside #[test] functions fail the test by panicking"
)]
mod terminate_support;

use std::sync::Arc;

use bytes::Bytes;
use http::Response;
use http_body_util::{BodyExt as _, Full};
use puddle_proxy::{InjectDecision, InjectRefusal, Unauthorized};
use terminate_support::h2_rig::{H2Server, Script, full};
use terminate_support::{CANARY, FakeServer, Flaw, Pki, Reply, RigBuilder, TestInjector, inject};

const WWW_AUTHENTICATE: &str = "www-authenticate: Basic realm=\"upstream\"\r\n";

fn rejected() -> Unauthorized {
    Unauthorized::new(|| {
        InjectRefusal::new(
            403,
            "credential_rejected",
            "the server did not accept the credential puddle added",
        )
    })
}

fn injected_and_watched() -> InjectDecision {
    let InjectDecision::Inject(injection) = inject(CANARY) else {
        unreachable!("inject() injects");
    };
    InjectDecision::Inject(injection.on_unauthorized(rejected()))
}

/// The server answers `401` to every request without `?ok` in the target, `200` to the rest.
fn picky_h1() -> Arc<dyn Fn(&terminate_support::Recorded) -> Reply + Send + Sync> {
    Arc::new(|request| {
        if request.target.contains("ok") {
            Reply::ok("fine")
        } else {
            Reply::status(401, WWW_AUTHENTICATE, "server says no")
        }
    })
}

fn picky_h2() -> Script {
    Arc::new(|request| {
        if request.path.contains("ok") {
            terminate_support::h2_rig::reply(200, "fine")
        } else {
            Response::builder()
                .status(401)
                .header("www-authenticate", "Basic realm=\"upstream\"")
                .body(
                    Full::new(Bytes::from("server says no"))
                        .map_err(|never| match never {})
                        .boxed_unsync(),
                )
                .unwrap()
        }
    })
}

async fn h1_rig(
    script: Box<dyn Fn() -> InjectDecision + Send + Sync>,
) -> (FakeServer, terminate_support::Rig, Arc<TestInjector>) {
    let pki = Pki::new();
    let server = FakeServer::tls(pki.server_config("bound.test", Flaw::None), picky_h1()).await;
    let injector = TestInjector::new(move |_| script());
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .injector(injector.clone())
        .build();
    (server, rig, injector)
}

#[tokio::test]
async fn a_401_for_a_request_with_an_added_credential_becomes_the_injectors_refusal() {
    let (server, rig, _) = h1_rig(Box::new(injected_and_watched)).await;
    let mut guest = rig.guest().await;
    let mut client = guest.tls("bound.test:443", None).await.unwrap();
    let answer = client.get("bound.test", "/acme/web.git/info/refs").await;
    assert_eq!(answer.status, 403);
    assert_eq!(
        answer.header("x-puddle-blocked"),
        Some("credential_rejected")
    );
    assert_eq!(answer.header("www-authenticate"), None);
    assert!(answer.text().starts_with("puddle: "), "{}", answer.text());
    assert!(!answer.text().contains("server says no"));
    assert!(!answer.text().contains(CANARY));
    // The credential did go out (that is what the server rejected).
    assert_eq!(
        server.recorded()[0].headers_named("authorization"),
        [format!("Basic {CANARY}")]
    );
    let events = rig.events(1).await;
    assert!(
        events[0].injected,
        "the record still says a credential was added"
    );
}

#[tokio::test]
async fn a_request_the_server_accepts_is_not_touched_by_the_401_watch() {
    let (_server, rig, _injector) = h1_rig(Box::new(injected_and_watched)).await;
    let mut guest = rig.guest().await;
    let mut client = guest.tls("bound.test:443", None).await.unwrap();
    let answer = client.get("bound.test", "/acme/web.git/info/refs?ok").await;
    assert_eq!((answer.status, answer.text().as_str()), (200, "fine"));
}

#[tokio::test]
async fn a_401_for_a_request_the_injector_had_no_credential_for_becomes_the_injectors_refusal() {
    let (server, rig, _) =
        h1_rig(Box::new(|| InjectDecision::PassThroughGuarded(rejected()))).await;
    let mut guest = rig.guest().await;
    let mut client = guest.tls("bound.test:443", None).await.unwrap();
    let answer = client
        .get("bound.test", "/acme/private.git/info/refs")
        .await;
    assert_eq!(answer.status, 403);
    assert_eq!(
        answer.header("x-puddle-blocked"),
        Some("credential_rejected")
    );
    assert_eq!(server.recorded()[0].header("authorization"), None);
    let events = rig.events(1).await;
    assert!(!events[0].injected);
}

#[tokio::test]
async fn any_other_401_is_the_servers_answer_unchanged() {
    for decision in [
        (|| InjectDecision::PassThrough) as fn() -> InjectDecision,
        || inject(CANARY),
    ] {
        let (_server, rig, _injector) = h1_rig(Box::new(decision)).await;
        let mut guest = rig.guest().await;
        let mut client = guest.tls("bound.test:443", None).await.unwrap();
        let answer = client.get("bound.test", "/acme/web.git/info/refs").await;
        assert_eq!(answer.status, 401);
        assert_eq!(
            answer.header("www-authenticate"),
            Some("Basic realm=\"upstream\"")
        );
        assert_eq!(answer.text(), "server says no");
        assert_eq!(answer.header("x-puddle-blocked"), None);
    }
}

#[tokio::test]
async fn the_replacement_ends_that_connection_and_the_next_one_works() {
    let (server, rig, _) = h1_rig(Box::new(injected_and_watched)).await;
    let mut guest = rig.guest().await;
    let mut client = guest.tls("bound.test:443", None).await.unwrap();
    assert_eq!(client.get("bound.test", "/a/b").await.status, 403);
    assert!(client.closed().await);
    let mut again = guest.tls("bound.test:443", None).await.unwrap();
    assert_eq!(again.get("bound.test", "/a/b?ok").await.status, 200);
    assert_eq!(
        server.accepted(),
        2,
        "the rejected connection is not reused"
    );
}

async fn h2_rig(
    script: Box<dyn Fn() -> InjectDecision + Send + Sync>,
) -> (H2Server, terminate_support::Rig) {
    let pki = Pki::new();
    let server = H2Server::recording(&pki, "bound.test", picky_h2()).await;
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .injector(TestInjector::new(move |_| script()))
        .build();
    (server, rig)
}

#[tokio::test]
async fn over_http2_a_401_for_an_added_credential_becomes_the_injectors_refusal_and_the_next_stream_works()
 {
    let (server, rig) = h2_rig(Box::new(injected_and_watched)).await;
    let mut guest = rig.guest().await;
    let mut client = guest.h2("bound.test:443", &[b"h2"]).await;
    let refused = client.get("bound.test", "/acme/web.git/info/refs").await;
    assert_eq!(refused.status, 403);
    assert_eq!(
        refused.header("x-puddle-blocked"),
        Some("credential_rejected")
    );
    assert_eq!(refused.header("www-authenticate"), None);
    assert!(refused.text().starts_with("puddle: "));
    // The same connection carries the next request.
    let fine = client.get("bound.test", "/acme/web.git/info/refs?ok").await;
    assert_eq!((fine.status, fine.text().as_str()), (200, "fine"));
    assert_eq!(server.recorded().len(), 2);
}

#[tokio::test]
async fn over_http2_a_401_with_no_credential_to_add_is_replaced_and_any_other_401_is_not() {
    let (_server, rig) = h2_rig(Box::new(|| InjectDecision::PassThroughGuarded(rejected()))).await;
    let mut guest = rig.guest().await;
    let mut client = guest.h2("bound.test:443", &[b"h2"]).await;
    assert_eq!(client.get("bound.test", "/x").await.status, 403);

    let (_server, rig) = h2_rig(Box::new(|| InjectDecision::PassThrough)).await;
    let mut guest = rig.guest().await;
    let mut client = guest.h2("bound.test:443", &[b"h2"]).await;
    let own = client
        .request(
            "GET",
            "bound.test",
            "/x",
            &[("authorization", "Bearer mine")],
            full(Bytes::new()),
        )
        .await;
    assert_eq!(own.status, 401);
    assert_eq!(
        own.header("www-authenticate"),
        Some("Basic realm=\"upstream\"")
    );
    assert_eq!(own.text(), "server says no");
}
