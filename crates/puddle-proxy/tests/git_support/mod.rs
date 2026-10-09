// SPDX-License-Identifier: GPL-3.0-or-later
//! A fake Git host behind the TLS rig, and a workspace whose injector is the real one over a real
//! in-memory store.
#![expect(
    clippy::unwrap_used,
    reason = "helpers outside #[test] functions fail the test by panicking"
)]
#![allow(dead_code, reason = "each test binary uses a different subset")]

use std::sync::Arc;

use puddle_inject::testing::World;
use puddle_proxy::{
    SecretValue, StandIn, StandInOrigin, StandIns, TerminationSet, secret_stand_in,
};
use puddle_types::{Event, GitAccess};

use crate::terminate_support::h2_rig::{H2Server, Script};
use crate::terminate_support::{FakeServer, Flaw, Pki, Recorded, Reply, Rig, RigBuilder};

pub(crate) const SHA: &str = "1111111111111111111111111111111111111111";

/// The tokens of the identities every test below makes.
pub(crate) const WORK: &str = "CANARY-WORK-token";
pub(crate) const PERSONAL: &str = "CANARY-PERSONAL-token";

/// One pkt-line.
fn pkt(text: &str) -> String {
    format!("{:04x}{text}", text.len() + 4)
}

/// What a Git host answers to `GET info/refs?service=<service>`.
pub(crate) fn advert(service: &str) -> String {
    let caps = if service == "git-receive-pack" {
        "report-status delete-refs"
    } else {
        "side-band-64k ofs-delta"
    };
    format!(
        "{}0000{}{}0000",
        pkt(&format!("# service={service}\n")),
        pkt(&format!(
            "{SHA} refs/heads/main\0{caps} agent=puddle-test\n"
        )),
        pkt(&format!("{SHA} refs/tags/v1\n")),
    )
}

/// What a stand-in the workspace holds stands for: only the real server may ever see it.
pub(crate) const REAL_SECRET: &str = "ghp_LIVE8f3b2a91c4d7e60";

/// A registry holding one secret, `GH_TOKEN`, for `bound.test`, and the stand-in the workspace
/// holds for it.
fn stand_ins() -> (Arc<StandIns>, String) {
    let registry = Arc::new(StandIns::new());
    let stand_in = secret_stand_in("GH_TOKEN").unwrap();
    registry
        .insert(
            StandIn::new(
                StandInOrigin::Secret,
                "GH_TOKEN",
                &stand_in,
                SecretValue::new(REAL_SECRET),
                TerminationSet::parse(["bound.test"]).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
    (registry, stand_in)
}

/// The `Authorization` of `Basic x-access-token:<token>`.
pub(crate) fn token_basic(token: &str) -> String {
    use base64::Engine as _;
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("x-access-token:{token}"))
    )
}

/// How the fake host judges a request: a repository whose name has `private` in it needs an
/// `Authorization` that is a token of this host (or the workspace's own `Bearer mine`); every
/// other path is public. `broken` makes it refuse every credential (a revoked token).
#[derive(Clone, Copy, Default)]
pub(crate) struct Host {
    pub(crate) revoked: bool,
}

impl Host {
    fn accepts(self, authorization: Option<&str>) -> bool {
        match authorization {
            Some("Bearer mine") => true,
            Some(value) => {
                !self.revoked && (value == token_basic(WORK) || value == token_basic(PERSONAL))
            }
            None => false,
        }
    }

    pub(crate) fn answer(self, method: &str, target: &str, authorization: Option<&str>) -> Answer {
        let path = target.split('?').next().unwrap_or_default();
        if path.contains("private") && !self.accepts(authorization) {
            return Answer::Unauthorized;
        }
        let service = target
            .split_once("service=")
            .map(|(_, rest)| rest.split('&').next().unwrap_or_default().to_owned());
        match (method, service) {
            ("GET", Some(service)) if path.ends_with("/info/refs") => Answer::Ok {
                content_type: format!("application/x-{service}-advertisement"),
                body: advert(&service),
            },
            _ => Answer::Ok {
                content_type: "text/plain".to_owned(),
                body: format!("{method} {path} ok"),
            },
        }
    }
}

pub(crate) enum Answer {
    Ok { content_type: String, body: String },
    Unauthorized,
}

impl Answer {
    fn reply(self) -> Reply {
        match self {
            Self::Ok { content_type, body } => Reply::raw(format!(
                "HTTP/1.1 200 OK\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\n\r\n{body}",
                body.len()
            )),
            Self::Unauthorized => Reply::status(
                401,
                "www-authenticate: Basic realm=\"fake git host\"\r\n",
                "Authentication required",
            ),
        }
    }
}

/// A workspace `box` with Work (owns `acme`) and Personal (the rest of `bound.test`), its own
/// repository `bound.test/acme/web` listed, an HTTP/1.1 Git host behind the rig.
pub(crate) struct GitRig {
    pub(crate) world: World,
    pub(crate) server: FakeServer,
    pub(crate) rig: Rig,
    /// The stand-in of `GH_TOKEN`, which the workspace holds and the proxy swaps for `REAL_SECRET`.
    pub(crate) stand_in: String,
}

impl GitRig {
    pub(crate) async fn new() -> Self {
        Self::with_host(Host::default()).await
    }

    pub(crate) async fn with_host(host: Host) -> Self {
        let world = Self::world();
        let pki = Pki::new();
        let server = FakeServer::tls(
            pki.server_config("bound.test", Flaw::None),
            Arc::new(move |request: &Recorded| {
                host.answer(
                    &request.method,
                    &request.target,
                    request.header("authorization"),
                )
                .reply()
            }),
        )
        .await;
        let (registry, stand_in) = stand_ins();
        let rig = RigBuilder::new(&pki)
            .name("bound.test", server.addr)
            .injector(world.injector.clone())
            .stand_ins(&registry)
            .build();
        Self {
            world,
            server,
            rig,
            stand_in,
        }
    }

    pub(crate) fn world() -> World {
        let world = World::new();
        world.identity("Work", "bound.test", &["acme"], false, WORK);
        world.identity("Personal", "bound.test", &[], true, PERSONAL);
        world.list("bound.test/acme/web", true, true);
        world
    }

    /// The events the injector raised since the last call.
    pub(crate) fn raised(&self) -> Vec<Event> {
        self.world.events.take()
    }
}

/// The same workspace behind an HTTP/2-only Git host.
pub(crate) struct H2GitRig {
    pub(crate) world: World,
    pub(crate) server: H2Server,
    pub(crate) rig: Rig,
    /// The stand-in of `GH_TOKEN`, which the workspace holds and the proxy swaps for `REAL_SECRET`.
    pub(crate) stand_in: String,
}

impl H2GitRig {
    pub(crate) async fn new(host: Host) -> Self {
        let world = GitRig::world();
        let pki = Pki::new();
        let script: Script = Arc::new(move |seen| {
            let authorization = seen.header("authorization");
            match host.answer(&seen.method, &seen.path, authorization) {
                Answer::Ok { content_type, body } => http::Response::builder()
                    .status(200)
                    .header("content-type", content_type)
                    .body(crate::terminate_support::h2_rig::full(body))
                    .unwrap(),
                Answer::Unauthorized => http::Response::builder()
                    .status(401)
                    .header("www-authenticate", "Basic realm=\"fake git host\"")
                    .body(crate::terminate_support::h2_rig::full(
                        "Authentication required",
                    ))
                    .unwrap(),
            }
        });
        let server = H2Server::recording(&pki, "bound.test", script).await;
        let (registry, stand_in) = stand_ins();
        let rig = RigBuilder::new(&pki)
            .name("bound.test", server.addr)
            .injector(world.injector.clone())
            .stand_ins(&registry)
            .build();
        Self {
            world,
            server,
            rig,
            stand_in,
        }
    }
}

/// The notice for a refused push or pull of `repo` (`owner/name` on `bound.test`).
pub(crate) fn denied(
    workspace: &puddle_types::WorkspaceName,
    repo: &str,
    access: GitAccess,
) -> Event {
    let (owner, name) = repo.split_once('/').unwrap();
    Event::GitAccessDenied {
        workspace: workspace.clone(),
        host: "bound.test".into(),
        owner: owner.into(),
        repo: name.into(),
        access,
    }
}
