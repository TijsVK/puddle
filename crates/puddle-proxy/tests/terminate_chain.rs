// SPDX-License-Identifier: GPL-3.0-or-later
//! I tests of the upstream leg of a terminated connection through a company proxy: the proxy
//! gets `CONNECT <name>:443` (and the `407` answer on the same connection), the TLS handshake
//! with the real server runs inside that tunnel and is verified exactly as without a proxy.
mod terminate_support;

use std::sync::Arc;
use std::time::Duration;

use puddle_proxy::Upstream;
use puddle_upstream::{
    AuthError, AuthSession, AuthStep, BasicAuth, Behaviour, Chain, ChainConfig, Config,
    Credentials, Discovery, FakeOs, FakeProxy, Hop, ProxyAddr, ProxyAuth, ProxyConfig,
};
use terminate_support::{CANARY, FakeServer, Flaw, Pki, Reply, RigBuilder};

fn through(proxy: &FakeProxy, user: &str, password: &str) -> Upstream {
    through_with(
        proxy,
        Arc::new(BasicAuth::new().with_default(Credentials::new(user, password))),
    )
}

fn through_with(proxy: &FakeProxy, auth: Arc<dyn ProxyAuth>) -> Upstream {
    let os = FakeOs::new(ProxyConfig {
        pac_url: Some("http://pac.corp/p.pac".into()),
        ..ProxyConfig::default()
    });
    let hops = vec![Hop::Proxy(proxy.proxy_addr())];
    os.set_pac(move |_| Ok(hops.clone()));
    let config = ChainConfig::default()
        .with_timeouts(Duration::from_millis(500), Duration::from_millis(400));
    Upstream::new(Chain::with_config(
        Discovery::new(os, Config::default()),
        auth,
        config,
    ))
}

#[tokio::test]
async fn a_terminated_connection_goes_through_a_basic_company_proxy_by_name() {
    let pki = Pki::new();
    let server = FakeServer::tls(
        pki.server_config("bound.test", Flaw::None),
        Arc::new(|_| Reply::ok("via the company proxy")),
    )
    .await;
    let proxy = FakeProxy::start(Behaviour::Basic {
        user: "corp".into(),
        password: "proxy-pw".into(),
    })
    .await;
    proxy.resolve_name("bound.test", server.addr);
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .via(through(&proxy, "corp", "proxy-pw"))
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.tls("bound.test:443", None).await.unwrap();
    let response = client.get("bound.test", "/x").await;
    assert_eq!(response.status, 200);
    assert_eq!(response.text(), "via the company proxy");

    let seen = proxy.seen();
    assert!(
        seen.iter()
            .any(|s| s.method == "CONNECT" && s.target == "bound.test:443"),
        "{seen:?}"
    );
    assert!(
        seen.iter().any(|s| s.proxy_authorization.is_some()),
        "the 407 was answered"
    );
    // The injected header travels inside the tunnel only; the company proxy never sees it.
    assert!(
        seen.iter()
            .all(|s| s.headers.iter().all(|(_, v)| !v.contains(CANARY))),
        "{seen:?}"
    );
    assert_eq!(
        server.recorded()[0].headers_named("authorization"),
        [format!("Basic {CANARY}")]
    );
}

#[tokio::test]
async fn a_bad_certificate_behind_the_company_proxy_is_still_a_502_with_nothing_sent() {
    let pki = Pki::new();
    let server = FakeServer::tls(
        pki.server_config("bound.test", Flaw::UnknownRoot),
        Arc::new(|_| Reply::ok("never")),
    )
    .await;
    let proxy = FakeProxy::start(Behaviour::Open).await;
    proxy.resolve_name("bound.test", server.addr);
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .via(through(&proxy, "u", "p"))
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.tls("bound.test:443", None).await.unwrap();
    let response = client.get("bound.test", "/x").await;
    assert_eq!(response.status, 502);
    assert!(server.recorded().is_empty());
}

#[tokio::test]
async fn a_company_proxy_that_refuses_the_tunnel_has_its_refusal_passed_on_and_nothing_is_injected()
{
    let pki = Pki::new();
    let server = FakeServer::tls(
        pki.server_config("bound.test", Flaw::None),
        Arc::new(|_| Reply::ok("never")),
    )
    .await;
    let proxy = FakeProxy::start(Behaviour::Refuse(403)).await;
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .via(through(&proxy, "u", "p"))
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.tls("bound.test:443", None).await.unwrap();
    let response = client.get("bound.test", "/x").await;
    // The company proxy's own refusal, as on a spliced tunnel.
    assert_eq!(response.status, 403);
    assert!(server.recorded().is_empty());
}

/// A scripted NTLM client (the Windows build uses SSPI behind the same seam).
#[derive(Debug)]
struct NtlmAuth;

#[derive(Debug)]
struct NtlmSession;

impl AuthSession for NtlmSession {
    fn step(&mut self, challenge: Option<&str>) -> Result<AuthStep, AuthError> {
        match challenge.map(str::trim) {
            Some("NTLM") => Ok(AuthStep::Authorization("NTLM T1".into())),
            Some("NTLM CHALLENGE") => Ok(AuthStep::Authorization("NTLM T3".into())),
            other => Err(AuthError::Failed(format!("unexpected challenge {other:?}"))),
        }
    }
}

impl ProxyAuth for NtlmAuth {
    fn begin(
        &self,
        _proxy: &ProxyAddr,
        offered: &[&str],
    ) -> Result<Option<Box<dyn AuthSession>>, AuthError> {
        Ok(offered
            .iter()
            .any(|s| s.eq_ignore_ascii_case("ntlm"))
            .then(|| Box::new(NtlmSession) as Box<dyn AuthSession>))
    }
}

#[tokio::test]
async fn a_terminated_connection_signs_in_to_an_ntlm_company_proxy_on_one_connection() {
    let pki = Pki::new();
    let server = FakeServer::tls(
        pki.server_config("bound.test", Flaw::None),
        Arc::new(|_| Reply::ok("via ntlm")),
    )
    .await;
    let proxy = FakeProxy::start(Behaviour::Ntlm).await;
    proxy.resolve_name("bound.test", server.addr);
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .via(through_with(&proxy, Arc::new(NtlmAuth)))
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.tls("bound.test:443", None).await.unwrap();
    let response = client.get("bound.test", "/x").await;
    assert_eq!(response.status, 200);
    assert_eq!(response.text(), "via ntlm");
    assert_eq!(proxy.connections(), 1, "three legs, one connection");
}

#[tokio::test]
async fn http2_runs_end_to_end_inside_the_company_proxy_tunnel() {
    use terminate_support::h2_rig::{H2Server, Script, full, reply};
    let pki = Pki::new();
    let script: Script = Arc::new(|_| reply(200, "h2 via the company proxy"));
    let server = H2Server::recording(&pki, "bound.test", script).await;
    let proxy = FakeProxy::start(Behaviour::Basic {
        user: "corp".into(),
        password: "proxy-pw".into(),
    })
    .await;
    proxy.resolve_name("bound.test", server.addr);
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .via(through(&proxy, "corp", "proxy-pw"))
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.h2("bound.test:443", &[b"h2", b"http/1.1"]).await;
    let mut tasks = Vec::new();
    for i in 0..20 {
        let mut sender = client.sender.clone();
        tasks.push(tokio::spawn(async move {
            let request = http::Request::builder()
                .uri(format!("https://bound.test/n/{i}"))
                .body(full(bytes::Bytes::new()))
                .unwrap();
            terminate_support::h2_rig::collect(sender.send_request(request).await.unwrap()).await
        }));
    }
    for task in tasks {
        let got = task.await.unwrap();
        assert_eq!(got.status, 200);
        assert_eq!(got.text(), "h2 via the company proxy");
    }
    let _ = &mut client;
    assert_eq!(proxy.connections(), 1, "twenty streams, one tunnel");
    let seen = proxy.seen();
    assert!(
        seen.iter()
            .any(|s| s.method == "CONNECT" && s.target == "bound.test:443"),
        "{seen:?}"
    );
    assert!(
        seen.iter()
            .all(|s| s.headers.iter().all(|(_, v)| !v.contains(CANARY))),
        "the credential travels inside the tunnel only"
    );
    assert_eq!(
        server.recorded()[0].headers_named("authorization"),
        [format!("Basic {CANARY}")]
    );
}

#[tokio::test]
async fn an_h2_guest_over_an_http11_server_behind_a_company_proxy_uses_a_few_tunnels() {
    use terminate_support::h2_rig::{collect, full};
    let pki = Pki::new();
    let server = FakeServer::tls(
        pki.server_config("bound.test", Flaw::None),
        Arc::new(|r| Reply::ok(&format!("h1 {}", r.target)).after(Duration::from_millis(50))),
    )
    .await;
    let proxy = FakeProxy::start(Behaviour::Open).await;
    proxy.resolve_name("bound.test", server.addr);
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .via(through(&proxy, "u", "p"))
        .build();
    let mut guest = rig.guest().await;
    let client = guest.h2("bound.test:443", &[b"h2"]).await;
    let mut tasks = Vec::new();
    for i in 0..40 {
        let mut sender = client.sender.clone();
        tasks.push(tokio::spawn(async move {
            let request = http::Request::builder()
                .uri(format!("https://bound.test/n/{i}"))
                .body(full(bytes::Bytes::new()))
                .unwrap();
            collect(sender.send_request(request).await.unwrap()).await
        }));
    }
    for (i, task) in tasks.into_iter().enumerate() {
        assert_eq!(task.await.unwrap().text(), format!("h1 /n/{i}"));
    }
    let tunnels = proxy.connections();
    assert!(
        (2..=8).contains(&tunnels),
        "{tunnels} tunnels for 40 streams"
    );
}
