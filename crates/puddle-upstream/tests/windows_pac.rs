// SPDX-License-Identifier: GPL-3.0-or-later
//! Windows only (T-134): the real WinHTTP engine against a local PAC server, and the registry
//! path end to end. The registry tests edit the *current user's* Internet Settings, so they run
//! only where `GITHUB_ACTIONS` is set (a throwaway runner), never on a developer's machine.
#![cfg(windows)]
#![expect(
    clippy::unwrap_used,
    clippy::print_stderr,
    reason = "test helpers outside #[test] functions; a panic is how they fail"
)]

use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use puddle_upstream::{
    Config, Destination, Discovery, EnvFallback, EnvOs, Hop, OsProxy, PacError, PacQuery,
    ProxyAddr, RouteSource, Scheme, WinOs,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const PAC: &str = r#"function FindProxyForURL(url, host) {
  if (dnsDomainIs(host, ".corp.test")) return "DIRECT";
  if (shExpMatch(host, "github.*")) return "PROXY 127.0.0.1:1; PROXY 127.0.0.1:3128; DIRECT";
  if (url.substring(0, 5) == "http:") return "PROXY 127.0.0.1:8080";
  return "PROXY 127.0.0.1:3128";
}
"#;

/// Serves `PAC` on a loopback port until the runtime ends. Returns the PAC URL.
async fn pac_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/proxy.pac", listener.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let _ = stream.read(&mut buf).await; // the request line and headers are not needed
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{PAC}",
                    PAC.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });
    url
}

fn query(pac_url: &str, url: &str) -> PacQuery {
    PacQuery {
        pac_url: Some(pac_url.into()),
        auto_detect: false,
        url: url.into(),
        timeout: Duration::from_secs(20),
    }
}

async fn resolve(q: PacQuery) -> Result<Vec<Hop>, PacError> {
    tokio::task::spawn_blocking(move || WinOs::new().resolve_pac(&q))
        .await
        .unwrap()
}

fn proxy(port: u16) -> Hop {
    Hop::Proxy(ProxyAddr::new("127.0.0.1", port))
}

#[tokio::test(flavor = "multi_thread")]
async fn winhttp_evaluates_a_local_pac_per_url_with_the_full_failover_list() {
    let pac = pac_server().await;
    assert_eq!(
        resolve(query(&pac, "https://github.com/")).await.unwrap(),
        vec![proxy(1), proxy(3128), Hop::Direct]
    );
    assert_eq!(
        resolve(query(&pac, "https://wiki.corp.test/"))
            .await
            .unwrap(),
        vec![Hop::Direct]
    );
    assert_eq!(
        resolve(query(&pac, "https://registry.npmjs.org/"))
            .await
            .unwrap(),
        vec![proxy(3128)]
    );
    assert_eq!(
        resolve(query(&pac, "http://deb.debian.org/"))
            .await
            .unwrap(),
        vec![proxy(8080)]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unreachable_pac_is_an_error_not_a_hang() {
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/proxy.pac", closed.local_addr().unwrap());
    drop(closed);
    let started = std::time::Instant::now();
    let err = resolve(query(&url, "https://github.com/"))
        .await
        .unwrap_err();
    eprintln!("unreachable PAC gave: {err}");
    assert!(matches!(
        err,
        PacError::Unavailable(_) | PacError::Timeout | PacError::Failed(_)
    ));
    assert!(started.elapsed() < Duration::from_secs(25));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_pac_server_that_never_answers_times_out_at_the_query_timeout() {
    let silent = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/proxy.pac", silent.local_addr().unwrap());
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = silent.accept().await {
            held.push(stream);
        }
    });
    let mut q = query(&url, "https://github.com/");
    q.timeout = Duration::from_secs(2);
    let started = std::time::Instant::now();
    let err = resolve(q).await.unwrap_err();
    assert!(
        matches!(err, PacError::Timeout | PacError::Unavailable(_)),
        "{err}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn parallel_pac_lookups_all_answer() {
    let pac = pac_server().await;
    let mut tasks = Vec::new();
    for i in 0..24 {
        let pac = pac.clone();
        tasks.push(tokio::spawn(async move {
            resolve(query(&pac, &format!("https://host{i}.example/"))).await
        }));
    }
    for task in tasks {
        assert_eq!(task.await.unwrap().unwrap(), vec![proxy(3128)]);
    }
}

#[test]
fn the_settings_call_works_on_any_machine_and_never_panics() {
    let settings = WinOs::new().config().unwrap();
    eprintln!(
        "auto_detect={} pac={} static={}",
        settings.auto_detect,
        settings.pac_url.is_some(),
        !settings.rules.is_empty()
    );
}

// --- registry tests: throwaway runners only ---------------------------------------------------

const KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";

fn on_throwaway_runner() -> bool {
    let yes = std::env::var_os("GITHUB_ACTIONS").is_some();
    if !yes {
        eprintln!(
            "skipped: edits HKCU Internet Settings, only run on a CI runner (GITHUB_ACTIONS)"
        );
    }
    yes
}

fn reg(args: &[&str]) -> bool {
    Command::new("reg")
        .args(args)
        .output()
        .unwrap()
        .status
        .success()
}

/// Puts one value in the Internet Settings key and puts the old state back on drop.
struct RegValue {
    name: &'static str,
    existed: bool,
}

impl RegValue {
    fn set(name: &'static str, kind: &str, data: &str) -> Self {
        let existed = reg(&["query", KEY, "/v", name]);
        assert!(
            reg(&["add", KEY, "/v", name, "/t", kind, "/d", data, "/f"]),
            "reg add {name}"
        );
        Self { name, existed }
    }
}

impl Drop for RegValue {
    fn drop(&mut self) {
        // A value that existed before is left as the test set it: runners are throwaway, and
        // restoring would need its old data and type.
        if !self.existed {
            let _ = reg(&["delete", KEY, "/v", self.name, "/f"]);
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn settings_and_discovery_follow_the_registry_end_to_end() {
    if !on_throwaway_runner() {
        return;
    }
    let pac = pac_server().await;
    let _url = RegValue::set("AutoConfigURL", "REG_SZ", &pac);
    let settings = WinOs::new().config().unwrap();
    assert_eq!(settings.pac_url.as_deref(), Some(pac.as_str()));

    let discovery = Discovery::new(
        Arc::new(EnvFallback::new(Arc::new(WinOs::new()), EnvOs::default())),
        Config::default(),
    );
    let decision = discovery
        .route(&Destination::new(Scheme::Https, "github.com", 443))
        .await;
    assert_eq!(decision.source, RouteSource::Pac);
    assert_eq!(
        decision.route.to_string(),
        "PROXY 127.0.0.1:1; PROXY 127.0.0.1:3128; DIRECT"
    );
    let direct = discovery
        .route(&Destination::new(Scheme::Https, "wiki.corp.test", 443))
        .await;
    assert!(direct.route.is_direct());
}

#[tokio::test(flavor = "multi_thread")]
async fn the_proxy_enable_switch_hides_a_static_proxy() {
    if !on_throwaway_runner() {
        return;
    }
    let _server = RegValue::set("ProxyServer", "REG_SZ", "static.corp:3128");
    let _bypass = RegValue::set("ProxyOverride", "REG_SZ", "*.corp.test;<local>");
    let _on = RegValue::set("ProxyEnable", "REG_DWORD", "1");
    let on = WinOs::new().config().unwrap();
    assert_eq!(
        on.rules.for_scheme(Scheme::Https),
        Some(&ProxyAddr::new("static.corp", 3128))
    );
    assert!(
        on.bypass
            .matches(&Destination::new(Scheme::Https, "wiki.corp.test", 443))
    );
    assert!(
        on.bypass
            .matches(&Destination::new(Scheme::Https, "intranet", 443))
    );
    assert!(reg(&[
        "add",
        KEY,
        "/v",
        "ProxyEnable",
        "/t",
        "REG_DWORD",
        "/d",
        "0",
        "/f"
    ]));
    let off = WinOs::new().config().unwrap();
    assert!(off.rules.is_empty(), "ProxyEnable=0 means no static proxy");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_registry_change_ends_the_epoch_once_after_the_debounce() {
    if !on_throwaway_runner() {
        return;
    }
    let config = Config {
        debounce: Duration::from_millis(300),
        ..Config::default()
    };
    let discovery = Discovery::new(
        Arc::new(EnvFallback::new(Arc::new(WinOs::new()), EnvOs::default())),
        config,
    );
    let mut epochs = discovery.subscribe();
    let watching = discovery
        .watch()
        .expect("the registry watch is available on every Windows");
    let before = discovery.epoch();
    let _flap: Vec<_> = (0..5)
        .map(|i| RegValue::set("ProxyServer", "REG_SZ", &format!("flap{i}.corp:3128")))
        .collect();
    tokio::time::timeout(Duration::from_secs(30), epochs.changed())
        .await
        .expect("an epoch change")
        .unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;
    let after = discovery.epoch();
    assert!(after > before, "epoch {before} -> {after}");
    assert!(
        after <= before + 2,
        "five quick edits must not give five epochs: {before} -> {after}"
    );
    drop(watching);
}
