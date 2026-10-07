// SPDX-License-Identifier: GPL-3.0-or-later
//! Discovery with faked OS answers: order of sources, per-epoch caching, PAC failure memory,
//! dead-proxy demotion and debounced change notification.

use std::ffi::OsString;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use puddle_upstream::{
    BypassList, Config, Destination, Discovery, EnvFallback, EnvOs, FakeOs, Hop, ManualProxy, Mode,
    PacError, ProxyAddr, ProxyConfig, ProxyRules, RouteSource, Scheme,
};

fn proxy(host: &str, port: u16) -> Hop {
    Hop::Proxy(ProxyAddr::new(host, port))
}

fn https(host: &str) -> Destination {
    Destination::new(Scheme::Https, host, 443)
}

fn env(pairs: &[(&str, &str)]) -> EnvOs {
    EnvOs::from_vars(
        pairs
            .iter()
            .map(|(k, v)| (OsString::from(k), OsString::from(v))),
    )
}

fn pac_settings() -> ProxyConfig {
    ProxyConfig {
        pac_url: Some("http://pac.corp/p.pac".into()),
        ..ProxyConfig::default()
    }
}

fn static_config(servers: &str, bypass: &str) -> ProxyConfig {
    ProxyConfig {
        rules: ProxyRules::parse(servers),
        bypass: BypassList::parse(bypass),
        ..ProxyConfig::default()
    }
}

/// Discovery over the fake OS with the environment behind it, as on Windows.
fn discovery(os: &Arc<FakeOs>, env: EnvOs, config: Config) -> Arc<Discovery> {
    Discovery::new(Arc::new(EnvFallback::new(os.clone(), env)), config)
}

#[tokio::test]
async fn loopback_goes_direct_without_asking_anyone() {
    let os = FakeOs::new(pac_settings());
    let d = discovery(&os, env(&[("HTTPS_PROXY", "p:1")]), Config::default());
    for host in ["localhost", "127.0.0.1", "::1"] {
        let decision = d.route(&https(host)).await;
        assert!(decision.route.is_direct());
        assert_eq!(decision.source, RouteSource::Loopback);
    }
    assert_eq!((os.config_calls(), os.pac_calls()), (0, 0));
}

#[tokio::test]
async fn pac_answer_is_the_route_and_a_direct_answer_is_final() {
    let os = FakeOs::new(ProxyConfig {
        rules: ProxyRules::parse("static:1"),
        ..pac_settings()
    });
    os.set_pac(|q| {
        assert_eq!(q.url, "https://github.com/");
        assert_eq!(q.pac_url.as_deref(), Some("http://pac.corp/p.pac"));
        Ok(vec![proxy("dead", 1), proxy("squid", 3128), Hop::Direct])
    });
    let d = discovery(&os, env(&[]), Config::default());
    let decision = d.route(&https("github.com")).await;
    assert_eq!(decision.source, RouteSource::Pac);
    assert_eq!(
        decision.route.to_string(),
        "PROXY dead:1; PROXY squid:3128; DIRECT"
    );

    os.set_pac(|_| Ok(vec![Hop::Direct]));
    let decision = d.route(&https("intranet.corp")).await;
    assert!(
        decision.route.is_direct(),
        "a PAC DIRECT does not fall through to the static proxy"
    );
    assert_eq!(decision.source, RouteSource::Pac);
}

#[tokio::test]
async fn auto_detect_asks_wpad_and_an_empty_answer_goes_direct() {
    let os = FakeOs::new(ProxyConfig {
        auto_detect: true,
        ..ProxyConfig::default()
    });
    os.set_pac(|q| {
        assert!(q.auto_detect && q.pac_url.is_none());
        Ok(vec![])
    });
    let d = discovery(&os, env(&[]), Config::default());
    let decision = d.route(&https("x.test")).await;
    assert_eq!(decision.source, RouteSource::PacUnsupported);
    assert!(decision.route.is_direct());
}

#[tokio::test]
async fn static_proxy_with_bypass_then_environment() {
    let os = FakeOs::new(static_config("http=a:1;https=b:2", "*.corp.test;<local>"));
    let d = discovery(&os, env(&[("HTTPS_PROXY", "e:5")]), Config::default());
    let d1 = d.route(&https("github.com")).await;
    assert_eq!(
        (d1.route.to_string(), d1.source),
        ("PROXY b:2".into(), RouteSource::System)
    );
    let d2 = d.route(&https("wiki.corp.test")).await;
    assert_eq!(
        (d2.route.is_direct(), d2.source),
        (true, RouteSource::Bypass)
    );
    let d3 = d.route(&Destination::new(Scheme::Http, "x.test", 80)).await;
    assert_eq!(d3.route.to_string(), "PROXY a:1");
    assert_eq!(
        d.route(&https("intranet")).await.source,
        RouteSource::Bypass
    );

    os.set_config(ProxyConfig::default());
    d.bump_epoch();
    let e = d.route(&https("x.test")).await;
    assert_eq!(
        (e.route.to_string(), e.source),
        ("PROXY e:5".into(), RouteSource::Env)
    );
    let none = discovery(
        &os,
        env(&[("NO_PROXY", "x.test"), ("HTTPS_PROXY", "e:5")]),
        Config::default(),
    );
    assert_eq!(
        none.route(&https("x.test")).await.source,
        RouteSource::Bypass
    );
    let nothing = discovery(&os, env(&[]), Config::default());
    assert_eq!(
        nothing.route(&https("x.test")).await.source,
        RouteSource::NoProxy
    );
}

#[tokio::test]
async fn the_environment_alone_is_the_unix_os_layer() {
    let vars = [
        ("HTTPS_PROXY", "http://u:pw@p.corp:3128"),
        ("HTTP_PROXY", "q:80"),
        ("NO_PROXY", "corp.test,10.0.0.0/8"),
    ];
    let d = Discovery::new(Arc::new(env(&vars)), Config::default());
    let via = d.route(&https("github.com")).await;
    assert_eq!(
        (via.route.to_string(), via.source),
        ("PROXY p.corp:3128".into(), RouteSource::Env)
    );
    assert_eq!(
        d.route(&Destination::new(Scheme::Http, "x.test", 80))
            .await
            .route
            .to_string(),
        "PROXY q:80"
    );
    assert_eq!(
        d.route(&https("git.corp.test")).await.source,
        RouteSource::Bypass
    );
    assert_eq!(
        d.route(&https("10.1.2.3")).await.source,
        RouteSource::Bypass
    );
    assert!(
        d.watch().is_none(),
        "no change notification from the environment"
    );
    let empty = Discovery::new(Arc::new(env(&[])), Config::default());
    assert_eq!(
        empty.route(&https("x.test")).await.source,
        RouteSource::NoProxy
    );
}

#[tokio::test]
async fn static_proxy_without_an_entry_for_the_scheme_goes_direct() {
    let os = FakeOs::new(static_config("https=b:2", ""));
    let d = discovery(&os, env(&[]), Config::default());
    let decision = d.route(&Destination::new(Scheme::Http, "x.test", 80)).await;
    assert!(decision.route.is_direct());
}

#[tokio::test]
async fn unreadable_settings_fall_back_to_the_environment() {
    let os = FakeOs::new(ProxyConfig::default());
    os.fail_config("boom");
    let d = discovery(&os, env(&[("HTTPS_PROXY", "e:5")]), Config::default());
    assert_eq!(d.route(&https("x.test")).await.source, RouteSource::Env);
    let bare = Discovery::new(os.clone(), Config::default());
    assert_eq!(
        bare.route(&https("x.test")).await.source,
        RouteSource::NoProxy
    );
}

#[tokio::test]
async fn modes_direct_and_manual_ignore_the_system() {
    let os = FakeOs::new(pac_settings());
    let direct = discovery(
        &os,
        env(&[("HTTPS_PROXY", "e:5")]),
        Config {
            mode: Mode::Direct,
            ..Config::default()
        },
    );
    assert_eq!(
        direct.route(&https("x.test")).await.source,
        RouteSource::Disabled
    );
    let manual = Mode::Manual(ManualProxy {
        proxy_server: "man:3128".into(),
        bypass: "*.corp.test".into(),
    });
    let d = discovery(
        &os,
        env(&[]),
        Config {
            mode: manual,
            ..Config::default()
        },
    );
    assert_eq!(
        d.route(&https("x.test")).await.route.to_string(),
        "PROXY man:3128"
    );
    assert_eq!(d.route(&https("x.test")).await.source, RouteSource::Manual);
    assert_eq!(
        d.route(&https("a.corp.test")).await.source,
        RouteSource::Bypass
    );
    assert_eq!((os.config_calls(), os.pac_calls()), (0, 0));
}

#[tokio::test]
async fn decisions_are_cached_per_destination_until_the_epoch_ends() {
    let os = FakeOs::new(pac_settings());
    let d = discovery(&os, env(&[]), Config::default());
    for _ in 0..5 {
        d.route(&https("a.test")).await;
    }
    d.route(&https("b.test")).await;
    assert_eq!(os.pac_calls(), 2);
    assert_eq!(os.config_calls(), 1);
    let before = d.epoch();
    d.bump_epoch();
    assert_eq!(d.epoch(), before + 1);
    d.route(&https("a.test")).await;
    assert_eq!((os.pac_calls(), os.config_calls()), (3, 2));
}

#[tokio::test]
async fn a_hundred_parallel_connections_share_one_pac_lookup() {
    let os = FakeOs::new(pac_settings());
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    os.set_pac(move |_| {
        counter.fetch_add(1, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(50));
        Ok(vec![proxy("squid", 3128)])
    });
    let d = discovery(&os, env(&[]), Config::default());
    let mut tasks = Vec::new();
    for _ in 0..100 {
        let d = Arc::clone(&d);
        tasks.push(tokio::spawn(async move {
            d.route(&https("registry.npmjs.org")).await
        }));
    }
    for task in tasks {
        assert_eq!(task.await.unwrap().route.to_string(), "PROXY squid:3128");
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn wpad_failure_is_remembered_for_every_host_then_retried() {
    let os = FakeOs::new(ProxyConfig {
        auto_detect: true,
        ..ProxyConfig::default()
    });
    os.set_pac(|_| Err(PacError::Unavailable("12180".into())));
    let d = discovery(&os, env(&[("HTTPS_PROXY", "e:5")]), Config::default());
    for host in ["a.test", "b.test", "c.test", "a.test"] {
        let decision = d.route(&https(host)).await;
        assert_eq!(
            decision.source,
            RouteSource::Env,
            "falls back, does not fail"
        );
    }
    assert_eq!(
        os.pac_calls(),
        1,
        "one failed lookup per outage, not one per host"
    );
    tokio::time::advance(Duration::from_secs(61)).await;
    os.set_pac(|_| Ok(vec![proxy("squid", 3128)]));
    let decision = d.route(&https("a.test")).await;
    assert_eq!(
        decision.source,
        RouteSource::Pac,
        "retried after pac_retry, and the outage answer was not cached"
    );
    assert_eq!(os.pac_calls(), 2);
}

#[tokio::test(start_paused = true)]
async fn a_new_epoch_retries_a_failed_wpad_at_once() {
    let os = FakeOs::new(ProxyConfig {
        auto_detect: true,
        ..ProxyConfig::default()
    });
    os.set_pac(|_| Err(PacError::Timeout));
    let d = discovery(&os, env(&[]), Config::default());
    d.route(&https("a.test")).await;
    d.route(&https("b.test")).await;
    assert_eq!(os.pac_calls(), 1);
    d.bump_epoch();
    d.route(&https("a.test")).await;
    assert_eq!(os.pac_calls(), 2);
}

#[tokio::test]
async fn a_pac_hang_is_cut_off_at_the_timeout() {
    let os = FakeOs::new(pac_settings());
    os.set_pac(|_| {
        std::thread::sleep(Duration::from_millis(400));
        Ok(vec![proxy("late", 1)])
    });
    let config = Config {
        pac_timeout: Duration::from_millis(50),
        ..Config::default()
    };
    let d = discovery(&os, env(&[("HTTPS_PROXY", "e:5")]), config);
    let decision = d.route(&https("x.test")).await;
    assert_eq!(decision.source, RouteSource::Env);
}

#[tokio::test]
async fn a_failure_for_one_destination_is_cached_for_it_only() {
    let os = FakeOs::new(pac_settings());
    os.set_pac(|q| {
        if q.url.contains("bad.test") {
            Err(PacError::Failed("script error".into()))
        } else {
            Ok(vec![proxy("squid", 3128)])
        }
    });
    let d = discovery(&os, env(&[]), Config::default());
    assert_eq!(
        d.route(&https("bad.test")).await.source,
        RouteSource::NoProxy
    );
    assert_eq!(
        d.route(&https("bad.test")).await.source,
        RouteSource::NoProxy
    );
    assert_eq!(d.route(&https("good.test")).await.source, RouteSource::Pac);
    assert_eq!(os.pac_calls(), 2);
}

#[tokio::test(start_paused = true)]
async fn a_dead_proxy_moves_back_for_the_ttl_and_is_never_dropped() {
    let os = FakeOs::new(pac_settings());
    os.set_pac(|_| Ok(vec![proxy("dead", 1), proxy("squid", 3128), Hop::Direct]));
    let d = discovery(&os, env(&[]), Config::default());
    assert_eq!(
        d.route(&https("a.test")).await.route.to_string(),
        "PROXY dead:1; PROXY squid:3128; DIRECT"
    );
    d.report_failure(&ProxyAddr::new("dead", 1));
    assert_eq!(
        d.route(&https("a.test")).await.route.to_string(),
        "PROXY squid:3128; DIRECT; PROXY dead:1"
    );
    assert_eq!(d.route(&https("other.test")).await.route.hops().len(), 3);
    tokio::time::advance(Duration::from_secs(301)).await;
    assert_eq!(
        d.route(&https("a.test")).await.route.to_string(),
        "PROXY dead:1; PROXY squid:3128; DIRECT"
    );
    d.report_failure(&ProxyAddr::new("dead", 1));
    d.bump_epoch();
    assert_eq!(
        d.route(&https("a.test")).await.route.hops().first(),
        Some(&proxy("dead", 1)),
        "a network change forgives"
    );
}

#[tokio::test(start_paused = true)]
async fn change_notifications_are_debounced_into_one_epoch() {
    let os = FakeOs::new(pac_settings());
    let d = discovery(&os, env(&[]), Config::default());
    let mut epochs = d.subscribe();
    let watching = d.watch().expect("fake can watch");
    assert!(os.is_watched());
    d.route(&https("a.test")).await;
    // A proxy client that flaps the setting ten times in a second:
    for _ in 0..10 {
        assert!(os.fire_change());
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(d.epoch(), 0, "still inside the quiet period");
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(d.epoch(), 1, "ten changes, one epoch");
    assert!(epochs.has_changed().unwrap());
    assert_eq!(*epochs.borrow_and_update(), 1);
    d.route(&https("a.test")).await;
    assert_eq!(os.pac_calls(), 2, "the decision was forgotten");
    drop(watching);
    assert!(!os.is_watched());
    assert!(!os.fire_change());
}

#[tokio::test]
async fn without_os_watch_support_watch_is_none() {
    let os = FakeOs::without_watch(ProxyConfig::default());
    let d = discovery(&os, env(&[]), Config::default());
    assert!(d.watch().is_none());
}

#[tokio::test]
async fn the_default_discovery_works_on_this_platform() {
    let d = Discovery::system();
    let decision = d.route(&https("localhost")).await;
    assert_eq!(decision.source, RouteSource::Loopback);
    assert_eq!(Hop::Direct.proxy(), None);
    assert_eq!(proxy("a", 1).proxy(), Some(&ProxyAddr::new("a", 1)));
}
