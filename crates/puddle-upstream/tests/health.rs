// SPDX-License-Identifier: GPL-3.0-or-later
//! What discovery reports about itself for the network-health page, over faked OS answers.

use std::ffi::OsString;
use std::sync::Arc;
use std::time::Duration;

use puddle_upstream::{
    BypassList, Config, Destination, Detected, Discovery, EnvFallback, EnvOs, FakeOs, Hop,
    ManualProxy, Mode, ModeKind, Origin, PacError, ProxyAddr, ProxyConfig, ProxyProblem,
    ProxyProblemKind, ProxyRules, RouteSource, Scheme,
};

fn https(host: &str) -> Destination {
    Destination::new(Scheme::Https, host, 443)
}

fn discovery(config: ProxyConfig) -> (Arc<FakeOs>, Arc<Discovery>) {
    let os = FakeOs::new(config);
    let d = Discovery::new(os.clone(), Config::default());
    (os, d)
}

#[tokio::test]
async fn a_pac_setup_is_reported_with_a_cleaned_address_and_the_routes_it_gave() {
    let (os, d) = discovery(ProxyConfig {
        pac_url: Some("http://svc:hunter2@pac.corp/p.pac?key=topsecret#x".into()),
        ..ProxyConfig::default()
    });
    let corp = ProxyAddr::new("proxy.corp", 8080);
    let answer = corp.clone();
    os.set_pac(move |_| Ok(vec![Hop::Proxy(answer.clone()), Hop::Direct]));
    let before = d.health().await;
    assert_eq!(before.detected, Detected::Pac);
    assert_eq!(before.mode, ModeKind::System);
    assert_eq!(before.pac_reachable, None, "nothing asked yet");
    assert_eq!(before.routes.len(), 0);

    d.route(&https("b.example")).await;
    d.route(&https("a.example")).await;
    let health = d.health().await;
    assert_eq!(health.pac_url.as_deref(), Some("http://pac.corp/p.pac"));
    assert_eq!(health.pac_reachable, Some(true));
    let hosts: Vec<_> = health.routes.iter().map(|r| r.destination.host()).collect();
    assert_eq!(hosts, ["a.example", "b.example"], "sorted by host");
    assert_eq!(health.routes[0].route.hops()[0], Hop::Proxy(corp));
    assert_eq!(health.changed_at, None, "the network has not changed yet");
    let shown = format!("{health:?}");
    assert!(
        !shown.contains("hunter2") && !shown.contains("topsecret"),
        "{shown}"
    );
}

#[tokio::test]
async fn an_unreachable_pac_is_reported_and_wpad_alone_is_wpad() {
    let (os, d) = discovery(ProxyConfig {
        auto_detect: true,
        rules: ProxyRules::parse("fallback.corp:3128"),
        bypass: BypassList::parse("*.corp;<local>"),
        ..ProxyConfig::default()
    });
    os.set_pac(|_| Err(PacError::Unavailable("no wpad.dat".into())));
    d.route(&https("x.example")).await;
    let health = d.health().await;
    assert_eq!(health.detected, Detected::Wpad);
    assert!(health.auto_detect);
    assert_eq!(health.pac_url, None);
    assert_eq!(health.pac_reachable, Some(false));
    assert_eq!(
        health.https_proxy,
        Some(ProxyAddr::new("fallback.corp", 3128))
    );
    assert_eq!(health.bypass_entries, 2);
}

#[tokio::test]
async fn static_env_and_direct_are_told_apart() {
    let (_, d) = discovery(ProxyConfig {
        rules: ProxyRules::parse("http=h.corp:80;https=s.corp:443"),
        ..ProxyConfig::default()
    });
    let health = d.health().await;
    assert_eq!(health.detected, Detected::Static);
    assert_eq!(health.http_proxy, Some(ProxyAddr::new("h.corp", 80)));
    assert_eq!(health.https_proxy, Some(ProxyAddr::new("s.corp", 443)));

    let env = EnvOs::from_vars([(
        OsString::from("HTTPS_PROXY"),
        OsString::from("http://u:pw-in-env@e.corp:3128"),
    )]);
    let d = Discovery::new(Arc::new(env), Config::default());
    let health = d.health().await;
    assert_eq!(health.detected, Detected::Env);
    assert_eq!(health.https_proxy, Some(ProxyAddr::new("e.corp", 3128)));
    assert!(!format!("{health:?}").contains("pw-in-env"));

    let (_, d) = discovery(ProxyConfig::default());
    assert_eq!(d.health().await.detected, Detected::Direct);
}

#[tokio::test]
async fn unreadable_settings_are_reported_as_the_reason_for_going_direct() {
    let os = FakeOs::new(ProxyConfig::default());
    os.fail_config("registry access denied");
    let d = Discovery::new(os, Config::default());
    let health = d.health().await;
    assert_eq!(health.detected, Detected::Direct);
    assert!(
        health
            .settings_error
            .unwrap()
            .contains("registry access denied")
    );
}

#[tokio::test]
async fn puddles_own_modes_are_reported_as_such() {
    let os = FakeOs::new(ProxyConfig {
        pac_url: Some("http://ignored/p.pac".into()),
        ..ProxyConfig::default()
    });
    let manual = Discovery::new(
        os.clone(),
        Config {
            mode: Mode::Manual(ManualProxy {
                proxy_server: "user:pw-manual@m.corp:8080".into(),
                bypass: "*.local".into(),
            }),
            ..Config::default()
        },
    );
    let health = manual.health().await;
    assert_eq!(health.mode, ModeKind::Manual);
    assert_eq!(health.detected, Detected::Static);
    assert_eq!(health.pac_url, None, "the system's PAC is ignored");
    assert_eq!(health.https_proxy, Some(ProxyAddr::new("m.corp", 8080)));
    assert!(!format!("{health:?}").contains("pw-manual"));
    assert_eq!(os.config_calls(), 0);

    let direct = Discovery::new(
        os,
        Config {
            mode: Mode::Direct,
            ..Config::default()
        },
    );
    let health = direct.health().await;
    assert_eq!(
        (health.mode, health.detected),
        (ModeKind::Direct, Detected::Direct)
    );
}

#[tokio::test(start_paused = true)]
async fn dead_proxies_and_the_last_network_change_are_reported() {
    let (_, d) = discovery(ProxyConfig {
        rules: ProxyRules::parse("p.corp:80"),
        ..ProxyConfig::default()
    });
    let dead = ProxyAddr::new("p.corp", 80);
    d.report_failure(&dead);
    let health = d.health().await;
    assert_eq!(health.dead.len(), 1);
    assert_eq!(health.dead[0].proxy, dead);
    assert!(health.dead[0].retry_in <= Duration::from_secs(300));
    assert!(health.dead[0].retry_in > Duration::from_secs(290));
    assert_eq!(health.epoch, 0);

    d.bump_epoch();
    let health = d.health().await;
    assert_eq!(health.epoch, 1);
    assert!(health.changed_at.is_some());
    assert!(health.dead.is_empty(), "a new epoch forgets dead marks");
    assert_eq!(health.routes.len(), 0);
}

#[tokio::test]
async fn a_proxy_typed_into_puddles_settings_that_cannot_be_used_is_reported_not_just_bypassed() {
    for (typed, mentions) in [
        ("socks5://corp-socks:1080", "socks5"),
        ("proxy.corp:eighty", "eighty"),
        ("  ", "empty"),
    ] {
        let d = Discovery::new(
            FakeOs::new(ProxyConfig::default()),
            Config {
                mode: Mode::Manual(ManualProxy {
                    proxy_server: typed.into(),
                    bypass: String::new(),
                }),
                ..Config::default()
            },
        );
        let decision = d.route(&https("github.com")).await;
        assert_eq!(decision.route.to_string(), "DIRECT", "{typed}");
        assert_eq!(decision.source, RouteSource::Manual, "{typed}");
        let health = d.health().await;
        assert_eq!(health.mode, ModeKind::Manual);
        assert_eq!(health.problems.len(), 1, "{typed}: {:?}", health.problems);
        assert_eq!(health.problems[0].kind, ProxyProblemKind::UnusableSetting);
        assert!(
            health.problems[0].detail.contains("puddle's settings")
                && health.problems[0].detail.contains(mentions),
            "{typed}: {:?}",
            health.problems
        );
    }
    let fine = Discovery::new(
        FakeOs::new(ProxyConfig::default()),
        Config {
            mode: Mode::Manual(ManualProxy {
                proxy_server: "http=a:1;https=b:2;socks=s:3".into(),
                bypass: String::new(),
            }),
            ..Config::default()
        },
    );
    assert_eq!(fine.health().await.problems, vec![]);
}

#[tokio::test]
async fn what_the_os_layer_could_not_use_is_in_the_report_without_credentials() {
    let (_, d) = discovery(ProxyConfig {
        rules: ProxyRules::parse("http=h:80"),
        problems: vec![ProxyProblem::unusable(
            "the HTTPS_PROXY variable (\"socks5://p:1080\"): unsupported proxy scheme, token Basic dXNlcjpwYXNzd29yZA==",
        )],
        ..ProxyConfig::default()
    });
    let health = d.health().await;
    assert_eq!(health.problems.len(), 1);
    assert!(health.problems[0].detail.contains("HTTPS_PROXY"));
    assert!(
        !health.problems[0].detail.contains("dXNlcjpwYXNzd29yZA"),
        "{:?}",
        health.problems
    );
    let (_, plain) = discovery(ProxyConfig::default());
    assert_eq!(plain.health().await.problems, vec![]);
}

#[tokio::test]
async fn a_system_layer_replaced_by_the_environment_still_shows_why() {
    let os = FakeOs::new(ProxyConfig::default());
    os.fail_config("registry access denied");
    let env = EnvOs::from_vars([(
        OsString::from("HTTPS_PROXY"),
        OsString::from("http://e.corp:3128"),
    )]);
    let d = Discovery::new(Arc::new(EnvFallback::new(os, env)), Config::default());
    let decision = d.route(&https("github.com")).await;
    assert_eq!(decision.source, RouteSource::Env);
    let health = d.health().await;
    assert_eq!(health.detected, Detected::Env);
    let why = health.settings_error.expect("the read failure is reported");
    assert!(why.contains("registry access denied"), "{why}");
}

#[tokio::test]
async fn a_machine_proxy_that_could_not_be_read_is_reported_though_the_rest_is_used() {
    let (_, d) = discovery(ProxyConfig {
        pac_url: Some("http://pac.corp/p.pac".into()),
        read_error: Some("the machine-wide WinHTTP proxy could not be read: access denied".into()),
        ..ProxyConfig::default()
    });
    let health = d.health().await;
    assert_eq!(health.detected, Detected::Pac);
    assert!(health.settings_error.unwrap().contains("machine-wide"));
}

#[tokio::test]
async fn changes_the_os_layer_cannot_watch_are_reported_when_the_watch_fails_and_when_it_stops() {
    // A layer that tried and failed says why, and there is no watch.
    let os = FakeOs::failing_watch(ProxyConfig::default(), "registry key could not be opened");
    let d = Discovery::new(os, Config::default());
    assert!(d.watch().is_none());
    let health = d.health().await;
    assert_eq!(health.problems.len(), 1, "{:?}", health.problems);
    assert_eq!(health.problems[0].kind, ProxyProblemKind::ChangesNotNoticed);
    assert!(
        health.problems[0]
            .detail
            .contains("registry key could not be opened")
    );

    // A layer that cannot by nature (no watch, no word) is not a problem.
    let quiet = Discovery::new(
        FakeOs::without_watch(ProxyConfig::default()),
        Config::default(),
    );
    assert!(quiet.watch().is_none());
    assert_eq!(quiet.health().await.problems, vec![]);

    // A watch that stops later: the report says so, and a new watch starts clean.
    let os = FakeOs::new(ProxyConfig::default());
    let d = Discovery::new(os.clone(), Config::default());
    let watching = d.watch().expect("fake can watch");
    assert_eq!(d.health().await.problems, vec![]);
    assert!(os.fire_watch_problem("the registry watch stopped (error 6)"));
    let health = d.health().await;
    assert_eq!(health.problems.len(), 1);
    assert_eq!(health.problems[0].kind, ProxyProblemKind::ChangesNotNoticed);
    drop(watching);
    let _again = d.watch().expect("fake can watch again");
    assert_eq!(d.health().await.problems, vec![]);
}

#[tokio::test]
async fn only_the_system_mode_cares_about_changes_it_cannot_watch() {
    let os = FakeOs::failing_watch(ProxyConfig::default(), "no registry");
    let d = Discovery::new(
        os,
        Config {
            mode: Mode::Direct,
            ..Config::default()
        },
    );
    assert!(d.watch().is_none());
    assert_eq!(d.health().await.problems, vec![]);
}

#[test]
fn origin_is_exported_for_building_configs() {
    assert_eq!(ProxyConfig::default().origin, Origin::System);
}
