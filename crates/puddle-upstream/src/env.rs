// SPDX-License-Identifier: GPL-3.0-or-later
//! The `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` / `NO_PROXY` variables as an [`OsProxy`]: the
//! whole OS layer on Unix, and the last fallback on Windows ([`crate::EnvFallback`]).

use std::ffi::OsString;
use std::sync::Arc;

use crate::health::ProxyProblem;
use crate::hop::ProxyAddr;
use crate::os::{
    ChangeCallback, Origin, OsProxy, PacError, PacQuery, ProblemCallback, ProxyConfig,
    SettingsError, WatchGuard,
};
use crate::parse::{BypassList, ProxyRules};

/// Proxy settings read from environment variables. Credentials in the URLs are dropped (see
/// [`ProxyAddr`]). The variables are read once, when this is built; a change of the process
/// environment is not noticed (Unix has no notification for it either).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EnvOs {
    rules: ProxyRules,
    bypass: BypassList,
    problems: Vec<ProxyProblem>,
}

impl EnvOs {
    /// Reads the current process environment.
    #[must_use]
    pub fn from_process() -> Self {
        Self::from_vars(std::env::vars_os())
    }

    /// Reads `vars`. Upper- and lower-case names both count; the lower-case one wins (curl's rule).
    /// A value puddle cannot use (`socks5://`, `https://`, no host) is ignored: it is listed in
    /// [`ProxyConfig::problems`], which discovery logs and the network-health report shows (the
    /// connections it was meant for go direct).
    #[must_use]
    pub fn from_vars(vars: impl IntoIterator<Item = (OsString, OsString)>) -> Self {
        let vars: Vec<(String, String)> = vars
            .into_iter()
            .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
            .collect();
        let get = |name: &str| {
            let lower = name.to_ascii_lowercase();
            let pick = |key: &str| {
                vars.iter()
                    .find(|(k, v)| k == key && !v.trim().is_empty())
                    .map(|(_, v)| v.as_str())
            };
            pick(&lower).or_else(|| pick(name))
        };
        let mut problems = Vec::new();
        let mut proxy = |name: &str| -> Option<ProxyAddr> {
            let value = get(name)?;
            match ProxyAddr::parse(value) {
                Ok(addr) => Some(addr),
                Err(err) => {
                    let shown = crate::redact::entry_text(value);
                    problems.push(ProxyProblem::unusable(format!(
                        "the {name} variable (\"{shown}\"): {err}"
                    )));
                    None
                }
            }
        };
        let rules = ProxyRules::new(
            proxy("HTTP_PROXY"),
            proxy("HTTPS_PROXY"),
            proxy("ALL_PROXY"),
        );
        Self {
            rules,
            bypass: get("NO_PROXY")
                .map(BypassList::parse_no_proxy)
                .unwrap_or_default(),
            problems,
        }
    }

    pub(crate) fn config(&self) -> ProxyConfig {
        ProxyConfig {
            rules: self.rules.clone(),
            bypass: self.bypass.clone(),
            origin: Origin::Environment,
            problems: self.problems.clone(),
            ..ProxyConfig::default()
        }
    }
}

impl OsProxy for EnvOs {
    fn config(&self) -> Result<ProxyConfig, SettingsError> {
        Ok(EnvOs::config(self))
    }

    fn resolve_pac(&self, _query: &PacQuery) -> Result<Vec<crate::hop::Hop>, PacError> {
        Err(PacError::Unavailable(
            "PAC evaluation is not available on this platform yet".into(),
        ))
    }

    fn watch(
        &self,
        _on_change: ChangeCallback,
        _on_problem: ProblemCallback,
    ) -> Option<Box<dyn WatchGuard>> {
        // Nothing notifies a process of a changed environment; not a failure to report.
        None
    }
}

/// An [`OsProxy`] that asks `primary`, and when it names no static proxy, adds the environment's.
/// PAC and change notification are the primary's.
#[derive(Debug)]
pub struct EnvFallback {
    primary: Arc<dyn OsProxy>,
    env: EnvOs,
}

impl EnvFallback {
    /// `primary` first, `env` when `primary` has no static proxy.
    #[must_use]
    pub fn new(primary: Arc<dyn OsProxy>, env: EnvOs) -> Self {
        Self { primary, env }
    }
}

impl OsProxy for EnvFallback {
    fn config(&self) -> Result<ProxyConfig, SettingsError> {
        let mut config = match self.primary.config() {
            Ok(config) => config,
            Err(err) => {
                tracing::warn!(error = %err, "system proxy settings unreadable; using the environment");
                ProxyConfig {
                    read_error: Some(err.0),
                    ..ProxyConfig::default()
                }
            }
        };
        // PAC settings stay the primary's (and are tried first); the environment backs them up
        // when the primary names no static proxy, so a PAC outage still has somewhere to go.
        if config.rules.is_empty() {
            let env = self.env.config();
            config.rules = env.rules;
            config.bypass = env.bypass;
            config.origin = Origin::Environment;
            config.problems.extend(env.problems);
        }
        Ok(config)
    }

    fn resolve_pac(&self, query: &PacQuery) -> Result<Vec<crate::hop::Hop>, PacError> {
        self.primary.resolve_pac(query)
    }

    fn watch(
        &self,
        on_change: ChangeCallback,
        on_problem: ProblemCallback,
    ) -> Option<Box<dyn WatchGuard>> {
        self.primary.watch(on_change, on_problem)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hop::{Destination, Scheme};

    fn env(pairs: &[(&str, &str)]) -> EnvOs {
        EnvOs::from_vars(
            pairs
                .iter()
                .map(|(k, v)| (OsString::from(k), OsString::from(v))),
        )
    }

    fn rules(e: &EnvOs, scheme: Scheme) -> Option<ProxyAddr> {
        e.rules.for_scheme(scheme).cloned()
    }

    #[test]
    fn variables_pick_the_scheme_then_all_and_lower_case_wins() {
        let e = env(&[
            ("HTTPS_PROXY", "http://a:1"),
            ("https_proxy", "http://b:2"),
            ("ALL_PROXY", "c:3"),
            ("HTTP_PROXY", "d"),
        ]);
        assert_eq!(rules(&e, Scheme::Https), Some(ProxyAddr::new("b", 2)));
        assert_eq!(rules(&e, Scheme::Http), Some(ProxyAddr::new("d", 80)));
        assert_eq!(
            rules(&env(&[("all_proxy", "c:3")]), Scheme::Http),
            Some(ProxyAddr::new("c", 3))
        );
        assert_eq!(rules(&env(&[]), Scheme::Https), None);
    }

    #[test]
    fn unusable_values_are_ignored_and_credentials_dropped() {
        let e = env(&[
            ("HTTPS_PROXY", "socks5://p:1080"),
            ("HTTP_PROXY", "  "),
            ("ALL_PROXY", "http://u:pw@p.corp:8080"),
        ]);
        assert_eq!(
            rules(&e, Scheme::Https),
            Some(ProxyAddr::new("p.corp", 8080))
        );
        assert!(!format!("{e:?}").contains("pw"));
    }

    #[test]
    fn an_unusable_variable_is_listed_as_a_problem_with_its_name_and_no_credential() {
        let e = env(&[
            ("HTTPS_PROXY", "socks5://user:hunter2@p:1080"),
            ("HTTP_PROXY", "http://good.corp:3128"),
            ("ALL_PROXY", "p:notaport"),
        ]);
        let config = e.config();
        assert_eq!(config.problems.len(), 2, "{:?}", config.problems);
        let shown = format!("{:?}", config.problems);
        assert!(
            shown.contains("HTTPS_PROXY") && shown.contains("socks5"),
            "{shown}"
        );
        assert!(
            shown.contains("ALL_PROXY") && shown.contains("p:notaport"),
            "{shown}"
        );
        assert!(!shown.contains("hunter2"), "{shown}");
        assert!(
            config
                .problems
                .iter()
                .all(|p| p.kind == crate::health::ProxyProblemKind::UnusableSetting)
        );
        assert_eq!(env(&[("HTTPS_PROXY", "p:1")]).config().problems, vec![]);
    }

    #[test]
    fn a_system_layer_that_cannot_be_read_is_replaced_by_the_environment_and_says_so() {
        let os = crate::FakeOs::new(ProxyConfig::default());
        os.fail_config("registry access denied");
        let fallback = EnvFallback::new(os, env(&[("HTTPS_PROXY", "e.corp:3128")]));
        let config = fallback.config().unwrap();
        assert_eq!(config.origin, Origin::Environment);
        assert_eq!(
            config.rules.for_scheme(Scheme::Https),
            Some(&ProxyAddr::new("e.corp", 3128))
        );
        assert_eq!(config.read_error.as_deref(), Some("registry access denied"));
    }

    #[test]
    fn environment_problems_count_only_when_the_environment_is_used() {
        let unusable = [("HTTPS_PROXY", "socks5://p:1")];
        let os = crate::FakeOs::new(ProxyConfig::default());
        let used = EnvFallback::new(os, env(&unusable)).config().unwrap();
        assert_eq!(used.problems.len(), 1);
        let system = ProxyConfig {
            rules: ProxyRules::new(Some(ProxyAddr::new("sys", 1)), None, None),
            ..ProxyConfig::default()
        };
        let os = crate::FakeOs::new(system);
        let unused = EnvFallback::new(os, env(&unusable)).config().unwrap();
        assert_eq!(unused.problems, vec![]);
        assert!(unused.read_error.is_none());
    }

    #[test]
    fn no_proxy_becomes_the_bypass_list() {
        let e = env(&[("NO_PROXY", "corp.test"), ("HTTPS_PROXY", "p:1")]);
        let config = e.config();
        assert_eq!(config.origin, Origin::Environment);
        assert!(
            config
                .bypass
                .matches(&Destination::new(Scheme::Https, "a.corp.test", 443))
        );
        assert!(
            !config
                .bypass
                .matches(&Destination::new(Scheme::Https, "github.com", 443))
        );
    }

    #[test]
    fn the_unix_os_layer_is_the_environment_with_no_pac_and_no_watch() {
        let e = env(&[("HTTPS_PROXY", "p:1")]);
        let config = OsProxy::config(&e).unwrap();
        assert!(config.pac_url.is_none() && !config.auto_detect);
        assert_eq!(
            config.rules.for_scheme(Scheme::Https),
            Some(&ProxyAddr::new("p", 1))
        );
        let query = PacQuery {
            pac_url: None,
            auto_detect: true,
            url: "http://x/".into(),
            timeout: std::time::Duration::from_secs(1),
        };
        assert!(matches!(
            e.resolve_pac(&query),
            Err(PacError::Unavailable(_))
        ));
        assert!(e.watch(Arc::new(|| {}), Arc::new(|_| {})).is_none());
        let _ = EnvOs::from_process();
    }
}
