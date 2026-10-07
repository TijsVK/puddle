// SPDX-License-Identifier: GPL-3.0-or-later
//! The `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` / `NO_PROXY` variables as an [`OsProxy`]: the
//! whole OS layer on Unix, and the last fallback on Windows ([`crate::EnvFallback`]).

use std::ffi::OsString;
use std::sync::Arc;

use crate::hop::ProxyAddr;
use crate::os::{
    ChangeCallback, Origin, OsProxy, PacError, PacQuery, ProxyConfig, SettingsError, WatchGuard,
};
use crate::parse::{BypassList, ProxyRules};

/// Proxy settings read from environment variables. Credentials in the URLs are dropped (see
/// [`ProxyAddr`]). The variables are read once, when this is built; a change of the process
/// environment is not noticed (Unix has no notification for it either).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EnvOs {
    rules: ProxyRules,
    bypass: BypassList,
}

impl EnvOs {
    /// Reads the current process environment.
    #[must_use]
    pub fn from_process() -> Self {
        Self::from_vars(std::env::vars_os())
    }

    /// Reads `vars`. Upper- and lower-case names both count; the lower-case one wins (curl's rule).
    /// A value puddle cannot use (`socks5://`, `https://`, no host) is ignored with a debug line.
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
        let proxy = |name: &str| -> Option<ProxyAddr> {
            let value = get(name)?;
            match ProxyAddr::parse(value) {
                Ok(addr) => Some(addr),
                Err(err) => {
                    tracing::debug!(variable = name, error = %err, "ignoring unusable proxy variable");
                    None
                }
            }
        };
        Self {
            rules: ProxyRules::new(
                proxy("HTTP_PROXY"),
                proxy("HTTPS_PROXY"),
                proxy("ALL_PROXY"),
            ),
            bypass: get("NO_PROXY")
                .map(BypassList::parse_no_proxy)
                .unwrap_or_default(),
        }
    }

    pub(crate) fn config(&self) -> ProxyConfig {
        ProxyConfig {
            rules: self.rules.clone(),
            bypass: self.bypass.clone(),
            origin: Origin::Environment,
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

    fn watch(&self, _on_change: ChangeCallback) -> Option<Box<dyn WatchGuard>> {
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
                ProxyConfig::default()
            }
        };
        // PAC settings stay the primary's (and are tried first); the environment backs them up
        // when the primary names no static proxy, so a PAC outage still has somewhere to go.
        if config.rules.is_empty() {
            let env = self.env.config();
            config.rules = env.rules;
            config.bypass = env.bypass;
            config.origin = Origin::Environment;
        }
        Ok(config)
    }

    fn resolve_pac(&self, query: &PacQuery) -> Result<Vec<crate::hop::Hop>, PacError> {
        self.primary.resolve_pac(query)
    }

    fn watch(&self, on_change: ChangeCallback) -> Option<Box<dyn WatchGuard>> {
        self.primary.watch(on_change)
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
        assert!(e.watch(Arc::new(|| {})).is_none());
        let _ = EnvOs::from_process();
    }
}
