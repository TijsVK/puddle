// SPDX-License-Identifier: GPL-3.0-or-later
//! The `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` / `NO_PROXY` fallback: last in line, after the
//! operating system's own settings.

use std::ffi::OsString;
use std::net::IpAddr;

use crate::hop::{Destination, ProxyAddr, Scheme};
use crate::parse::glob_match;

/// Proxy settings read from environment variables. Credentials in the URLs are dropped (see
/// [`ProxyAddr`]).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EnvProxy {
    http: Option<ProxyAddr>,
    https: Option<ProxyAddr>,
    all: Option<ProxyAddr>,
    no_proxy: Vec<String>,
}

impl EnvProxy {
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
        let proxy = |name: &str| {
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
            http: proxy("HTTP_PROXY"),
            https: proxy("HTTPS_PROXY"),
            all: proxy("ALL_PROXY"),
            no_proxy: get("NO_PROXY")
                .map(|v| {
                    v.split(',')
                        .map(|e| e.trim().to_ascii_lowercase())
                        .filter(|e| !e.is_empty())
                        .collect()
                })
                .unwrap_or_default(),
        }
    }

    /// The proxy for `scheme`, ignoring `NO_PROXY`.
    #[must_use]
    pub fn proxy_for(&self, scheme: Scheme) -> Option<&ProxyAddr> {
        let specific = match scheme {
            Scheme::Http => &self.http,
            Scheme::Https => &self.https,
        };
        specific.as_ref().or(self.all.as_ref())
    }

    /// True when `NO_PROXY` exempts `dest`: `*`, an exact name or address, a domain suffix
    /// (`corp.test`, `.corp.test`, `*.corp.test` all cover subdomains and the domain), `host:port`,
    /// or a CIDR range (`10.0.0.0/8`).
    #[must_use]
    pub fn bypassed(&self, dest: &Destination) -> bool {
        self.no_proxy
            .iter()
            .any(|entry| no_proxy_entry_matches(entry, dest))
    }
}

fn no_proxy_entry_matches(entry: &str, dest: &Destination) -> bool {
    if entry == "*" {
        return true;
    }
    if let Some((net, bits)) = entry.split_once('/')
        && let (Ok(net), Ok(bits), Ok(ip)) = (
            net.parse::<IpAddr>(),
            bits.parse::<u8>(),
            dest.host().parse::<IpAddr>(),
        )
    {
        return in_cidr(net, bits, ip);
    }
    let (host, port) = match entry.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => match port.parse::<u16>() {
            Ok(port) => (host, Some(port)),
            Err(_) => return false,
        },
        _ => (entry, None),
    };
    if port.is_some_and(|p| p != dest.port()) {
        return false;
    }
    let domain = host.trim_start_matches("*.").trim_start_matches('.');
    if domain.is_empty() {
        return false;
    }
    dest.host() == domain
        || dest
            .host()
            .strip_suffix(domain)
            .is_some_and(|rest| rest.ends_with('.'))
        || (host.contains('*') && glob_match(host, dest.host()))
}

fn in_cidr(net: IpAddr, bits: u8, ip: IpAddr) -> bool {
    match (net, ip) {
        (IpAddr::V4(n), IpAddr::V4(i)) if bits <= 32 => {
            let mask = u32::MAX.checked_shl(32 - u32::from(bits)).unwrap_or(0);
            u32::from(n) & mask == u32::from(i) & mask
        }
        (IpAddr::V6(n), IpAddr::V6(i)) if bits <= 128 => {
            let mask = u128::MAX.checked_shl(128 - u32::from(bits)).unwrap_or(0);
            u128::from(n) & mask == u128::from(i) & mask
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> EnvProxy {
        EnvProxy::from_vars(
            pairs
                .iter()
                .map(|(k, v)| (OsString::from(k), OsString::from(v))),
        )
    }

    fn dest(host: &str, port: u16) -> Destination {
        Destination::new(Scheme::Https, host, port)
    }

    #[test]
    fn variables_pick_the_scheme_then_all_and_lower_case_wins() {
        let e = env(&[
            ("HTTPS_PROXY", "http://a:1"),
            ("https_proxy", "http://b:2"),
            ("ALL_PROXY", "c:3"),
            ("HTTP_PROXY", "d"),
        ]);
        assert_eq!(e.proxy_for(Scheme::Https), Some(&ProxyAddr::new("b", 2)));
        assert_eq!(e.proxy_for(Scheme::Http), Some(&ProxyAddr::new("d", 80)));
        let only_all = env(&[("all_proxy", "c:3")]);
        assert_eq!(
            only_all.proxy_for(Scheme::Http),
            Some(&ProxyAddr::new("c", 3))
        );
        assert_eq!(env(&[]).proxy_for(Scheme::Https), None);
    }

    #[test]
    fn unusable_values_are_ignored_and_credentials_dropped() {
        let e = env(&[
            ("HTTPS_PROXY", "socks5://p:1080"),
            ("HTTP_PROXY", "  "),
            ("ALL_PROXY", "http://u:pw@p.corp:8080"),
        ]);
        assert_eq!(
            e.proxy_for(Scheme::Https),
            Some(&ProxyAddr::new("p.corp", 8080))
        );
        assert!(!format!("{e:?}").contains("pw"));
    }

    #[test]
    fn no_proxy_forms() {
        let e = env(&[(
            "NO_PROXY",
            "corp.test, .dotted.test,*.star.test,exact.example,host.test:8443,10.0.0.0/8,fd00::/8, ,bad:x,/8",
        )]);
        for (host, port, expected) in [
            ("corp.test", 443, true),
            ("a.corp.test", 443, true),
            ("evilcorp.test", 443, false),
            ("a.dotted.test", 443, true),
            ("dotted.test", 443, true),
            ("a.star.test", 443, true),
            ("exact.example", 443, true),
            ("x.exact.example", 443, true),
            ("host.test", 8443, true),
            ("host.test", 443, false),
            ("10.9.9.9", 443, true),
            ("11.0.0.1", 443, false),
            ("fd12::1", 443, true),
            ("fe80::1", 443, false),
            ("github.com", 443, false),
        ] {
            assert_eq!(e.bypassed(&dest(host, port)), expected, "{host}:{port}");
        }
        assert!(env(&[("no_proxy", "*")]).bypassed(&dest("anything", 1)));
        assert!(!env(&[]).bypassed(&dest("anything", 1)));
    }

    #[test]
    fn cidr_edges() {
        let e = env(&[("NO_PROXY", "0.0.0.0/0,1.2.3.4/32,::1/128,1.2.3.4/33")]);
        assert!(e.bypassed(&dest("200.1.1.1", 1)));
        assert!(!env(&[("NO_PROXY", "1.2.3.4/32")]).bypassed(&dest("1.2.3.5", 1)));
        assert!(env(&[("NO_PROXY", "1.2.3.4/32")]).bypassed(&dest("1.2.3.4", 1)));
        assert!(!env(&[("NO_PROXY", "1.2.3.4/33")]).bypassed(&dest("1.2.3.4", 1)));
        assert!(!env(&[("NO_PROXY", "10.0.0.0/8")]).bypassed(&dest("fd00::1", 1)));
    }

    #[test]
    fn process_environment_is_readable() {
        let _ = EnvProxy::from_process();
    }
}
