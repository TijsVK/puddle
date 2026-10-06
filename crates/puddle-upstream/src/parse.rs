// SPDX-License-Identifier: GPL-3.0-or-later
//! Readers for the text formats proxies are described in: PAC answers, the WinINet
//! `ProxyServer` value, and the `ProxyOverride` bypass list.

use crate::hop::{Destination, Hop, ProxyAddr, Scheme};

/// A PAC answer read into hops.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PacAnswer {
    /// The hops puddle can use, in order.
    pub hops: Vec<Hop>,
    /// Entries left out because puddle cannot speak them (`SOCKS`, `HTTPS` proxies, garbage).
    pub skipped: usize,
}

/// Reads `PROXY a:1; PROXY b:2; DIRECT`. `HTTP` is `PROXY`; `HTTPS`, `SOCKS*` and unknown entries
/// are counted in [`PacAnswer::skipped`].
#[must_use]
pub fn parse_pac_answer(text: &str) -> PacAnswer {
    let mut answer = PacAnswer::default();
    for entry in text.split(';').map(str::trim).filter(|e| !e.is_empty()) {
        let mut words = entry.split_whitespace();
        let hop = match (
            words.next().map(str::to_ascii_uppercase).as_deref(),
            words.next(),
        ) {
            (Some("DIRECT"), _) => Some(Hop::Direct),
            (Some("PROXY" | "HTTP"), Some(target)) => ProxyAddr::parse(target).ok().map(Hop::Proxy),
            _ => None,
        };
        match hop {
            Some(hop) => answer.hops.push(hop),
            None => answer.skipped += 1,
        }
    }
    answer
}

/// The WinINet `ProxyServer` value: `host:port` for every scheme, or
/// `http=h:p;https=h:p;ftp=h:p;socks=h:p`. Machine WinHTTP uses the same syntax.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProxyServer {
    all: Option<ProxyAddr>,
    http: Option<ProxyAddr>,
    https: Option<ProxyAddr>,
}

impl ProxyServer {
    /// Reads the value. Entries puddle cannot use (`ftp=`, `socks=`, bad ports) are ignored.
    #[must_use]
    pub fn parse(text: &str) -> Self {
        let mut server = Self::default();
        for entry in text
            .split([';', ' '])
            .map(str::trim)
            .filter(|e| !e.is_empty())
        {
            match entry.split_once('=') {
                None => server.all = server.all.take().or_else(|| ProxyAddr::parse(entry).ok()),
                Some((key, value)) => {
                    let Ok(addr) = ProxyAddr::parse(value) else {
                        continue;
                    };
                    match key.to_ascii_lowercase().as_str() {
                        "http" => server.http = Some(addr),
                        "https" => server.https = Some(addr),
                        _ => {}
                    }
                }
            }
        }
        server
    }

    /// The proxy for `scheme`, if the value names one.
    #[must_use]
    pub fn for_scheme(&self, scheme: Scheme) -> Option<&ProxyAddr> {
        let specific = match scheme {
            Scheme::Http => &self.http,
            Scheme::Https => &self.https,
        };
        specific.as_ref().or(self.all.as_ref())
    }
}

/// One `ProxyOverride` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Entry {
    /// `<local>`: a name without a dot.
    Local,
    /// A host pattern, `*` matching any run of characters, with an optional scheme and port.
    Pattern {
        scheme: Option<Scheme>,
        glob: String,
        port: Option<u16>,
        /// A leading-dot entry (`.corp.test`) also matches the bare domain.
        bare: Option<String>,
    },
}

/// The `ProxyOverride` list: destinations that skip the proxy. Entries are separated by `;`,
/// spaces or commas. Matching is case-insensitive; `*` is a wildcard anywhere (`*.corp.test`,
/// `10.*`); `<local>` is any name without a dot; `https://host` and `host:port` narrow an entry.
/// A leading dot (`.corp.test`) matches the domain and its subdomains, as the lab's PoC did.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BypassList {
    entries: Vec<Entry>,
}

impl BypassList {
    /// Reads the list.
    #[must_use]
    pub fn parse(text: &str) -> Self {
        let entries = text
            .split([';', ' ', ','])
            .map(str::trim)
            .filter(|e| !e.is_empty())
            .filter_map(parse_entry)
            .collect();
        Self { entries }
    }

    /// True when `dest` skips the proxy.
    #[must_use]
    pub fn matches(&self, dest: &Destination) -> bool {
        self.entries.iter().any(|entry| match entry {
            Entry::Local => {
                !dest.host().contains('.') && dest.host().parse::<std::net::Ipv6Addr>().is_err()
            }
            Entry::Pattern {
                scheme,
                glob,
                port,
                bare,
            } => {
                scheme.is_none_or(|s| s == dest.scheme())
                    && port.is_none_or(|p| p == dest.port())
                    && (glob_match(glob, dest.host()) || bare.as_deref() == Some(dest.host()))
            }
        })
    }
}

fn parse_entry(raw: &str) -> Option<Entry> {
    let lower = raw.to_ascii_lowercase();
    if lower == "<local>" {
        return Some(Entry::Local);
    }
    if lower.starts_with('<') {
        return None; // `<-loopback>` and friends: loopback never uses a proxy here anyway
    }
    let (scheme, rest) = match lower.split_once("://") {
        Some(("http", rest)) => (Some(Scheme::Http), rest),
        Some(("https", rest)) => (Some(Scheme::Https), rest),
        Some(_) => return None,
        None => (None, lower.as_str()),
    };
    let rest = rest.trim_end_matches('/');
    let (host, port) = match rest.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => (host, Some(port.parse::<u16>().ok()?)),
        _ => (rest, None),
    };
    let host = host.trim_matches(['[', ']']);
    if host.is_empty() {
        return None;
    }
    let (glob, bare) = match host.strip_prefix('.') {
        Some(domain) => (format!("*.{domain}"), Some(domain.to_string())),
        None => (host.to_string(), None),
    };
    Some(Entry::Pattern {
        scheme,
        glob,
        port,
        bare,
    })
}

/// `*` matches any run of characters (including none); everything else matches itself.
#[must_use]
pub(crate) fn glob_match(pattern: &str, text: &str) -> bool {
    let (p, t): (Vec<char>, Vec<char>) = (pattern.chars().collect(), text.chars().collect());
    let (mut pi, mut ti) = (0, 0);
    let (mut star, mut mark) = (None, 0);
    while ti < t.len() {
        match p.get(pi) {
            Some('*') => {
                star = Some(pi);
                mark = ti;
                pi += 1;
            }
            Some(c) if t.get(ti) == Some(c) => {
                pi += 1;
                ti += 1;
            }
            _ => match star {
                Some(s) => {
                    pi = s + 1;
                    mark += 1;
                    ti = mark;
                }
                None => return false,
            },
        }
    }
    p.get(pi..)
        .is_some_and(|rest| rest.iter().all(|c| *c == '*'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dest(host: &str) -> Destination {
        Destination::new(Scheme::Https, host, 443)
    }

    #[test]
    fn pac_answers_become_ordered_hops_and_count_what_is_skipped() {
        let a = parse_pac_answer("PROXY 127.0.0.1:1; proxy p.corp:3128;HTTP q:8080 ; DIRECT");
        assert_eq!(
            a.hops,
            vec![
                Hop::Proxy(ProxyAddr::new("127.0.0.1", 1)),
                Hop::Proxy(ProxyAddr::new("p.corp", 3128)),
                Hop::Proxy(ProxyAddr::new("q", 8080)),
                Hop::Direct
            ]
        );
        assert_eq!(a.skipped, 0);
        let b = parse_pac_answer("SOCKS s:1; HTTPS t:443; PROXY; BOGUS x; DIRECT");
        assert_eq!(b.hops, vec![Hop::Direct]);
        assert_eq!(b.skipped, 4);
        assert_eq!(parse_pac_answer(""), PacAnswer::default());
    }

    #[test]
    fn proxy_server_value_per_scheme() {
        let split = ProxyServer::parse("http=a:1;https=b:2;ftp=c:3;socks=d:4");
        assert_eq!(
            split.for_scheme(Scheme::Https),
            Some(&ProxyAddr::new("b", 2))
        );
        assert_eq!(
            split.for_scheme(Scheme::Http),
            Some(&ProxyAddr::new("a", 1))
        );
        let one = ProxyServer::parse("a:1");
        assert_eq!(one.for_scheme(Scheme::Https), Some(&ProxyAddr::new("a", 1)));
        let https_only = ProxyServer::parse("https=b:2");
        assert_eq!(https_only.for_scheme(Scheme::Http), None);
        assert_eq!(
            ProxyServer::parse("ftp=a:1").for_scheme(Scheme::Https),
            None
        );
        assert_eq!(ProxyServer::parse("").for_scheme(Scheme::Http), None);
        // WinHTTP's machine list is space separated and may carry a default plus overrides.
        let mixed = ProxyServer::parse("x:1 https=y:2");
        assert_eq!(
            mixed.for_scheme(Scheme::Https),
            Some(&ProxyAddr::new("y", 2))
        );
        assert_eq!(
            mixed.for_scheme(Scheme::Http),
            Some(&ProxyAddr::new("x", 1))
        );
    }

    #[test]
    fn bypass_list_matches_like_proxy_override() {
        let list = BypassList::parse(
            "*.corp.test;<local>;exact.example;10.*;https://only.tls;web:8080;.dom.test",
        );
        for (host, expected) in [
            ("nexus.corp.test", true),
            ("corp.test", false),
            ("intranet", true),
            ("EXACT.example.", true),
            ("sub.exact.example", false),
            ("10.1.2.3", true),
            ("110.1.2.3", false),
            ("only.tls", true),
            ("dom.test", true),
            ("a.dom.test", true),
            ("evildom.test", false),
            ("::2", false),
            ("github.com", false),
        ] {
            assert_eq!(list.matches(&dest(host)), expected, "{host}");
        }
        assert!(!list.matches(&Destination::new(Scheme::Http, "only.tls", 80)));
        assert!(list.matches(&Destination::new(Scheme::Http, "web", 8080)));
        assert!(!list.matches(&Destination::new(Scheme::Http, "web.x", 80)));
        assert!(!BypassList::parse("").matches(&dest("x")));
        assert!(!BypassList::parse("<-loopback>;ftp://x;:80;web:zz").matches(&dest("web")));
    }

    #[test]
    fn glob_handles_stars_anywhere() {
        assert!(glob_match("*", ""));
        assert!(glob_match("a*b*c", "aXXbYYc"));
        assert!(glob_match("*.x", "a.b.x"));
        assert!(!glob_match("*.x", "x"));
        assert!(!glob_match("a*b", "acd"));
        assert!(glob_match("a**", "a"));
    }

    mod props {
        use super::super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn parsers_never_panic(text in "\\PC{0,80}") {
                let _ = parse_pac_answer(&text);
                let _ = ProxyServer::parse(&text);
                let list = BypassList::parse(&text);
                let _ = list.matches(&Destination::new(Scheme::Https, &text, 443));
                let _ = ProxyAddr::parse(&text);
            }

            #[test]
            fn a_literal_pattern_matches_only_itself(host in "[a-z0-9.-]{0,19}[a-z0-9-]", other in "[a-z0-9.-]{0,19}[a-z0-9-]") {
                prop_assume!(!host.starts_with('.') && !host.starts_with('<'));
                let list = BypassList::parse(&host);
                let own = Destination::new(Scheme::Https, &host, 443);
                prop_assert_eq!(list.matches(&Destination::new(Scheme::Https, &other, 443)), own.host() == other);
                prop_assert!(list.matches(&own));
            }

            #[test]
            fn pac_hops_never_exceed_entries(text in "[A-Za-z0-9:;. ]{0,60}") {
                let a = parse_pac_answer(&text);
                prop_assert!(a.hops.len() + a.skipped <= text.split(';').count());
            }
        }
    }
}
