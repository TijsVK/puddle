// SPDX-License-Identifier: GPL-3.0-or-later
//! Readers for the text formats proxies are described in: PAC answers, the WinINet
//! `ProxyRules` value, and the `ProxyOverride` bypass list.

use std::net::IpAddr;

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

/// Which proxy serves which scheme. Read from the common list syntax (`host:port` for every
/// scheme, or `http=h:p;https=h:p;ftp=h:p;socks=h:p`, as WinINet and WinHTTP store it and as a
/// puddle setting may spell it), or built from environment variables.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProxyRules {
    all: Option<ProxyAddr>,
    http: Option<ProxyAddr>,
    https: Option<ProxyAddr>,
}

impl ProxyRules {
    /// Rules from explicit proxies: `http` and `https` for their scheme, `all` for the rest.
    #[must_use]
    pub fn new(http: Option<ProxyAddr>, https: Option<ProxyAddr>, all: Option<ProxyAddr>) -> Self {
        Self { all, http, https }
    }

    /// True when no scheme has a proxy.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.all.is_none() && self.http.is_none() && self.https.is_none()
    }

    /// Reads the list syntax. Entries puddle cannot use (`ftp=`, `socks=`, bad ports) are ignored.
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
    /// `*` in `NO_PROXY`: everything.
    All,
    /// A `NO_PROXY` domain: the name itself and every subdomain, optionally on one port.
    Suffix { domain: String, port: Option<u16> },
    /// A `NO_PROXY` address range.
    Cidr { net: IpAddr, bits: u8 },
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

    /// Reads the `NO_PROXY` syntax: comma separated; `*` is everything; `corp.test`, `.corp.test`
    /// and `*.corp.test` cover the domain and its subdomains; `host:port` narrows to a port;
    /// `10.0.0.0/8` is an address range.
    #[must_use]
    pub fn parse_no_proxy(text: &str) -> Self {
        let entries = text
            .split(',')
            .map(|e| e.trim().to_ascii_lowercase())
            .filter(|e| !e.is_empty())
            .filter_map(|e| parse_no_proxy_entry(&e))
            .collect();
        Self { entries }
    }

    /// True when `dest` skips the proxy.
    #[must_use]
    pub fn matches(&self, dest: &Destination) -> bool {
        self.entries.iter().any(|entry| match entry {
            Entry::All => true,
            Entry::Suffix { domain, port } => {
                port.is_none_or(|p| p == dest.port())
                    && (dest.host() == domain
                        || dest
                            .host()
                            .strip_suffix(domain.as_str())
                            .is_some_and(|rest| rest.ends_with('.')))
            }
            Entry::Cidr { net, bits } => dest
                .host()
                .parse::<IpAddr>()
                .is_ok_and(|ip| in_cidr(*net, *bits, ip)),
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

fn parse_no_proxy_entry(entry: &str) -> Option<Entry> {
    if entry == "*" {
        return Some(Entry::All);
    }
    if let Some((net, bits)) = entry.split_once('/') {
        let (net, bits) = (net.parse::<IpAddr>().ok()?, bits.parse::<u8>().ok()?);
        let max = if net.is_ipv4() { 32 } else { 128 };
        return (bits <= max).then_some(Entry::Cidr { net, bits });
    }
    let (host, port) = match entry.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => (host, Some(port.parse::<u16>().ok()?)),
        _ => (entry, None),
    };
    let domain = host.trim_start_matches("*.").trim_start_matches('.');
    (!domain.is_empty()).then(|| Entry::Suffix {
        domain: domain.to_string(),
        port,
    })
}

fn in_cidr(net: IpAddr, bits: u8, ip: IpAddr) -> bool {
    match (net, ip) {
        (IpAddr::V4(n), IpAddr::V4(i)) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(bits)).unwrap_or(0);
            u32::from(n) & mask == u32::from(i) & mask
        }
        (IpAddr::V6(n), IpAddr::V6(i)) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(bits)).unwrap_or(0);
            u128::from(n) & mask == u128::from(i) & mask
        }
        _ => false,
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
    fn proxy_rules_per_scheme() {
        let split = ProxyRules::parse("http=a:1;https=b:2;ftp=c:3;socks=d:4");
        assert_eq!(
            split.for_scheme(Scheme::Https),
            Some(&ProxyAddr::new("b", 2))
        );
        assert_eq!(
            split.for_scheme(Scheme::Http),
            Some(&ProxyAddr::new("a", 1))
        );
        let one = ProxyRules::parse("a:1");
        assert_eq!(one.for_scheme(Scheme::Https), Some(&ProxyAddr::new("a", 1)));
        let https_only = ProxyRules::parse("https=b:2");
        assert_eq!(https_only.for_scheme(Scheme::Http), None);
        assert_eq!(ProxyRules::parse("ftp=a:1").for_scheme(Scheme::Https), None);
        assert_eq!(ProxyRules::parse("").for_scheme(Scheme::Http), None);
        // WinHTTP's machine list is space separated and may carry a default plus overrides.
        let mixed = ProxyRules::parse("x:1 https=y:2");
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
    fn no_proxy_forms() {
        let list = BypassList::parse_no_proxy(
            "corp.test, .dotted.test,*.star.test,exact.example,host.test:8443,10.0.0.0/8,fd00::/8, ,bad:x,/8,1.2.3.4/33",
        );
        for (host, port, expected) in [
            ("corp.test", 443, true),
            ("a.corp.test", 443, true),
            ("evilcorp.test", 443, false),
            ("a.dotted.test", 443, true),
            ("dotted.test", 443, true),
            ("a.star.test", 443, true),
            ("x.exact.example", 443, true),
            ("host.test", 8443, true),
            ("host.test", 443, false),
            ("10.9.9.9", 443, true),
            ("11.0.0.1", 443, false),
            ("fd12::1", 443, true),
            ("fe80::1", 443, false),
            ("github.com", 443, false),
        ] {
            assert_eq!(
                list.matches(&Destination::new(Scheme::Https, host, port)),
                expected,
                "{host}:{port}"
            );
        }
        assert!(BypassList::parse_no_proxy("*").matches(&dest("anything")));
        assert!(!BypassList::parse_no_proxy("").matches(&dest("anything")));
        let all = BypassList::parse_no_proxy("0.0.0.0/0,1.2.3.4/32");
        assert!(all.matches(&dest("200.1.1.1")));
        assert!(!BypassList::parse_no_proxy("1.2.3.4/32").matches(&dest("1.2.3.5")));
        assert!(!BypassList::parse_no_proxy("10.0.0.0/8").matches(&dest("fd00::1")));
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
                let _ = ProxyRules::parse(&text);
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
