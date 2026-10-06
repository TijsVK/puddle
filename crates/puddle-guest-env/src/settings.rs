// SPDX-License-Identifier: GPL-3.0-or-later
//! The inputs: where the proxy is, and which destinations bypass it.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use puddle_types::GuestPath;

use crate::ConfigError;

/// The agent's proxy listener in the guest (`puddle-boot`'s default agent port).
pub const DEFAULT_PROXY: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3128);

/// The same listener as containers inside the guest see it: Docker's default bridge gateway.
pub const DEFAULT_CONTAINER_PROXY: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 17, 0, 1)), 3128);

/// Home of the user sessions run as (root, T-003; `puddle-boot` writes VS Code's Machine settings
/// there too).
pub const DEFAULT_HOME: &str = "/root";

/// Longest host name (RFC 1035).
const MAX_NAME_LEN: usize = 253;
/// Longest label.
const MAX_LABEL_LEN: usize = 63;

/// What [`crate::guest_proxy_config`] builds from.
///
/// ```
/// use puddle_guest_env::{NoProxyEntry, ProxySettings};
/// let settings = ProxySettings {
///     no_proxy: vec![NoProxyEntry::new(".corp.example").unwrap()],
///     ..ProxySettings::default()
/// };
/// assert_eq!(settings.proxy.port(), 3128);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxySettings {
    /// The proxy address processes in the guest use (the agent).
    pub proxy: SocketAddr,
    /// The proxy address for containers inside the guest (Docker CLI config), or `None` to write
    /// no container config.
    pub container_proxy: Option<SocketAddr>,
    /// Destinations that bypass the proxy, after the fixed loopback entries.
    pub no_proxy: Vec<NoProxyEntry>,
    /// The session user's home, for per-user tool config (Gradle, Docker CLI).
    pub home: GuestPath,
}

impl Default for ProxySettings {
    fn default() -> Self {
        Self {
            proxy: DEFAULT_PROXY,
            container_proxy: Some(DEFAULT_CONTAINER_PROXY),
            no_proxy: Vec::new(),
            home: default_home(),
        }
    }
}

#[expect(
    clippy::expect_used,
    reason = "invariant: DEFAULT_HOME is a constant valid guest path (unit test)"
)]
fn default_home() -> GuestPath {
    GuestPath::new(DEFAULT_HOME).expect("DEFAULT_HOME is a valid guest path")
}

/// One destination that bypasses the proxy: a host name (which also covers its subdomains, as
/// curl and most tools read `NO_PROXY`), a `.suffix` (subdomains only), or an IP address.
///
/// CIDR ranges, wildcards and ports are refused: half the tools don't read them (T-030 §4), and
/// a value that works in some tools and not others is worse than none.
///
/// ```
/// use puddle_guest_env::NoProxyEntry;
/// assert_eq!(NoProxyEntry::new("Build.Corp.Example").unwrap().as_str(), "build.corp.example");
/// assert!(NoProxyEntry::new("10.0.0.0/8").is_err());
/// assert!(NoProxyEntry::new("*.corp.example").is_err());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NoProxyEntry(Kind);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Kind {
    Name(String),
    Suffix(String),
    Ip(IpAddr),
}

impl NoProxyEntry {
    /// Checks `entry` and normalises it (lower case; an IPv6 address without brackets).
    ///
    /// # Errors
    ///
    /// [`ConfigError::NoProxyEntry`] when `entry` is empty, too long, a CIDR range, a wildcard,
    /// has a port, or isn't a valid host name or IP address.
    pub fn new(entry: &str) -> Result<Self, ConfigError> {
        let bad = |reason| ConfigError::NoProxyEntry {
            entry: entry.to_owned(),
            reason,
        };
        if entry.is_empty() {
            return Err(bad("is empty"));
        }
        if entry.contains('/') {
            return Err(bad(
                "CIDR ranges are not supported by every tool; name the hosts",
            ));
        }
        if entry.contains('*') {
            return Err(bad("wildcards are not supported; use a .suffix"));
        }
        let unbracketed = entry
            .strip_prefix('[')
            .and_then(|e| e.strip_suffix(']'))
            .unwrap_or(entry);
        if let Ok(ip) = unbracketed.parse::<IpAddr>() {
            return Ok(Self(Kind::Ip(ip)));
        }
        if entry.contains(':') {
            return Err(bad("ports are not supported"));
        }
        let (suffix, name) = match entry.strip_prefix('.') {
            Some(rest) => (true, rest),
            None => (false, entry),
        };
        check_name(name).map_err(bad)?;
        let name = name.to_ascii_lowercase();
        Ok(Self(if suffix {
            Kind::Suffix(name)
        } else {
            Kind::Name(name)
        }))
    }

    /// The entry as it goes into `NO_PROXY` (`.suffix` with its dot, IPv6 without brackets).
    #[must_use]
    pub fn as_str(&self) -> String {
        match &self.0 {
            Kind::Name(n) => n.clone(),
            Kind::Suffix(s) => format!(".{s}"),
            Kind::Ip(ip) => ip.to_string(),
        }
    }

    /// The entry in Java's `http.nonProxyHosts` syntax: a name matches itself and its subdomains
    /// (as in `NO_PROXY`), a suffix only subdomains, an IPv6 address in brackets.
    pub(crate) fn java_patterns(&self) -> Vec<String> {
        match &self.0 {
            Kind::Name(n) => vec![n.clone(), format!("*.{n}")],
            Kind::Suffix(s) => vec![format!("*.{s}")],
            Kind::Ip(ip) => vec![java_ip(*ip)],
        }
    }

    /// The exact host apt should reach directly, if apt can express it (a name or IPv4 address;
    /// apt has no suffix match, and an IPv6 address can't be a config key).
    pub(crate) fn apt_host(&self) -> Option<String> {
        match &self.0 {
            Kind::Name(n) => Some(n.clone()),
            Kind::Ip(IpAddr::V4(ip)) => Some(ip.to_string()),
            Kind::Suffix(_) | Kind::Ip(IpAddr::V6(_)) => None,
        }
    }

    pub(crate) fn ip(ip: IpAddr) -> Self {
        Self(Kind::Ip(ip))
    }

    pub(crate) fn name(name: &str) -> Self {
        Self(Kind::Name(name.to_owned()))
    }
}

impl fmt::Display for NoProxyEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_str())
    }
}

/// An IP address the way Java's proxy patterns write it.
pub(crate) fn java_ip(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("[{v6}]"),
    }
}

/// The loopback entries every config starts with (`NO_PROXY` and Java alike).
pub(crate) fn loopback_entries() -> [NoProxyEntry; 3] {
    [
        NoProxyEntry::name("localhost"),
        NoProxyEntry::ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        NoProxyEntry::ip(IpAddr::V6(Ipv6Addr::LOCALHOST)),
    ]
}

fn check_name(name: &str) -> Result<(), &'static str> {
    if name.is_empty() {
        return Err("is empty");
    }
    if name.len() > MAX_NAME_LEN {
        return Err("is longer than 253 characters");
    }
    for label in name.split('.') {
        if label.is_empty() {
            return Err("has an empty label");
        }
        if label.len() > MAX_LABEL_LEN {
            return Err("has a label longer than 63 characters");
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err("may hold only letters, digits, '-' and '.' (IDNA names in ASCII form)");
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("has a label starting or ending with '-'");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_the_agent_the_bridge_and_root() {
        let s = ProxySettings::default();
        assert_eq!(s.proxy.to_string(), "127.0.0.1:3128");
        assert_eq!(s.container_proxy.unwrap().to_string(), "172.17.0.1:3128");
        assert_eq!(s.home.as_str(), "/root");
        assert_eq!(s.no_proxy, []);
    }

    #[test]
    fn accepted_entries_are_normalised() {
        for (input, out) in [
            ("Example.COM", "example.com"),
            (".corp.example", ".corp.example"),
            ("host-1", "host-1"),
            ("10.1.2.3", "10.1.2.3"),
            ("fd00::1", "fd00::1"),
            ("[fd00::1]", "fd00::1"),
            ("xn--bcher-kva.example", "xn--bcher-kva.example"),
        ] {
            assert_eq!(NoProxyEntry::new(input).unwrap().as_str(), out, "{input}");
            assert_eq!(NoProxyEntry::new(input).unwrap().to_string(), out);
        }
    }

    #[test]
    fn refused_entries_say_why() {
        let long_label = format!("{}.example", "a".repeat(64));
        let long_name = ["a"; 128].join(".");
        for (input, reason) in [
            ("", "empty"),
            ("10.0.0.0/8", "CIDR"),
            ("*.corp", "wildcards"),
            ("host:8080", "ports"),
            (".", "empty"),
            ("a..b", "empty label"),
            ("bad_name", "letters"),
            ("b\u{fc}cher.example", "letters"),
            ("-a.example", "'-'"),
            ("a-.example", "'-'"),
            ("a b", "letters"),
            ("a,b", "letters"),
            ("a\"b", "letters"),
            (long_label.as_str(), "63"),
            (long_name.as_str(), "253"),
        ] {
            let err = NoProxyEntry::new(input).unwrap_err();
            let ConfigError::NoProxyEntry { entry, reason: r } = &err else {
                panic!("{err:?}")
            };
            assert_eq!(entry, input);
            assert!(r.contains(reason), "{input:?}: {err}");
        }
    }

    #[test]
    fn java_and_apt_forms() {
        let e = |s| NoProxyEntry::new(s).unwrap();
        assert_eq!(
            e("corp.example").java_patterns(),
            ["corp.example", "*.corp.example"]
        );
        assert_eq!(e(".corp.example").java_patterns(), ["*.corp.example"]);
        assert_eq!(e("fd00::1").java_patterns(), ["[fd00::1]"]);
        assert_eq!(e("10.0.0.1").java_patterns(), ["10.0.0.1"]);
        assert_eq!(
            e("corp.example").apt_host().as_deref(),
            Some("corp.example")
        );
        assert_eq!(e("10.0.0.1").apt_host().as_deref(), Some("10.0.0.1"));
        assert_eq!(e(".corp.example").apt_host(), None);
        assert_eq!(e("fd00::1").apt_host(), None);
    }
}
