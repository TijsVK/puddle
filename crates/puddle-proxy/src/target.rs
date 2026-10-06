// SPDX-License-Identifier: GPL-3.0-or-later
//! The destination of a request, normalised into a [`Host`] the rules engine accepts.
//!
//! Normalisation here is the minimum the proxy needs to be safe: ASCII lower case, one trailing
//! dot removed, IP literals in canonical form, and anything else that [`Host::parse_normalised`]
//! refuses (non-canonical numbers such as `0x7f.1`, `_`, empty labels) is a `400`. Non-ASCII
//! names are refused until T-132 adds IDNA.

use std::net::IpAddr;

use puddle_types::Host;

/// A normalised destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Target {
    /// The host.
    pub(crate) host: Host,
    /// The port.
    pub(crate) port: u16,
}

impl Target {
    /// The `Host` header value for an absolute-form request: the authority, without the port when
    /// it is 80, with brackets around an IPv6 literal.
    pub(crate) fn host_header(&self) -> String {
        let host = match &self.host {
            Host::Ip(IpAddr::V6(ip)) => format!("[{ip}]"),
            other => other.to_string(),
        };
        if self.port == 80 {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }
}

/// Normalises a host as the guest wrote it.
pub(crate) fn normalise_host(raw: &str) -> Result<Host, &'static str> {
    if let Ok(ip) = raw.parse::<IpAddr>() {
        return Ok(Host::Ip(ip));
    }
    if !raw.is_ascii() {
        return Err("non-ASCII host names are not supported yet");
    }
    let lower = raw.to_ascii_lowercase();
    let name = lower.strip_suffix('.').unwrap_or(&lower);
    if name.contains(':') {
        return Err("not a valid IP address");
    }
    match Host::parse_normalised(name) {
        Ok(Host::Name(name)) => Ok(Host::Name(name)),
        // An IPv4 literal with a trailing dot ("1.2.3.4.") is refused: resolvers disagree on it.
        Ok(Host::Ip(_)) | Err(_) => Err("not a valid host name"),
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn norm(raw: &str) -> Result<String, &'static str> {
        normalise_host(raw).map(|h| h.to_string())
    }

    #[test]
    fn names_are_lower_cased_and_lose_one_trailing_dot() {
        assert_eq!(norm("Example.COM"), Ok("example.com".into()));
        assert_eq!(norm("example.com."), Ok("example.com".into()));
        assert_eq!(norm("localhost"), Ok("localhost".into()));
        assert!(norm("example.com..").is_err());
    }

    #[test]
    fn ip_literals_come_out_canonical() {
        assert_eq!(norm("127.0.0.1"), Ok("127.0.0.1".into()));
        assert_eq!(norm("2001:DB8:0::1"), Ok("2001:db8::1".into()));
        assert_eq!(
            norm("::ffff:169.254.169.254"),
            Ok("::ffff:169.254.169.254".into())
        );
    }

    #[test]
    fn numbers_resolvers_would_reinterpret_are_refused() {
        for raw in [
            "2852039166",
            "0x7f.1",
            "0177.0.0.1",
            "127.1",
            "1.2.3.4.",
            "01.2.3.4",
            "1.2.3.256",
        ] {
            assert!(norm(raw).is_err(), "{raw}");
        }
    }

    #[test]
    fn junk_is_refused() {
        for raw in [
            "",
            ".",
            "a_b.com",
            "bücher.example",
            "*.example.com",
            "a..b",
            "-a.com",
            "1:2",
        ] {
            assert!(norm(raw).is_err(), "{raw}");
        }
        assert_eq!(
            norm("bücher.example"),
            Err("non-ASCII host names are not supported yet")
        );
    }

    #[test]
    fn host_header_omits_port_80_and_brackets_ipv6() {
        let t = |h: &str, port| Target {
            host: normalise_host(h).unwrap(),
            port,
        };
        assert_eq!(t("example.com", 80).host_header(), "example.com");
        assert_eq!(t("example.com", 8080).host_header(), "example.com:8080");
        assert_eq!(t("::1", 80).host_header(), "[::1]");
        assert_eq!(t("::1", 8080).host_header(), "[::1]:8080");
        assert_eq!(t("10.0.0.1", 81).host_header(), "10.0.0.1:81");
    }

    proptest! {
        /// A normalised host is a fixed point: normalising its text again gives the same host.
        #[test]
        fn normalisation_is_idempotent(raw in "\\PC{0,40}") {
            if let Ok(host) = normalise_host(&raw) {
                prop_assert_eq!(normalise_host(&host.to_string()), Ok(host));
            }
        }
    }
}
