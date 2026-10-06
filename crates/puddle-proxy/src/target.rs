// SPDX-License-Identifier: GPL-3.0-or-later
//! The destination of a request, normalised into a [`Host`] the rules engine accepts
//! (`puddle_netpolicy::normalise_host`: lower case, IDNA to ASCII, LDH labels, canonical IP
//! literals; anything else is a `400`).

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

#[cfg(test)]
mod tests {
    use puddle_netpolicy::normalise_host;

    use super::*;

    #[test]
    fn host_header_omits_port_80_and_brackets_ipv6() {
        let t = |h: &str, port| Target {
            host: normalise_host(h).unwrap().into_host(),
            port,
        };
        assert_eq!(t("example.com", 80).host_header(), "example.com");
        assert_eq!(t("example.com", 8080).host_header(), "example.com:8080");
        assert_eq!(
            t("bücher.example", 80).host_header(),
            "xn--bcher-kva.example"
        );
        assert_eq!(t("::1", 80).host_header(), "[::1]");
        assert_eq!(t("::1", 8080).host_header(), "[::1]:8080");
        assert_eq!(t("10.0.0.1", 81).host_header(), "10.0.0.1:81");
    }
}
