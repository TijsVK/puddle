// SPDX-License-Identifier: GPL-3.0-or-later
//! Normalised egress destinations.
//!
//! The proxy normalises what a guest asks for (W2); everything downstream, the rules engine
//! included, accepts only these validated types and never parses raw input itself
//! (`docs/spec/rules.md` §1).

use std::fmt;
use std::net::IpAddr;

use crate::ValidationError;

/// Longest DNS name puddle accepts, in bytes, without a trailing dot.
pub const MAX_NAME_LEN: usize = 253;
/// Longest DNS label, in bytes.
pub const MAX_LABEL_LEN: usize = 63;

const WHAT_NAME: &str = "host name";
const WHAT_IP: &str = "ip literal";

/// A DNS name in puddle's normal form: lower-case ASCII (IDNA already applied), LDH labels of
/// 1 to 63 bytes, no trailing dot, at most 253 bytes, last label not all digits (such a name
/// reads as an IPv4 address to many resolvers).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DomainName(String);

impl DomainName {
    /// Accepts `name` only if it is already normalised; never rewrites it.
    ///
    /// # Errors
    /// A [`ValidationError`] naming the first rule `name` breaks.
    pub fn parse_normalised(name: &str) -> Result<Self, ValidationError> {
        let fail = |reason: &str| ValidationError::new(WHAT_NAME, name, reason);
        if name.is_empty() {
            return Err(fail("must not be empty"));
        }
        if name.len() > MAX_NAME_LEN {
            return Err(fail("must be at most 253 characters"));
        }
        let mut last = "";
        for label in name.split('.') {
            check_label(label).map_err(fail)?;
            last = label;
        }
        if last.bytes().all(|b| b.is_ascii_digit()) {
            return Err(fail("must not end in an all-numeric label"));
        }
        Ok(Self(name.to_owned()))
    }

    /// The name as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The labels from left to right.
    pub fn labels(&self) -> impl Iterator<Item = &str> {
        self.0.split('.')
    }
}

fn check_label(label: &str) -> Result<(), &'static str> {
    let bytes = label.as_bytes();
    let (Some(first), Some(last)) = (bytes.first(), bytes.last()) else {
        return Err("must not have an empty label");
    };
    if bytes.len() > MAX_LABEL_LEN {
        return Err("must not have a label longer than 63 characters");
    }
    let ldh = |b: &u8| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-';
    if !bytes.iter().all(ldh) || *first == b'-' || *last == b'-' {
        return Err("may only contain a-z, 0-9 and inner '-' per label");
    }
    Ok(())
}

impl fmt::Display for DomainName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A destination as the proxy normalised it: a [`DomainName`] or a canonical IP literal.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Host {
    /// A DNS name.
    Name(DomainName),
    /// An IP literal (IPv4 dotted quad, or IPv6 per RFC 5952 without brackets).
    Ip(IpAddr),
}

impl Host {
    /// Accepts `text` only if it is already a normalised name or a canonical IP literal.
    ///
    /// ```
    /// use puddle_types::Host;
    /// assert!(Host::parse_normalised("api.example.com").is_ok());
    /// assert!(Host::parse_normalised("2001:db8::1").is_ok());
    /// assert!(Host::parse_normalised("API.example.com").is_err());
    /// assert!(Host::parse_normalised("2001:DB8:0::1").is_err());
    /// ```
    ///
    /// # Errors
    /// A [`ValidationError`] when `text` is neither.
    pub fn parse_normalised(text: &str) -> Result<Self, ValidationError> {
        if let Ok(ip) = text.parse::<IpAddr>() {
            return if ip.to_string() == text {
                Ok(Self::Ip(ip))
            } else {
                Err(ValidationError::new(
                    WHAT_IP,
                    text,
                    "must be in canonical form",
                ))
            };
        }
        if text.contains(':') {
            return Err(ValidationError::new(
                WHAT_IP,
                text,
                "must be in canonical form",
            ));
        }
        DomainName::parse_normalised(text).map(Self::Name)
    }

    /// The name, or `None` for an IP literal.
    #[must_use]
    pub fn name(&self) -> Option<&DomainName> {
        match self {
            Self::Name(name) => Some(name),
            Self::Ip(_) => None,
        }
    }
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name(name) => name.fmt(f),
            Self::Ip(ip) => ip.fmt(f),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn reason(text: &str) -> String {
        Host::parse_normalised(text)
            .unwrap_err()
            .reason()
            .to_owned()
    }

    #[test]
    fn accepts_normalised_names() {
        for ok in [
            "example.com",
            "a.b-c.example",
            "localhost",
            "xn--bcher-kva.example",
            "1a.com",
        ] {
            assert!(Host::parse_normalised(ok).is_ok(), "{ok}");
        }
    }

    #[test]
    fn refuses_unnormalised_names() {
        let cases = [
            ("", "must not be empty"),
            ("Example.com", "may only contain"),
            ("example.com.", "empty label"),
            (".example.com", "empty label"),
            ("a..b", "empty label"),
            ("-a.com", "may only contain"),
            ("a-.com", "may only contain"),
            ("a_b.com", "may only contain"),
            ("bücher.example", "may only contain"),
            ("*.example.com", "may only contain"),
            ("01.2.3.4", "all-numeric"),
            ("example.123", "all-numeric"),
        ];
        for (input, want) in cases {
            assert!(reason(input).contains(want), "{input:?}: {}", reason(input));
        }
        let long_label = format!("{}.com", "a".repeat(64));
        assert!(reason(&long_label).contains("longer than 63"));
        let long_name = vec!["a".repeat(63); 4].join(".");
        assert!(reason(&long_name).contains("at most 253"));
        assert_eq!(
            Host::parse_normalised("Example.com").unwrap_err().what(),
            "host name"
        );
    }

    #[test]
    fn ip_literals_must_be_canonical() {
        for ok in ["10.0.0.1", "::1", "::ffff:10.0.0.1"] {
            assert!(
                matches!(Host::parse_normalised(ok), Ok(Host::Ip(_))),
                "{ok}"
            );
        }
        for bad in [
            "0:0:0:0:0:0:0:1",
            "2001:DB8::1",
            "[::1]",
            "::1%eth0",
            "fe80::1:",
        ] {
            let err = Host::parse_normalised(bad).unwrap_err();
            assert_eq!(err.what(), "ip literal", "{bad}");
        }
    }

    #[test]
    fn host_accessors_and_display() {
        let name = Host::parse_normalised("a.example.com").unwrap();
        assert_eq!(name.to_string(), "a.example.com");
        let labels: Vec<_> = name.name().unwrap().labels().collect();
        assert_eq!(labels, ["a", "example", "com"]);
        assert_eq!(name.name().unwrap().as_str(), "a.example.com");
        let ip = Host::parse_normalised("2001:db8::1").unwrap();
        assert!(ip.name().is_none());
        assert_eq!(ip.to_string(), "2001:db8::1");
    }

    proptest! {
        #[test]
        fn accepted_hosts_display_as_their_input(s in "[a-z0-9.:-]{1,40}") {
            if let Ok(host) = Host::parse_normalised(&s) {
                prop_assert_eq!(host.to_string(), s);
            }
        }

        #[test]
        fn ips_round_trip(ip in any::<IpAddr>()) {
            let text = ip.to_string();
            prop_assert_eq!(Host::parse_normalised(&text), Ok(Host::Ip(ip)));
        }

        #[test]
        fn arbitrary_input_never_panics(s in ".{0,300}") {
            let _ = Host::parse_normalised(&s);
        }
    }
}
