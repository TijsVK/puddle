// SPDX-License-Identifier: GPL-3.0-or-later
//! Which names a CA may certify, and the host names a leaf is issued for.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::CaError;

const MAX_DNS_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;

/// The names a CA may certify: DNS subtrees (a name and every name below it, RFC 5280
/// §4.2.1.10) and IP prefixes.
///
/// The proxy CA permits the workspace's bound hosts (`github.com`, `dev.azure.com`); a later dev CA
/// would permit `localhost`, `127.0.0.1/32` and `::1/128`. Address families with no permitted
/// prefix are excluded outright in the certificate, because RFC 5280 leaves a name form without
/// a permitted subtree unconstrained.
///
/// ```
/// use puddle_ca::NameConstraints;
///
/// let constraints = NameConstraints::new()
///     .permit_dns("GitHub.com.")?
///     .permit_ip("127.0.0.1".parse().unwrap(), 32)?;
/// assert!(constraints.permits("api.github.com"));
/// assert!(constraints.permits("127.0.0.1"));
/// assert!(!constraints.permits("github.com.evil.example"));
/// # Ok::<(), puddle_ca::CaError>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NameConstraints {
    dns: Vec<String>,
    ips: Vec<IpPrefix>,
}

impl NameConstraints {
    /// No permitted names yet. A CA needs at least one DNS name.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Also permit `name` and every name below it. The name is lower-cased and a trailing dot
    /// dropped.
    ///
    /// # Errors
    ///
    /// [`CaError::InvalidConstraint`] when `name` is not a plain DNS name (no wildcards, no
    /// leading dot, ASCII only: IDNs are given in their `xn--` form) or is an IP address.
    pub fn permit_dns(mut self, name: &str) -> Result<Self, CaError> {
        let Some(Host::Dns(name)) = Host::parse(name) else {
            return Err(CaError::InvalidConstraint {
                value: name.to_owned(),
                reason: "not a DNS name",
            });
        };
        if !self.dns.contains(&name) {
            self.dns.push(name);
        }
        Ok(self)
    }

    /// Also permit the addresses in `addr/prefix`. Host bits below the prefix are cleared.
    ///
    /// # Errors
    ///
    /// [`CaError::InvalidConstraint`] when `prefix` exceeds the address length.
    pub fn permit_ip(mut self, addr: IpAddr, prefix: u8) -> Result<Self, CaError> {
        let prefix = IpPrefix::new(addr, prefix).ok_or_else(|| CaError::InvalidConstraint {
            value: format!("{addr}/{prefix}"),
            reason: "prefix longer than the address",
        })?;
        if !self.ips.contains(&prefix) {
            self.ips.push(prefix);
        }
        Ok(self)
    }

    /// Whether a leaf for `host` (a DNS name or an IP address) falls within these constraints.
    /// An invalid host is not permitted.
    #[must_use]
    pub fn permits(&self, host: &str) -> bool {
        Host::parse(host).is_some_and(|host| self.permits_host(&host))
    }

    pub(crate) fn permits_host(&self, host: &Host) -> bool {
        match host {
            Host::Dns(name) => self.dns.iter().any(|base| dns_within(name, base)),
            Host::Ip(addr) => self.ips.iter().any(|prefix| prefix.contains(*addr)),
        }
    }

    pub(crate) fn has_dns(&self) -> bool {
        !self.dns.is_empty()
    }

    /// The certificate extension: the permitted subtrees, plus an excluded "everything" for each
    /// IP family with no permitted prefix.
    pub(crate) fn to_rcgen(&self) -> rcgen::NameConstraints {
        let mut permitted: Vec<rcgen::GeneralSubtree> = self
            .dns
            .iter()
            .map(|name| rcgen::GeneralSubtree::DnsName(name.clone()))
            .collect();
        permitted.extend(
            self.ips
                .iter()
                .map(|prefix| rcgen::GeneralSubtree::IpAddress(prefix.to_rcgen())),
        );
        let mut excluded = Vec::new();
        if !self.ips.iter().any(|prefix| prefix.addr.is_ipv4()) {
            excluded.push(rcgen::GeneralSubtree::IpAddress(
                rcgen::CidrSubnet::from_v4_prefix([0; 4], 0),
            ));
        }
        if !self.ips.iter().any(|prefix| prefix.addr.is_ipv6()) {
            excluded.push(rcgen::GeneralSubtree::IpAddress(
                rcgen::CidrSubnet::from_v6_prefix([0; 16], 0),
            ));
        }
        rcgen::NameConstraints {
            permitted_subtrees: permitted,
            excluded_subtrees: excluded,
        }
    }
}

/// `name` equals `base` or lies below it, on a label boundary.
fn dns_within(name: &str, base: &str) -> bool {
    name == base
        || name
            .strip_suffix(base)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

/// A validated, normalised leaf host.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum Host {
    Dns(String),
    Ip(IpAddr),
}

impl Host {
    /// An IP address (IPv6 with or without brackets) or a lower-cased DNS name without its
    /// trailing dot. `None` for anything else, including wildcards.
    pub(crate) fn parse(input: &str) -> Option<Self> {
        let unbracketed = input
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
            .unwrap_or(input);
        if let Ok(addr) = unbracketed.parse::<IpAddr>() {
            return Some(Self::Ip(addr));
        }
        let name = input
            .strip_suffix('.')
            .unwrap_or(input)
            .to_ascii_lowercase();
        valid_dns(&name).then_some(Self::Dns(name))
    }
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dns(name) => f.write_str(name),
            Self::Ip(addr) => write!(f, "{addr}"),
        }
    }
}

/// Lower-case letters, digits, `-` and `_` in labels of 1–63 bytes, no label starting or ending
/// with `-`, at most 253 bytes, and not all-numeric in the last label (so `1.2.3.4.5` and other
/// strings that look like addresses are refused).
fn valid_dns(name: &str) -> bool {
    if name.is_empty() || name.len() > MAX_DNS_LEN {
        return false;
    }
    let labels_ok = name.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= MAX_LABEL_LEN
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
    });
    let last_not_numeric = name
        .rsplit('.')
        .next()
        .is_some_and(|last| !last.bytes().all(|b| b.is_ascii_digit()));
    labels_ok && last_not_numeric
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IpPrefix {
    addr: IpAddr,
    len: u8,
}

impl IpPrefix {
    fn new(addr: IpAddr, len: u8) -> Option<Self> {
        let addr = match addr {
            IpAddr::V4(v4) => IpAddr::V4(Ipv4Addr::from(
                u32::try_from(mask_bits(u32::from(v4).into(), len, 32)?).ok()?,
            )),
            IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(mask_bits(u128::from(v6), len, 128)?)),
        };
        Some(Self { addr, len })
    }

    fn contains(&self, addr: IpAddr) -> bool {
        match (self.addr, addr) {
            (IpAddr::V4(base), IpAddr::V4(addr)) => {
                mask_bits(u32::from(addr).into(), self.len, 32) == Some(u32::from(base).into())
            }
            (IpAddr::V6(base), IpAddr::V6(addr)) => {
                mask_bits(u128::from(addr), self.len, 128) == Some(u128::from(base))
            }
            _ => false,
        }
    }

    fn to_rcgen(self) -> rcgen::CidrSubnet {
        rcgen::CidrSubnet::from_addr_prefix(self.addr, self.len)
    }
}

/// `value` (an address of `bits` bits, right-aligned) with every bit after the first `len`
/// cleared; `None` if `len > bits`.
fn mask_bits(value: u128, len: u8, bits: u8) -> Option<u128> {
    if len > bits {
        return None;
    }
    let host_bits = u32::from(bits - len);
    let mask = u128::MAX.checked_shl(host_bits).unwrap_or(0);
    Some(value & mask)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn dns_subtree_covers_the_name_and_names_below_it_only() {
        let c = NameConstraints::new().permit_dns("github.com").unwrap();
        assert!(c.permits("github.com"));
        assert!(c.permits("GITHUB.COM."));
        assert!(c.permits("api.github.com"));
        assert!(!c.permits("evilgithub.com"));
        assert!(!c.permits("github.com.evil.example"));
        assert!(!c.permits("gitlab.com"));
        assert!(!c.permits("140.82.112.3"));
    }

    #[test]
    fn invalid_dns_constraints_are_refused() {
        for bad in [
            "",
            ".",
            "*.github.com",
            ".github.com",
            "git hub.com",
            "-a.com",
            "a-.com",
            "a..com",
            "1.2.3.4",
            "[::1]",
            "1.2.3.4.5",
            "bücher.example",
            &"a".repeat(64),
        ] {
            assert!(
                matches!(
                    NameConstraints::new().permit_dns(bad),
                    Err(CaError::InvalidConstraint { .. })
                ),
                "{bad:?} accepted"
            );
        }
    }

    #[test]
    fn duplicate_constraints_are_kept_once() {
        let c = NameConstraints::new()
            .permit_dns("a.example")
            .unwrap()
            .permit_dns("A.example.")
            .unwrap()
            .permit_ip("10.0.0.1".parse().unwrap(), 8)
            .unwrap()
            .permit_ip("10.9.9.9".parse().unwrap(), 8)
            .unwrap();
        assert_eq!(c.dns.len(), 1);
        assert_eq!(c.ips.len(), 1);
    }

    #[test]
    fn ip_prefixes_match_by_family_and_prefix() {
        let c = NameConstraints::new()
            .permit_dns("localhost")
            .unwrap()
            .permit_ip("127.0.0.1".parse().unwrap(), 32)
            .unwrap()
            .permit_ip("fd00::".parse().unwrap(), 8)
            .unwrap();
        assert!(c.permits("127.0.0.1"));
        assert!(!c.permits("127.0.0.2"));
        assert!(c.permits("[fd12::1]"));
        assert!(c.permits("fdff::1"));
        assert!(!c.permits("fe80::1"));
        assert!(!c.permits("::ffff:127.0.0.1"));
        assert!(c.permits("app.localhost"));
    }

    #[test]
    fn prefix_longer_than_the_address_is_refused() {
        assert!(
            NameConstraints::new()
                .permit_ip("10.0.0.0".parse().unwrap(), 33)
                .is_err()
        );
        assert!(
            NameConstraints::new()
                .permit_ip("::".parse().unwrap(), 129)
                .is_err()
        );
        assert!(
            NameConstraints::new()
                .permit_ip("::".parse().unwrap(), 128)
                .is_ok()
        );
    }

    #[test]
    fn families_without_a_prefix_are_excluded_in_the_extension() {
        let dns_only = NameConstraints::new()
            .permit_dns("github.com")
            .unwrap()
            .to_rcgen();
        assert_eq!(dns_only.excluded_subtrees.len(), 2);
        let v4 = NameConstraints::new()
            .permit_dns("localhost")
            .unwrap()
            .permit_ip("127.0.0.1".parse().unwrap(), 32)
            .unwrap()
            .to_rcgen();
        assert_eq!(
            v4.excluded_subtrees,
            vec![rcgen::GeneralSubtree::IpAddress(
                rcgen::CidrSubnet::from_v6_prefix([0; 16], 0)
            )]
        );
        let both = NameConstraints::new()
            .permit_dns("localhost")
            .unwrap()
            .permit_ip("127.0.0.1".parse().unwrap(), 32)
            .unwrap()
            .permit_ip("::1".parse().unwrap(), 128)
            .unwrap()
            .to_rcgen();
        assert_eq!(both.excluded_subtrees, [] as [rcgen::GeneralSubtree; 0]);
        assert_eq!(both.permitted_subtrees.len(), 3);
    }

    #[test]
    fn host_display_round_trips() {
        assert_eq!(
            Host::parse("Api.GitHub.com.").unwrap().to_string(),
            "api.github.com"
        );
        assert_eq!(Host::parse("[::1]").unwrap().to_string(), "::1");
    }

    proptest! {
        #[test]
        fn a_name_is_permitted_only_on_a_label_boundary(
            base in "[a-z]{1,10}\\.[a-z]{2,5}",
            sub in "[a-z0-9]{1,10}",
            glue in "[a-z0-9]{1,5}",
        ) {
            let c = NameConstraints::new().permit_dns(&base).unwrap();
            let below = format!("{sub}.{base}");
            let glued = format!("{glue}{base}");
            let appended = format!("{base}.{sub}x");
            prop_assert!(c.permits(&below));
            prop_assert!(!c.permits(&glued));
            prop_assert!(!c.permits(&appended));
        }

        #[test]
        fn host_parsing_never_panics_and_is_idempotent(input in "\\PC{0,80}") {
            if let Some(host) = Host::parse(&input) {
                prop_assert_eq!(Host::parse(&host.to_string()), Some(host));
            }
        }
    }
}
