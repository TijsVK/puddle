// SPDX-License-Identifier: GPL-3.0-or-later
//! The name stage: turn the host a guest asked for into puddle's normal form, before any rule
//! lookup and before DNS (`docs/spec/rules.md` §1).
//!
//! Strict on purpose: what comes out is either a canonical IP literal or a [`DomainName`]
//! (lower-case ASCII, IDNA applied, LDH labels, no trailing dot, at most 253 bytes). Anything a
//! resolver could read in two ways is refused rather than guessed at.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use idna::uts46::{AsciiDenyList, DnsLength, Hyphens, Uts46};
use puddle_types::{DomainName, Host, LocalCategory};

/// Longest raw host accepted, in bytes, before any mapping. Bounds the IDNA work a hostile guest
/// can cause; a valid name is at most 253 bytes, and its Unicode form at most a few times that.
pub const MAX_RAW_HOST_LEN: usize = 1024;

/// Longest prefix of a refused host kept in a [`NameError`] (it came from the guest).
const MAX_ECHOED_CHARS: usize = 64;

/// Names that mean "the metadata service" wherever they are resolved.
const METADATA_NAMES: [&str; 5] = [
    "metadata",
    "metadata.google.internal",
    "metadata.goog",
    "instance-data",
    "instance-data.ec2.internal",
];

/// A normalised destination, plus the local category its *name* alone puts it in.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Target {
    host: Host,
    named: Option<LocalCategory>,
}

impl Target {
    /// The normalised host, what rules match on.
    #[must_use]
    pub fn host(&self) -> &Host {
        &self.host
    }

    /// The category a name is in by itself: [`LocalCategory::Loopback`] for `localhost` and
    /// `*.localhost`, [`LocalCategory::Metadata`] for the cloud metadata names. `None` for IP
    /// literals (classify those) and ordinary names (classify what they resolve to).
    #[must_use]
    pub fn named_category(&self) -> Option<LocalCategory> {
        self.named
    }

    /// The target for a host that is already normalised (from a rule or a stored request).
    #[must_use]
    pub fn from_host(host: Host) -> Self {
        let named = host.name().and_then(|n| named_category(n.as_str()));
        Self { host, named }
    }

    /// The target as a [`Host`].
    #[must_use]
    pub fn into_host(self) -> Host {
        self.host
    }
}

/// The guest's host could not be normalised. The proxy answers with a client error (400) or, for
/// a non-canonical number, a refusal that says which address it decodes to.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum NameError {
    /// A number that platform resolvers would read as an IPv4 address (`127.1`, `0x7f000001`,
    /// `0177.0.0.1`). Refused as a matter of form: written canonically, it falls under that
    /// address's category like any literal.
    #[error("{input:?} is not a canonical IP address{}", decoded_hint(*.decoded))]
    NonCanonicalIp {
        /// The refused host (truncated, from the guest).
        input: String,
        /// The address it decodes to, if it decodes at all.
        decoded: Option<Ipv4Addr>,
    },
    /// Not a host name or IP literal.
    #[error("invalid host {input:?}: {reason}")]
    Invalid {
        /// The refused host (truncated, from the guest).
        input: String,
        /// Which rule it breaks.
        reason: &'static str,
    },
}

fn decoded_hint(decoded: Option<Ipv4Addr>) -> String {
    decoded.map_or_else(
        || ": it reads as a number but decodes to no address".to_owned(),
        |ip| format!(": it decodes to {ip}, write that instead"),
    )
}

fn echo(raw: &str) -> String {
    let mut out: String = raw.chars().take(MAX_ECHOED_CHARS).collect();
    if raw.chars().count() > MAX_ECHOED_CHARS {
        out.push('…');
    }
    out
}

fn invalid(raw: &str, reason: &'static str) -> NameError {
    NameError::Invalid {
        input: echo(raw),
        reason,
    }
}

/// Normalises the host part of a request target (`CONNECT` authority or absolute-form URL, the
/// port already split off; IPv6 may still be in brackets).
///
/// - IPv6 literals are parsed with or without brackets and written per RFC 5952; zone IDs are
///   refused.
/// - Names are mapped with UTS #46 (non-transitional, STD3 ASCII rules: upper case folded,
///   full-width characters mapped, Unicode to `xn--` Punycode), then must be LDH labels.
///   One trailing dot is dropped.
/// - A name whose last label is a number (WHATWG "ends in a number") is an IPv4 address: the
///   canonical dotted quad is accepted, any other spelling is [`NameError::NonCanonicalIp`].
///
/// ```
/// use puddle_netpolicy::normalise_host;
/// use puddle_types::LocalCategory;
///
/// assert_eq!(normalise_host("Bücher.Example.").unwrap().host().to_string(), "xn--bcher-kva.example");
/// assert_eq!(normalise_host("[2001:DB8::1]").unwrap().host().to_string(), "2001:db8::1");
/// assert_eq!(normalise_host("LOCALHOST").unwrap().named_category(), Some(LocalCategory::Loopback));
/// assert!(normalise_host("127.1").is_err());
/// assert!(normalise_host("user@example.com").is_err());
/// ```
///
/// # Errors
/// [`NameError::NonCanonicalIp`] for a non-canonical number, [`NameError::Invalid`] for anything
/// else that isn't a host.
pub fn normalise_host(raw: &str) -> Result<Target, NameError> {
    if raw.is_empty() {
        return Err(invalid(raw, "is empty"));
    }
    if raw.len() > MAX_RAW_HOST_LEN {
        return Err(invalid(raw, "is too long"));
    }
    if let Some(inner) = raw.strip_prefix('[') {
        let inner = inner
            .strip_suffix(']')
            .ok_or_else(|| invalid(raw, "has an unclosed '['"))?;
        return parse_v6(raw, inner);
    }
    if raw.contains(':') {
        return parse_v6(raw, raw);
    }
    let ascii = Uts46::new()
        .to_ascii(
            raw.as_bytes(),
            AsciiDenyList::STD3,
            Hyphens::Allow,
            DnsLength::Ignore,
        )
        .map_err(|_| invalid(raw, "is not a valid host name (IDNA/LDH rules)"))?;
    let name = ascii.strip_suffix('.').unwrap_or(&ascii);
    if ends_in_a_number(name) {
        return match parse_ipv4_number(name) {
            Some(ip) if ip.to_string() == name => Ok(literal(IpAddr::V4(ip))),
            decoded => Err(NameError::NonCanonicalIp {
                input: echo(raw),
                decoded,
            }),
        };
    }
    let name = DomainName::parse_normalised(name).map_err(|e| NameError::Invalid {
        input: echo(raw),
        reason: name_rule(e.reason()),
    })?;
    let named = named_category(name.as_str());
    Ok(Target {
        host: Host::Name(name),
        named,
    })
}

fn literal(ip: IpAddr) -> Target {
    Target {
        host: Host::Ip(ip),
        named: None,
    }
}

fn parse_v6(raw: &str, text: &str) -> Result<Target, NameError> {
    if text.contains('%') {
        return Err(invalid(raw, "has an IPv6 zone ID"));
    }
    text.parse::<Ipv6Addr>()
        .map(|ip| literal(IpAddr::V6(ip)))
        .map_err(|_| invalid(raw, "is not a valid IPv6 address"))
}

/// `DomainName` reasons are `String`s; map the ones it can give to static text (it validates
/// what IDNA produced, so only length and empty labels are reachable here).
fn name_rule(reason: &str) -> &'static str {
    if reason.contains("253") {
        "is longer than 253 characters"
    } else if reason.contains("63") {
        "has a label longer than 63 characters"
    } else if reason.contains("empty") {
        "has an empty label"
    } else {
        "is not a valid host name"
    }
}

fn named_category(name: &str) -> Option<LocalCategory> {
    if name == "localhost" || name.ends_with(".localhost") {
        Some(LocalCategory::Loopback)
    } else if METADATA_NAMES.contains(&name) {
        Some(LocalCategory::Metadata)
    } else {
        None
    }
}

/// WHATWG URL "ends in a number": the last label is all digits, or `0x` followed by hex digits.
fn ends_in_a_number(name: &str) -> bool {
    let last = name.rsplit('.').next().unwrap_or(name);
    if !last.is_empty() && last.bytes().all(|b| b.is_ascii_digit()) {
        return true;
    }
    last.strip_prefix("0x")
        .is_some_and(|hex| hex.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// WHATWG / `inet_aton` IPv4 parsing: 1 to 4 parts, each decimal, `0`-prefixed octal or
/// `0x`-prefixed hex; the last part fills the remaining bytes. `None` if it isn't one.
fn parse_ipv4_number(name: &str) -> Option<Ipv4Addr> {
    let parts: Vec<&str> = name.split('.').collect();
    if parts.len() > 4 {
        return None;
    }
    let numbers = parts
        .iter()
        .map(|p| parse_ipv4_part(p))
        .collect::<Option<Vec<u64>>>()?;
    let (last, head) = numbers.split_last()?;
    if head.iter().any(|n| *n > 255) {
        return None;
    }
    let free_bits = 8 * (4 - head.len());
    if *last >= 1u64 << free_bits {
        return None;
    }
    let mut value = *last;
    for (i, n) in head.iter().enumerate() {
        value |= n << (24 - 8 * i);
    }
    u32::try_from(value).ok().map(Ipv4Addr::from_bits)
}

fn parse_ipv4_part(part: &str) -> Option<u64> {
    if let Some(hex) = part.strip_prefix("0x") {
        return if hex.is_empty() {
            Some(0)
        } else {
            u64::from_str_radix(hex, 16).ok()
        };
    }
    match part.strip_prefix('0') {
        Some(octal) if !octal.is_empty() => u64::from_str_radix(octal, 8).ok(),
        _ => part.parse().ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn norm(raw: &str) -> String {
        normalise_host(raw)
            .unwrap_or_else(|e| panic!("{raw:?}: {e}"))
            .host()
            .to_string()
    }

    fn reason(raw: &str) -> &'static str {
        match normalise_host(raw) {
            Err(NameError::Invalid { reason, .. }) => reason,
            other => panic!("{raw:?}: expected Invalid, got {other:?}"),
        }
    }

    fn decoded(raw: &str) -> Option<Ipv4Addr> {
        match normalise_host(raw) {
            Err(NameError::NonCanonicalIp { decoded, .. }) => decoded,
            other => panic!("{raw:?}: expected NonCanonicalIp, got {other:?}"),
        }
    }

    /// The normalisation table: input, normal form.
    #[test]
    fn normalisation_table() {
        let table = [
            // Plain names, case, trailing dot.
            ("example.com", "example.com"),
            ("EXAMPLE.com", "example.com"),
            ("example.com.", "example.com"),
            ("a-b.c-d.example", "a-b.c-d.example"),
            ("r3---sn-abc.googlevideo.com", "r3---sn-abc.googlevideo.com"),
            ("1e100.net", "1e100.net"),
            ("dead.cafe", "dead.cafe"),
            ("0x.example.com", "0x.example.com"),
            // IDNA: Unicode to Punycode, mapping of full-width and compatibility forms.
            ("bücher.example", "xn--bcher-kva.example"),
            ("BÜCHER.example", "xn--bcher-kva.example"),
            ("xn--bcher-kva.example", "xn--bcher-kva.example"),
            ("XN--BCHER-KVA.example", "xn--bcher-kva.example"),
            ("ｅｘａｍｐｌｅ.com", "example.com"),
            ("example。com", "example.com"),
            ("faß.de", "xn--fa-hia.de"),
            ("ⓛocalhost", "localhost"),
            // IP literals.
            ("10.0.0.1", "10.0.0.1"),
            ("127.0.0.1.", "127.0.0.1"),
            ("１２７.０.０.１", "127.0.0.1"),
            ("::1", "::1"),
            ("[::1]", "::1"),
            ("[2001:DB8:0:0::1]", "2001:db8::1"),
            ("0:0:0:0:0:0:0:1", "::1"),
            ("::FFFF:127.0.0.1", "::ffff:127.0.0.1"),
        ];
        for (raw, want) in table {
            assert_eq!(norm(raw), want, "{raw:?}");
            // Normal forms are fixed points and pass the shared type's own check.
            assert_eq!(norm(want), want, "{want:?}");
            assert!(Host::parse_normalised(want).is_ok(), "{want:?}");
        }
    }

    #[test]
    fn literals_and_names_land_in_the_right_variant() {
        assert!(matches!(
            normalise_host("[fe80::1]").unwrap().host(),
            Host::Ip(IpAddr::V6(_))
        ));
        assert!(matches!(
            normalise_host("１２７.０.０.１").unwrap().into_host(),
            Host::Ip(IpAddr::V4(ip)) if ip == Ipv4Addr::LOCALHOST
        ));
        assert!(
            normalise_host("example.com")
                .unwrap()
                .host()
                .name()
                .is_some()
        );
        for h in ["localhost", "metadata.goog", "example.com", "10.0.0.1"] {
            let t = normalise_host(h).unwrap();
            assert_eq!(Target::from_host(t.host().clone()), t, "{h}");
        }
    }

    #[test]
    fn refused_hosts_and_why() {
        let table = [
            ("", "is empty"),
            ("user@example.com", "IDNA/LDH"),
            ("a b.com", "IDNA/LDH"),
            ("exa/mple.com", "IDNA/LDH"),
            ("ex\\ample.com", "IDNA/LDH"),
            ("nul\0.com", "IDNA/LDH"),
            ("tab\t.com", "IDNA/LDH"),
            ("under_score.example", "IDNA/LDH"),
            ("percent%41.com", "IDNA/LDH"),
            ("*.example.com", "IDNA/LDH"),
            ("-lead.example", "valid host name"),
            ("trail-.example", "valid host name"),
            ("xn--zz.example", "IDNA/LDH"),
            ("ｕｓｅｒ＠example.com", "IDNA/LDH"),
            (".", "empty label"),
            ("..", "empty label"),
            ("a..b", "empty label"),
            (".example.com", "empty label"),
            ("example.com..", "empty label"),
            ("[::1", "unclosed"),
            ("[10.0.0.1]", "IPv6"),
            ("[]", "IPv6"),
            ("fe80::1%eth0", "zone"),
            ("[fe80::1%25eth0]", "zone"),
            ("::zz", "IPv6"),
            ("host:80", "IPv6"),
        ];
        for (raw, want) in table {
            assert!(reason(raw).contains(want), "{raw:?}: {}", reason(raw));
        }
        let long_label = format!("{}.com", "a".repeat(64));
        assert!(reason(&long_label).contains("63"));
        let long_name = vec!["a".repeat(63); 4].join(".");
        assert!(reason(&long_name).contains("253"));
        assert!(reason(&"a".repeat(MAX_RAW_HOST_LEN + 1)).contains("too long"));
    }

    #[test]
    fn non_canonical_numbers_decode_but_are_refused() {
        let metadata = Some(Ipv4Addr::new(169, 254, 169, 254));
        for raw in [
            "2852039166",
            "0xA9FEA9FE",
            "0251.0376.0251.0376",
            "169.254.43518",
            "0xa9.0xfe.0xa9.0xfe",
        ] {
            assert_eq!(decoded(raw), metadata, "{raw}");
        }
        for raw in ["0x7f.1", "127.1", "0177.0.0.1", "0x7f000001", "127.0.1"] {
            assert_eq!(decoded(raw), Some(Ipv4Addr::LOCALHOST), "{raw}");
        }
        assert_eq!(decoded("010.0.0.1"), Some(Ipv4Addr::new(8, 0, 0, 1)));
        assert_eq!(decoded("0x"), Some(Ipv4Addr::UNSPECIFIED));
        // Still refused when it decodes to nothing.
        for raw in [
            "1.2.3.4.5",
            "example.256",
            "999.1.1.1",
            "1.2.3.256",
            "1.2.65536",
            "4294967296",
            "09.1.1.1",
            "0xg.1",
            "a.0x1",
        ] {
            assert_eq!(decoded(raw), None, "{raw}");
        }
    }

    #[test]
    fn non_canonical_errors_say_what_to_write() {
        let err = normalise_host("127.1").unwrap_err();
        assert_eq!(
            err.to_string(),
            r#""127.1" is not a canonical IP address: it decodes to 127.0.0.1, write that instead"#
        );
        let err = normalise_host("999.1.1.1").unwrap_err();
        assert!(err.to_string().ends_with("decodes to no address"), "{err}");
        let err = normalise_host("a b").unwrap_err();
        assert!(
            err.to_string().starts_with(r#"invalid host "a b": "#),
            "{err}"
        );
    }

    #[test]
    fn echoed_input_is_bounded() {
        let raw = format!("{}!", "x".repeat(200));
        let NameError::Invalid { input, .. } = normalise_host(&raw).unwrap_err() else {
            panic!("expected Invalid");
        };
        assert_eq!(input.chars().count(), MAX_ECHOED_CHARS + 1);
        assert!(input.ends_with('…'));
    }

    #[test]
    fn names_that_are_a_category_by_themselves() {
        for raw in ["localhost", "LOCALHOST.", "foo.localhost", "a.b.localhost"] {
            assert_eq!(
                normalise_host(raw).unwrap().named_category(),
                Some(LocalCategory::Loopback),
                "{raw}"
            );
        }
        for raw in [
            "metadata.google.internal",
            "metadata",
            "instance-data.ec2.internal",
            "instance-data",
            "Metadata.Goog.",
        ] {
            assert_eq!(
                normalise_host(raw).unwrap().named_category(),
                Some(LocalCategory::Metadata),
                "{raw}"
            );
        }
        for raw in [
            "localhost.example.com",
            "notlocalhost",
            "svc.corp.internal",
            "nas.local",
            "127.0.0.1",
        ] {
            assert_eq!(normalise_host(raw).unwrap().named_category(), None, "{raw}");
        }
    }

    #[test]
    fn name_rule_maps_every_domain_name_reason() {
        assert_eq!(name_rule("other"), "is not a valid host name");
    }
}
