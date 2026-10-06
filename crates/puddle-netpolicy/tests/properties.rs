// SPDX-License-Identifier: GPL-3.0-or-later
//! Property tests for the normaliser and the classifier: they see guest input.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use proptest::prelude::*;
use puddle_netpolicy::{
    AddressClass, AddressVerdict, LocalAccess, LocalCategory, NameError, NetPolicy, classify_ip,
    normalise_host,
};
use puddle_types::{Host, SandboxName};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// Whatever comes out is a fixed point and passes the shared type's own check.
    #[test]
    fn normal_forms_are_fixed_points(raw in "\\PC{0,60}") {
        if let Ok(target) = normalise_host(&raw) {
            let text = target.host().to_string();
            prop_assert_eq!(Host::parse_normalised(&text), Ok(target.host().clone()));
            prop_assert_eq!(normalise_host(&text), Ok(target));
        }
    }

    /// Hostile bytes never panic and never produce something outside the normal form.
    #[test]
    fn arbitrary_input_never_panics(raw in ".{0,300}") {
        let _ = normalise_host(&raw);
    }

    /// Case never changes the destination.
    #[test]
    fn ascii_case_is_folded(name in "[a-z][a-z0-9-]{0,20}[a-z0-9](\\.[a-z][a-z0-9]{0,10}){1,3}") {
        let upper = name.to_ascii_uppercase();
        prop_assert_eq!(normalise_host(&upper), normalise_host(&name));
    }

    /// Every IP literal is accepted as itself, bracketed or not for IPv6.
    #[test]
    fn ip_literals_round_trip(ip in any::<IpAddr>()) {
        let text = ip.to_string();
        prop_assert_eq!(normalise_host(&text).unwrap().into_host(), Host::Ip(ip));
        if ip.is_ipv6() {
            prop_assert_eq!(normalise_host(&format!("[{text}]")).unwrap().into_host(), Host::Ip(ip));
        }
    }

    /// A 32-bit number is never accepted as a name: it is the address it decodes to, refused.
    #[test]
    fn integers_are_refused_as_non_canonical(n in any::<u32>()) {
        let refused = normalise_host(&n.to_string());
        prop_assert_eq!(
            refused,
            Err(NameError::NonCanonicalIp { input: n.to_string(), decoded: Some(Ipv4Addr::from_bits(n)) })
        );
    }

    /// An IPv4 address in IPv4-mapped IPv6 is always in the same class as itself.
    #[test]
    fn mapped_ipv4_classifies_as_the_ipv4_address(a in any::<Ipv4Addr>()) {
        let v4 = classify_ip(IpAddr::V4(a)).category();
        let mapped = classify_ip(IpAddr::V6(a.to_ipv6_mapped())).category();
        prop_assert_eq!(v4, mapped);
        let nat64 = Ipv6Addr::from_bits((0x0064_ff9b_u128 << 96) | u128::from(a.to_bits()));
        prop_assert_eq!(classify_ip(IpAddr::V6(nat64)).category(), v4);
    }

    /// With every toggle off, nothing outside "public" is ever allowed; with the toggles on,
    /// a local address is at most exact-only.
    #[test]
    fn only_public_addresses_pass_without_toggles(ip in any::<IpAddr>(), port in any::<u16>()) {
        let sandbox = SandboxName::new("box").unwrap();
        let addr = SocketAddr::new(ip, port);
        let off = NetPolicy::new(Arc::new(LocalAccess::NONE));
        let class = classify_ip(ip);
        let verdict = off.check_address(&sandbox, addr);
        prop_assert_eq!(verdict == AddressVerdict::Allow, class == AddressClass::Public);
        let all_on = LocalCategory::ALL.into_iter().fold(LocalAccess::NONE, |a, c| a.with_toggle(c, true));
        let on = NetPolicy::new(Arc::new(all_on));
        if let Some(category) = class.category() {
            prop_assert_eq!(on.check_address(&sandbox, addr), AddressVerdict::ExactOnly(category));
        }
    }
}
