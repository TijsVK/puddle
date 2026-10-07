// SPDX-License-Identifier: GPL-3.0-or-later
//! Which names the stub answers itself, and which are plain enough to carry to the host.

use puddle_agent_proto::resolve::MAX_NAME;

/// Zones that can never be a connect target: the reverse zones are address lookups, not hosts.
const LOCAL_SUFFIXES: [&str; 2] = [".in-addr.arpa", ".ip6.arpa"];

/// Whether `name` (lower case, no trailing dot) is answered locally with `NXDOMAIN`: empty, a
/// reverse zone, or something shaped like an address (a name never ends in a number, so it is no
/// host to connect to). Everything else, including single labels and zones such as `.internal`
/// or `.local`, goes to the host, which decides by the rules like any other name: a company's
/// intranet names must work once allowed, and nothing is denied in advance.
#[must_use]
pub fn is_local_only(name: &str) -> bool {
    name.is_empty()
        || LOCAL_SUFFIXES.iter().any(|zone| name.ends_with(zone))
        || name
            .rsplit('.')
            .next()
            .is_some_and(|last| last.bytes().all(|b| b.is_ascii_digit()))
}

/// Whether `name` is a plain host name: labels of 1 to 63 lower-case letters, digits, `-` or `_`
/// (`_` for service names such as `_mongodb._tcp.example.net`), at most 253 characters.
/// Anything else (escape characters, spaces, non-ASCII bytes) is never sent to the host.
#[must_use]
pub fn is_plain(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME
        && name.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        })
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn reverse_zones_and_address_shaped_names_stay_in_the_sandbox() {
        for name in [
            "",
            "4.3.2.1.in-addr.arpa",
            "1.0.0.127.ip6.arpa",
            "1.2.3.4",
            "example.123",
        ] {
            assert!(is_local_only(name), "{name:?}");
        }
    }

    #[test]
    fn ordinary_names_go_to_the_host() {
        for name in [
            "example.com",
            "api.github.com",
            "printer",
            "localhost",
            "host.local",
            "metadata.google.internal",
            "db.default.svc.cluster.local",
            "xn--bcher-kva.example",
            "x.localdomain.example",
            "notlocal.example",
            "_mongodb._tcp.db.example.net",
            "a1.b2.example",
        ] {
            assert!(!is_local_only(name), "{name:?}");
            assert!(is_plain(name), "{name:?}");
        }
    }

    #[test]
    fn a_name_that_is_not_plain_never_goes_to_the_host() {
        for name in [
            "",
            ".",
            "a..b",
            "a.b.",
            "Upper.example",
            "sp ace.example",
            "esc\u{1b}[2K.example",
            "bücher.example",
            "*.example",
            &"a".repeat(64),
            &format!("{0}.{0}.{0}.{0}", "a".repeat(63)),
        ] {
            assert!(!is_plain(name), "{name:?}");
        }
    }

    proptest! {
        #[test]
        fn classification_never_panics(name in ".{0,300}") {
            let _ = is_local_only(&name);
            let _ = is_plain(&name);
        }
    }
}
