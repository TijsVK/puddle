// SPDX-License-Identifier: GPL-3.0-or-later
//! Property tests: `NO_PROXY` entries are parsed strictly, and whatever entries pass can't break
//! the syntax of a generated file (a stray quote in sudoers would lock `sudo` for everyone).

use proptest::prelude::*;
use puddle_guest_env::{
    APT_CONF_GUEST, MAVEN_SETTINGS_GUEST, NoProxyEntry, ProxySettings, SSH_CONFIG_GUEST,
    SUDOERS_GUEST, guest_proxy_config,
};

/// Characters a generated value may hold beyond letters and digits.
const SAFE_PUNCT: &[char] = &['.', '-', ':', ',', '|', '*', '[', ']', '/', ' ', '='];

#[expect(
    clippy::unwrap_used,
    reason = "constant regexes; a bad one fails every test"
)]
fn valid_entry() -> impl Strategy<Value = String> {
    let label = "[a-zA-Z0-9]([a-zA-Z0-9-]{0,8}[a-zA-Z0-9])?";
    prop_oneof![
        proptest::string::string_regex(&format!("{label}(\\.{label}){{0,3}}")).unwrap(),
        proptest::string::string_regex(&format!("\\.{label}(\\.{label}){{0,2}}")).unwrap(),
        any::<std::net::Ipv4Addr>().prop_map(|ip| ip.to_string()),
        any::<std::net::Ipv6Addr>().prop_map(|ip| ip.to_string()),
    ]
}

proptest! {
    #[test]
    fn arbitrary_input_never_panics_and_accepted_entries_are_plain(s in ".{0,80}") {
        if let Ok(e) = NoProxyEntry::new(&s) {
            let out = e.as_str();
            prop_assert!(out.chars().all(|c| c.is_ascii_alphanumeric() || ".-:".contains(c)), "{out}");
            prop_assert_eq!(NoProxyEntry::new(&out).unwrap(), e);
        }
    }

    #[test]
    fn valid_entries_round_trip(s in valid_entry()) {
        let e = NoProxyEntry::new(&s).unwrap();
        prop_assert_eq!(NoProxyEntry::new(&e.as_str()).unwrap(), e.clone());
        prop_assert_eq!(e.as_str(), if s.parse::<std::net::IpAddr>().is_ok() { s } else { s.to_ascii_lowercase() });
    }

    #[test]
    fn generated_files_keep_their_syntax(entries in proptest::collection::vec(valid_entry(), 0..6)) {
        let settings = ProxySettings {
            no_proxy: entries.iter().map(|e| NoProxyEntry::new(e).unwrap()).collect(),
            ..ProxySettings::default()
        };
        let c = guest_proxy_config(&settings, &[]).unwrap();
        for (name, value) in c.env.iter() {
            prop_assert!(
                value.chars().all(|ch| ch.is_ascii_alphanumeric() || SAFE_PUNCT.contains(&ch)),
                "{name}={value}"
            );
        }
        for f in &c.files {
            let text = std::str::from_utf8(f.contents()).unwrap();
            prop_assert!(text.ends_with('\n'));
            // Tabs only as the merged JSON's indent (the Docker CLI's own layout).
            let tab_ok = matches!(f.apply(), puddle_types::ApplyKind::Merge(_));
            prop_assert!(
                !text.chars().any(|ch| ch.is_control() && ch != '\n' && !(tab_ok && ch == '\t')),
                "{}",
                f.path()
            );
        }
        let file = |p: &str| {
            let f = c.files.iter().find(|f| f.path().as_str() == p).unwrap();
            String::from_utf8(f.contents().to_vec()).unwrap()
        };
        // apt: every statement is `key "value";` with exactly two quotes.
        for line in file(APT_CONF_GUEST).lines().filter(|l| !l.starts_with("//")) {
            prop_assert_eq!(line.matches('"').count(), 2, "{}", line);
            prop_assert!(line.ends_with("\";"), "{}", line);
        }
        // sudoers: one Defaults line, two quotes.
        let sudoers = file(SUDOERS_GUEST);
        let defaults: Vec<&str> = sudoers.lines().filter(|l| !l.starts_with('#')).collect();
        prop_assert_eq!(defaults.len(), 1);
        prop_assert_eq!(defaults[0].matches('"').count(), 2);
        // Maven: no markup inside values.
        let maven = file(MAVEN_SETTINGS_GUEST);
        for line in maven.lines().filter(|l| l.contains("<nonProxyHosts>")) {
            let inner = line.trim().trim_start_matches("<nonProxyHosts>").trim_end_matches("</nonProxyHosts>");
            prop_assert!(!inner.contains(['<', '>', '&', '"']), "{}", inner);
        }
        // ssh: one Match and its ProxyCommand, whatever the user's NO_PROXY entries are.
        let ssh = file(SSH_CONFIG_GUEST);
        let active: Vec<&str> = ssh.lines().filter(|l| !l.starts_with('#')).collect();
        prop_assert_eq!(active.len(), 2, "{}", ssh);
        prop_assert!(active[0].starts_with("Match host \"*,!"), "{}", active[0]);
        prop_assert!(active[1].starts_with("    ProxyCommand '"), "{}", active[1]);
        // Every user entry is in NO_PROXY once.
        let no_proxy: Vec<&str> = c.env.get("NO_PROXY").unwrap().split(',').collect();
        for e in &settings.no_proxy {
            let count = no_proxy.iter().filter(|x| **x == e.as_str()).count();
            prop_assert_eq!(count, 1, "{}", e);
        }
    }
}
