// SPDX-License-Identifier: GPL-3.0-or-later
//! Making text safe to show: the network-health report and the logs may name proxies, PAC
//! addresses and what went wrong, never a credential or a token. Two layers back each other:
//! the types that carry proxies ([`crate::ProxyAddr`]) cannot hold credentials at all, and
//! text that came from outside (a PAC address, an error message) passes through here.

/// The longest text the report carries from outside.
const MAX_TEXT: usize = 240;

const SCHEMES: [&str; 5] = ["negotiate", "ntlm", "basic", "bearer", "digest"];

/// A URL without user info, query or fragment: `http://user:pw@host/proxy.pac?token=x#y`
/// becomes `http://host/proxy.pac`. Text that is not a URL is passed through [`redact_text`].
#[must_use]
pub fn redact_url(url: &str) -> String {
    let url = url.trim();
    let Some((scheme, rest)) = url.split_once("://") else {
        return redact_text(url);
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let path = tail.split(['?', '#']).next().unwrap_or("");
    clip(&format!("{scheme}://{host}{path}"))
}

/// `text` with the parts that could be secrets removed and its length bounded: user info in
/// every `scheme://user:password@host`, and the token after `Negotiate`, `NTLM`, `Basic`,
/// `Bearer` or `Digest`. Control characters become spaces.
#[must_use]
pub fn redact_text(text: &str) -> String {
    let cleaned: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let mut out = Vec::new();
    let mut words = cleaned.split(' ').filter(|w| !w.is_empty()).peekable();
    while let Some(word) = words.next() {
        let bare = word.trim_matches(|c: char| !c.is_ascii_alphanumeric());
        if SCHEMES.iter().any(|s| bare.eq_ignore_ascii_case(s)) {
            out.push(word.to_owned());
            // The token after a scheme word: anything that is not an ordinary word.
            if words.peek().is_some_and(|next| looks_like_token(next)) {
                words.next();
                out.push("[redacted]".to_owned());
            }
        } else if word.contains("://") {
            out.push(redact_url(word));
        } else {
            out.push(word.to_owned());
        }
    }
    clip(&out.join(" "))
}

fn looks_like_token(word: &str) -> bool {
    let word = word.trim_end_matches([',', ';', '.']);
    word.len() >= 8
        && word
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '-' | '_'))
        && word
            .chars()
            .any(|c| c.is_ascii_digit() || c.is_ascii_uppercase())
}

fn clip(text: &str) -> String {
    if text.chars().count() <= MAX_TEXT {
        return text.to_owned();
    }
    let mut out: String = text.chars().take(MAX_TEXT).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_url_loses_user_info_query_and_fragment() {
        assert_eq!(
            redact_url("http://alice:s3cret@wpad.corp.test:8080/proxy.pac?token=abc#frag"),
            "http://wpad.corp.test:8080/proxy.pac"
        );
        assert_eq!(redact_url("https://h.test"), "https://h.test");
    }

    #[test]
    fn text_with_a_url_or_token_is_cleaned() {
        let out = redact_text(
            "failed at http://bob:pw123@proxy.test:3128/ with Negotiate YIIBCgYGKwYBBQUCoIH5MIH2",
        );
        assert!(!out.contains("pw123") && !out.contains("bob") && !out.contains("YIIB"));
        assert!(out.contains("proxy.test:3128") && out.contains("Negotiate [redacted]"));
    }

    #[test]
    fn plain_words_after_a_scheme_word_stay() {
        assert_eq!(
            redact_text("the proxy offers Basic, NTLM"),
            "the proxy offers Basic, NTLM"
        );
        assert_eq!(redact_text("Basic realm"), "Basic realm");
    }

    #[test]
    fn control_characters_and_length_are_bounded() {
        assert_eq!(redact_text("a\r\nb\u{0}c"), "a b c");
        let long = "x ".repeat(500);
        assert!(redact_text(&long).chars().count() <= MAX_TEXT + 1);
    }
}
