// SPDX-License-Identifier: GPL-3.0-or-later
//! Stand-ins that look like the token they stand for.
//!
//! A tool that is handed a stand-in may look at it: GitHub's tokens start with a type prefix
//! and secret scanners and some clients check it, Claude Code keeps the last characters of an
//! API key to remember that the user approved it. So a stand-in keeps the real token's prefix,
//! its length, its alphabet and, when a profile asks, its last characters; only the characters in
//! between are random. It is never a valid token: it carries no checksum, and it comes from the
//! system's random bytes, not from the real token.

use zeroize::Zeroizing;

use crate::profile::Field;

/// The shortest and longest token a stand-in can copy the length of: the registry's own limits.
const MIN_LEN: usize = 16;
const MAX_LEN: usize = 256;

/// The fewest random characters a stand-in has, so it cannot be guessed or confused with another.
const MIN_RANDOM: usize = 8;

/// Why a stand-in could not be made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ShapeError {
    /// The token is shorter than 16 or longer than 256 characters, or has a character that is not
    /// visible ASCII (a space, a control character, anything outside ASCII): a header could not
    /// carry it as it is, or the registry would not accept its stand-in.
    #[error("the token has a length or characters a stand-in cannot copy")]
    Unusable,
    /// The operating system has no randomness to give.
    #[error("the operating system has no randomness to give")]
    Random,
}

const HEX: &[u8] = b"0123456789abcdef";
const BASE62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const BASE64URL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// The smallest alphabet that holds `body`; any other characters give the common one.
fn alphabet_of(body: &str) -> &'static [u8] {
    if body.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        HEX
    } else if body.bytes().all(|b| b.is_ascii_alphanumeric()) {
        BASE62
    } else if body
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        BASE64URL
    } else {
        BASE62
    }
}

/// `count` characters of `alphabet`, uniformly, from `fill`'s random bytes (bytes that would make
/// the choice uneven are dropped, not folded).
fn random_text(
    alphabet: &[u8],
    count: usize,
    fill: &mut dyn FnMut(&mut [u8]) -> bool,
) -> Result<String, ShapeError> {
    // The largest multiple of the alphabet's size that fits in a byte.
    let limit = (256 / alphabet.len()) * alphabet.len();
    let mut text = String::with_capacity(count);
    let mut bytes = [0_u8; 64];
    while text.len() < count {
        if !fill(&mut bytes) {
            return Err(ShapeError::Random);
        }
        for byte in bytes {
            if usize::from(byte) >= limit {
                continue;
            }
            if let Some(&c) = alphabet.get(usize::from(byte) % alphabet.len()) {
                text.push(char::from(c));
            }
            if text.len() == count {
                break;
            }
        }
    }
    Ok(text)
}

/// Whether a token can be copied by a stand-in and can be swapped back into a header: 16 to 256
/// visible ASCII characters.
pub(crate) fn usable(real: &str) -> bool {
    (MIN_LEN..=MAX_LEN).contains(&real.len()) && real.bytes().all(|b| b.is_ascii_graphic())
}

/// A stand-in for `real`, a token of the kind `field` describes: the same length, the prefix it
/// has among `field.prefixes`, the same alphabet and its last `field.keep_last` characters (when
/// the token is long enough to keep them and still leave random characters in between).
///
/// # Errors
/// [`ShapeError::Unusable`] for a token that cannot be copied; [`ShapeError::Random`] when the
/// system has no randomness.
pub fn stand_in_for(real: &str, field: &Field) -> Result<String, ShapeError> {
    stand_in_with(real, field, &mut |bytes| getrandom::fill(bytes).is_ok())
}

pub(crate) fn stand_in_with(
    real: &str,
    field: &Field,
    fill: &mut dyn FnMut(&mut [u8]) -> bool,
) -> Result<String, ShapeError> {
    if !usable(real) {
        return Err(ShapeError::Unusable);
    }
    let prefix = field
        .prefixes
        .iter()
        .copied()
        .find(|prefix| real.starts_with(prefix))
        .unwrap_or_default();
    // `real` is visible ASCII, so every split below is on a character boundary.
    let body = real.strip_prefix(prefix).unwrap_or(real);
    let keep = if body.len() >= field.keep_last + MIN_RANDOM {
        field.keep_last
    } else {
        0
    };
    let (middle, tail) = body
        .split_at_checked(body.len() - keep)
        .unwrap_or((body, ""));
    let random = Zeroizing::new(random_text(alphabet_of(middle), middle.len(), fill)?);
    let stand_in = format!("{prefix}{}{tail}", *random);
    if stand_in == real {
        // 62^-8 at best: still never hand the real token back as its own stand-in.
        return Err(ShapeError::Random);
    }
    Ok(stand_in)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::profile::{CLAUDE, GITHUB};

    fn github_access() -> &'static Field {
        &GITHUB.endpoints[0].fields[0]
    }

    fn claude_key() -> &'static Field {
        &CLAUDE.endpoints[1].fields[0]
    }

    fn counting() -> impl FnMut(&mut [u8]) -> bool {
        let mut n = 0_u8;
        move |bytes| {
            for b in bytes {
                *b = n;
                n = n.wrapping_add(37);
            }
            true
        }
    }

    #[test]
    fn a_github_token_keeps_its_prefix_its_length_and_its_alphabet() {
        let real = "gho_CANARY-fake-github-token-0123456789ab";
        let stand_in = stand_in_for(real, github_access()).unwrap();
        assert_eq!(stand_in.len(), real.len());
        assert!(stand_in.starts_with("gho_"));
        assert_ne!(stand_in, real);
        assert!(
            stand_in
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        );
        assert!(
            !stand_in.contains(&real[4..12]),
            "nothing of the middle is kept"
        );
    }

    #[test]
    fn a_claude_api_key_keeps_its_last_twenty_characters() {
        let real = format!(
            "sk-ant-api03-{}{}",
            "A".repeat(60),
            "wXyZ-_0123456789abcdef"
        );
        assert!(real.len() > 13 + 20 + 8);
        let stand_in = stand_in_for(&real, claude_key()).unwrap();
        assert_eq!(stand_in.len(), real.len());
        assert!(stand_in.starts_with("sk-ant-api03-"));
        assert!(stand_in.ends_with(&real[real.len() - 20..]));
        assert_ne!(stand_in, real);
        assert!(!stand_in.contains(&"A".repeat(10)));
    }

    #[test]
    fn a_token_too_short_to_keep_its_end_and_stay_random_keeps_nothing_of_it() {
        let real = "sk-ant-api03-ABCDEFGHIJ1234567";
        let stand_in = stand_in_for(real, claude_key()).unwrap();
        assert_eq!(stand_in.len(), real.len());
        assert!(!stand_in.ends_with("1234567"));
    }

    #[test]
    fn the_alphabet_follows_the_token() {
        assert_eq!(alphabet_of("0123abcdef"), HEX);
        assert_eq!(alphabet_of("0123abcDEF"), BASE62);
        assert_eq!(alphabet_of("ab-cd_ef"), BASE64URL);
        assert_eq!(alphabet_of("ab.cd~ef"), BASE62);
        let hex = stand_in_for(&"0123456789abcdef".repeat(2), github_access()).unwrap();
        assert!(hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
    }

    #[test]
    fn an_unknown_prefix_is_not_kept() {
        let stand_in =
            stand_in_for("ghx_CANARY-fake-github-token-0123456789ab", github_access()).unwrap();
        assert!(!stand_in.starts_with("ghx_"));
    }

    #[test]
    fn tokens_a_stand_in_cannot_copy_are_refused() {
        for real in [
            "",
            "short",
            "gho_with a space in the middle 123456",
            "gho_tab\there1234567890123456",
            "gho_non-ascii-é-0123456789012345",
            &"x".repeat(257),
        ] {
            assert_eq!(
                stand_in_for(real, github_access()),
                Err(ShapeError::Unusable),
                "{real:?}"
            );
        }
        assert!(stand_in_for(&"x".repeat(256), github_access()).is_ok());
        assert!(stand_in_for(&"x".repeat(16), github_access()).is_ok());
    }

    #[test]
    fn no_randomness_is_an_error_not_a_weak_stand_in() {
        let real = "gho_CANARY-fake-github-token-0123456789ab";
        assert_eq!(
            stand_in_with(real, github_access(), &mut |_| false),
            Err(ShapeError::Random)
        );
    }

    #[test]
    fn a_stand_in_equal_to_the_real_token_is_refused() {
        // A source of bytes that spells the token itself.
        let real = "gho_abcdefghijklmnopqrstuvwxyz0123456789";
        let body = real.as_bytes()[4..].to_vec();
        let mut at = 0;
        let mut fill = |bytes: &mut [u8]| {
            for b in bytes {
                // BASE62 index of the wanted character.
                let want = body[at % body.len()];
                *b = u8::try_from(BASE62.iter().position(|c| *c == want).unwrap()).unwrap();
                at += 1;
            }
            true
        };
        assert_eq!(
            stand_in_with(real, github_access(), &mut fill),
            Err(ShapeError::Random)
        );
    }

    #[test]
    fn bytes_that_would_make_the_choice_uneven_are_dropped() {
        // 62 does not divide 256: bytes 248..=255 would favour the first eight characters.
        let mut calls = 0;
        let mut fill = |bytes: &mut [u8]| {
            calls += 1;
            bytes.fill(250);
            if calls > 1 {
                bytes.fill(1);
            }
            true
        };
        let text = random_text(BASE62, 5, &mut fill).unwrap();
        assert_eq!(text, "11111");
        assert!(calls >= 2);
    }

    #[test]
    fn the_same_source_gives_the_same_stand_in() {
        let real = "gho_CANARY-fake-github-token-0123456789ab";
        let a = stand_in_with(real, github_access(), &mut counting()).unwrap();
        let b = stand_in_with(real, github_access(), &mut counting()).unwrap();
        assert_eq!(a, b);
    }

    proptest! {
        #[test]
        fn a_stand_in_has_the_shape_of_its_token(
            prefix in prop::sample::select(vec!["gho_", "ghu_", ""]),
            body in "[A-Za-z0-9]{16,120}",
        ) {
            let real = format!("{prefix}{body}");
            let stand_in = stand_in_for(&real, github_access()).unwrap();
            prop_assert_eq!(stand_in.len(), real.len());
            prop_assert_ne!(&stand_in, &real);
            prop_assert!(stand_in.starts_with(prefix));
            prop_assert!(stand_in.bytes().all(|b| b.is_ascii_graphic()));
        }

        #[test]
        fn any_text_either_gives_a_graphic_stand_in_of_its_length_or_is_refused(
            real in prop_oneof!["[!-~]{0,300}", "\\PC{0,300}"]
        ) {
            match stand_in_for(&real, claude_key()) {
                Ok(stand_in) => {
                    prop_assert_eq!(stand_in.len(), real.len());
                    prop_assert!(stand_in.bytes().all(|b| b.is_ascii_graphic()));
                }
                // Too short, too long or not visible ASCII; the system's randomness does not fail.
                Err(ShapeError::Unusable | ShapeError::Random) => {}
            }
        }
    }
}
