// SPDX-License-Identifier: GPL-3.0-or-later
//! `Alt-Svc` on responses puddle decrypts: the HTTP/3 alternatives are removed.
//!
//! A workspace has no UDP path out, so a client that is told "this server speaks HTTP/3" would
//! try it, fail and only then use TCP. Removing the `h3` entries (and the draft and Google
//! variants of them) spares it the attempt; every other entry, and every other field, goes to the
//! guest as the server sent it. A spliced connection is not touched: puddle does not see inside it,
//! and the client falls back on its own when its QUIC attempt fails.

use ::http::HeaderMap;
use ::http::header::{ALT_SVC, HeaderValue};

/// Removes the HTTP/3 entries from every `Alt-Svc` field of `headers` and returns how many entries
/// went. A field whose entries all go is removed; a field with nothing to remove is left as it is.
pub(super) fn strip_h3(headers: &mut HeaderMap) -> usize {
    let mut kept = Vec::new();
    let mut removed = 0;
    for value in headers.get_all(ALT_SVC) {
        match without_h3(value.as_bytes()) {
            Some(stripped) => {
                removed += stripped.removed;
                kept.extend(stripped.rest);
            }
            None => kept.push(value.clone()),
        }
    }
    if removed > 0 {
        headers.remove(ALT_SVC);
        for value in kept {
            headers.append(ALT_SVC, value);
        }
        tracing::debug!(removed, "removed HTTP/3 from Alt-Svc");
    }
    removed
}

/// What is left of one field after its HTTP/3 entries are removed.
struct Stripped {
    /// `None` when no entry is left.
    rest: Option<HeaderValue>,
    removed: usize,
}

/// `value` without its HTTP/3 entries, or `None` when it has none.
fn without_h3(value: &[u8]) -> Option<Stripped> {
    let mut kept: Vec<&[u8]> = Vec::new();
    let mut removed = 0;
    for entry in entries(value) {
        if is_h3(entry) {
            removed += 1;
        } else {
            kept.push(entry);
        }
    }
    (removed > 0).then(|| Stripped {
        rest: (!kept.is_empty())
            .then(|| HeaderValue::from_bytes(&kept.join(&b", "[..])).ok())
            .flatten(),
        removed,
    })
}

/// The comma-separated entries of a field value, each without its surrounding blanks. A comma
/// inside a quoted string (`v="46,43"`) does not end an entry, and neither does a quote that is
/// never closed: the rest of the value is then one entry.
fn entries(value: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut rest = Some(value);
    std::iter::from_fn(move || {
        let current = rest.take()?;
        let mut quoted = false;
        let mut escaped = false;
        for (at, &byte) in current.iter().enumerate() {
            match (quoted, escaped, byte) {
                (true, true, _) => escaped = false,
                (true, false, b'\\') => escaped = true,
                (true, false, b'"') => quoted = false,
                (false, _, b'"') => quoted = true,
                (false, _, b',') => {
                    let (head, tail) = current.split_at(at);
                    rest = tail.split_first().map(|(_, after)| after);
                    return Some(head.trim_ascii());
                }
                _ => {}
            }
        }
        Some(current.trim_ascii())
    })
}

/// Whether an entry offers HTTP/3: its protocol id (the part before `=`, percent-encoded by the
/// server's choice) is `h3`, a draft such as `h3-29` or `h3-Q050`, or Google's older `quic`.
fn is_h3(entry: &[u8]) -> bool {
    let mut parts = entry.splitn(2, |&byte| byte == b'=');
    let (Some(id), Some(_)) = (parts.next(), parts.next()) else {
        return false;
    };
    let id = percent_decoded(id);
    id == b"h3" || id == b"quic" || id.starts_with(b"h3-")
}

fn percent_decoded(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    let mut bytes = raw.iter().copied();
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            let mut ahead = bytes.clone();
            if let (Some(high), Some(low)) =
                (ahead.next().and_then(hex), ahead.next().and_then(hex))
            {
                out.push((high << 4) | low);
                bytes = ahead;
                continue;
            }
        }
        out.push(byte);
    }
    out
}

fn hex(byte: u8) -> Option<u8> {
    char::from(byte)
        .to_digit(16)
        .and_then(|digit| u8::try_from(digit).ok())
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn stripped(fields: &[&[u8]]) -> (Vec<Vec<u8>>, usize) {
        let mut headers = HeaderMap::new();
        for field in fields {
            headers.append(ALT_SVC, HeaderValue::from_bytes(field).unwrap());
        }
        let removed = strip_h3(&mut headers);
        let left = headers
            .get_all(ALT_SVC)
            .iter()
            .map(|v| v.as_bytes().to_vec())
            .collect();
        (left, removed)
    }

    fn one(field: &str) -> (Vec<String>, usize) {
        let (left, removed) = stripped(&[field.as_bytes()]);
        let left = left
            .into_iter()
            .map(|v| String::from_utf8(v).unwrap())
            .collect();
        (left, removed)
    }

    #[test]
    fn a_field_of_h3_entries_only_is_removed() {
        assert_eq!(one(r#"h3=":443"; ma=86400"#), (vec![], 1));
        assert_eq!(
            one(r#"h3=":443"; ma=2592000,h3-29=":443"; ma=2592000"#),
            (vec![], 2)
        );
    }

    #[test]
    fn the_other_entries_stay_as_the_server_wrote_them() {
        assert_eq!(
            one(r#"h3=":443"; ma=86400, h2="alt.example.com:8443"; ma=60; persist=1"#),
            (
                vec![r#"h2="alt.example.com:8443"; ma=60; persist=1"#.into()],
                1
            )
        );
        assert_eq!(
            one(r#"h2=":443",h3-29=":443" ,  h3=":443" , h2=":8443"; ma=5"#),
            (vec![r#"h2=":443", h2=":8443"; ma=5"#.into()], 2)
        );
    }

    #[test]
    fn google_quic_and_percent_encoded_ids_count_as_h3() {
        assert_eq!(
            one(r#"quic=":443"; ma=2592000; v="46,43", h2=":443""#),
            (vec![r#"h2=":443""#.into()], 1)
        );
        assert_eq!(
            one(r#"h3%2D29=":443", h%33=":443", h3-Q050=":443", h2=":443""#),
            (vec![r#"h2=":443""#.into()], 3)
        );
    }

    #[test]
    fn a_comma_in_a_quoted_string_does_not_split_an_entry() {
        assert_eq!(
            one(r#"h2=":443"; note="a, h3=b", h3=":443""#),
            (vec![r#"h2=":443"; note="a, h3=b""#.into()], 1)
        );
        assert_eq!(
            one(r#"h2=":443"; note="a\", h3=b", h3=":443""#),
            (vec![r#"h2=":443"; note="a\", h3=b""#.into()], 1)
        );
        // A quote that never closes makes the rest one entry; it is not an h3 entry.
        assert_eq!(
            one(r#"h2=":443; ma=1, h3=":443""#),
            (vec![r#"h2=":443; ma=1, h3=":443""#.into()], 0)
        );
    }

    #[test]
    fn what_is_not_h3_is_left_alone() {
        for field in [
            r#"h2=":443"; ma=60"#,
            "clear",
            r#"h30=":443""#,
            r#"H3=":443""#,
            "h3",
            r#"h2=":443",,h2=":8443""#,
            "",
        ] {
            assert_eq!(one(field), (vec![field.into()], 0), "{field}");
        }
    }

    #[test]
    fn each_field_is_stripped_on_its_own_and_other_headers_stay() {
        let mut headers = HeaderMap::new();
        headers.append(ALT_SVC, HeaderValue::from_static(r#"h3=":443""#));
        headers.append(ALT_SVC, HeaderValue::from_static(r#"h2=":443", h3=":443""#));
        headers.append(ALT_SVC, HeaderValue::from_static("clear"));
        headers.insert("x-other", HeaderValue::from_static("kept"));
        assert_eq!(strip_h3(&mut headers), 2);
        let left: Vec<_> = headers.get_all(ALT_SVC).iter().collect();
        assert_eq!(left, [r#"h2=":443""#, "clear"]);
        assert_eq!(headers["x-other"], "kept");
        assert_eq!(strip_h3(&mut HeaderMap::new()), 0);
    }

    #[test]
    fn bytes_outside_ascii_are_kept() {
        let (left, removed) = stripped(&[b"h2=\":443\"; note=\"a\xe9b\", h3=\":443\""]);
        assert_eq!(removed, 1);
        assert_eq!(left, [b"h2=\":443\"; note=\"a\xe9b\"".to_vec()]);
    }

    fn entry() -> impl Strategy<Value = String> {
        (
            prop_oneof![
                Just("h3"),
                Just("h3-29"),
                Just("quic"),
                Just("h2"),
                Just("http/1.1"),
                Just("clear"),
                Just("h3%2D27"),
            ],
            prop_oneof![Just(r#"":443""#), Just(r#"":8443"; ma=60; v="46,43""#)],
        )
            .prop_map(|(id, rest)| format!("{id}={rest}"))
    }

    proptest! {
        /// What survives is the input's entries in order, none of them HTTP/3, and a second pass
        /// changes nothing.
        #[test]
        fn what_is_left_has_no_h3_and_keeps_the_order(
            entries in proptest::collection::vec(entry(), 0..8),
            blanks in "[ \t]{0,3}",
        ) {
            let field = entries.join(&format!("{blanks},{blanks}"));
            let (left, removed) = stripped(&[field.as_bytes()]);
            let expected: Vec<&String> = entries.iter().filter(|e| !is_h3(e.as_bytes())).collect();
            prop_assert_eq!(removed, entries.len() - expected.len());
            if removed == 0 {
                prop_assert_eq!(&left, &[field.clone().into_bytes()]);
            } else if expected.is_empty() {
                prop_assert!(left.is_empty());
            } else {
                let joined = expected.iter().map(|e| e.as_str()).collect::<Vec<_>>();
                prop_assert_eq!(&left, &[joined.join(", ").into_bytes()]);
            }
            let (again, removed_again) = stripped(&left.iter().map(Vec::as_slice).collect::<Vec<_>>());
            prop_assert_eq!(removed_again, 0);
            prop_assert_eq!(again, left);
        }

        /// Any field value passes without a panic, and a value with no `h3` or `quic` in it
        /// is returned byte for byte.
        #[test]
        fn any_field_value_is_handled(bytes in proptest::collection::vec(any::<u8>(), 0..120)) {
            let Ok(value) = HeaderValue::from_bytes(&bytes) else { return Ok(()); };
            let mut headers = HeaderMap::new();
            headers.append(ALT_SVC, value.clone());
            let removed = strip_h3(&mut headers);
            if removed == 0 {
                prop_assert_eq!(&headers[ALT_SVC], &value);
            }
        }
    }
}
