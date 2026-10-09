// SPDX-License-Identifier: GPL-3.0-or-later
//! The body of a token request or answer: a JSON object or a URL-encoded form, with typed access
//! to its top-level text fields.
//!
//! A login's token endpoint is the one place puddle reads a body: Claude Code posts and answers
//! JSON, `gh` posts and reads a form, and GitHub answers either, by the request's `Accept`. The
//! format follows the message's own `Content-Type`, in both directions, so no profile says
//! which one a service uses. Only top-level text fields are read or replaced; every other part of
//! the body goes through as it was (a form keeps the exact bytes of the fields that were not
//! touched).

use std::borrow::Cow;

use serde_json::{Map, Value};
use zeroize::{Zeroize as _, Zeroizing};

/// How the body is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyFormat {
    /// A JSON object (`application/json`, or a `+json` type).
    Json,
    /// `application/x-www-form-urlencoded`.
    Form,
}

/// Why a body could not be read as a token message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TokenBodyError {
    /// The content type is neither JSON nor a form.
    #[error("the body is neither JSON nor a form")]
    Format,
    /// The body is not valid text for its content type, or not a JSON object.
    #[error("the body does not parse")]
    Malformed,
}

/// One top-level field of a form: its text as sent, and what it says once decoded.
#[derive(Debug, Clone)]
struct Pair {
    raw: String,
    key: String,
    value: String,
}

#[derive(Debug, Clone)]
enum Parsed {
    Json(Map<String, Value>),
    Form(Vec<Pair>),
}

/// A token request or answer body, parsed by its content type.
///
/// ```
/// use puddle_proxy::terminate::TokenBody;
///
/// let mut body = TokenBody::parse(Some("application/json"), br#"{"access_token":"a1","expires_in":60}"#).unwrap();
/// assert_eq!(body.text("access_token").as_deref(), Some("a1"));
/// body.set_text("access_token", "b2");
/// assert_eq!(*body.render(), br#"{"access_token":"b2","expires_in":60}"#);
/// ```
#[derive(Debug, Clone)]
pub struct TokenBody {
    parsed: Parsed,
}

/// The media type of a `Content-Type` value, lower-cased and without parameters.
fn media_type(content_type: &str) -> String {
    content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
}

impl TokenBody {
    /// Whether [`Self::parse`] reads bodies of this `content_type`: JSON or a form.
    #[must_use]
    pub fn reads(content_type: Option<&str>) -> bool {
        let media = media_type(content_type.unwrap_or_default());
        media == "application/json"
            || media.ends_with("+json")
            || media == "application/x-www-form-urlencoded"
    }

    /// Parses `body` as the format `content_type` names.
    ///
    /// # Errors
    /// [`TokenBodyError::Format`] for another content type (or none), [`TokenBodyError::Malformed`]
    /// for a body that is not valid in its format.
    pub fn parse(content_type: Option<&str>, body: &[u8]) -> Result<Self, TokenBodyError> {
        let media = media_type(content_type.unwrap_or_default());
        if media == "application/json" || media.ends_with("+json") {
            let Value::Object(map) =
                serde_json::from_slice(body).map_err(|_| TokenBodyError::Malformed)?
            else {
                return Err(TokenBodyError::Malformed);
            };
            return Ok(Self {
                parsed: Parsed::Json(map),
            });
        }
        if media == "application/x-www-form-urlencoded" {
            let text = std::str::from_utf8(body).map_err(|_| TokenBodyError::Malformed)?;
            let pairs = text
                .split('&')
                .filter(|raw| !raw.is_empty())
                .map(|raw| {
                    let (key, value) = url::form_urlencoded::parse(raw.as_bytes())
                        .next()
                        .unwrap_or((Cow::Borrowed(""), Cow::Borrowed("")));
                    Pair {
                        raw: raw.to_owned(),
                        key: key.into_owned(),
                        value: value.into_owned(),
                    }
                })
                .collect();
            return Ok(Self {
                parsed: Parsed::Form(pairs),
            });
        }
        Err(TokenBodyError::Format)
    }

    /// The format the body is in.
    #[must_use]
    pub fn format(&self) -> BodyFormat {
        match self.parsed {
            Parsed::Json(_) => BodyFormat::Json,
            Parsed::Form(_) => BodyFormat::Form,
        }
    }

    /// The text of the top-level field `name`: a JSON string, or a form value decoded. `None`
    /// when there is no such field, it is not text, or (a form) it appears more than once, so
    /// that what puddle reads is what a server picking the first or the last one would read.
    #[must_use]
    pub fn text(&self, name: &str) -> Option<Cow<'_, str>> {
        match &self.parsed {
            Parsed::Json(map) => map.get(name)?.as_str().map(Cow::Borrowed),
            Parsed::Form(pairs) => {
                let mut found = pairs.iter().filter(|pair| pair.key == name);
                let first = found.next()?;
                found.next().is_none().then(|| Cow::Borrowed(&*first.value))
            }
        }
    }

    /// Replaces the text of the field `name` with `value`; `false` (nothing changed) when
    /// [`Self::text`] would not have found it.
    pub fn set_text(&mut self, name: &str, value: &str) -> bool {
        // `text` is the one rule for which field counts: a field it would not find is not changed.
        if self.text(name).is_none() {
            return false;
        }
        match &mut self.parsed {
            Parsed::Json(map) => map
                .get_mut(name)
                .map(|slot| *slot = Value::String(value.to_owned()))
                .is_some(),
            Parsed::Form(pairs) => pairs
                .iter_mut()
                .find(|pair| pair.key == name)
                .map(|pair| {
                    let encode = |text: &str| -> String {
                        url::form_urlencoded::byte_serialize(text.as_bytes()).collect()
                    };
                    pair.raw = format!("{}={}", encode(&pair.key), encode(value));
                    value.clone_into(&mut pair.value);
                })
                .is_some(),
        }
    }

    /// The body as bytes: JSON compact, a form with each untouched field as it was sent. The
    /// bytes are zeroised when dropped, since they may hold a token.
    #[must_use]
    pub fn render(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(match &self.parsed {
            Parsed::Json(map) => serde_json::to_vec(map).unwrap_or_default(),
            Parsed::Form(pairs) => pairs
                .iter()
                .map(|pair| pair.raw.as_str())
                .collect::<Vec<_>>()
                .join("&")
                .into_bytes(),
        })
    }
}

/// Wipes every text in `value`: a body can hold a token.
fn wipe(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(wipe),
        Value::Object(map) => map.values_mut().for_each(wipe),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

impl Drop for TokenBody {
    fn drop(&mut self) {
        match &mut self.parsed {
            Parsed::Json(map) => map.values_mut().for_each(wipe),
            Parsed::Form(pairs) => {
                for pair in pairs {
                    pair.raw.zeroize();
                    pair.value.zeroize();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn json(text: &str) -> TokenBody {
        TokenBody::parse(Some("application/json; charset=utf-8"), text.as_bytes()).unwrap()
    }

    fn form(text: &str) -> TokenBody {
        TokenBody::parse(Some("Application/X-WWW-Form-Urlencoded"), text.as_bytes()).unwrap()
    }

    #[test]
    fn json_fields_are_read_and_replaced_and_the_rest_is_kept() {
        let mut body = json(
            r#"{"grant_type":"refresh_token","refresh_token":"old","n":1,"nested":{"refresh_token":"deep"}}"#,
        );
        assert_eq!(body.format(), BodyFormat::Json);
        assert_eq!(body.text("refresh_token").as_deref(), Some("old"));
        assert_eq!(body.text("nested"), None, "only text fields are read");
        assert_eq!(body.text("n"), None);
        assert_eq!(body.text("missing"), None);
        assert!(body.set_text("refresh_token", "new"));
        assert!(!body.set_text("missing", "x"));
        let rendered: Value = serde_json::from_slice(&body.render()).unwrap();
        assert_eq!(rendered["refresh_token"], "new");
        assert_eq!(rendered["nested"]["refresh_token"], "deep");
        assert_eq!(rendered["n"], 1);
    }

    #[test]
    fn a_form_keeps_the_exact_bytes_of_the_fields_it_does_not_touch() {
        let mut body = form(
            "client_id=abc&grant_type=refresh_token&refresh_token=old%2Bvalue&scope=repo+gist",
        );
        assert_eq!(body.format(), BodyFormat::Form);
        assert_eq!(body.text("refresh_token").as_deref(), Some("old+value"));
        assert_eq!(body.text("scope").as_deref(), Some("repo gist"));
        assert!(body.set_text("refresh_token", "gho_a+b/c"));
        assert_eq!(
            *body.render(),
            b"client_id=abc&grant_type=refresh_token&refresh_token=gho_a%2Bb%2Fc&scope=repo+gist"
        );
    }

    #[test]
    fn a_form_field_that_appears_twice_is_not_read() {
        let mut body = form("refresh_token=one&refresh_token=two&x=1");
        assert_eq!(body.text("refresh_token"), None);
        assert!(!body.set_text("refresh_token", "new"));
        assert_eq!(*body.render(), b"refresh_token=one&refresh_token=two&x=1");
        assert_eq!(body.text("x").as_deref(), Some("1"));
    }

    #[test]
    fn a_form_with_empty_parts_and_a_field_without_a_value_still_parses() {
        let mut body = form("&a&b=&&c=1&");
        assert_eq!(body.text("a").as_deref(), Some(""));
        assert_eq!(body.text("b").as_deref(), Some(""));
        assert!(body.set_text("c", "2"));
        assert_eq!(*body.render(), b"a&b=&c=2");
        assert_eq!(*form("").render(), b"");
    }

    #[test]
    fn reads_says_which_content_types_parse() {
        for yes in [
            "application/json",
            "Application/JSON; charset=utf-8",
            "application/x-www-form-urlencoded",
            "application/problem+json",
        ] {
            assert!(TokenBody::reads(Some(yes)), "{yes}");
        }
        for no in ["text/html", "application/xml", "", "application/jsonp"] {
            assert!(!TokenBody::reads(Some(no)), "{no}");
        }
        assert!(!TokenBody::reads(None));
    }

    #[test]
    fn the_content_type_decides_and_other_types_are_refused() {
        assert_eq!(
            TokenBody::parse(Some("text/plain"), b"{}").unwrap_err(),
            TokenBodyError::Format
        );
        assert_eq!(
            TokenBody::parse(None, b"{}").unwrap_err(),
            TokenBodyError::Format
        );
        assert!(TokenBody::parse(Some("application/vnd.x+json"), b"{}").is_ok());
    }

    #[test]
    fn bodies_that_do_not_parse_are_refused() {
        for (content_type, body) in [
            ("application/json", &b"not json"[..]),
            ("application/json", b"[1,2]"),
            ("application/json", b"\"text\""),
            ("application/json", b""),
            ("application/x-www-form-urlencoded", b"\xff\xfe=1"),
        ] {
            assert_eq!(
                TokenBody::parse(Some(content_type), body).unwrap_err(),
                TokenBodyError::Malformed,
                "{content_type} {body:?}"
            );
        }
    }

    #[test]
    fn hostile_json_does_not_panic() {
        let deep = format!("{}1{}", "[".repeat(10_000), "]".repeat(10_000));
        let object = format!("{{\"a\":{deep}}}");
        assert_eq!(
            TokenBody::parse(Some("application/json"), object.as_bytes()).unwrap_err(),
            TokenBodyError::Malformed
        );
    }

    proptest! {
        #[test]
        fn nothing_a_guest_sends_panics_the_parser(
            bytes in prop::collection::vec(any::<u8>(), 0..400),
            json in any::<bool>(),
        ) {
            let content_type = if json { "application/json" } else { "application/x-www-form-urlencoded" };
            if let Ok(mut body) = TokenBody::parse(Some(content_type), &bytes) {
                let _ = body.text("refresh_token");
                let _ = body.set_text("refresh_token", "x");
                let _ = body.render();
            }
        }

        #[test]
        fn replacing_a_json_field_changes_that_field_only(
            fields in prop::collection::btree_map("[a-z_]{1,12}", "[ -~]{0,30}", 1..8),
            pick in 0_usize..8,
            value in "[ -~]{0,30}",
        ) {
            let object: Map<String, Value> = fields
                .iter()
                .map(|(k, v)| (k.clone(), Value::String(v.clone())))
                .collect();
            let text = Value::Object(object).to_string();
            let mut body = TokenBody::parse(Some("application/json"), text.as_bytes()).unwrap();
            let names: Vec<&String> = fields.keys().collect();
            let name = names[pick % names.len()].clone();
            prop_assert!(body.set_text(&name, &value));
            let after: Value = serde_json::from_slice(&body.render()).unwrap();
            for (key, old) in &fields {
                let want = if *key == name { &value } else { old };
                prop_assert_eq!(after[key].as_str(), Some(want.as_str()));
            }
        }

        #[test]
        fn replacing_a_form_field_keeps_every_other_pair_byte_for_byte(
            others in prop::collection::vec("[a-z]{1,6}=[A-Za-z0-9%+._~-]{0,12}", 0..6),
            before in 0_usize..6,
            value in "[ -~]{0,30}",
        ) {
            let at = before.min(others.len());
            let mut parts = others.clone();
            parts.insert(at, "zz_target=old".to_owned());
            // A pair of ours must stay unique for the field to be read.
            prop_assume!(!others.iter().any(|p| p.starts_with("zz_target=")));
            let sent = parts.join("&");
            let mut body = TokenBody::parse(Some("application/x-www-form-urlencoded"), sent.as_bytes()).unwrap();
            prop_assert!(body.set_text("zz_target", &value));
            let rendered = String::from_utf8(body.render().to_vec()).unwrap();
            let pieces: Vec<&str> = rendered.split('&').collect();
            prop_assert_eq!(pieces.len(), parts.len());
            for (i, (got, was)) in pieces.iter().zip(&parts).enumerate() {
                if i != at {
                    prop_assert_eq!(got, was);
                }
            }
            let again = TokenBody::parse(Some("application/x-www-form-urlencoded"), rendered.as_bytes()).unwrap();
            let read = again.text("zz_target");
            prop_assert_eq!(read.as_deref(), Some(value.as_str()));
        }
    }
}
