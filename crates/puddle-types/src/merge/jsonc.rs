// SPDX-License-Identifier: GPL-3.0-or-later
//! JSON with comments, as VS Code reads its settings files: `//` and `/* */` comments and a
//! trailing comma before `}` or `]`.
//!
//! [`blank`] gives a *view* of the text that is plain JSON and has exactly the same length: every
//! comment byte (apart from line breaks) and every trailing comma becomes a space. The JSON engine
//! scans and parses the view and splices the original, so offsets from one are valid in the other
//! and the user's comments stay where they are.

use std::ops::Range;

use super::MergeRefusal;

/// The strict-JSON view of a text, and where its comments are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Blanked {
    /// The text with comments and trailing commas replaced by spaces (line breaks stay).
    pub view: String,
    /// The byte range of each comment: `//` up to (not including) the line break, `/*` up to and
    /// including `*/`.
    pub comments: Vec<Range<usize>>,
}

impl Blanked {
    /// A text that is already strict JSON: nothing to blank.
    pub(super) fn strict(text: &str) -> Self {
        Self {
            view: text.to_owned(),
            comments: Vec::new(),
        }
    }

    /// Whether any comment lies inside `range`.
    pub(super) fn has_comment_in(&self, range: Range<usize>) -> bool {
        self.comments
            .iter()
            .any(|c| c.start >= range.start && c.end <= range.end)
    }
}

fn syntax(reason: &str) -> MergeRefusal {
    MergeRefusal::Syntax {
        format: "JSONC",
        reason: reason.to_owned(),
    }
}

/// Blanks the comments and trailing commas of `text`.
///
/// # Errors
///
/// A [`MergeRefusal::Syntax`] for a `/*` that is never closed. Anything else that isn't JSON is
/// left for the JSON parser to reject.
pub(super) fn blank(text: &str) -> Result<Blanked, MergeRefusal> {
    let src = text.as_bytes();
    let mut out = src.to_vec();
    let mut comments = Vec::new();
    // A comma not yet followed by anything but whitespace and comments.
    let mut pending: Option<usize> = None;
    let mut i = 0;
    while let Some(&c) = src.get(i) {
        match c {
            b'"' => {
                pending = None;
                i = string_end(src, i);
            }
            b'/' if src.get(i + 1) == Some(&b'/') => {
                let end = src
                    .get(i..)
                    .and_then(|s| s.iter().position(|&b| b == b'\n' || b == b'\r'))
                    .map_or(src.len(), |n| i + n);
                comments.push(i..end);
                fill(&mut out, i..end);
                i = end;
            }
            b'/' if src.get(i + 1) == Some(&b'*') => {
                let close = src
                    .get(i + 2..)
                    .and_then(|s| s.windows(2).position(|w| w == b"*/"))
                    .ok_or_else(|| syntax("a comment is never closed"))?;
                let end = i + 2 + close + 2;
                comments.push(i..end);
                fill(&mut out, i..end);
                i = end;
            }
            b',' => {
                pending = Some(i);
                i += 1;
            }
            b'}' | b']' => {
                if let Some(p) = pending.take()
                    && let Some(b) = out.get_mut(p)
                {
                    *b = b' ';
                }
                i += 1;
            }
            b' ' | b'\t' | b'\n' | b'\r' => i += 1,
            _ => {
                pending = None;
                i += 1;
            }
        }
    }
    // Only whole comments (ASCII delimiters) and single commas were replaced by ASCII, so the
    // bytes are still UTF-8.
    let view = String::from_utf8(out).map_err(|_| syntax("invalid byte sequence"))?;
    Ok(Blanked { view, comments })
}

/// `i` is on a `"`; the offset after the closing one (or the end of an unterminated string, which
/// the JSON parser then rejects).
fn string_end(b: &[u8], mut i: usize) -> usize {
    i += 1;
    while let Some(&c) = b.get(i) {
        match c {
            b'\\' => i += 2,
            b'"' => return i + 1,
            _ => i += 1,
        }
    }
    b.len()
}

/// Spaces over `range`, keeping line breaks (block comments can span lines).
fn fill(out: &mut [u8], range: Range<usize>) {
    for b in out.get_mut(range).unwrap_or_default() {
        if *b != b'\n' && *b != b'\r' {
            *b = b' ';
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view(text: &str) -> String {
        blank(text).unwrap().view
    }

    #[test]
    fn comments_become_spaces_and_the_length_is_unchanged() {
        let t = "{ // one\n  \"a\": 1, /* two\nlines */ \"b\": 2 }";
        let b = blank(t).unwrap();
        assert_eq!(b.view.len(), t.len());
        assert_eq!(b.view, "{       \n  \"a\": 1,       \n         \"b\": 2 }");
        assert_eq!(b.comments, [2..8, 19..34]);
        assert!(serde_json::from_str::<serde_json::Value>(&b.view).is_ok());
    }

    #[test]
    fn comment_lookalikes_inside_strings_stay() {
        let t = r#"{"url": "http://x/*y*/", "e": "\"//"}"#;
        let b = blank(t).unwrap();
        assert_eq!(b.view, t);
        assert_eq!(b.comments.len(), 0);
    }

    #[test]
    fn trailing_commas_are_blanked_only_before_a_closer() {
        assert_eq!(view("{\"a\": [1, 2,],}"), "{\"a\": [1, 2 ] }");
        assert_eq!(view("{\"a\": 1, // c\n}"), "{\"a\": 1      \n}");
        // Not trailing: kept. A doubled comma is left for the JSON parser to reject.
        assert_eq!(view("[1,2]"), "[1,2]");
        let b = blank("[1,,]").unwrap();
        assert!(serde_json::from_str::<serde_json::Value>(&b.view).is_err());
    }

    #[test]
    fn line_comments_end_at_either_line_break() {
        let b = blank("{} // a\r\n// b\n").unwrap();
        assert_eq!(b.comments, [3..7, 9..13]);
        assert_eq!(b.view, "{}     \r\n    \n");
    }

    #[test]
    fn multibyte_text_in_comments_keeps_the_length() {
        let t = "{\"é\": 1} // héllo ✓";
        let b = blank(t).unwrap();
        assert_eq!(b.view.len(), t.len());
        assert!(b.view.is_char_boundary(10));
    }

    #[test]
    fn an_unclosed_block_comment_is_a_syntax_error() {
        assert_eq!(
            blank("{} /* nope"),
            Err(MergeRefusal::Syntax {
                format: "JSONC",
                reason: "a comment is never closed".into()
            })
        );
    }

    #[test]
    fn has_comment_in_looks_inside_a_range_only() {
        let b = blank("{ /* c */ }").unwrap();
        assert!(b.has_comment_in(1..10));
        assert!(!b.has_comment_in(0..5));
    }
}
