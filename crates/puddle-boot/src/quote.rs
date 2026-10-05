// SPDX-License-Identifier: GPL-3.0-or-later
//! Quoting for the plan, which `boot.sh` sources as POSIX sh. Everything puddle puts into the plan
//! goes through one of these two functions, so no value can end a word or run a command.

use std::fmt::Write as _;

/// `s` as one single-quoted shell word: `it's` becomes `'it'\''s'`.
pub(crate) fn sh_word(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

/// `bytes` as a single-quoted `printf` format that prints exactly `bytes`. Printable ASCII stays
/// as it is, except the bytes `printf` or the quoting would interpret (`%`, `\`, `'`) and `-` (a
/// leading `-` could read as an option to some `printf`s); every other byte becomes a three-digit
/// octal escape, which POSIX `printf` formats support.
pub(crate) fn printf_format(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() + 2);
    out.push('\'');
    for &b in bytes {
        if (0x20..0x7f).contains(&b) && !matches!(b, b'%' | b'\\' | b'\'' | b'-') {
            out.push(char::from(b));
        } else {
            // Writing to a String can't fail.
            let _ = write!(out, "\\{b:03o}");
        }
    }
    out.push('\'');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words_are_single_quoted_with_quotes_escaped() {
        assert_eq!(sh_word(""), "''");
        assert_eq!(sh_word("a b"), "'a b'");
        assert_eq!(sh_word("it's"), r"'it'\''s'");
        assert_eq!(sh_word("$(x) `y` \\ \n"), "'$(x) `y` \\ \n'");
    }

    #[test]
    fn printf_formats_escape_everything_special() {
        assert_eq!(printf_format(b""), "''");
        assert_eq!(printf_format(b"abc XYZ/09.:="), "'abc XYZ/09.:='");
        assert_eq!(printf_format(b"%s"), r"'\045s'");
        assert_eq!(printf_format(b"\\n"), r"'\134n'");
        assert_eq!(printf_format(b"'"), r"'\047'");
        assert_eq!(printf_format(b"-----BEGIN"), r"'\055\055\055\055\055BEGIN'");
        assert_eq!(printf_format(b"a\nb\0\xff"), r"'a\012b\000\377'");
    }

    #[test]
    fn printf_formats_hold_no_quote_or_control_byte() {
        let all: Vec<u8> = (0..=255).collect();
        let f = printf_format(&all);
        let inner = &f[1..f.len() - 1];
        assert!(!inner.contains('\''));
        assert!(inner.bytes().all(|b| (0x20..0x7f).contains(&b)));
    }
}
