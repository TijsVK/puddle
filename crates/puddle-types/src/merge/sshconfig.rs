// SPDX-License-Identifier: GPL-3.0-or-later
//! `ssh_config`: puddle owns one `Include <pattern>` line, so `ssh` reads the drop-in folder
//! puddle writes into.
//!
//! The file is the image's, so nothing else in it is touched: when no `Include` that reaches the
//! pattern stands before the first `Host` or `Match` (an `Include` inside a block only applies
//! to that block), the line goes at the very top, behind one comment that says who added it and
//! why, and every other byte of the file stays where it is. The top is where the distributions
//! put it, and the first value `ssh` reads for an option wins, so puddle's drop-in then comes
//! before the system defaults.
//!
//! A file with a NUL byte, invalid UTF-8 or more than [`MAX_MERGE_FILE`] bytes is refused.

use super::{MAX_MERGE_FILE, MergeEntry, MergeRefusal, Merged, Unmerged};

/// The comment above the line puddle adds. Removal finds the pair by it, so it never changes.
pub(super) const MARKER: &str = "# Added by Puddle at boot: this image's ssh_config did not read the folder that holds Puddle's ssh settings.";

/// The only key path of this format.
pub(super) const KEY: &str = "Include";

fn read(existing: Option<&[u8]>) -> Result<Option<&str>, MergeRefusal> {
    let Some(bytes) = existing else {
        return Ok(None);
    };
    if bytes.len() > MAX_MERGE_FILE {
        return Err(MergeRefusal::TooLarge);
    }
    if bytes.contains(&0) {
        return Err(MergeRefusal::NulByte);
    }
    std::str::from_utf8(bytes)
        .map(Some)
        .map_err(|_| MergeRefusal::Syntax {
            format: "UTF-8",
            reason: "invalid byte sequence".to_owned(),
        })
}

/// The pattern as the entry holds it.
fn pattern(entries: &[MergeEntry]) -> &str {
    entries.first().map_or("", MergeEntry::value)
}

/// The file with the line set: as it is when an `Include` already reaches the pattern, else the
/// line behind its comment on top.
pub(super) fn apply(
    existing: Option<&[u8]>,
    entries: &[MergeEntry],
) -> Result<String, MergeRefusal> {
    let original = read(existing)?.unwrap_or("");
    let wanted = pattern(entries);
    if reaches(original, wanted) {
        return Ok(original.to_owned());
    }
    Ok(format!("{MARKER}\nInclude {wanted}\n{original}"))
}

/// Removes the pair puddle added; whether the file is empty afterwards. A pair the user edited
/// or moved is not puddle's any more and stays.
pub(super) fn unmerge(existing: &[u8]) -> Result<Unmerged, MergeRefusal> {
    let original = read(Some(existing))?.unwrap_or("");
    let (out, empty) = remove_pair(original);
    let merged = if out == original {
        Merged::Unchanged
    } else {
        Merged::Write(out.into_bytes())
    };
    Ok(Unmerged { merged, empty })
}

/// `text` without the first marker comment and the `Include` line right behind it.
fn remove_pair(text: &str) -> (String, bool) {
    let mut out = String::with_capacity(text.len());
    let mut lines = text.split_inclusive('\n').peekable();
    while let Some(line) = lines.next() {
        if line.trim_end_matches(['\r', '\n']) == MARKER
            && lines.peek().is_some_and(|next| {
                keyword(next).is_some_and(|k| k.eq_ignore_ascii_case("include"))
            })
        {
            lines.next();
            out.extend(lines);
            break;
        }
        out.push_str(line);
    }
    let empty = out.trim().is_empty();
    (out, empty)
}

/// The first word of a configuration line (`Key value` or `Key=value`); `None` for a blank line
/// or a comment.
fn keyword(line: &str) -> Option<&str> {
    let line = line.trim_start();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let end = line
        .find(|c: char| c.is_whitespace() || c == '=')
        .unwrap_or(line.len());
    Some(&line[..end])
}

/// The arguments after the keyword, quotes removed.
fn arguments(line: &str) -> Vec<String> {
    let line = line.trim_start();
    let rest = line
        .find(|c: char| c.is_whitespace() || c == '=')
        .map_or("", |i| &line[i..]);
    rest.trim_start_matches(|c: char| c.is_whitespace() || c == '=')
        .split_whitespace()
        .take_while(|w| !w.starts_with('#'))
        .map(|w| w.trim_matches('"').to_owned())
        .collect()
}

/// Whether an `Include` before the first `Host` or `Match` reads `wanted`'s files: the same
/// pattern, or its folder's `*`. A relative pattern is relative to `/etc/ssh`.
fn reaches(text: &str, wanted: &str) -> bool {
    let folder = wanted.rsplit_once('/').map_or("", |(dir, _)| dir);
    for line in text.lines() {
        let Some(word) = keyword(line) else { continue };
        if word.eq_ignore_ascii_case("host") || word.eq_ignore_ascii_case("match") {
            return false;
        }
        if !word.eq_ignore_ascii_case("include") {
            continue;
        }
        let hit = arguments(line).iter().any(|arg| {
            let arg = if arg.starts_with('/') || arg.starts_with('~') {
                arg.clone()
            } else {
                format!("/etc/ssh/{arg}")
            };
            arg == wanted || (!folder.is_empty() && arg == format!("{folder}/*"))
        });
        if hit {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MergeFormat, MergeSpec};

    const WANTED: &str = "/etc/ssh/ssh_config.d/*.conf";

    fn spec() -> MergeSpec {
        MergeSpec::new(
            MergeFormat::SshConfig,
            vec![MergeEntry::ssh_include(WANTED)],
        )
        .unwrap()
    }

    fn line() -> String {
        format!("{MARKER}\nInclude {WANTED}\n")
    }

    fn applied(file: &str) -> Merged {
        spec().apply(Some(file.as_bytes()), &[]).unwrap()
    }

    /// Debian's file: the line is there, so the file is not rewritten.
    const DEBIAN: &str =
        "\nInclude /etc/ssh/ssh_config.d/*.conf\n\nHost *\n    SendEnv LANG LC_*\n";

    #[test]
    fn a_file_without_the_line_gets_it_on_top_and_keeps_every_other_byte() {
        for file in [
            "Host *\n    SendEnv LANG LC_*\n",
            "# comment\r\nHost *\r\n\tForwardAgent no",
            "  \n\n",
            "Match host x\n  User y\n",
            "# Include /etc/ssh/ssh_config.d/*.conf\n",
            "Host a\n    Include /etc/ssh/ssh_config.d/*.conf\n",
            "Host *\n  # Include /etc/ssh/ssh_config.d/*.conf\n  Port=22\n",
            "Include /etc/ssh/other.d/*.conf\n",
            "Port 22\nHost x\n  Include /etc/ssh/ssh_config.d/*.conf\n",
        ] {
            let expected = Merged::Write(format!("{}{file}", line()).into_bytes());
            assert_eq!(applied(file), expected, "{file:?}");
        }
    }

    #[test]
    fn a_missing_or_empty_file_becomes_just_the_line() {
        let fresh = spec().fresh();
        assert_eq!(String::from_utf8(fresh.clone()).unwrap(), line());
        assert_eq!(
            spec().apply(None, &[]).unwrap(),
            Merged::Write(fresh.clone())
        );
        assert_eq!(spec().apply(Some(b""), &[]).unwrap(), Merged::Write(fresh));
    }

    #[test]
    fn an_include_that_reaches_the_folder_leaves_the_file_alone() {
        for file in [
            DEBIAN,
            "Include /etc/ssh/ssh_config.d/*.conf",
            "# top\ninclude=/etc/ssh/ssh_config.d/*.conf\nHost *\n",
            "Include ssh_config.d/*.conf\n",
            "Include \"/etc/ssh/ssh_config.d/*.conf\"\n",
            "Include /etc/ssh/ssh_config.d/*\n",
            "Include /nowhere/*.conf /etc/ssh/ssh_config.d/*.conf # both\n",
            "Include\t/etc/ssh/ssh_config.d/*.conf\n",
        ] {
            assert_eq!(applied(file), Merged::Unchanged, "{file:?}");
        }
    }

    #[test]
    fn applying_twice_changes_nothing_the_second_time() {
        let first = format!("{}Host *\n    Port 22\n", line());
        assert_eq!(
            applied("Host *\n    Port 22\n"),
            Merged::Write(first.clone().into_bytes())
        );
        assert_eq!(applied(&first), Merged::Unchanged);
    }

    #[test]
    fn an_unreadable_file_is_refused_and_not_quoted() {
        let s = spec();
        assert_eq!(
            s.apply(Some(&vec![b' '; MAX_MERGE_FILE + 1]), &[]),
            Err(MergeRefusal::TooLarge)
        );
        assert_eq!(
            s.apply(Some(b"Host a\0\n"), &[]),
            Err(MergeRefusal::NulByte)
        );
        let e = s.apply(Some(b"Host \xff\n"), &[]).unwrap_err();
        assert_eq!(
            e.to_string(),
            "the file is not valid UTF-8: invalid byte sequence"
        );
        assert_eq!(
            crate::unmerge(MergeFormat::SshConfig, b"\xff", &[vec!["Include".into()]]),
            Err(e)
        );
    }

    #[test]
    fn removal_takes_out_exactly_the_pair_puddle_added() {
        let keys = [vec!["Include".to_owned()]];
        let user = "Host *\n    Port 22\n";
        let unmerge =
            |file: &str| crate::unmerge(MergeFormat::SshConfig, file.as_bytes(), &keys).unwrap();
        let back = unmerge(&format!("{}{user}", line()));
        assert_eq!(back.merged, Merged::Write(user.as_bytes().to_vec()));
        assert!(!back.empty);
        // A file puddle created is empty once the pair is gone.
        let alone = unmerge(&line());
        assert!(alone.empty);
        assert_eq!(alone.merged, Merged::Write(Vec::new()));
        // The image's own line, an edited pair and a moved line are not puddle's.
        for file in [DEBIAN, "Host *\nInclude /etc/ssh/ssh_config.d/*.conf\n"] {
            let u = unmerge(file);
            assert_eq!(u.merged, Merged::Unchanged, "{file:?}");
            assert!(!u.empty);
        }
        let edited = format!("{MARKER}\nHost x\nInclude {WANTED}\n");
        assert_eq!(unmerge(&edited).merged, Merged::Unchanged);
        assert_eq!(unmerge(MARKER).merged, Merged::Unchanged);
        assert!(unmerge("  \n").empty);
    }

    #[test]
    fn removal_after_the_user_added_lines_below_keeps_them() {
        let file = format!("{}Host a\r\n  User b\r\n", line());
        let u = crate::unmerge(
            MergeFormat::SshConfig,
            file.as_bytes(),
            &[vec!["Include".into()]],
        )
        .unwrap();
        assert_eq!(u.merged, Merged::Write(b"Host a\r\n  User b\r\n".to_vec()));
    }

    #[test]
    fn the_spec_owns_only_one_include_word() {
        let bad = |entry| {
            MergeSpec::new(MergeFormat::SshConfig, vec![entry])
                .unwrap_err()
                .to_string()
        };
        assert!(bad(MergeEntry::json(&["Host"], &serde_json::json!("x"))).contains("only Include"));
        for value in ["", "a b", "a\"b", "a#b", "a\nb"] {
            assert!(
                bad(MergeEntry::ssh_include(value)).contains("one word"),
                "{value:?}"
            );
        }
    }
}
