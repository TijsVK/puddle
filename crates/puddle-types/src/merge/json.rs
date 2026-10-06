// SPDX-License-Identifier: GPL-3.0-or-later
//! The JSON engine: edits the text in place, so every byte outside the owned keys stays.
//!
//! Each edit validates the whole text with `serde_json` first, then scans it (iteratively, so
//! deep nesting can't overflow the stack) to find the byte spans of the members on an owned
//! path, and splices only those spans. After all edits, the result is parsed again and compared
//! with the same edits done on the parsed value; any difference refuses the merge
//! ([`MergeRefusal::Inconsistent`]) instead of writing a file puddle can't vouch for.

use serde_json::{Map, Value};

use super::{MergeEntry, MergeRefusal, display_key};

/// Indent unit for new members when the file shows none (the Docker CLI writes tabs).
const DEFAULT_UNIT: &str = "\t";

/// Applies a spec: removes `dropped`, sets every entry. `None` in means no file; the result is
/// `None` only when nothing was written and nothing exists.
pub(super) fn apply(
    original: Option<&str>,
    dropped: &[&[String]],
    entries: &[MergeEntry],
) -> Result<Option<String>, MergeRefusal> {
    let start = original.unwrap_or("{}\n");
    let before = parse_root(start)?;
    let mut expected = before.clone();
    let mut text = start.to_owned();
    for key in dropped {
        text = remove(&text, key)?;
        value_remove(&mut expected, key);
    }
    for e in entries {
        let value: Value =
            serde_json::from_str(&e.value).map_err(|_| MergeRefusal::Inconsistent)?;
        text = set(&text, &e.key, &value)?;
        value_set(&mut expected, &e.key, value);
    }
    check(&text, &expected)?;
    Ok(Some(text))
}

/// Removes `keys` (and objects left empty on their paths). Returns the text and whether the top
/// level is empty.
pub(super) fn unmerge(original: &str, keys: &[&[String]]) -> Result<(String, bool), MergeRefusal> {
    let mut expected = parse_root(original)?;
    let mut text = original.to_owned();
    for key in keys {
        text = remove(&text, key)?;
        value_remove(&mut expected, key);
    }
    check(&text, &expected)?;
    let empty = expected.as_object().is_some_and(Map::is_empty);
    Ok((text, empty))
}

fn parse_root(text: &str) -> Result<Value, MergeRefusal> {
    let v: Value = serde_json::from_str(text).map_err(|e| MergeRefusal::Syntax {
        format: "JSON",
        reason: e.to_string(),
    })?;
    if v.is_object() {
        Ok(v)
    } else {
        Err(MergeRefusal::NotAnObject)
    }
}

fn check(text: &str, expected: &Value) -> Result<(), MergeRefusal> {
    match serde_json::from_str::<Value>(text) {
        Ok(v) if &v == expected => Ok(()),
        _ => Err(MergeRefusal::Inconsistent),
    }
}

// --- The value-level twin of each edit, for the self-check ------------------------------------

fn value_set(root: &mut Value, key: &[String], value: Value) {
    let Some((last, parents)) = key.split_last() else {
        return;
    };
    let mut cur = root;
    for k in parents {
        let Some(obj) = cur.as_object_mut() else {
            return;
        };
        cur = obj
            .entry(k.clone())
            .or_insert_with(|| Value::Object(Map::new()));
    }
    if let Some(obj) = cur.as_object_mut() {
        obj.insert(last.clone(), value);
    }
}

/// Removes `key`; then every parent on the path that is left empty. Returns whether `key` was
/// there.
fn value_remove(root: &mut Value, key: &[String]) -> bool {
    let Some((first, rest)) = key.split_first() else {
        return false;
    };
    let Some(obj) = root.as_object_mut() else {
        return false;
    };
    if rest.is_empty() {
        return obj.remove(first).is_some();
    }
    let Some(child) = obj.get_mut(first) else {
        return false;
    };
    let removed = value_remove(child, rest);
    if removed && child.as_object().is_some_and(Map::is_empty) {
        obj.remove(first);
    }
    removed
}

// --- The scanner -----------------------------------------------------------------------------

/// One `"key": value` member: byte offsets into the text.
struct Member {
    key: String,
    key_start: usize,
    value_start: usize,
    value_end: usize,
}

/// An object: the offsets of its braces and its members.
struct Object {
    open: usize,
    close: usize,
    members: Vec<Member>,
}

/// The text is valid JSON when the scanner runs, so a surprise is a bug, not bad input.
fn bug<T>() -> Result<T, MergeRefusal> {
    Err(MergeRefusal::Inconsistent)
}

fn at(b: &[u8], i: usize) -> Option<u8> {
    b.get(i).copied()
}

fn skip_ws(b: &[u8], mut i: usize) -> usize {
    while matches!(at(b, i), Some(b' ' | b'\t' | b'\n' | b'\r')) {
        i += 1;
    }
    i
}

/// `i` is on a `"`; returns the offset after the closing one.
fn skip_string(b: &[u8], mut i: usize) -> Result<usize, MergeRefusal> {
    i += 1;
    loop {
        match at(b, i) {
            Some(b'\\') => i += 2,
            Some(b'"') => return Ok(i + 1),
            Some(_) => i += 1,
            None => return bug(),
        }
    }
}

/// `i` is on the first byte of a value; returns the offset after it.
fn skip_value(b: &[u8], mut i: usize) -> Result<usize, MergeRefusal> {
    match at(b, i) {
        Some(b'"') => skip_string(b, i),
        Some(b'{' | b'[') => {
            let mut depth = 0usize;
            loop {
                match at(b, i) {
                    Some(b'"') => {
                        i = skip_string(b, i)?;
                        continue;
                    }
                    Some(b'{' | b'[') => depth += 1,
                    Some(b'}' | b']') => {
                        depth -= 1;
                        if depth == 0 {
                            return Ok(i + 1);
                        }
                    }
                    Some(_) => {}
                    None => return bug(),
                }
                i += 1;
            }
        }
        Some(_) => {
            while let Some(c) = at(b, i) {
                if matches!(c, b',' | b'}' | b']' | b' ' | b'\t' | b'\n' | b'\r') {
                    break;
                }
                i += 1;
            }
            Ok(i)
        }
        None => bug(),
    }
}

/// The object whose `{` is at `open`.
fn object_at(text: &str, open: usize) -> Result<Object, MergeRefusal> {
    let b = text.as_bytes();
    if at(b, open) != Some(b'{') {
        return bug();
    }
    let mut members = Vec::new();
    let mut i = open + 1;
    loop {
        i = skip_ws(b, i);
        match at(b, i) {
            Some(b'}') => {
                return Ok(Object {
                    open,
                    close: i,
                    members,
                });
            }
            Some(b'"') => {}
            _ => return bug(),
        }
        let key_start = i;
        let key_end = skip_string(b, i)?;
        let Some(raw) = text.get(key_start..key_end) else {
            return bug();
        };
        let key: String = serde_json::from_str(raw).map_err(|_| MergeRefusal::Inconsistent)?;
        i = skip_ws(b, key_end);
        if at(b, i) != Some(b':') {
            return bug();
        }
        let value_start = skip_ws(b, i + 1);
        let value_end = skip_value(b, value_start)?;
        members.push(Member {
            key,
            key_start,
            value_start,
            value_end,
        });
        i = skip_ws(b, value_end);
        if at(b, i) == Some(b',') {
            i += 1;
        }
    }
}

fn root(text: &str) -> Result<Object, MergeRefusal> {
    object_at(text, skip_ws(text.as_bytes(), 0))
}

/// Where an owned path stands in the file.
enum Found {
    /// The member for the whole path: `obj.members[idx]`.
    Member { obj: Object, idx: usize },
    /// `obj` is the object at `key[..depth]`, and it has no member `key[depth]`.
    Missing { obj: Object, depth: usize },
}

fn find(text: &str, key: &[String]) -> Result<Found, MergeRefusal> {
    let mut obj = root(text)?;
    for (depth, k) in key.iter().enumerate() {
        let mut hits = obj
            .members
            .iter()
            .enumerate()
            .filter(|(_, m)| &m.key == k)
            .map(|(i, _)| i);
        let Some(idx) = hits.next() else {
            return Ok(Found::Missing { obj, depth });
        };
        let shown = || display_key(key.get(..=depth).unwrap_or(key));
        if hits.next().is_some() {
            return Err(MergeRefusal::DuplicateKey { key: shown() });
        }
        if depth + 1 == key.len() {
            return Ok(Found::Member { obj, idx });
        }
        let Some(m) = obj.members.get(idx) else {
            return bug();
        };
        if at(text.as_bytes(), m.value_start) != Some(b'{') {
            return Err(MergeRefusal::Conflict { key: shown() });
        }
        obj = object_at(text, m.value_start)?;
    }
    bug()
}

// --- Layout ----------------------------------------------------------------------------------

/// The whitespace that starts the line holding offset `pos`.
fn line_indent(text: &str, pos: usize) -> &str {
    let head = text.get(..pos).unwrap_or("");
    let line = head
        .rfind('\n')
        .map_or(head, |n| head.get(n + 1..).unwrap_or(""));
    let end = line
        .find(|c: char| c != ' ' && c != '\t')
        .unwrap_or(line.len());
    line.get(..end).unwrap_or("")
}

/// Whether `pos` is the first non-blank byte on its line, after `after` (i.e. on a later line).
fn starts_line(text: &str, pos: usize, after: usize) -> bool {
    let head = text.get(..pos).unwrap_or("");
    match head.rfind('\n') {
        Some(n) if n >= after => head
            .get(n + 1..)
            .is_some_and(|s| s.bytes().all(|c| c == b' ' || c == b'\t')),
        _ => false,
    }
}

/// How much deeper `obj`'s members are indented than the object itself, when its first member
/// starts a line.
fn own_unit(text: &str, obj: &Object) -> Option<String> {
    let first = obj.members.first()?;
    if !starts_line(text, first.key_start, obj.open) {
        return None;
    }
    line_indent(text, first.key_start)
        .strip_prefix(line_indent(text, obj.open))
        .filter(|u| !u.is_empty())
        .map(str::to_owned)
}

/// The indent unit for new lines in `obj`: its own, else the top level's, else a tab.
fn indent_unit(text: &str, obj: &Object) -> String {
    own_unit(text, obj)
        .or_else(|| root(text).ok().and_then(|r| own_unit(text, &r)))
        .unwrap_or_else(|| DEFAULT_UNIT.to_owned())
}

/// `value` on lines indented by `unit`, continuation lines starting with `base`.
fn pretty(value: &Value, unit: &str, base: &str) -> String {
    let mut out = Vec::new();
    let fmt = serde_json::ser::PrettyFormatter::with_indent(unit.as_bytes());
    let mut ser = serde_json::Serializer::with_formatter(&mut out, fmt);
    // Serialising a `Value` into a Vec can't fail.
    let text = match serde::Serialize::serialize(value, &mut ser) {
        Ok(()) => String::from_utf8(out).unwrap_or_default(),
        Err(_) => value.to_string(),
    };
    text.replace('\n', &format!("\n{base}"))
}

fn quoted(key: &str) -> String {
    Value::String(key.to_owned()).to_string()
}

fn splice(text: &str, start: usize, end: usize, with: &str) -> Result<String, MergeRefusal> {
    match (text.get(..start), text.get(end..)) {
        (Some(head), Some(tail)) => Ok([head, with, tail].concat()),
        _ => bug(),
    }
}

// --- Edits -----------------------------------------------------------------------------------

/// Sets `key` to `value`, creating the objects on its path. An equal value is left as it is.
fn set(text: &str, key: &[String], value: &Value) -> Result<String, MergeRefusal> {
    match find(text, key)? {
        Found::Member { obj, idx } => {
            let unit = indent_unit(text, &obj);
            let Some(m) = obj.members.get(idx) else {
                return bug();
            };
            let Some(old) = text.get(m.value_start..m.value_end) else {
                return bug();
            };
            if serde_json::from_str::<Value>(old).ok().as_ref() == Some(value) {
                return Ok(text.to_owned());
            }
            let rendered = if starts_line(text, m.key_start, obj.open) {
                pretty(value, &unit, line_indent(text, m.key_start))
            } else {
                value.to_string()
            };
            splice(text, m.value_start, m.value_end, &rendered)
        }
        Found::Missing { obj, depth } => {
            let Some((name, below)) = key.get(depth..).and_then(<[String]>::split_first) else {
                return bug();
            };
            let mut nested = value.clone();
            for k in below.iter().rev() {
                let mut map = Map::new();
                map.insert(k.clone(), nested);
                nested = Value::Object(map);
            }
            insert(text, &obj, name, &nested, &indent_unit(text, &obj))
        }
    }
}

/// Adds `"name": value` as the last member of `obj`, in the object's layout.
fn insert(
    text: &str,
    obj: &Object,
    name: &str,
    value: &Value,
    unit: &str,
) -> Result<String, MergeRefusal> {
    let Some(last) = obj.members.last() else {
        // An empty object becomes a multi-line one.
        let outer = line_indent(text, obj.open);
        let inner = format!("{outer}{unit}");
        let member = format!(
            "\n{inner}{}: {}\n{outer}",
            quoted(name),
            pretty(value, unit, &inner)
        );
        return splice(text, obj.open + 1, obj.close, &member);
    };
    let member = if starts_line(text, last.key_start, obj.open) {
        let indent = line_indent(text, last.key_start);
        format!(
            ",\n{indent}{}: {}",
            quoted(name),
            pretty(value, unit, indent)
        )
    } else {
        format!(", {}: {value}", quoted(name))
    };
    splice(text, last.value_end, last.value_end, &member)
}

/// Removes `key`, then each object on its path that is left empty. A missing key, or a path
/// through a non-object, leaves the text as it is.
fn remove(text: &str, key: &[String]) -> Result<String, MergeRefusal> {
    let mut text = text.to_owned();
    for len in (1..=key.len()).rev() {
        let Some(path) = key.get(..len) else {
            return bug();
        };
        let (obj, idx) = match find(&text, path) {
            Ok(Found::Member { obj, idx }) => (obj, idx),
            Ok(Found::Missing { .. }) | Err(MergeRefusal::Conflict { .. }) => return Ok(text),
            Err(e) => return Err(e),
        };
        if len < key.len() {
            // A parent: remove it only when the removal below left it empty.
            let Some(m) = obj.members.get(idx) else {
                return bug();
            };
            if !object_at(&text, m.value_start)?.members.is_empty() {
                return Ok(text);
            }
        }
        text = remove_member(&text, &obj, idx)?;
    }
    Ok(text)
}

fn remove_member(text: &str, obj: &Object, idx: usize) -> Result<String, MergeRefusal> {
    let m = &obj.members;
    match (
        idx.checked_sub(1).and_then(|p| m.get(p)),
        m.get(idx),
        m.get(idx + 1),
    ) {
        // The only member: the object becomes `{}`.
        (None, Some(_), None) => splice(text, obj.open + 1, obj.close, ""),
        // The first of several: up to the next key, so the next one takes its place.
        (None, Some(this), Some(next)) => splice(text, this.key_start, next.key_start, ""),
        // Any later one: from the end of the previous value (its comma goes with it).
        (Some(prev), Some(this), _) => splice(text, prev.value_end, this.value_end, ""),
        (_, None, _) => bug(),
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use serde_json::json;

    use super::super::{MergeFormat, MergeSpec, Merged, unmerge as unmerge_bytes};
    use super::*;

    fn k(path: &str) -> Vec<String> {
        path.split('.').map(str::to_owned).collect()
    }

    fn docker_spec() -> MergeSpec {
        MergeSpec::new(
            MergeFormat::Json,
            vec![MergeEntry::json(
                &["proxies", "default"],
                &json!({"httpProxy": "http://172.17.0.1:3128", "httpsProxy": "http://172.17.0.1:3128"}),
            )],
        )
        .unwrap()
    }

    fn applied(spec: &MergeSpec, file: &str, previous: &[Vec<String>]) -> String {
        match spec.apply(Some(file.as_bytes()), previous).unwrap() {
            Merged::Write(b) => String::from_utf8(b).unwrap(),
            Merged::Unchanged => file.to_owned(),
        }
    }

    /// What `docker login` leaves behind: auths and helpers, tab-indented.
    const DOCKER_LOGIN: &str = "{\n\t\"auths\": {\n\t\t\"registry.example.test\": {\n\t\t\t\"auth\": \"dXNlcjpwYXNz\"\n\t\t}\n\t},\n\t\"credHelpers\": {\n\t\t\"gcr.io\": \"gcloud\"\n\t}\n}";

    #[test]
    fn docker_login_entries_survive_and_proxies_are_added_in_the_files_layout() {
        let spec = docker_spec();
        let out = applied(&spec, DOCKER_LOGIN, &[]);
        assert_eq!(
            out,
            "{\n\t\"auths\": {\n\t\t\"registry.example.test\": {\n\t\t\t\"auth\": \"dXNlcjpwYXNz\"\n\t\t}\n\t},\n\t\"credHelpers\": {\n\t\t\"gcr.io\": \"gcloud\"\n\t},\n\t\"proxies\": {\n\t\t\"default\": {\n\t\t\t\"httpProxy\": \"http://172.17.0.1:3128\",\n\t\t\t\"httpsProxy\": \"http://172.17.0.1:3128\"\n\t\t}\n\t}\n}"
        );
        // The second boot leaves it alone, byte for byte.
        assert_eq!(
            spec.apply(Some(out.as_bytes()), &spec.keys()).unwrap(),
            Merged::Unchanged
        );
    }

    #[test]
    fn a_changed_value_is_rewritten_in_place_and_nothing_else_moves() {
        let file = "{ \"auths\" :{\"r\":{ \"auth\":\"x\"}} ,\n  \"proxies\": {\n    \"default\": {\"httpProxy\": \"http://old\"},\n    \"tcp://other:2376\": {\"httpProxy\": \"http://user\"}\n  },\"z\":1.50}";
        let out = applied(&docker_spec(), file, &[]);
        assert_eq!(
            out,
            "{ \"auths\" :{\"r\":{ \"auth\":\"x\"}} ,\n  \"proxies\": {\n    \"default\": {\n      \"httpProxy\": \"http://172.17.0.1:3128\",\n      \"httpsProxy\": \"http://172.17.0.1:3128\"\n    },\n    \"tcp://other:2376\": {\"httpProxy\": \"http://user\"}\n  },\"z\":1.50}"
        );
    }

    #[test]
    fn minified_files_get_compact_members() {
        let spec = docker_spec();
        let out = applied(&spec, r#"{"auths":{}}"#, &[]);
        assert_eq!(
            out,
            r#"{"auths":{}, "proxies": {"default":{"httpProxy":"http://172.17.0.1:3128","httpsProxy":"http://172.17.0.1:3128"}}}"#
        );
        let out = applied(&spec, r#"{"proxies":{"x":1}}"#, &[]);
        assert_eq!(
            out,
            r#"{"proxies":{"x":1, "default": {"httpProxy":"http://172.17.0.1:3128","httpsProxy":"http://172.17.0.1:3128"}}}"#
        );
    }

    #[test]
    fn an_empty_object_takes_the_files_indent() {
        let spec = MergeSpec::new(
            MergeFormat::Json,
            vec![MergeEntry::json(&["a", "b"], &json!(1))],
        )
        .unwrap();
        assert_eq!(
            applied(&spec, "{\n  \"x\": 1,\n  \"a\": {}\n}\n", &[]),
            "{\n  \"x\": 1,\n  \"a\": {\n    \"b\": 1\n  }\n}\n"
        );
        assert_eq!(
            applied(&spec, "{}", &[]),
            "{\n\t\"a\": {\n\t\t\"b\": 1\n\t}\n}"
        );
    }

    #[test]
    fn keys_puddle_no_longer_owns_are_removed_with_their_empty_parents() {
        let old = MergeSpec::new(
            MergeFormat::Json,
            vec![
                MergeEntry::json(&["proxies", "default"], &json!({"httpProxy": "x"})),
                MergeEntry::json(&["features", "puddle"], &json!(true)),
            ],
        )
        .unwrap();
        let with_user = applied(&old, DOCKER_LOGIN, &[]);
        let out = applied(&docker_spec(), &with_user, &old.keys());
        assert!(!out.contains("features"), "{out}");
        assert!(
            out.contains("httpsProxy") && out.contains("dXNlcjpwYXNz"),
            "{out}"
        );
        // Removing everything puddle owns gives back the user's file exactly.
        let u = unmerge_bytes(MergeFormat::Json, out.as_bytes(), &docker_spec().keys()).unwrap();
        assert_eq!(u.merged, Merged::Write(DOCKER_LOGIN.as_bytes().to_vec()));
        assert!(!u.empty);
    }

    #[test]
    fn a_parent_the_user_also_uses_is_kept() {
        let file = r#"{"proxies": {"default": {"httpProxy": "x"}, "tcp://h": {}}}"#;
        let (out, empty) = unmerge(file, &[&k("proxies.default")]).unwrap();
        assert_eq!(out, r#"{"proxies": {"tcp://h": {}}}"#);
        assert!(!empty);
        let (out, empty) = unmerge(
            "{\n\t\"proxies\": {\n\t\t\"default\": 1\n\t}\n}\n",
            &[&k("proxies.default")],
        )
        .unwrap();
        assert_eq!(out, "{}\n");
        assert!(empty);
    }

    #[test]
    fn removal_handles_first_middle_last_and_missing_members() {
        let file = "{\n  \"a\": 1,\n  \"b\": [1, {\"c\": \"}\"}],\n  \"d\": \"\\\"\"\n}";
        assert_eq!(
            unmerge(file, &[&k("a")]).unwrap().0,
            "{\n  \"b\": [1, {\"c\": \"}\"}],\n  \"d\": \"\\\"\"\n}"
        );
        assert_eq!(
            unmerge(file, &[&k("b")]).unwrap().0,
            "{\n  \"a\": 1,\n  \"d\": \"\\\"\"\n}"
        );
        assert_eq!(
            unmerge(file, &[&k("d")]).unwrap().0,
            "{\n  \"a\": 1,\n  \"b\": [1, {\"c\": \"}\"}]\n}"
        );
        assert_eq!(
            unmerge(file, &[&k("x"), &k("a.b"), &k("b.c")]).unwrap().0,
            file
        );
    }

    #[test]
    fn non_object_parents_and_duplicate_keys_are_refused() {
        let spec = docker_spec();
        assert_eq!(
            spec.apply(Some(br#"{"proxies": "nope"}"#), &[]),
            Err(MergeRefusal::Conflict {
                key: "proxies".into()
            })
        );
        assert_eq!(
            spec.apply(Some(br#"{"proxies": {}, "proxies": {}}"#), &[]),
            Err(MergeRefusal::DuplicateKey {
                key: "proxies".into()
            })
        );
        // A duplicate elsewhere is the user's business and stays as it is.
        let out = applied(&spec, r#"{"a": 1, "a": 2}"#, &[]);
        assert!(out.starts_with(r#"{"a": 1, "a": 2, "proxies""#), "{out}");
    }

    #[test]
    fn keys_with_escapes_and_unicode_are_matched_by_value() {
        let spec = MergeSpec::new(
            MergeFormat::Json,
            vec![MergeEntry::json(&["é\"x"], &json!("v"))],
        )
        .unwrap();
        let out = applied(&spec, r#"{"é\"x": "old", "ü": 1}"#, &[]);
        assert_eq!(out, r#"{"é\"x": "v", "ü": 1}"#);
    }

    #[test]
    fn deep_nesting_is_refused_by_the_parser_not_a_stack_overflow() {
        let deep = format!("{{\"a\": {}{}}}", "[".repeat(100_000), "]".repeat(100_000));
        assert!(matches!(
            docker_spec().apply(Some(deep.as_bytes()), &[]),
            Err(MergeRefusal::Syntax { .. })
        ));
    }

    fn arb_json() -> impl Strategy<Value = Value> {
        let leaf = prop_oneof![
            Just(Value::Null),
            any::<bool>().prop_map(Value::Bool),
            any::<i32>().prop_map(|n| json!(n)),
            "[a-z\"\\\\é ]{0,6}".prop_map(Value::String),
        ];
        leaf.prop_recursive(4, 32, 4, |inner| {
            prop_oneof![
                prop::collection::vec(inner.clone(), 0..4).prop_map(Value::Array),
                prop::collection::btree_map("[a-c]{1,2}", inner, 0..4)
                    .prop_map(|m| Value::Object(m.into_iter().collect())),
            ]
        })
    }

    fn arb_doc() -> impl Strategy<Value = (Value, String)> {
        (
            prop::collection::btree_map("[a-c]{1,2}", arb_json(), 0..5),
            0..3usize,
        )
            .prop_map(|(m, style)| {
                let v = Value::Object(m.into_iter().collect());
                let text = match style {
                    0 => v.to_string(),
                    1 => serde_json::to_string_pretty(&v).unwrap(),
                    _ => pretty(&v, "\t", "") + "\n",
                };
                (v, text)
            })
    }

    fn arb_key() -> impl Strategy<Value = Vec<String>> {
        prop::collection::vec("[a-c]{1,2}", 1..3)
    }

    /// `v` without `key` and without the objects on its path that are (then) empty.
    fn strip(mut v: Value, key: &[String]) -> Value {
        value_remove(&mut v, key);
        for len in (1..key.len()).rev() {
            let path = &key[..len];
            let empty = path
                .iter()
                .try_fold(&v, |cur, k| cur.get(k))
                .is_some_and(|o| o.as_object().is_some_and(Map::is_empty));
            if empty {
                let (last, parents) = path.split_last().unwrap();
                let parent = parents
                    .iter()
                    .fold(&mut v, |cur, k| cur.get_mut(k).unwrap());
                parent.as_object_mut().unwrap().remove(last);
            }
        }
        v
    }

    proptest! {
        #[test]
        fn merge_keeps_the_rest_and_converges(
            (doc, text) in arb_doc(),
            key in arb_key(),
            value in arb_json(),
        ) {
            let spec = MergeSpec::new(MergeFormat::Json, vec![MergeEntry {
                key: key.clone(),
                value: value.to_string(),
            }]).unwrap();
            match spec.apply(Some(text.as_bytes()), &[]) {
                Ok(merged) => {
                    let out = match merged {
                        Merged::Write(b) => String::from_utf8(b).unwrap(),
                        Merged::Unchanged => text.clone(),
                    };
                    // The self-check passed, so the result is the value-level merge; applying
                    // again changes nothing, byte for byte.
                    prop_assert_eq!(spec.apply(Some(out.as_bytes()), &spec.keys()).unwrap(), Merged::Unchanged);
                    // Removing the key again gives the original minus that key.
                    let back = unmerge_bytes(MergeFormat::Json, out.as_bytes(), &spec.keys()).unwrap();
                    let back = match back.merged {
                        Merged::Write(b) => String::from_utf8(b).unwrap(),
                        Merged::Unchanged => out.clone(),
                    };
                    // (Up to empty objects on the key's path, which the removal prunes.)
                    prop_assert_eq!(
                        strip(serde_json::from_str::<Value>(&back).unwrap(), &key),
                        strip(doc.clone(), &key)
                    );
                }
                // A non-object on the path is the only reason to refuse a valid document.
                Err(e) => prop_assert!(matches!(e, MergeRefusal::Conflict { .. }), "{e}"),
            }
        }

        #[test]
        fn arbitrary_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..64)) {
            let _ = docker_spec().apply(Some(&bytes), &[k("a.b")]);
            let _ = unmerge_bytes(MergeFormat::Json, &bytes, &[k("a")]);
        }
    }
}
