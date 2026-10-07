// SPDX-License-Identifier: GPL-3.0-or-later
//! `puddle-agent merge-file`: applies a merged guest file for the boot hook.
//!
//! The boot hook (`boot.sh`) can't parse JSON, so for each [`ApplyKind::Merge`] file it runs
//!
//! ```text
//! puddle-agent merge-file apply  <state-dir> <guest-path> <file> <mode>  < spec.json
//! puddle-agent merge-file remove <state-dir> <guest-path> <file>
//! puddle-agent merge-file forget <state-dir> <guest-path>
//! ```
//!
//! `<guest-path>` names the file in the hook's records, `<file>` is where it is on disk (the same
//! path in a VM). The result is one line on stdout: `changed`, `unchanged`, `removed` (puddle
//! deleted a file it had created) or `left: <reason>` (the file can't be parsed: it is not
//! touched). Exit status 1 is an I/O error (message on stderr), 2 bad usage.
//!
//! A small state file per guest path (in `<state-dir>`) records the keys puddle owned at the
//! last apply and whether puddle created the file, so a later apply drops keys puddle no longer
//! owns, and `remove` deletes exactly puddle's keys (and the file, if puddle created it and
//! nothing else is left).
//!
//! The file is rewritten atomically (temporary file, then rename) with its mode and owner kept;
//! a symbolic link is followed (dotfile managers link `~/.docker/config.json`), as the Docker CLI
//! does when it saves.
//!
//! [`ApplyKind::Merge`]: puddle_types::ApplyKind::Merge

use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use puddle_types::{MAX_MERGE_FILE, MergeFormat, MergeSpec, Merged, unmerge};
use serde::{Deserialize, Serialize};

/// What the hook asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Set the owned keys (the spec comes on stdin); create the file with `mode` if missing.
    Apply {
        /// Permission bits for a file puddle creates.
        mode: u32,
    },
    /// Remove the keys puddle owned (no provider lists the file any more).
    Remove,
    /// Drop the record only (the file is now written whole by a replace).
    Forget,
}

/// One `merge-file` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// What to do.
    pub action: Action,
    /// Where the state files live (`/var/lib/puddle/merge`).
    pub state_dir: PathBuf,
    /// The file's guest path, its name in the records.
    pub key: String,
    /// The file on disk (unused by [`Action::Forget`]).
    pub file: PathBuf,
}

/// Usage text.
pub const USAGE: &str = "usage: puddle-agent merge-file apply <state-dir> <guest-path> <file> <octal mode> < spec\n       puddle-agent merge-file remove <state-dir> <guest-path> <file>\n       puddle-agent merge-file forget <state-dir> <guest-path>";

impl Request {
    /// Parses the arguments after `merge-file`.
    ///
    /// # Errors
    ///
    /// A usage message.
    pub fn parse<S: AsRef<str>>(args: &[S]) -> Result<Self, String> {
        let args: Vec<&str> = args.iter().map(AsRef::as_ref).collect();
        let request = |action, state: &str, key: &str, file: &str| Request {
            action,
            state_dir: PathBuf::from(state),
            key: key.to_owned(),
            file: PathBuf::from(file),
        };
        match args.as_slice() {
            ["apply", state, key, file, mode] => {
                let mode = u32::from_str_radix(mode, 8)
                    .ok()
                    .filter(|m| m & !0o7777 == 0)
                    .ok_or_else(|| format!("bad mode {mode:?}\n{USAGE}"))?;
                Ok(request(Action::Apply { mode }, state, key, file))
            }
            ["remove", state, key, file] => Ok(request(Action::Remove, state, key, file)),
            ["forget", state, key] => Ok(request(Action::Forget, state, key, "")),
            _ => Err(USAGE.to_owned()),
        }
    }
}

/// What a call did; printed as one line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The file was written.
    Changed,
    /// Nothing needed writing.
    Unchanged,
    /// puddle deleted the file it had created.
    Removed,
    /// The file is left as it is, for this reason.
    Left(String),
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Changed => f.write_str("changed"),
            Self::Unchanged => f.write_str("unchanged"),
            Self::Removed => f.write_str("removed"),
            Self::Left(why) => write!(f, "left: {why}"),
        }
    }
}

/// Why a call failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MergeFileError {
    /// The spec on stdin isn't a valid [`MergeSpec`].
    #[error("bad merge spec on stdin: {0}")]
    Spec(String),
    /// A file operation failed.
    #[error("cannot {what} {path}: {source}")]
    Io {
        /// What was being done.
        what: &'static str,
        /// The path.
        path: PathBuf,
        /// The cause.
        source: io::Error,
    },
}

fn io_err(what: &'static str, path: &Path) -> impl FnOnce(io::Error) -> MergeFileError {
    let path = path.to_owned();
    move |source| MergeFileError::Io { what, path, source }
}

/// What the state file records about one merged file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct State {
    path: String,
    format: MergeFormat,
    keys: Vec<Vec<String>>,
    created: bool,
}

/// Runs one call; `stdin` carries the spec for [`Action::Apply`].
///
/// # Errors
///
/// [`MergeFileError`] for a bad spec or a failed file operation. A file that can't be parsed is
/// not an error: it is [`Outcome::Left`].
pub fn run(request: &Request, stdin: impl Read) -> Result<Outcome, MergeFileError> {
    match request.action {
        Action::Apply { mode } => {
            let mut input = Vec::new();
            stdin
                .take(u64::try_from(MAX_MERGE_FILE).unwrap_or(u64::MAX))
                .read_to_end(&mut input)
                .map_err(|e| MergeFileError::Spec(e.to_string()))?;
            let spec: MergeSpec =
                serde_json::from_slice(&input).map_err(|e| MergeFileError::Spec(e.to_string()))?;
            apply(request, &spec, mode)
        }
        Action::Remove => remove(request),
        Action::Forget => {
            forget(request)?;
            Ok(Outcome::Unchanged)
        }
    }
}

fn apply(request: &Request, spec: &MergeSpec, mode: u32) -> Result<Outcome, MergeFileError> {
    let state = read_state(request)?.filter(|s| s.format == spec.format());
    let Some(target) = resolve(&request.file)? else {
        return Ok(Outcome::Left(DANGLING.to_owned()));
    };
    let existing = read_file(&target)?;
    let previous = state.as_ref().map(|s| s.keys.clone()).unwrap_or_default();
    let merged = match spec.apply(existing.as_ref().map(|(b, _)| b.as_slice()), &previous) {
        Ok(m) => m,
        Err(refusal) => return Ok(Outcome::Left(refusal.to_string())),
    };
    let outcome = match merged {
        Merged::Unchanged => Outcome::Unchanged,
        Merged::Write(bytes) => {
            write_atomic(&target, &bytes, existing.as_ref().map(|(_, m)| m), mode)?;
            Outcome::Changed
        }
    };
    let created = existing.is_none() || state.as_ref().is_some_and(|s| s.created);
    write_state(
        request,
        &State {
            path: request.key.clone(),
            format: spec.format(),
            keys: spec.keys(),
            created,
        },
    )?;
    Ok(outcome)
}

fn remove(request: &Request) -> Result<Outcome, MergeFileError> {
    let Some(state) = read_state(request)? else {
        return Ok(Outcome::Unchanged);
    };
    let outcome = remove_keys(request, &state)?;
    forget(request)?;
    Ok(outcome)
}

fn remove_keys(request: &Request, state: &State) -> Result<Outcome, MergeFileError> {
    let Some(target) = resolve(&request.file)? else {
        return Ok(Outcome::Left(DANGLING.to_owned()));
    };
    let Some((bytes, meta)) = read_file(&target)? else {
        return Ok(Outcome::Unchanged);
    };
    let unmerged = match unmerge(state.format, &bytes, &state.keys) {
        Ok(u) => u,
        Err(refusal) => return Ok(Outcome::Left(refusal.to_string())),
    };
    if unmerged.empty && state.created {
        fs::remove_file(&target).map_err(io_err("remove", &target))?;
        return Ok(Outcome::Removed);
    }
    match unmerged.merged {
        Merged::Unchanged => Ok(Outcome::Unchanged),
        Merged::Write(new) => {
            write_atomic(&target, &new, Some(&meta), 0)?;
            Ok(Outcome::Changed)
        }
    }
}

const DANGLING: &str = "it is a symbolic link to a file that doesn't exist";

/// The file to edit: `file` itself, or the end of its symbolic links. `None` for a dangling
/// link.
fn resolve(file: &Path) -> Result<Option<PathBuf>, MergeFileError> {
    match fs::symlink_metadata(file) {
        Ok(m) if m.file_type().is_symlink() => match fs::canonicalize(file) {
            Ok(p) => Ok(Some(p)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io_err("resolve", file)(e)),
        },
        Ok(_) => Ok(Some(file.to_owned())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Some(file.to_owned())),
        Err(e) => Err(io_err("inspect", file)(e)),
    }
}

/// The file's bytes (at most one more than the engine accepts) and metadata, or `None`.
fn read_file(path: &Path) -> Result<Option<(Vec<u8>, fs::Metadata)>, MergeFileError> {
    let file = match fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io_err("open", path)(e)),
    };
    let meta = file.metadata().map_err(io_err("inspect", path))?;
    if !meta.is_file() {
        return Err(io_err("edit", path)(io::Error::other("not a regular file")));
    }
    let mut bytes = Vec::new();
    file.take(u64::try_from(MAX_MERGE_FILE).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut bytes)
        .map_err(io_err("read", path))?;
    Ok(Some((bytes, meta)))
}

/// Writes `bytes` to `path` through a temporary file in the same directory and a rename. An
/// existing file's mode and owner carry over; a new file gets `mode`.
fn write_atomic(
    path: &Path,
    bytes: &[u8],
    existing: Option<&fs::Metadata>,
    mode: u32,
) -> Result<(), MergeFileError> {
    let dir = path.parent().unwrap_or(Path::new("/"));
    fs::create_dir_all(dir).map_err(io_err("create", dir))?;
    let name = path
        .file_name()
        .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
    let tmp = dir.join(format!(".{name}.puddle-merge.{}", std::process::id()));
    let result = (|| {
        let _ = fs::remove_file(&tmp); // a leftover from a killed run; absent is fine
        fs::write(&tmp, bytes).map_err(io_err("write", &tmp))?;
        permissions(&tmp, existing, mode)?;
        fs::File::open(&tmp)
            .and_then(|f| f.sync_all())
            .map_err(io_err("sync", &tmp))?;
        fs::rename(&tmp, path).map_err(io_err("replace", path))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp); // best effort; the error that matters is returned
    }
    result
}

#[cfg(unix)]
fn permissions(
    tmp: &Path,
    existing: Option<&fs::Metadata>,
    mode: u32,
) -> Result<(), MergeFileError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    let bits = existing.map_or(mode, |m| m.mode() & 0o7777);
    if let Some(m) = existing {
        std::os::unix::fs::chown(tmp, Some(m.uid()), Some(m.gid()))
            .map_err(io_err("chown", tmp))?;
    }
    fs::set_permissions(tmp, fs::Permissions::from_mode(bits)).map_err(io_err("chmod", tmp))
}

#[cfg(not(unix))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "the same signature as the unix version"
)]
fn permissions(_: &Path, _: Option<&fs::Metadata>, _: u32) -> Result<(), MergeFileError> {
    Ok(())
}

/// The state file for a guest path: a hash of the path (paths can be longer than a file name).
fn state_path(request: &Request) -> PathBuf {
    // FNV-1a, 64 bit: stable across builds, no dependency. A collision is caught by the path
    // recorded inside.
    let hash = request.key.bytes().fold(0xcbf2_9ce4_8422_2325_u64, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
    });
    request.state_dir.join(format!("{hash:016x}.json"))
}

fn read_state(request: &Request) -> Result<Option<State>, MergeFileError> {
    let path = state_path(request);
    match fs::read(&path) {
        // An unreadable or foreign record counts as none: puddle then owns nothing yet.
        Ok(bytes) => Ok(serde_json::from_slice::<State>(&bytes)
            .ok()
            .filter(|s| s.path == request.key)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(io_err("read", &path)(e)),
    }
}

fn write_state(request: &Request, state: &State) -> Result<(), MergeFileError> {
    let path = state_path(request);
    let text = serde_json::to_vec(state).map_err(|e| MergeFileError::Spec(e.to_string()))?;
    write_atomic(&path, &text, None, 0o600)
}

fn forget(request: &Request) -> Result<(), MergeFileError> {
    let path = state_path(request);
    match fs::remove_file(&path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(io_err("remove", &path)(e)),
        _ => Ok(()),
    }
}

#[cfg(all(test, unix))]
#[expect(
    clippy::unwrap_used,
    reason = "test helpers outside #[test] fns: a failed setup fails the test"
)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use puddle_types::MergeEntry;
    use serde_json::json;

    use super::*;

    struct Dir(PathBuf);

    impl Dir {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!(
                "puddle-merge-file-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .subsec_nanos()
            ));
            fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    const KEY: &str = "/root/.docker/config.json";

    fn req(dir: &Dir, action: Action) -> Request {
        Request {
            action,
            state_dir: dir.0.join("state"),
            key: KEY.to_owned(),
            file: dir.0.join("home/.docker/config.json"),
        }
    }

    fn spec_json(entries: Vec<MergeEntry>) -> Vec<u8> {
        serde_json::to_vec(&MergeSpec::new(MergeFormat::Json, entries).unwrap()).unwrap()
    }

    fn docker() -> Vec<u8> {
        spec_json(vec![MergeEntry::json(
            &["proxies", "default"],
            &json!({"httpProxy": "http://172.17.0.1:3128"}),
        )])
    }

    fn apply(dir: &Dir, spec: &[u8]) -> Outcome {
        run(&req(dir, Action::Apply { mode: 0o640 }), spec).unwrap()
    }

    const LOGIN: &str =
        "{\n\t\"auths\": {\n\t\t\"r.example.test\": {\n\t\t\t\"auth\": \"dTpw\"\n\t\t}\n\t}\n}\n";

    #[test]
    fn apply_creates_then_converges_then_remove_deletes_what_it_created() {
        let d = Dir::new("create");
        let r = req(&d, Action::Apply { mode: 0o640 });
        assert_eq!(apply(&d, &docker()), Outcome::Changed);
        let mode = fs::metadata(&r.file).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o640);
        assert_eq!(apply(&d, &docker()), Outcome::Unchanged);
        assert_eq!(
            run(&req(&d, Action::Remove), io::empty()).unwrap(),
            Outcome::Removed
        );
        assert!(!r.file.exists());
        // The record is gone: a second remove does nothing.
        assert_eq!(
            run(&req(&d, Action::Remove), io::empty()).unwrap(),
            Outcome::Unchanged
        );
    }

    #[test]
    fn a_docker_login_survives_apply_and_remove_gives_it_back() {
        let d = Dir::new("login");
        let r = req(&d, Action::Remove);
        fs::create_dir_all(r.file.parent().unwrap()).unwrap();
        fs::write(&r.file, LOGIN).unwrap();
        fs::set_permissions(&r.file, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(apply(&d, &docker()), Outcome::Changed);
        let merged = fs::read_to_string(&r.file).unwrap();
        assert!(merged.starts_with("{\n\t\"auths\": {\n\t\t\"r.example.test\": {\n\t\t\t\"auth\": \"dTpw\"\n\t\t}\n\t},\n\t\"proxies\""), "{merged}");
        // The user's mode is kept, not the spec's.
        assert_eq!(
            fs::metadata(&r.file).unwrap().permissions().mode() & 0o7777,
            0o600
        );
        // Not created by puddle: removing the keys keeps the file, exactly as it was.
        assert_eq!(run(&r, io::empty()).unwrap(), Outcome::Changed);
        assert_eq!(fs::read_to_string(&r.file).unwrap(), LOGIN);
    }

    #[test]
    fn keys_dropped_from_the_spec_are_removed_at_the_next_apply() {
        let d = Dir::new("drop");
        let two = spec_json(vec![
            MergeEntry::json(&["proxies", "default"], &json!({"httpProxy": "x"})),
            MergeEntry::json(&["puddle"], &json!(true)),
        ]);
        apply(&d, &two);
        assert!(
            fs::read_to_string(&req(&d, Action::Remove).file)
                .unwrap()
                .contains("puddle")
        );
        assert_eq!(apply(&d, &docker()), Outcome::Changed);
        let text = fs::read_to_string(&req(&d, Action::Remove).file).unwrap();
        assert!(
            !text.contains("puddle") && text.contains("172.17.0.1"),
            "{text}"
        );
    }

    #[test]
    fn an_unparsable_file_is_left_untouched_and_keeps_the_record() {
        let d = Dir::new("bad");
        let r = req(&d, Action::Remove);
        apply(&d, &docker());
        fs::write(&r.file, "{ not json").unwrap();
        let out = apply(&d, &docker());
        assert!(
            matches!(&out, Outcome::Left(why) if why.contains("not valid JSON")),
            "{out}"
        );
        assert_eq!(fs::read_to_string(&r.file).unwrap(), "{ not json");
        let out = run(&r, io::empty()).unwrap();
        assert!(
            out.to_string()
                .starts_with("left: the file is not valid JSON"),
            "{out}"
        );
        assert_eq!(fs::read_to_string(&r.file).unwrap(), "{ not json");
    }

    #[test]
    fn a_symlinked_file_is_edited_at_its_target() {
        let d = Dir::new("link");
        let r = req(&d, Action::Remove);
        let real = d.0.join("dotfiles/config.json");
        fs::create_dir_all(real.parent().unwrap()).unwrap();
        fs::create_dir_all(r.file.parent().unwrap()).unwrap();
        fs::write(&real, LOGIN).unwrap();
        std::os::unix::fs::symlink(&real, &r.file).unwrap();
        assert_eq!(apply(&d, &docker()), Outcome::Changed);
        assert!(
            fs::symlink_metadata(&r.file)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(fs::read_to_string(&real).unwrap().contains("proxies"));
        // A dangling link is left alone.
        fs::remove_file(&real).unwrap();
        let out = apply(&d, &docker());
        assert_eq!(out, Outcome::Left(DANGLING.to_owned()));
        assert_eq!(
            run(&r, io::empty()).unwrap(),
            Outcome::Left(DANGLING.to_owned())
        );
    }

    #[test]
    fn forget_drops_the_record_and_bad_input_is_an_error() {
        let d = Dir::new("forget");
        apply(&d, &docker());
        assert_eq!(
            run(&req(&d, Action::Forget), io::empty()).unwrap(),
            Outcome::Unchanged
        );
        assert_eq!(
            run(&req(&d, Action::Remove), io::empty()).unwrap(),
            Outcome::Unchanged
        );
        assert!(req(&d, Action::Remove).file.exists());
        let err = run(&req(&d, Action::Apply { mode: 0o644 }), &b"{}"[..]).unwrap_err();
        assert!(
            err.to_string().starts_with("bad merge spec on stdin"),
            "{err}"
        );
        let r = req(&d, Action::Apply { mode: 0o644 });
        fs::remove_file(&r.file).unwrap();
        fs::create_dir(&r.file).unwrap();
        let err = run(&r, &docker()[..]).unwrap_err();
        assert!(
            err.to_string().contains("not a regular file") || err.to_string().contains("directory"),
            "{err}"
        );
    }

    #[test]
    fn a_record_for_another_path_is_ignored() {
        let d = Dir::new("foreign");
        let r = req(&d, Action::Remove);
        fs::create_dir_all(&r.state_dir).unwrap();
        fs::write(
            state_path(&r),
            br#"{"path":"/other","format":"json","keys":[["auths"]],"created":true}"#,
        )
        .unwrap();
        fs::create_dir_all(r.file.parent().unwrap()).unwrap();
        fs::write(&r.file, LOGIN).unwrap();
        apply(&d, &docker());
        assert!(fs::read_to_string(&r.file).unwrap().contains("auths"));
    }

    #[test]
    fn arguments_parse_strictly() {
        let ok = Request::parse(&["apply", "/s", "/g", "/f", "0600"]).unwrap();
        assert_eq!(ok.action, Action::Apply { mode: 0o600 });
        assert_eq!(ok.key, "/g");
        assert_eq!(
            Request::parse(&["remove", "/s", "/g", "/f"])
                .unwrap()
                .action,
            Action::Remove
        );
        assert_eq!(
            Request::parse(&["forget", "/s", "/g"]).unwrap().action,
            Action::Forget
        );
        assert!(
            Request::parse(&["apply", "/s", "/g", "/f", "9"])
                .unwrap_err()
                .contains("bad mode")
        );
        assert!(Request::parse(&["apply", "/s", "/g", "/f", "17777"]).is_err());
        assert_eq!(Request::parse(&["nope"]).unwrap_err(), USAGE);
    }
}
