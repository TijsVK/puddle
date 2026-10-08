// SPDX-License-Identifier: GPL-3.0-or-later
//! Which repository, and what kind of access, a request on a Git host is about.
//!
//! The push and pull lists and the choice of credential all hang on this reading, so it is
//! strict: a path is read only when it is in one canonical spelling, and a path that looks like a
//! Git request but is not (a dot segment, an encoded slash, `//`, a backslash, a NUL, a
//! percent-encoding that is not the canonical one) is refused, because the Git host may read it
//! as another repository than the one Puddle checked. A path that cannot be a Git request under
//! any reading is none of this module's business.
//!
//! Shapes read (case-insensitively, `.git` optional, as the hosts treat them):
//!
//! - GitHub and every other host: `/{owner}/{repo}[.git]/...`;
//! - Azure DevOps: `dev.azure.com/{org}/{project}/_git/{repo}/...`, `.../{org}/_git/{repo}/...`
//!   (the project has the repository's name) and `{org}.visualstudio.com/[DefaultCollection/]
//!   {project}/_git/{repo}/...`.
//!
//! followed by one of `info/refs`, `git-upload-pack`, `git-receive-pack` or `info/lfs/...`.

use puddle_store::RepoRef;

/// What a request asks of a repository.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Access {
    /// Reading: a fetch, a clone, an LFS download.
    Pull,
    /// Writing: a push, an LFS upload or lock.
    Push,
    /// A Git LFS batch request, which reads or writes depending on the `operation` in its body.
    Batch,
}

/// A request that names a repository and an access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GitPath {
    /// The host asked for, lower-case.
    pub(crate) host: String,
    /// The host the credential is chosen for: Azure DevOps has several names for one service.
    pub(crate) credential_host: String,
    /// The user or organisation, lower-case.
    pub(crate) owner: String,
    /// `repo`, or `project/repo` on Azure DevOps, lower-case, without `.git`.
    pub(crate) repo: String,
    /// What the request asks of the repository.
    pub(crate) access: Access,
}

impl GitPath {
    /// The repository as the workspace's table spells it; `None` for a name the table cannot hold
    /// (a space in an Azure DevOps project, say).
    pub(crate) fn repo_ref(&self) -> Option<RepoRef> {
        RepoRef::new(&self.host, &self.owner, &self.repo).ok()
    }

    /// `host/owner/repo`, for messages.
    pub(crate) fn describe(&self) -> String {
        format!("{}/{}/{}", self.host, self.owner, self.repo)
    }
}

/// What a request on a Git host is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Classified {
    /// Not a Git request under any reading: nothing to decide here.
    NotGit,
    /// It may be a Git request, but not in one canonical spelling; the reason is one clause.
    Ambiguous(&'static str),
    /// A Git request for a repository.
    Git(GitPath),
}

/// The services' own words in a path, found after every decoding a server might apply.
const MARKERS: [&str; 4] = [
    "info/refs",
    "git-upload-pack",
    "git-receive-pack",
    "info/lfs",
];

/// Reads `method path?query` on `host` (lower-case, as the proxy normalises it).
pub(crate) fn classify(host: &str, method: &str, path: &str, query: Option<&str>) -> Classified {
    let segments = match canonical_segments(path) {
        Ok(segments) => segments,
        Err(why) if looks_like_git(path) => return Classified::Ambiguous(why),
        Err(_) => return Classified::NotGit,
    };
    let Some(found) = locate(host, &segments) else {
        return Classified::NotGit;
    };
    let Some(endpoint) = Endpoint::of(&found.rest) else {
        return Classified::NotGit;
    };
    let service = match service(query) {
        Ok(service) => service,
        Err(why) => return Classified::Ambiguous(why),
    };
    let reading = method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD");
    let posting = method.eq_ignore_ascii_case("POST");
    let mut access = endpoint.access(reading, posting, service);
    if service == Some(Service::Receive) {
        access = Access::Push;
    }
    Classified::Git(GitPath {
        host: host.to_owned(),
        credential_host: found.credential_host,
        owner: found.owner,
        repo: found.repo,
        access,
    })
}

/// The segments of `path`, each percent-decoded, when the path is in its one canonical spelling.
///
/// Canonical: it starts with `/`, has no empty segment, no `.` or `..`, no backslash, `;`,
/// control, non-ASCII or other byte a path may not carry raw (a space, `"`, `<`, `{`, ...), and
/// every `%XX` is upper-case hexadecimal for a byte that has to be encoded (never a letter, digit
/// or `-._~`, a separator, a control byte) and the decoded bytes are UTF-8.
fn canonical_segments(path: &str) -> Result<Vec<String>, &'static str> {
    let rest = path
        .strip_prefix('/')
        .ok_or("the path does not start with /")?;
    if rest.is_empty() {
        return Ok(Vec::new());
    }
    rest.split('/').map(decode_segment).collect()
}

fn decode_segment(part: &str) -> Result<String, &'static str> {
    if part.is_empty() {
        return Err("an empty path segment (// or a trailing /)");
    }
    if part == "." || part == ".." {
        return Err("a dot segment");
    }
    let mut out = Vec::with_capacity(part.len());
    let mut bytes = part.bytes();
    while let Some(byte) = bytes.next() {
        match byte {
            b'%' => {
                let high = bytes.next().and_then(upper_hex);
                let low = bytes.next().and_then(upper_hex);
                let (Some(high), Some(low)) = (high, low) else {
                    return Err("a percent-encoding that is not canonical");
                };
                let decoded = high << 4 | low;
                if is_unreserved(decoded)
                    || matches!(decoded, b'/' | b'\\' | b'%' | b'?' | b'#' | b';')
                    || decoded < 0x20
                    || decoded == 0x7f
                {
                    return Err("a percent-encoding that is not canonical");
                }
                out.push(decoded);
            }
            b'\\' => return Err("a backslash"),
            b';' => return Err("a path parameter (;)"),
            0..=0x1f | 0x7f => return Err("a control character"),
            0x80.. => return Err("a non-ASCII character"),
            other if is_unreserved(other) || SUB_DELIMS_AND_MORE.contains(&other) => {
                out.push(other);
            }
            _ => return Err("a character that must be percent-encoded"),
        }
    }
    String::from_utf8(out).map_err(|_| "an encoding that is not UTF-8")
}

/// The other bytes RFC 3986 lets a path segment carry as they are (`pchar`).
const SUB_DELIMS_AND_MORE: &[u8] = b"!$&'()*+,:=@";

fn upper_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn any_hex(byte: u8) -> Option<u8> {
    upper_hex(byte.to_ascii_uppercase())
}

fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

/// Percent-decodes `text` leniently (any hexadecimal case, bad escapes left as they are).
fn decode_lossy(text: &str) -> String {
    let mut out = Vec::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut i = 0;
    while let Some(&byte) = bytes.get(i) {
        let escaped = (byte == b'%')
            .then(|| {
                let high = bytes.get(i + 1).copied().and_then(any_hex)?;
                let low = bytes.get(i + 2).copied().and_then(any_hex)?;
                Some(high << 4 | low)
            })
            .flatten();
        if let Some(decoded) = escaped {
            out.push(decoded);
            i += 3;
        } else {
            out.push(byte);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Whether `path` could be a Git request once a server has read it however it likes: decoded
/// (repeatedly), folded to lower case, backslashes as slashes, `.` and `..` resolved, empty
/// segments and `;` parameters dropped. Wider than the canonical reading on purpose.
fn looks_like_git(path: &str) -> bool {
    let mut text = path.to_owned();
    for _ in 0..4 {
        let decoded = decode_lossy(&text);
        if decoded == text {
            break;
        }
        text = decoded;
    }
    text.make_ascii_lowercase();
    let text = text.replace('\\', "/");
    let mut resolved: Vec<&str> = Vec::new();
    let mut plain: Vec<&str> = Vec::new();
    for segment in text.split('/') {
        let segment = segment.split(';').next().unwrap_or_default();
        match segment {
            "" | "." => {}
            ".." => {
                resolved.pop();
            }
            other => {
                resolved.push(other);
                plain.push(other);
            }
        }
    }
    [resolved.join("/"), plain.join("/")]
        .iter()
        .any(|joined| MARKERS.iter().any(|marker| joined.contains(marker)))
}

/// Where a repository sits in a path.
struct Located {
    credential_host: String,
    owner: String,
    repo: String,
    rest: Vec<String>,
}

fn is_git_segment(segment: &str) -> bool {
    segment.eq_ignore_ascii_case("_git")
}

fn repo_name(segment: &str) -> String {
    let lower = segment.to_ascii_lowercase();
    lower.strip_suffix(".git").unwrap_or(&lower).to_owned()
}

fn tail(segments: &[String], from: usize) -> Vec<String> {
    segments
        .iter()
        .skip(from)
        .map(|segment| segment.to_ascii_lowercase())
        .collect()
}

/// Finds the owner and the repository in `segments` by what `host` is.
fn locate(host: &str, segments: &[String]) -> Option<Located> {
    let segment = |i: usize| segments.get(i).map(String::as_str);
    let lower = |i: usize| segment(i).map(str::to_ascii_lowercase);
    if host == "dev.azure.com" {
        let (project, repo, rest_from) = if segment(2).is_some_and(is_git_segment) {
            (lower(1)?, repo_name(segment(3)?), 4)
        } else if segment(1).is_some_and(is_git_segment) {
            let repo = repo_name(segment(2)?);
            (repo.clone(), repo, 3)
        } else {
            return None;
        };
        return Some(Located {
            credential_host: host.to_owned(),
            owner: lower(0)?,
            repo: format!("{project}/{repo}"),
            rest: tail(segments, rest_from),
        });
    }
    if let Some(org) = host.strip_suffix(".visualstudio.com") {
        let (project, repo, rest_from) = if segment(1).is_some_and(is_git_segment) {
            (lower(0)?, repo_name(segment(2)?), 3)
        } else if segment(0).is_some_and(|s| s.eq_ignore_ascii_case("DefaultCollection"))
            && segment(2).is_some_and(is_git_segment)
        {
            (lower(1)?, repo_name(segment(3)?), 4)
        } else {
            return None;
        };
        return Some(Located {
            credential_host: "dev.azure.com".to_owned(),
            owner: org.to_ascii_lowercase(),
            repo: format!("{project}/{repo}"),
            rest: tail(segments, rest_from),
        });
    }
    Some(Located {
        credential_host: host.to_owned(),
        owner: lower(0)?,
        repo: repo_name(segment(1)?),
        rest: tail(segments, 2),
    })
}

/// The service a request reaches.
enum Endpoint {
    InfoRefs,
    UploadPack,
    ReceivePack,
    /// `info/lfs/...`: what follows `info/lfs`.
    Lfs(Vec<String>),
}

impl Endpoint {
    fn of(rest: &[String]) -> Option<Self> {
        let words: Vec<&str> = rest.iter().map(String::as_str).collect();
        match words.as_slice() {
            ["info", "refs"] => Some(Self::InfoRefs),
            ["git-upload-pack"] => Some(Self::UploadPack),
            ["git-receive-pack"] => Some(Self::ReceivePack),
            ["info", "lfs", more @ ..] => {
                Some(Self::Lfs(more.iter().map(ToString::to_string).collect()))
            }
            _ => None,
        }
    }

    /// What it asks for. Anything that is not clearly a read is a write: a method that changes
    /// state, a service this reading does not know.
    fn access(&self, reading: bool, posting: bool, service: Option<Service>) -> Access {
        let by_method = if reading { Access::Pull } else { Access::Push };
        match self {
            Self::InfoRefs => match service {
                Some(Service::Upload) if reading => Access::Pull,
                None => by_method,
                Some(_) => Access::Push,
            },
            Self::UploadPack => {
                if posting || reading {
                    Access::Pull
                } else {
                    Access::Push
                }
            }
            Self::ReceivePack => Access::Push,
            Self::Lfs(more) => {
                let words: Vec<&str> = more.iter().map(String::as_str).collect();
                match words.as_slice() {
                    ["objects", "batch"] if posting => Access::Batch,
                    ["objects", "verify"] | ["locks", _, "unlock"] => Access::Push,
                    ["locks", "verify"] if posting => Access::Pull,
                    _ => by_method,
                }
            }
        }
    }
}

/// The `service` of an `info/refs` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Service {
    Upload,
    Receive,
    Other,
}

/// The one `service` parameter in `query`, if there is one.
fn service(query: Option<&str>) -> Result<Option<Service>, &'static str> {
    let mut found = None;
    for pair in query.unwrap_or_default().split(['&', ';']) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if !decode_lossy(key).eq_ignore_ascii_case("service") {
            continue;
        }
        if found.is_some() {
            return Err("more than one service in the query");
        }
        let value = decode_lossy(value).to_ascii_lowercase();
        found = Some(match value.as_str() {
            "git-upload-pack" => Service::Upload,
            "git-receive-pack" => Service::Receive,
            _ => Service::Other,
        });
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn git(host: &str, method: &str, path: &str, query: Option<&str>) -> GitPath {
        match classify(host, method, path, query) {
            Classified::Git(found) => found,
            other => panic!("{method} {path}?{query:?} on {host}: {other:?}"),
        }
    }

    fn ambiguous(host: &str, method: &str, path: &str) -> &'static str {
        match classify(host, method, path, None) {
            Classified::Ambiguous(why) => why,
            other => panic!("{method} {path} on {host}: {other:?}"),
        }
    }

    fn ref_of(host: &str, path: &str) -> String {
        git(host, "GET", path, Some("service=git-upload-pack")).describe()
    }

    #[test]
    fn github_paths_name_owner_and_repository_the_way_the_host_reads_them() {
        for (path, repo) in [
            ("/acme/web.git/info/refs", "github.com/acme/web"),
            ("/acme/web/info/refs", "github.com/acme/web"),
            ("/Acme/Web.GIT/info/refs", "github.com/acme/web"),
            ("/ACME/WEB/INFO/REFS", "github.com/acme/web"),
            ("/acme/web.git.git/info/refs", "github.com/acme/web.git"),
        ] {
            assert_eq!(ref_of("github.com", path), repo, "{path}");
        }
    }

    #[test]
    fn azure_devops_paths_in_every_shape() {
        for (host, path, repo) in [
            (
                "dev.azure.com",
                "/Org/Proj/_git/Repo/info/refs",
                "dev.azure.com/org/proj/repo",
            ),
            (
                "dev.azure.com",
                "/org/_GIT/repo/info/refs",
                "dev.azure.com/org/repo/repo",
            ),
            (
                "contoso.visualstudio.com",
                "/proj/_git/repo/info/refs",
                "contoso.visualstudio.com/contoso/proj/repo",
            ),
            (
                "contoso.visualstudio.com",
                "/DefaultCollection/proj/_git/repo/info/refs",
                "contoso.visualstudio.com/contoso/proj/repo",
            ),
        ] {
            let found = git(host, "GET", path, Some("service=git-upload-pack"));
            assert_eq!(found.describe(), repo, "{path}");
            assert_eq!(found.credential_host, "dev.azure.com");
        }
        // The table spells a repository by its host, owner and `project/repo`.
        let found = git(
            "dev.azure.com",
            "GET",
            "/org/proj/_git/repo.git/info/refs",
            None,
        );
        let table = found.repo_ref().unwrap();
        assert_eq!(table.to_string(), "dev.azure.com/org/proj/repo");
        // Not a repository path: no `_git`, an unknown collection.
        for (host, path) in [
            ("dev.azure.com", "/org/proj/repo/info/refs"),
            ("dev.azure.com", "/org/_apis/git/repositories"),
            (
                "contoso.visualstudio.com",
                "/Other/proj/_git/repo/info/refs",
            ),
            ("contoso.visualstudio.com", "/info/refs"),
        ] {
            assert_eq!(
                classify(host, "GET", path, None),
                Classified::NotGit,
                "{path}"
            );
        }
    }

    #[test]
    fn the_credential_host_of_every_azure_devops_name_is_one() {
        let on_visualstudio = git(
            "contoso.visualstudio.com",
            "GET",
            "/p/_git/r/git-upload-pack",
            None,
        );
        assert_eq!(
            (
                on_visualstudio.credential_host.as_str(),
                on_visualstudio.owner.as_str()
            ),
            ("dev.azure.com", "contoso")
        );
        assert_eq!(on_visualstudio.host, "contoso.visualstudio.com");
        let elsewhere = git("git.example", "POST", "/team/app/git-upload-pack", None);
        assert_eq!(elsewhere.credential_host, "git.example");
    }

    #[test]
    fn what_each_endpoint_asks_for() {
        use Access::{Batch, Pull, Push};
        let cases: [(&str, &str, &str, Option<&str>, Access); 22] = [
            (
                "GET",
                "info/refs",
                "",
                Some("service=git-upload-pack"),
                Pull,
            ),
            (
                "GET",
                "info/refs",
                "",
                Some("service=git-receive-pack"),
                Push,
            ),
            ("GET", "info/refs", "", None, Pull),
            (
                "GET",
                "info/refs",
                "",
                Some("service=git-upload-archive"),
                Push,
            ),
            (
                "POST",
                "info/refs",
                "",
                Some("service=git-upload-pack"),
                Push,
            ),
            ("POST", "git-upload-pack", "", None, Pull),
            ("GET", "git-upload-pack", "", None, Pull),
            ("PUT", "git-upload-pack", "", None, Push),
            ("POST", "git-receive-pack", "", None, Push),
            ("GET", "git-receive-pack", "", None, Push),
            // `service=git-receive-pack` anywhere is a push.
            (
                "POST",
                "git-upload-pack",
                "",
                Some("service=git-receive-pack"),
                Push,
            ),
            ("POST", "info/lfs/objects/batch", "", None, Batch),
            ("GET", "info/lfs/objects/batch", "", None, Pull),
            ("PUT", "info/lfs/objects/batch", "", None, Push),
            ("POST", "info/lfs/objects/verify", "", None, Push),
            ("GET", "info/lfs/objects/abc123", "", None, Pull),
            ("PUT", "info/lfs/objects/abc123", "", None, Push),
            ("GET", "info/lfs/locks", "", None, Pull),
            ("POST", "info/lfs/locks", "", None, Push),
            ("POST", "info/lfs/locks/verify", "", None, Pull),
            ("POST", "info/lfs/locks/42/unlock", "", None, Push),
            ("DELETE", "info/lfs", "", None, Push),
        ];
        for (method, endpoint, _, query, want) in cases {
            let path = format!("/acme/web.git/{endpoint}");
            assert_eq!(
                git("github.com", method, &path, query).access,
                want,
                "{method} {endpoint} {query:?}"
            );
        }
    }

    #[test]
    fn two_service_parameters_or_a_hidden_one_are_ambiguous_or_a_push() {
        let path = "/acme/web.git/info/refs";
        assert_eq!(
            classify(
                "github.com",
                "GET",
                path,
                Some("service=git-upload-pack&service=git-receive-pack")
            ),
            Classified::Ambiguous("more than one service in the query")
        );
        for query in [
            "service=git%2Dreceive%2Dpack",
            "SERVICE=git-receive-pack",
            "servic%65=git-receive-pack",
            "x=1;service=git-receive-pack",
            "service=GIT-RECEIVE-PACK",
        ] {
            assert_eq!(
                git("github.com", "GET", path, Some(query)).access,
                Access::Push,
                "{query}"
            );
        }
    }

    #[test]
    fn a_path_that_is_not_a_git_request_is_none_of_our_business() {
        for (host, path) in [
            ("github.com", "/"),
            ("github.com", "/acme"),
            ("github.com", "/acme/web"),
            ("github.com", "/acme/web/blob/main/info/refs"),
            ("github.com", "/acme/web/pull/1/files"),
            ("github.com", "/login/oauth/access_token"),
            ("github.com", "/acme/web.git/HEAD"),
            ("github.com", "/acme/web.git/info/refsx"),
            ("github.com", "/acme/web.git/x/git-receive-pack"),
            // Odd, but no reading makes it a Git request.
            ("github.com", "/a//b"),
            ("github.com", "/a/../b"),
            ("github.com", "/a%2Fb/c"),
            ("github.com", "/a/b;x=1"),
        ] {
            assert_eq!(
                classify(host, "GET", path, None),
                Classified::NotGit,
                "{host}{path}"
            );
        }
    }

    // The bypass probes of the first credential-injection test on a real host: every spelling
    // that could let a push reach a repository the table does not list.

    #[test]
    fn probe_dot_segments_are_refused() {
        for path in [
            "/acme/web.git/../other.git/git-receive-pack",
            "/acme/web.git/./info/refs",
            "/acme/web.git/info/./refs",
            "/acme/../other/web.git/info/refs",
            "/acme/web.git/%2e%2e/other.git/info/refs",
            "/acme/web.git/%2E%2E/other.git/info/refs",
            "/acme/web.git/.%2e/other.git/git-receive-pack",
        ] {
            assert!(
                matches!(
                    classify("github.com", "POST", path, None),
                    Classified::Ambiguous(_)
                ),
                "{path}"
            );
        }
        assert_eq!(
            ambiguous("github.com", "GET", "/acme/web.git/../x/info/refs"),
            "a dot segment"
        );
    }

    #[test]
    fn probe_an_encoded_slash_is_refused() {
        for path in [
            "/acme%2Fother/web.git/info/refs",
            "/acme%2fother/web.git/info/refs",
            "/acme/web.git%2Finfo%2Frefs",
            "/acme/web.git/info%2Frefs",
            "/acme/web.git/git-receive-pack%2F",
            "/acme%2F..%2Fother/web.git/git-receive-pack",
        ] {
            assert!(
                matches!(
                    classify("github.com", "POST", path, None),
                    Classified::Ambiguous(_)
                ),
                "{path}"
            );
        }
    }

    #[test]
    fn probe_double_slashes_and_trailing_slashes_are_refused() {
        for path in [
            "//acme/web.git/info/refs",
            "/acme//web.git/info/refs",
            "/acme/web.git//info/refs",
            "/acme/web.git/info//refs",
            "/acme/web.git/info/refs/",
            "/acme/web.git/git-receive-pack/",
        ] {
            assert!(
                matches!(
                    classify("github.com", "POST", path, None),
                    Classified::Ambiguous(_)
                ),
                "{path}"
            );
        }
    }

    #[test]
    fn probe_backslashes_nul_and_control_bytes_are_refused() {
        for path in [
            "/acme\\other/web.git/info/refs",
            "/acme/web.git\\..\\other.git/git-receive-pack",
            "/acme/web.git/info/refs\\",
            "/acme/web.git/info/refs%5C",
            "/acme/web.git%5C..%5Cx/git-receive-pack",
            "/acme/web.git/git-receive-pack%00",
            "/acme/web.git/git-receive-pack\0",
            "/acme/web.git/git-receive-pack\n",
            "/acme/web.git/info/refs%0A",
        ] {
            assert!(
                matches!(
                    classify("github.com", "POST", path, None),
                    Classified::Ambiguous(_)
                ),
                "{path:?}"
            );
        }
    }

    #[test]
    fn probe_non_canonical_percent_encoding_is_refused() {
        for path in [
            // An encoded letter, digit or `-._~`.
            "/acme/web.git/info/%72efs",
            "/acme/web.git/%67it-receive-pack",
            "/acme/we%62.git/git-receive-pack",
            "/acme/web%2Egit/git-receive-pack",
            "/acme/web.git/git%2Dreceive%2Dpack",
            // Lower-case hexadecimal, a bare or half escape, a double encoding.
            "/acme/web.git/info/refs%2f",
            "/acme/web.git/info/refs%",
            "/acme/web.git/info/refs%2",
            "/acme/web.git/info/refs%zz",
            "/acme/web.git/info/refs%252E",
            "/acme/web.git/%252e%252e/other/git-receive-pack",
            // Bytes that are not UTF-8 once decoded.
            "/acme/web.git/info/refs%C0%AE",
            "/acme/web.git/info/refs%FF",
        ] {
            assert!(
                matches!(
                    classify("github.com", "POST", path, None),
                    Classified::Ambiguous(_)
                ),
                "{path:?}"
            );
        }
    }

    #[test]
    fn probe_path_parameters_and_raw_non_ascii_are_refused() {
        for path in [
            "/acme/web.git;x=1/git-receive-pack",
            "/acme/web.git/git-receive-pack;jsessionid=1",
            "/acme/web.git/info;/refs",
            "/acme/web.git/info/refs\u{e9}",
            "/acme/web.git/info/refs ",
            "/acme/web.git/info/refs\"",
            "/acme/{web}.git/info/refs",
            "/acme/web\u{2024}git/git-receive-pack",
        ] {
            assert!(
                matches!(
                    classify("github.com", "POST", path, None),
                    Classified::Ambiguous(_)
                ),
                "{path:?}"
            );
        }
    }

    #[test]
    fn probe_case_and_the_git_suffix_do_not_make_another_repository() {
        let listed = ref_of("github.com", "/acme/web.git/info/refs");
        for path in [
            "/ACME/WEB/info/refs",
            "/acme/WEB.GIT/info/refs",
            "/Acme/Web/Info/Refs",
        ] {
            assert_eq!(ref_of("github.com", path), listed, "{path}");
        }
        // And a different repository stays different.
        assert_ne!(ref_of("github.com", "/acme/web2.git/info/refs"), listed);
        assert_ne!(ref_of("github.com", "/acme/web.git.git/info/refs"), listed);
    }

    #[test]
    fn a_canonical_escape_for_a_byte_that_needs_one_is_read_and_a_name_the_table_cannot_hold_has_no_repo_ref()
     {
        let found = git(
            "dev.azure.com",
            "GET",
            "/org/My%20Project/_git/repo/info/refs",
            None,
        );
        assert_eq!(found.repo, "my project/repo");
        assert!(found.repo_ref().is_none());
    }
}
