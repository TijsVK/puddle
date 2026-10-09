// SPDX-License-Identifier: GPL-3.0-or-later
//! Stand-ins: values a workspace holds in place of secrets.
//!
//! A workspace never holds a secret. It holds a random *stand-in* (an environment variable the
//! user set, or the token a login inside the workspace produced), and the proxy swaps the real
//! value in on the way out, on a terminated connection to a host that stand-in is for, and
//! nowhere else. That is what keeps a stand-in worthless to a workspace that sends it to its own
//! server: the swap needs the host to be on the stand-in's list.
//!
//! [`StandIns`] is the registry of one workspace, shared by everything that creates stand-ins
//! (user secrets, captured logins) and consulted by every terminated request. The rules the swap
//! follows:
//!
//! - **Where**: header values only. Never names, the request target, the query string or a body.
//!   A value that starts with `Basic ` is decoded, swapped and encoded again, because git sends
//!   `user:stand-in` base64-encoded. Headers an injector sets are never looked at.
//! - **Which hosts**: the connection's host (the one the certificate, `Host`/`:authority` and the
//!   `CONNECT` agree on) must match one of the stand-in's hosts. A stand-in seen on any other
//!   terminated host goes out unchanged and is reported for the audit. Plain HTTP and spliced
//!   connections never reach this code, so a stand-in there is unchanged too.
//! - **Whose**: only the stand-ins in this workspace's registry are known. Another workspace's
//!   stand-in is just a string here and is left alone.
//! - **When**: after the upstream's certificate is verified, so a server that is not accepted
//!   never sees a real value, and each request on its own, so a stand-in added while a
//!   connection is open applies from its next request.
//!
//! A real value is zeroised when its entry is dropped. The copy in a request that is on its way
//! out lives in the HTTP library's buffers and is not.

use std::cmp::Reverse;
use std::sync::{Arc, PoisonError, RwLock};

use ::http::header::{HeaderMap, HeaderName, HeaderValue};
use base64::Engine as _;
use base64::alphabet;
use base64::engine::DecodePaddingMode;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig, STANDARD};
use memchr::memmem::Finder;
use puddle_types::Host;
use zeroize::Zeroizing;

use super::inject::{InjectedHeader, Injection, SecretValue};
use super::set::TerminationSet;

/// The shortest stand-in accepted. A short one would match inside ordinary header text and swap
/// it.
const MIN_STAND_IN_LEN: usize = 16;

/// The longest stand-in or name accepted.
const MAX_LEN: usize = 256;

/// Most random bytes of a generated stand-in: 128 bits.
const RANDOM_BYTES: usize = 16;

/// Standard base64 that accepts a missing `=` padding (some clients leave it off).
const LENIENT_BASE64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

/// Where a stand-in came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum StandInOrigin {
    /// A secret the user gave the workspace, set as an environment variable.
    Secret,
    /// A token captured from a login made inside the workspace.
    CapturedLogin,
}

impl StandInOrigin {
    fn label(self) -> &'static str {
        match self {
            Self::Secret => "secret",
            Self::CapturedLogin => "login",
        }
    }
}

/// Why a stand-in could not be made or registered.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum StandInError {
    /// A name is 1 to 64 characters of letters, digits, `_`, `-` and `.`.
    #[error("{0:?} is not a name a stand-in can have")]
    Name(String),
    /// A stand-in is at least 16 visible ASCII characters without spaces, so it cannot match
    /// ordinary header text.
    #[error("a stand-in is {MIN_STAND_IN_LEN} to {MAX_LEN} visible characters without spaces")]
    Shape,
    /// A stand-in with no host is not allowed: it would be worth nothing anywhere.
    #[error("a stand-in needs at least one host")]
    NoHosts,
    /// A `*.` pattern over a domain anyone can register a name under (`*.github.io`, `*.co.uk`):
    /// the real value would go to whoever registers one.
    #[error("*.{0} covers names anyone can register; list the exact hosts instead")]
    SharedDomain(String),
    /// The real value is empty or has characters a header cannot carry (line breaks, control
    /// characters).
    #[error("the real value is empty or has characters a header cannot carry")]
    Value,
    /// Another entry has the same stand-in, or one inside the other, which would make a swap
    /// ambiguous.
    #[error(
        "another entry has a stand-in that equals or contains this one (or the other way round)"
    )]
    Overlaps,
    /// The operating system has no randomness to give.
    #[error("the operating system has no randomness to give")]
    Random,
    /// An entry handed to [`StandIns::replace_origin`] is of another origin than the one being
    /// replaced.
    #[error("an entry is not of the origin being replaced")]
    Origin,
}

/// One stand-in and what it stands for.
pub struct StandIn {
    origin: StandInOrigin,
    name: String,
    text: String,
    /// Finds `text` in a header value.
    finder: Finder<'static>,
    real: SecretValue,
    hosts: TerminationSet,
}

impl std::fmt::Debug for StandIn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Neither the stand-in's text nor the real value: both end up in logs by accident.
        f.debug_struct("StandIn")
            .field("id", &self.id())
            .field("hosts", &self.hosts)
            .finish_non_exhaustive()
    }
}

fn is_header_safe(value: &str) -> bool {
    !value.is_empty() && HeaderValue::from_str(value).is_ok()
}

fn is_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

impl StandIn {
    /// A stand-in `stand_in` for `real`, to be swapped in only toward `hosts` (exact names or
    /// `*.suffix` patterns, as in a [`TerminationSet`]).
    ///
    /// `name` labels it in logs and in the audit (the environment variable's name, or the login's
    /// name); it is never secret.
    ///
    /// # Errors
    /// [`StandInError`] for a name, stand-in or real value that is not acceptable, no hosts, or a
    /// `*.` pattern over a domain anyone can register a name under.
    pub fn new(
        origin: StandInOrigin,
        name: &str,
        stand_in: &str,
        real: SecretValue,
        hosts: TerminationSet,
    ) -> Result<Self, StandInError> {
        if !is_name(name) {
            return Err(StandInError::Name(name.to_owned()));
        }
        let shape_ok = (MIN_STAND_IN_LEN..=MAX_LEN).contains(&stand_in.len())
            && stand_in.bytes().all(|b| b.is_ascii_graphic());
        if !shape_ok {
            return Err(StandInError::Shape);
        }
        if hosts.is_empty() {
            return Err(StandInError::NoHosts);
        }
        if let Some(base) = hosts
            .wildcard_bases()
            .find(|base| psl::domain(base.as_bytes()).is_none())
        {
            return Err(StandInError::SharedDomain(base.to_owned()));
        }
        if !is_header_safe(real.expose()) {
            return Err(StandInError::Value);
        }
        Ok(Self {
            origin,
            name: name.to_owned(),
            text: stand_in.to_owned(),
            finder: Finder::new(stand_in).into_owned(),
            real,
            hosts,
        })
    }

    /// What the audit and logs call it: `stand-in:secret:<name>` or `stand-in:login:<name>`.
    #[must_use]
    pub fn id(&self) -> String {
        format!("stand-in:{}:{}", self.origin.label(), self.name)
    }

    /// Where it came from.
    #[must_use]
    pub fn origin(&self) -> StandInOrigin {
        self.origin
    }

    /// The hosts the real value may be swapped in toward.
    #[must_use]
    pub fn hosts(&self) -> &TerminationSet {
        &self.hosts
    }
}

/// A fresh stand-in for the secret `name`, an environment variable's name: `puddle-secret-<name>-`
/// and 128 random bits as 32 hex characters.
///
/// # Errors
/// [`StandInError::Name`] when `name` cannot be one (see [`StandIn::new`]),
/// [`StandInError::Random`] when the operating system has no randomness.
pub fn secret_stand_in(name: &str) -> Result<String, StandInError> {
    let mut random = [0_u8; RANDOM_BYTES];
    getrandom::fill(&mut random).map_err(|_| StandInError::Random)?;
    stand_in_with(name, &random)
}

fn stand_in_with(name: &str, random: &[u8; RANDOM_BYTES]) -> Result<String, StandInError> {
    use std::fmt::Write as _;
    if !is_name(name) {
        return Err(StandInError::Name(name.to_owned()));
    }
    let mut text = format!("puddle-secret-{name}-");
    for byte in random {
        let _ = write!(text, "{byte:02x}");
    }
    Ok(text)
}

/// What a swap did to one request.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Swapped {
    /// The ids of the stand-ins that were replaced (each once).
    pub(crate) swapped: Vec<String>,
    /// The ids of the stand-ins that were seen toward a host they are not for (each once).
    pub(crate) unbound: Vec<String>,
}

impl Swapped {
    fn note(list: &mut Vec<String>, id: String) {
        if !list.contains(&id) {
            list.push(id);
        }
    }
}

/// One workspace's stand-ins. Cheap to share (`Arc`); safe to change while requests are served.
#[derive(Debug, Default)]
pub struct StandIns {
    entries: RwLock<Vec<Arc<StandIn>>>,
}

impl StandIns {
    /// An empty registry: nothing is swapped.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers `entry`. It applies from the next request.
    ///
    /// # Errors
    /// [`StandInError::Overlaps`] when another entry's stand-in equals this one or one contains
    /// the other.
    pub fn insert(&self, entry: StandIn) -> Result<(), StandInError> {
        let mut entries = self.entries.write().unwrap_or_else(PoisonError::into_inner);
        let overlaps = entries
            .iter()
            .any(|e| e.text.contains(&entry.text) || entry.text.contains(&e.text));
        if overlaps {
            return Err(StandInError::Overlaps);
        }
        entries.push(Arc::new(entry));
        Ok(())
    }

    /// Makes the entries of `origin` exactly `entries`, in one step: a request sees the old
    /// entries or the new ones, never a registry with a stand-in missing. Entries of other origins
    /// stay. An entry that is in both lists (the same stand-in) is replaced, so a new real value
    /// or new hosts apply from the next request.
    ///
    /// # Errors
    /// [`StandInError::Overlaps`] when two stand-ins of the result equal or contain each other;
    /// the registry is not changed then. [`StandInError::Origin`] when an entry is not of `origin`.
    pub fn replace_origin(
        &self,
        origin: StandInOrigin,
        entries: Vec<StandIn>,
    ) -> Result<(), StandInError> {
        if entries.iter().any(|e| e.origin != origin) {
            return Err(StandInError::Origin);
        }
        let mut held = self.entries.write().unwrap_or_else(PoisonError::into_inner);
        let others: Vec<Arc<StandIn>> = held
            .iter()
            .filter(|e| e.origin != origin)
            .cloned()
            .collect();
        let mut next = others;
        next.extend(entries.into_iter().map(Arc::new));
        let overlap = next.iter().enumerate().any(|(i, a)| {
            next.iter()
                .skip(i + 1)
                .any(|b| a.text.contains(&b.text) || b.text.contains(&a.text))
        });
        if overlap {
            return Err(StandInError::Overlaps);
        }
        *held = next;
        Ok(())
    }

    /// The ids of the entries, `stand-in:secret:<name>` or `stand-in:login:<name>`, in the order
    /// they were registered. Names only: for logs, tests and screens.
    #[must_use]
    pub fn ids(&self) -> Vec<String> {
        self.entries
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|e| e.id())
            .collect()
    }

    /// Removes the entry whose stand-in is `stand_in`. `true` when there was one.
    pub fn remove(&self, stand_in: &str) -> bool {
        let mut entries = self.entries.write().unwrap_or_else(PoisonError::into_inner);
        let before = entries.len();
        entries.retain(|e| e.text != stand_in);
        entries.len() != before
    }

    /// Gives the entry whose stand-in is `stand_in` a new real value (a refreshed token). `true`
    /// when there was one.
    ///
    /// # Errors
    /// [`StandInError::Value`] when the value cannot go in a header.
    pub fn set_real(&self, stand_in: &str, real: SecretValue) -> Result<bool, StandInError> {
        if !is_header_safe(real.expose()) {
            return Err(StandInError::Value);
        }
        let mut entries = self.entries.write().unwrap_or_else(PoisonError::into_inner);
        let Some(slot) = entries.iter_mut().find(|e| e.text == stand_in) else {
            return Ok(false);
        };
        let old = &**slot;
        *slot = Arc::new(StandIn {
            origin: old.origin,
            name: old.name.clone(),
            text: old.text.clone(),
            finder: old.finder.clone(),
            real,
            hosts: old.hosts.clone(),
        });
        Ok(true)
    }

    /// How many stand-ins are registered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// Whether no stand-in is registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Every host any stand-in is for. A stand-in is swapped only on a terminated connection, so
    /// whoever builds the workspace's [`TerminationSet`] adds these.
    #[must_use]
    pub fn hosts(&self) -> TerminationSet {
        let mut all = TerminationSet::new();
        for entry in self
            .entries
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
        {
            all.extend(&entry.hosts);
        }
        all
    }

    /// Swaps the stand-ins in `headers`' values for their real values, for a request to `host`.
    /// Headers `injected` sets are left alone.
    pub(crate) fn swap(
        &self,
        headers: &mut HeaderMap,
        host: &Host,
        injected: Option<&Injection>,
    ) -> Swapped {
        let mut report = Swapped::default();
        let guard = self.entries.read().unwrap_or_else(PoisonError::into_inner);
        let entries: &[Arc<StandIn>] = &guard;
        if entries.is_empty() {
            return report;
        }
        let skip: Vec<&HeaderName> = injected
            .map(|i| i.headers().iter().map(InjectedHeader::name).collect())
            .unwrap_or_default();
        for (name, value) in headers.iter_mut() {
            if skip.contains(&name) {
                continue;
            }
            if let Some(mut new) = swap_value(value.as_bytes(), entries, host, &mut report) {
                new.set_sensitive(true);
                *value = new;
            }
        }
        report
    }
}

/// The new value of one header, or `None` when nothing in it was swapped.
fn swap_value(
    value: &[u8],
    entries: &[Arc<StandIn>],
    host: &Host,
    report: &mut Swapped,
) -> Option<HeaderValue> {
    if let Some(new) = swap_bytes(value, entries, host, report) {
        return HeaderValue::from_bytes(&new).ok();
    }
    let token = basic_credentials(value)?;
    let decoded = Zeroizing::new(LENIENT_BASE64.decode(token).ok()?);
    let new = swap_bytes(&decoded, entries, host, report)?;
    let scheme = value.get(..5)?;
    let mut out = Zeroizing::new(scheme.to_vec());
    out.push(b' ');
    out.extend_from_slice(STANDARD.encode(&*new).as_bytes());
    HeaderValue::from_bytes(&out).ok()
}

/// The base64 part of an `Authorization`-style `Basic <credentials>` value.
fn basic_credentials(value: &[u8]) -> Option<&[u8]> {
    let scheme = value.get(..5)?;
    if !scheme.eq_ignore_ascii_case(b"basic") {
        return None;
    }
    let rest = value.get(5..)?;
    let credentials = rest.trim_ascii_start();
    let separated = credentials.len() < rest.len();
    (separated && !credentials.is_empty()).then(|| credentials.trim_ascii_end())
}

/// Swaps every stand-in in `input` that is for `host`, in one left-to-right pass, so a real value
/// is never searched for stand-ins. At each place the longest stand-in wins. `None` when nothing
/// was swapped.
fn swap_bytes(
    input: &[u8],
    entries: &[Arc<StandIn>],
    host: &Host,
    report: &mut Swapped,
) -> Option<Zeroizing<Vec<u8>>> {
    // Every place each stand-in occurs, found with one scan per stand-in: the work is bounded by
    // the stand-ins times the value, however many copies a guest puts in it.
    let mut hits: Vec<(usize, &StandIn)> = Vec::new();
    for entry in entries {
        let mut from = 0;
        while let Some(at) = entry.finder.find(input.get(from..)?) {
            hits.push((from + at, entry));
            from += at + entry.text.len();
        }
    }
    hits.sort_by_key(|(at, entry)| (*at, Reverse(entry.text.len())));
    let mut out: Option<Zeroizing<Vec<u8>>> = None;
    let mut copied = 0;
    for (at, entry) in hits {
        if at < copied {
            continue;
        }
        let end = at + entry.text.len();
        if entry.hosts.contains(host) {
            let out = out.get_or_insert_with(|| Zeroizing::new(Vec::with_capacity(input.len())));
            out.extend_from_slice(input.get(copied..at)?);
            out.extend_from_slice(entry.real.expose().as_bytes());
            copied = end;
            Swapped::note(&mut report.swapped, entry.id());
        } else {
            Swapped::note(&mut report.unbound, entry.id());
        }
    }
    let mut out = out?;
    out.extend_from_slice(input.get(copied..)?);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GH: &str = "puddle-secret-GH_TOKEN-00112233445566778899aabbccddeeff";
    const API: &str = "puddle-secret-API_KEY-ffeeddccbbaa99887766554433221100";
    const REAL_GH: &str = "ghp_realRealReal1111";
    const REAL_API: &str = "sk-real-2222";
    const LOGIN: &str = "login-token-abcdefghijklmnop";
    const NEW: &str = "puddle-secret-NEW-0000000000000000000000000000000a";

    fn host(name: &str) -> Host {
        Host::parse_normalised(name).unwrap()
    }

    fn entry(name: &str, text: &str, real: &str, hosts: &[&str]) -> StandIn {
        StandIn::new(
            StandInOrigin::Secret,
            name,
            text,
            SecretValue::new(real),
            TerminationSet::parse(hosts.iter().copied()).unwrap(),
        )
        .unwrap()
    }

    fn registry() -> StandIns {
        let registry = StandIns::new();
        registry
            .insert(entry(
                "GH_TOKEN",
                GH,
                REAL_GH,
                &["github.com", "*.githubcopilot.com"],
            ))
            .unwrap();
        registry
            .insert(entry("API_KEY", API, REAL_API, &["api.example.com"]))
            .unwrap();
        registry
    }

    fn map(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        map
    }

    fn swap(registry: &StandIns, pairs: &[(&str, &str)], to: &str) -> (HeaderMap, Swapped) {
        let mut headers = map(pairs);
        let report = registry.swap(&mut headers, &host(to), None);
        (headers, report)
    }

    fn basic(text: &str) -> String {
        format!("Basic {}", STANDARD.encode(text))
    }

    fn decoded(value: &HeaderValue) -> String {
        let text = value.to_str().unwrap();
        let (scheme, rest) = text.split_once(' ').unwrap();
        assert!(scheme.eq_ignore_ascii_case("basic"), "{text}");
        String::from_utf8(LENIENT_BASE64.decode(rest).unwrap()).unwrap()
    }

    #[test]
    fn a_stand_in_is_swapped_in_any_header_value_toward_its_hosts() {
        let registry = registry();
        let (headers, report) = swap(
            &registry,
            &[
                ("authorization", &format!("Bearer {GH}")),
                ("x-api-key", GH),
                ("cookie", &format!("a=1; token={GH}; b=2")),
                ("user-agent", "git/2.47"),
            ],
            "github.com",
        );
        assert_eq!(headers["authorization"], format!("Bearer {REAL_GH}"));
        assert_eq!(headers["x-api-key"], REAL_GH);
        assert_eq!(headers["cookie"], format!("a=1; token={REAL_GH}; b=2"));
        assert_eq!(headers["user-agent"], "git/2.47");
        assert_eq!(report.swapped, ["stand-in:secret:GH_TOKEN"]);
        assert_eq!(report.unbound, Vec::<String>::new());
        assert!(headers["authorization"].is_sensitive());
        assert!(!headers["user-agent"].is_sensitive());
    }

    fn login(name: &str, text: &str, real: &str) -> StandIn {
        StandIn::new(
            StandInOrigin::CapturedLogin,
            name,
            text,
            SecretValue::new(real),
            TerminationSet::parse(["login.example.com"]).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn replacing_an_origin_changes_its_entries_in_one_step_and_leaves_the_others() {
        let registry = registry();
        registry
            .insert(login("claude", LOGIN, "real-login"))
            .unwrap();
        assert_eq!(
            registry.ids(),
            [
                "stand-in:secret:GH_TOKEN",
                "stand-in:secret:API_KEY",
                "stand-in:login:claude"
            ]
        );
        // GH_TOKEN stays with a new real value and hosts, API_KEY goes, NEW comes.
        registry
            .replace_origin(
                StandInOrigin::Secret,
                vec![
                    entry("GH_TOKEN", GH, "ghp_rotated", &["gitlab.com"]),
                    entry("NEW", NEW, "real-new", &["new.example.com"]),
                ],
            )
            .unwrap();
        assert_eq!(
            registry.ids(),
            [
                "stand-in:login:claude",
                "stand-in:secret:GH_TOKEN",
                "stand-in:secret:NEW"
            ]
        );
        let (headers, _) = swap(&registry, &[("a", GH)], "gitlab.com");
        assert_eq!(headers["a"], "ghp_rotated");
        let (headers, report) = swap(&registry, &[("a", GH)], "github.com");
        assert_eq!(headers["a"], GH, "its old host no longer swaps it");
        assert_eq!(report.unbound, ["stand-in:secret:GH_TOKEN"]);
        let (headers, _) = swap(&registry, &[("a", API)], "api.example.com");
        assert_eq!(headers["a"], API, "a removed stand-in is just text");
        let (headers, _) = swap(&registry, &[("a", LOGIN)], "login.example.com");
        assert_eq!(
            headers["a"], "real-login",
            "the login entry was not touched"
        );
        let hosts = registry.hosts();
        assert!(hosts.contains(&host("new.example.com")));
        assert!(hosts.contains(&host("login.example.com")));
        assert!(!hosts.contains(&host("api.example.com")));
        // An empty list removes every entry of the origin.
        registry
            .replace_origin(StandInOrigin::Secret, Vec::new())
            .unwrap();
        assert_eq!(registry.ids(), ["stand-in:login:claude"]);
    }

    #[test]
    fn a_replacement_that_overlaps_or_is_of_another_origin_changes_nothing() {
        let registry = registry();
        let before = registry.ids();
        let twin = format!("{GH}-more-text");
        for bad in [
            vec![
                entry("A", GH, "x1", &["a.example.com"]),
                entry("B", &twin, "x2", &["b.example.com"]),
            ],
            vec![login("claude", "login-token-abcdefghijklmnop", "r")],
        ] {
            assert!(registry.replace_origin(StandInOrigin::Secret, bad).is_err());
            assert_eq!(registry.ids(), before);
        }
        // A secret's stand-in that equals a login's is refused too.
        registry
            .insert(login("claude", "login-token-abcdefghijklmnop", "r"))
            .unwrap();
        let clash = entry("C", "login-token-abcdefghijklmnop", "x", &["c.example.com"]);
        assert_eq!(
            registry.replace_origin(StandInOrigin::Secret, vec![clash]),
            Err(StandInError::Overlaps)
        );
        assert_eq!(registry.len(), 3);
    }

    #[test]
    fn a_pattern_host_and_a_name_below_it_are_covered() {
        let registry = registry();
        let (headers, _) = swap(&registry, &[("authorization", GH)], "api.githubcopilot.com");
        assert_eq!(headers["authorization"], REAL_GH);
        let (headers, report) = swap(&registry, &[("authorization", GH)], "githubcopilot.com");
        assert_eq!(
            headers["authorization"], GH,
            "the suffix itself is not below it"
        );
        assert_eq!(report.unbound, ["stand-in:secret:GH_TOKEN"]);
    }

    #[test]
    fn several_stand_ins_and_copies_in_one_value_are_all_swapped_once() {
        let registry = StandIns::new();
        registry
            .insert(entry("GH_TOKEN", GH, REAL_GH, &["github.com"]))
            .unwrap();
        registry
            .insert(entry("API_KEY", API, REAL_API, &["github.com"]))
            .unwrap();
        let value = format!("{GH},{API},{GH}");
        let (headers, report) = swap(&registry, &[("x-multi", &value)], "github.com");
        assert_eq!(
            headers["x-multi"],
            format!("{REAL_GH},{REAL_API},{REAL_GH}")
        );
        assert_eq!(report.swapped.len(), 2);
    }

    #[test]
    fn stand_ins_that_overlap_in_a_value_swap_the_first_and_keep_the_rest_of_the_other() {
        // The end of one is the start of the other: neither contains the other, so both register.
        let first = "prefix-aaaaaaaa-ZZZZ12345678";
        let second = "ZZZZ12345678-bbbbbbbbbbbb";
        let registry = StandIns::new();
        registry
            .insert(entry("FIRST", first, "real-first", &["github.com"]))
            .unwrap();
        registry
            .insert(entry("SECOND", second, "real-second", &["github.com"]))
            .unwrap();
        let sent = "prefix-aaaaaaaa-ZZZZ12345678-bbbbbbbbbbbb";
        let (headers, report) = swap(&registry, &[("x-value", sent)], "github.com");
        assert_eq!(headers["x-value"], "real-first-bbbbbbbbbbbb");
        assert_eq!(report.swapped, ["stand-in:secret:FIRST"]);
    }

    #[test]
    fn a_real_value_is_never_searched_for_stand_ins() {
        // The real value of one entry contains the stand-in of the other: one pass, no cascade.
        let registry = StandIns::new();
        registry
            .insert(entry("API_KEY", API, &format!("see-{GH}"), &["github.com"]))
            .unwrap();
        registry
            .insert(entry("GH_TOKEN", GH, REAL_GH, &["github.com"]))
            .unwrap();
        let (headers, _) = swap(&registry, &[("x-k", API)], "github.com");
        assert_eq!(headers["x-k"], format!("see-{GH}"));
    }

    #[test]
    fn only_whole_stand_ins_match() {
        let registry = registry();
        let truncated = &GH[..GH.len() - 1];
        let other_random = "puddle-secret-GH_TOKEN-ffffffffffffffffffffffffffffffff";
        let near = format!("{}{}", &GH[..GH.len() - 2], "zz");
        for value in [
            truncated.to_owned(),
            other_random.to_owned(),
            near,
            GH.to_ascii_uppercase(),
            "puddle-secret".to_owned(),
        ] {
            let (headers, report) = swap(&registry, &[("authorization", &value)], "github.com");
            assert_eq!(headers["authorization"], value.as_str(), "{value}");
            assert_eq!(report, Swapped::default(), "{value}");
        }
        // Text around a whole one is kept as it is.
        let (headers, _) = swap(
            &registry,
            &[("authorization", &format!("x{GH}y"))],
            "github.com",
        );
        assert_eq!(headers["authorization"], format!("x{REAL_GH}y"));
    }

    #[test]
    fn a_stand_in_toward_another_host_goes_out_unchanged_and_is_reported() {
        let registry = registry();
        let (headers, report) = swap(
            &registry,
            &[("authorization", &format!("Bearer {API}")), ("x-gh", GH)],
            "github.com",
        );
        assert_eq!(headers["authorization"], format!("Bearer {API}"));
        assert_eq!(headers["x-gh"], REAL_GH, "the other one is still swapped");
        assert_eq!(report.unbound, ["stand-in:secret:API_KEY"]);
        assert_eq!(report.swapped, ["stand-in:secret:GH_TOKEN"]);
        assert!(!headers["authorization"].is_sensitive());
    }

    #[test]
    fn a_stand_in_this_workspace_does_not_know_is_left_alone_and_not_reported() {
        // Another workspace's stand-in for the same secret name.
        let theirs = "puddle-secret-GH_TOKEN-0123456789abcdef0123456789abcdef";
        let registry = registry();
        let (headers, report) = swap(&registry, &[("authorization", theirs)], "github.com");
        assert_eq!(headers["authorization"], theirs);
        assert_eq!(report, Swapped::default());
    }

    #[test]
    fn a_basic_value_is_decoded_swapped_and_encoded_again() {
        let registry = registry();
        for credentials in [
            basic(&format!("x-access-token:{GH}")),
            basic(&format!("{GH}:")),
            basic(&format!("oauth2:{GH}")).replace('=', ""),
        ] {
            let (headers, report) =
                swap(&registry, &[("authorization", &credentials)], "github.com");
            let value = decoded(&headers["authorization"]);
            assert!(value.contains(REAL_GH) && !value.contains(GH), "{value}");
            assert_eq!(report.swapped, ["stand-in:secret:GH_TOKEN"]);
            assert!(headers["authorization"].is_sensitive());
        }
        let (headers, _) = swap(
            &registry,
            &[(
                "authorization",
                &format!("basic   {}", STANDARD.encode(format!("u:{GH}"))),
            )],
            "github.com",
        );
        assert_eq!(decoded(&headers["authorization"]), format!("u:{REAL_GH}"));
        assert!(
            headers["authorization"]
                .to_str()
                .unwrap()
                .starts_with("basic ")
        );
    }

    #[test]
    fn a_basic_value_for_another_host_is_left_as_it_was_sent() {
        let registry = registry();
        let sent = basic(&format!("u:{API}"));
        let (headers, report) = swap(&registry, &[("authorization", &sent)], "github.com");
        assert_eq!(headers["authorization"], sent.as_str());
        assert_eq!(report.unbound, ["stand-in:secret:API_KEY"]);
        assert_eq!(report.swapped, Vec::<String>::new());
        // One bound and one unbound inside the same value: the bound one is swapped, the other kept.
        let sent = basic(&format!("{GH}:{API}"));
        let (headers, report) = swap(&registry, &[("authorization", &sent)], "github.com");
        assert_eq!(
            decoded(&headers["authorization"]),
            format!("{REAL_GH}:{API}")
        );
        assert_eq!(report.unbound, ["stand-in:secret:API_KEY"]);
    }

    #[test]
    fn a_basic_value_that_is_not_credentials_is_left_alone() {
        let registry = registry();
        for sent in [
            "Basic".to_owned(),
            "Basic ".to_owned(),
            "Basicx dXNlcjpwdw==".to_owned(),
            "Basic not base64 at all!".to_owned(),
            "Basic dXNlcjpwdw==".to_owned(),
            format!("Basic {}", STANDARD.encode([0xff_u8, 0xfe, 0x00])),
            "Bearer abc".to_owned(),
        ] {
            let (headers, report) = swap(&registry, &[("authorization", &sent)], "github.com");
            assert_eq!(headers["authorization"], sent.as_str(), "{sent}");
            assert_eq!(report, Swapped::default(), "{sent}");
        }
    }

    #[test]
    fn a_basic_value_with_bytes_that_are_not_text_still_swaps() {
        let registry = registry();
        let mut raw = vec![0xff_u8, b':'];
        raw.extend_from_slice(GH.as_bytes());
        let sent = format!("Basic {}", STANDARD.encode(&raw));
        let (headers, _) = swap(&registry, &[("authorization", &sent)], "github.com");
        let value = headers["authorization"].to_str().unwrap();
        let bytes = LENIENT_BASE64
            .decode(value.strip_prefix("Basic ").unwrap())
            .unwrap();
        let mut expected = vec![0xff_u8, b':'];
        expected.extend_from_slice(REAL_GH.as_bytes());
        assert_eq!(bytes, expected);
    }

    #[test]
    fn headers_an_injector_set_are_never_scanned() {
        use super::super::inject::{InjectedHeader, Injection};
        let registry = registry();
        let injection = Injection::new(
            "b1",
            vec![
                InjectedHeader::new("authorization", SecretValue::new(format!("Bearer {GH}")))
                    .unwrap(),
            ],
        );
        let mut headers = map(&[("authorization", &format!("Bearer {GH}")), ("x-other", GH)]);
        let report = registry.swap(&mut headers, &host("github.com"), Some(&injection));
        assert_eq!(headers["authorization"], format!("Bearer {GH}"));
        assert_eq!(headers["x-other"], REAL_GH);
        assert_eq!(report.swapped, ["stand-in:secret:GH_TOKEN"]);
    }

    #[test]
    fn nothing_registered_nothing_changes() {
        let registry = StandIns::new();
        assert!(registry.is_empty());
        let (headers, report) = swap(&registry, &[("authorization", GH)], "github.com");
        assert_eq!(headers["authorization"], GH);
        assert_eq!(report, Swapped::default());
    }

    #[test]
    fn a_value_full_of_copies_is_swapped_without_blowing_up() {
        let registry = StandIns::new();
        for i in 0..64 {
            let text = format!("puddle-secret-N{i}-00112233445566778899aabbccddeeff");
            registry
                .insert(entry(&format!("N{i}"), &text, "r", &["github.com"]))
                .unwrap();
        }
        registry
            .insert(entry("GH_TOKEN", GH, REAL_GH, &["github.com"]))
            .unwrap();
        let many = vec![GH; 1000].join(",");
        let (headers, report) = swap(&registry, &[("x-many", &many)], "github.com");
        assert_eq!(headers["x-many"], vec![REAL_GH; 1000].join(",").as_str());
        assert_eq!(report.swapped.len(), 1);
    }

    #[test]
    fn registering_is_checked() {
        let hosts = || TerminationSet::parse(["github.com"]).unwrap();
        let new = |name: &str, text: &str, real: &str, hosts: TerminationSet| {
            StandIn::new(
                StandInOrigin::Secret,
                name,
                text,
                SecretValue::new(real),
                hosts,
            )
        };
        assert!(matches!(
            new("", GH, "r", hosts()),
            Err(StandInError::Name(_))
        ));
        assert!(matches!(
            new("a b", GH, "r", hosts()),
            Err(StandInError::Name(_))
        ));
        assert!(matches!(
            new(&"n".repeat(65), GH, "r", hosts()),
            Err(StandInError::Name(_))
        ));
        for text in [
            "short",
            "has a space in it, long enough",
            "tab\tin-it-and-long-enough",
            &"x".repeat(257),
        ] {
            assert_eq!(
                new("N", text, "r", hosts()).unwrap_err(),
                StandInError::Shape,
                "{text:?}"
            );
        }
        assert_eq!(
            new("N", GH, "r", TerminationSet::new()).unwrap_err(),
            StandInError::NoHosts
        );
        for shared in [
            "*.github.io",
            "*.co.uk",
            "*.azurewebsites.net",
            "*.s3.amazonaws.com",
        ] {
            let wide = TerminationSet::parse(["github.com", shared]).unwrap();
            assert!(
                matches!(new("N", GH, "r", wide), Err(StandInError::SharedDomain(_))),
                "{shared}"
            );
        }
        // An exact name below a shared domain is the user's own choice; a pattern below a
        // registrable domain is fine.
        for fine in ["a.github.io", "*.githubcopilot.com", "*.example.co.uk"] {
            let set = TerminationSet::parse([fine]).unwrap();
            assert!(new("N", GH, "r", set).is_ok(), "{fine}");
        }
        for real in ["", "a\r\nb: c", "a\0b"] {
            assert_eq!(
                new("N", GH, real, hosts()).unwrap_err(),
                StandInError::Value,
                "{real:?}"
            );
        }
        let registry = registry();
        assert_eq!(
            registry.insert(entry("DUP", GH, "r", &["a.example.com"])),
            Err(StandInError::Overlaps)
        );
        let longer = format!("{GH}-more");
        assert_eq!(
            registry.insert(entry("LONG", &longer, "r", &["a.example.com"])),
            Err(StandInError::Overlaps)
        );
        assert_eq!(
            registry.insert(entry("SHORT", &GH[..20], "r", &["a.example.com"])),
            Err(StandInError::Overlaps)
        );
        assert_eq!(registry.len(), 2);
    }

    #[test]
    fn the_registry_changes_while_in_use() {
        let registry = registry();
        assert!(registry.remove(API));
        assert!(!registry.remove(API));
        assert_eq!(registry.len(), 1);
        let (headers, report) = swap(&registry, &[("x", API)], "api.example.com");
        assert_eq!(headers["x"], API);
        assert_eq!(report, Swapped::default(), "a removed stand-in is unknown");

        assert_eq!(
            registry.set_real(GH, SecretValue::new("ghp_refreshed")),
            Ok(true)
        );
        assert_eq!(
            registry.set_real("nope-nope-nope-nope", SecretValue::new("x")),
            Ok(false)
        );
        assert_eq!(
            registry.set_real(GH, SecretValue::new("a\nb")),
            Err(StandInError::Value)
        );
        let (headers, _) = swap(&registry, &[("x", GH)], "github.com");
        assert_eq!(headers["x"], "ghp_refreshed");
    }

    #[test]
    fn the_hosts_to_terminate_are_the_hosts_of_every_entry() {
        let registry = registry();
        let hosts = registry.hosts();
        for yes in ["github.com", "x.githubcopilot.com", "api.example.com"] {
            assert!(hosts.contains(&host(yes)), "{yes}");
        }
        assert!(!hosts.contains(&host("example.com")));
        assert!(StandIns::new().hosts().is_empty());
    }

    #[test]
    fn debug_shows_neither_the_stand_in_nor_the_real_value() {
        let text = format!(
            "{:?} {:?}",
            registry(),
            entry("GH_TOKEN", GH, REAL_GH, &["github.com"])
        );
        assert!(
            !text.contains(REAL_GH) && !text.contains(&GH[GH.len() - 12..]),
            "{text}"
        );
        assert!(text.contains("stand-in:secret:GH_TOKEN"));
        let id = entry("login", API, "r", &["a.example.com"]);
        assert_eq!(id.id(), "stand-in:secret:login");
        assert_eq!(id.origin(), StandInOrigin::Secret);
        assert!(id.hosts().contains(&host("a.example.com")));
        let captured = StandIn::new(
            StandInOrigin::CapturedLogin,
            "github",
            "ghp_0123456789abcdefghij",
            SecretValue::new("x"),
            TerminationSet::parse(["github.com"]).unwrap(),
        )
        .unwrap();
        assert_eq!(captured.id(), "stand-in:login:github");
    }

    mod properties {
        use proptest::prelude::*;

        use super::*;

        /// Pieces of a header value. The text has no hex digit, so no text can finish a cut-off
        /// stand-in into a whole one.
        #[derive(Debug, Clone)]
        enum Piece {
            Text(String),
            /// The stand-in that is for `github.com`.
            Bound,
            /// The stand-in that is for another host.
            Unbound,
            /// The bound stand-in with its last character gone.
            CutOff,
        }

        fn piece() -> impl Strategy<Value = Piece> {
            prop_oneof![
                "[G-Z ,;=]{0,20}".prop_map(Piece::Text),
                Just(Piece::Bound),
                Just(Piece::Unbound),
                Just(Piece::CutOff),
            ]
        }

        /// The value as the guest sends it, and as the real server must get it.
        fn build(pieces: &[Piece]) -> (String, String) {
            let (mut sent, mut expected) = (String::new(), String::new());
            for piece in pieces {
                let (from, to) = match piece {
                    Piece::Text(text) => (text.as_str(), text.as_str()),
                    Piece::Bound => (GH, REAL_GH),
                    Piece::Unbound => (API, API),
                    Piece::CutOff => (&GH[..GH.len() - 1], &GH[..GH.len() - 1]),
                };
                sent.push_str(from);
                expected.push_str(to);
            }
            (sent, expected)
        }

        proptest! {
            #[test]
            fn a_value_built_from_pieces_comes_out_with_only_the_bound_ones_swapped(
                pieces in proptest::collection::vec(piece(), 0..12),
            ) {
                let registry = registry();
                let (sent, expected) = build(&pieces);
                let (headers, report) = swap(&registry, &[("x-value", &sent)], "github.com");
                prop_assert_eq!(headers["x-value"].to_str().unwrap(), expected.as_str());
                let has = |wanted: fn(&Piece) -> bool| pieces.iter().any(wanted);
                prop_assert_eq!(
                    report.swapped.is_empty(),
                    !has(|p| matches!(p, Piece::Bound))
                );
                prop_assert_eq!(
                    report.unbound.is_empty(),
                    !has(|p| matches!(p, Piece::Unbound))
                );
            }

            #[test]
            fn the_same_inside_a_basic_value(
                pieces in proptest::collection::vec(piece(), 0..12),
            ) {
                let registry = registry();
                let (sent, expected) = build(&pieces);
                let basic = format!("Basic {}", STANDARD.encode(format!("user:{sent}")));
                let (headers, _) = swap(&registry, &[("authorization", &basic)], "github.com");
                let text = headers["authorization"].to_str().unwrap();
                let credentials = text.strip_prefix("Basic ").unwrap();
                prop_assert_eq!(
                    String::from_utf8(LENIENT_BASE64.decode(credentials).unwrap()).unwrap(),
                    format!("user:{expected}")
                );
            }

            #[test]
            fn any_bytes_in_a_header_never_panic_and_without_a_stand_in_never_change(
                bytes in proptest::collection::vec(any::<u8>(), 0..200),
            ) {
                let registry = registry();
                let mut headers = HeaderMap::new();
                if let Ok(value) = HeaderValue::from_bytes(&bytes) {
                    headers.insert("x-value", value.clone());
                    registry.swap(&mut headers, &host("github.com"), None);
                    prop_assert_eq!(&headers["x-value"], &value);
                }
            }
        }
    }

    #[test]
    fn generated_stand_ins_have_the_documented_shape_and_differ() {
        let a = secret_stand_in("OPENAI_API_KEY").unwrap();
        let b = secret_stand_in("OPENAI_API_KEY").unwrap();
        assert_ne!(a, b);
        let random = a.strip_prefix("puddle-secret-OPENAI_API_KEY-").unwrap();
        assert_eq!(random.len(), 32);
        assert!(random.bytes().all(|c| c.is_ascii_hexdigit()));
        // The shortest name still makes a stand-in `StandIn::new` accepts.
        let short = secret_stand_in("A").unwrap();
        entry("A", &short, "r", &["github.com"]);
        assert_eq!(
            stand_in_with("A", &[0xab; RANDOM_BYTES]).unwrap(),
            format!("puddle-secret-A-{}", "ab".repeat(16))
        );
        for bad in ["", "with space", "a/b", &"n".repeat(65)] {
            assert!(
                matches!(secret_stand_in(bad), Err(StandInError::Name(_))),
                "{bad:?}"
            );
        }
    }
}
