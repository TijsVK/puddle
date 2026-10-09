// SPDX-License-Identifier: GPL-3.0-or-later
//! One workspace's captured logins: what the token endpoints answer, what is kept, what the
//! workspace holds instead.
//!
//! The workspace's tool logs in as it always does. When the token endpoint of a profile answers
//! with tokens, the real ones go to the operating system's credential store and the answer the
//! tool receives carries stand-ins with the tokens' shape. When the tool refreshes, it sends the
//! stand-in of its refresh token; the proxy swaps the real one into that one field of the request
//! ([`puddle_proxy::Exchange::swapping`]) and the new answer is captured the same way, behind the
//! same stand-in: a stand-in names a slot (a profile's role in this workspace), so a refresh
//! changes the real token behind it and nothing the tool has stored.
//!
//! Where the stand-ins are swapped back is the proxy's ([`puddle_proxy::StandIns`]): in the headers
//! of requests to the profile's hosts, and nowhere else.
//!
//! If a login cannot be captured (the answer is not in a form puddle reads, the token is bound to
//! a key, the credential store is not there) the answer goes to the tool as it is, so the tool
//! keeps working, and the user is told that this login is not protected.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use puddle_proxy::{
    AnswerHead, AnswerRewriter, Exchange, ExchangeRewriter, MAX_EXCHANGE_BODY, SecretValue,
    StandIn, StandInError, StandInOrigin, StandIns, TerminationSet, TokenBody,
};
use puddle_secrets::SecretStore;
use puddle_types::{Host, WorkspaceName};
use zeroize::Zeroizing;

use crate::profile::{Endpoint, Field, Profile, Role, Scope};
use crate::shape;
use crate::vault::{STORE_TIMEOUT, Vault, VaultError};

/// What went wrong with a login, for the notice the user sees. Names only: no value is in any of
/// these.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Problem {
    /// The operating system's credential store did not take the token, so the answer went to the
    /// tool as it was.
    StoreUnavailable,
    /// The service's answer was not in a form puddle reads (not JSON or a form, compressed, or
    /// larger than a token answer is), so it went to the tool as it was.
    UnexpectedAnswer,
    /// A token cannot be copied: a length or a character a stand-in cannot have.
    UnusableToken,
    /// The service ties its tokens to a key of the tool's own (`DPoP`), which a stand-in cannot
    /// stand in for.
    BoundToken,
    /// A login puddle kept earlier could not be read back at the workspace's start; the tool will
    /// ask for a new sign-in.
    Unreadable,
}

/// Where a [`Problem`] goes. Implementations must not block.
pub trait LoginNotices: Send + Sync {
    /// Tells the user that `profile`'s login in `workspace` has `problem`.
    fn problem(&self, workspace: &WorkspaceName, profile: &Profile, problem: Problem);
}

/// A login puddle holds for a workspace, as the user is shown it: no value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kept {
    /// The profile's short name (`claude`).
    pub profile: &'static str,
    /// What the user calls the service (`Claude Code`).
    pub name: &'static str,
    /// The tokens held.
    pub roles: Vec<Role>,
}

/// A token endpoint of a profile and its host, ready to match requests.
struct Route {
    host: Host,
    /// The endpoint's path as [`canonical_path`] spells it.
    path: String,
    profile: &'static Profile,
    endpoint: &'static Endpoint,
}

struct Inner {
    workspace: WorkspaceName,
    enabled: bool,
    profiles: &'static [Profile],
    routes: Vec<Route>,
    registry: Arc<StandIns>,
    vault: Vault,
    notices: Arc<dyn LoginNotices>,
    /// One capture at a time, so two refreshes at once do not interleave their writes.
    capture: tokio::sync::Mutex<()>,
    /// How long a call on the credential store may take, in milliseconds.
    store_timeout_ms: AtomicU64,
    /// The stand-in of each slot that has one.
    slots: Mutex<BTreeMap<(&'static str, Role), String>>,
}

/// One workspace's captured logins. Cheap to clone.
#[derive(Clone)]
pub struct Logins {
    inner: Arc<Inner>,
}

impl fmt::Debug for Logins {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Neither stand-ins nor tokens: only what is configured.
        f.debug_struct("Logins")
            .field("workspace", &self.inner.workspace)
            .field("enabled", &self.inner.enabled)
            .field("profiles", &self.inner.profiles.len())
            .finish_non_exhaustive()
    }
}

/// A path as a server may read it: percent-decoded, lower case, without parameters, empty and
/// `.` segments, and with `..` applied. The token endpoint is recognised by this spelling, so a
/// request that names it another way is still read.
pub(crate) fn canonical_path(path: &str) -> String {
    let path = path.split(['?', '#', ';']).next().unwrap_or_default();
    let mut decoded = Vec::with_capacity(path.len());
    let bytes = path.as_bytes();
    let mut at = 0;
    while let Some(&byte) = bytes.get(at) {
        let hex = |i: usize| bytes.get(i).and_then(|b| char::from(*b).to_digit(16));
        if let (b'%', Some(hi), Some(lo)) = (byte, hex(at + 1), hex(at + 2)) {
            decoded.push(u8::try_from(hi * 16 + lo).unwrap_or(b'/'));
            at += 3;
        } else {
            decoded.push(byte);
            at += 1;
        }
    }
    let decoded = String::from_utf8_lossy(&decoded).to_ascii_lowercase();
    let mut segments: Vec<&str> = Vec::new();
    for segment in decoded.split(['/', '\\']) {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            other => segments.push(other),
        }
    }
    format!("/{}", segments.join("/"))
}

impl Logins {
    /// The captured logins of `workspace`, for the profiles `profiles`.
    ///
    /// `registry` is the workspace's stand-in registry (the one its termination swaps from) and
    /// `store` the operating system's credential store. With `enabled` false nothing is captured
    /// and nothing is swapped: the workspace's logins stay in the workspace.
    #[must_use]
    pub fn new(
        workspace: WorkspaceName,
        enabled: bool,
        profiles: &'static [Profile],
        registry: Arc<StandIns>,
        store: Arc<dyn SecretStore>,
        notices: Arc<dyn LoginNotices>,
    ) -> Self {
        let routes = profiles
            .iter()
            .flat_map(|profile| {
                profile.endpoints.iter().filter_map(move |endpoint| {
                    // The literals of the profiles; a test checks each parses.
                    let host = Host::parse_normalised(endpoint.host).ok()?;
                    Some(Route {
                        host,
                        path: canonical_path(endpoint.path),
                        profile,
                        endpoint,
                    })
                })
            })
            .collect();
        Self {
            inner: Arc::new(Inner {
                vault: Vault::new(store, &workspace),
                workspace,
                enabled,
                profiles,
                routes,
                registry,
                notices,
                capture: tokio::sync::Mutex::new(()),
                store_timeout_ms: AtomicU64::new(
                    u64::try_from(STORE_TIMEOUT.as_millis()).unwrap_or(u64::MAX),
                ),
                slots: Mutex::new(BTreeMap::new()),
            }),
        }
    }

    /// Gives up on a call on the credential store after `limit` instead of the default ten seconds
    /// (a locked store can wait for the user to unlock it). A call that is given up on counts as
    /// the store being unavailable.
    pub fn set_store_timeout(&self, limit: Duration) {
        self.inner.store_timeout_ms.store(
            u64::try_from(limit.as_millis()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }

    /// The hosts the workspace decrypts for its logins: every profile's token endpoints and API
    /// hosts while capture is on, none while it is off.
    #[must_use]
    pub fn hosts(&self) -> TerminationSet {
        let mut set = TerminationSet::new();
        if self.inner.enabled {
            for profile in self.inner.profiles {
                set.extend(&profile.hosts());
            }
        }
        set
    }

    fn slots(&self) -> std::sync::MutexGuard<'_, BTreeMap<(&'static str, Role), String>> {
        self.inner
            .slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn notify(&self, profile: &Profile, problem: Problem) {
        tracing::warn!(
            workspace = %self.inner.workspace,
            profile = profile.id,
            ?problem,
            "a login is not protected"
        );
        self.inner
            .notices
            .problem(&self.inner.workspace, profile, problem);
    }

    /// Runs a blocking call on the credential store off the async threads, with a time limit.
    async fn store<T: Send + 'static>(
        &self,
        call: impl FnOnce(&Vault) -> Result<T, VaultError> + Send + 'static,
    ) -> Result<T, VaultError> {
        let vault = self.inner.vault.clone();
        let limit = Duration::from_millis(self.inner.store_timeout_ms.load(Ordering::Relaxed));
        match tokio::time::timeout(limit, tokio::task::spawn_blocking(move || call(&vault))).await {
            Ok(Ok(result)) => result,
            // The call was cut off or panicked: the store is not usable now.
            Ok(Err(_)) | Err(_) => Err(VaultError::Unavailable),
        }
    }

    /// Puts a pair into the registry and the slots: the stand-in the workspace holds and the real
    /// token behind it, swapped toward the hosts `scope` names. The registry is the one place
    /// that checks a stand-in and a real value; what it refuses is the error.
    fn install(
        &self,
        profile: &'static Profile,
        (role, scope): (Role, Scope),
        stand_in: &str,
        real: &str,
    ) -> Result<(), StandInError> {
        let entry = StandIn::new(
            StandInOrigin::CapturedLogin,
            &profile.slot_name(role),
            stand_in,
            SecretValue::new(real),
            profile.hosts_for(scope),
        )?;
        let old = self.slots().insert((profile.id, role), stand_in.to_owned());
        if let Some(old) = old {
            self.inner.registry.remove(&old);
        }
        self.inner.registry.insert(entry)
    }

    /// Reads the logins kept for the workspace and registers their stand-ins, at the workspace's
    /// start: the workspace's disk still holds the stand-ins its tool was given.
    pub async fn load(&self) {
        // With capture off nothing is registered, and the credential store is not touched: off
        // means off. A login kept before is not used until capture is on again.
        if !self.inner.enabled {
            return;
        }
        let mut unreadable: Vec<&'static Profile> = Vec::new();
        let mut store_down = false;
        for profile in self.inner.profiles {
            for slot in profile.slots() {
                if store_down {
                    // One call that did not answer is enough to know; the next would wait as long.
                    continue;
                }
                match self.store(move |vault| vault.read(profile, slot.0)).await {
                    Ok(Some(saved)) => {
                        if self
                            .install(profile, slot, &saved.stand_in, &saved.real)
                            .is_err()
                        {
                            unreadable.push(profile);
                        }
                    }
                    Ok(None) => {}
                    Err(VaultError::Damaged) => unreadable.push(profile),
                    Err(VaultError::Unavailable) => store_down = true,
                }
            }
        }
        // With the store down nothing can be kept either, so every service is told once, with
        // the words for a login that is not protected.
        let down: Vec<&'static Profile> = if store_down {
            self.inner.profiles.iter().collect()
        } else {
            Vec::new()
        };
        for (list, problem) in [
            (down, Problem::StoreUnavailable),
            (unreadable, Problem::Unreadable),
        ] {
            let mut seen: Vec<&str> = Vec::new();
            for profile in list {
                if !seen.contains(&profile.id) {
                    seen.push(profile.id);
                    self.notify(profile, problem);
                }
            }
        }
    }

    /// The logins puddle holds for this workspace (the ones registered since its start), without
    /// any value.
    #[must_use]
    pub fn kept(&self) -> Vec<Kept> {
        let slots = self.slots();
        self.inner
            .profiles
            .iter()
            .filter_map(|profile| {
                let roles: Vec<Role> = profile
                    .roles()
                    .into_iter()
                    .filter(|role| slots.contains_key(&(profile.id, *role)))
                    .collect();
                (!roles.is_empty()).then_some(Kept {
                    profile: profile.id,
                    name: profile.name,
                    roles,
                })
            })
            .collect()
    }

    /// Forgets `profile`'s login for this workspace: its stand-ins stop being swapped (the tool
    /// will ask for a new sign-in) and its real tokens are deleted from the credential store.
    /// `false` when the profile is not one of this workspace's.
    ///
    /// # Errors
    /// [`ForgetError::Store`] when the credential store did not delete a token; the stand-ins are
    /// already gone, and trying again deletes what is left.
    pub async fn forget(&self, profile_id: &str) -> Result<bool, ForgetError> {
        let Some(profile) = self.inner.profiles.iter().find(|p| p.id == profile_id) else {
            return Ok(false);
        };
        let mut failed = false;
        for role in profile.roles() {
            if let Some(stand_in) = self.slots().remove(&(profile.id, role)) {
                self.inner.registry.remove(&stand_in);
            }
            failed |= self
                .store(move |vault| vault.delete(profile, role))
                .await
                .is_err();
        }
        if failed {
            Err(ForgetError::Store)
        } else {
            Ok(true)
        }
    }

    /// Deletes every token kept for `workspace`, when the workspace is deleted. Blocking. Returns
    /// how many deletions the store refused (the rest are gone).
    #[must_use]
    pub fn delete_workspace(
        store: &Arc<dyn SecretStore>,
        workspace: &WorkspaceName,
        profiles: &[Profile],
    ) -> usize {
        let vault = Vault::new(Arc::clone(store), workspace);
        profiles
            .iter()
            .flat_map(|profile| profile.roles().into_iter().map(move |role| (profile, role)))
            .filter(|(profile, role)| vault.delete(profile, *role).is_err())
            .count()
    }

    /// Captures one token answer: keeps the real tokens, and gives back the body with stand-ins
    /// in their place. `Ok(None)`: nothing in the answer to capture.
    async fn capture(
        &self,
        route: (&'static Profile, &'static Endpoint),
        body: &[u8],
        content_type: Option<&str>,
    ) -> Result<Option<Bytes>, Problem> {
        let (profile, endpoint) = route;
        let mut parsed =
            TokenBody::parse(content_type, body).map_err(|_| Problem::UnexpectedAnswer)?;
        let found: Vec<(&'static Field, Zeroizing<String>)> = endpoint
            .fields
            .iter()
            .filter_map(|field| {
                let text = parsed.text(field.name)?;
                (!text.is_empty()).then(|| (field, Zeroizing::new(text.into_owned())))
            })
            .collect();
        if found.is_empty() {
            // A pending device code, an error, a refusal: nothing to keep.
            return Ok(None);
        }
        if parsed
            .text("token_type")
            .is_some_and(|kind| kind.eq_ignore_ascii_case("dpop"))
        {
            return Err(Problem::BoundToken);
        }
        if found.iter().any(|(_, real)| !shape::usable(real)) {
            return Err(Problem::UnusableToken);
        }
        let _one_at_a_time = self.inner.capture.lock().await;
        let mut planned: Vec<(&'static Field, Zeroizing<String>, String, bool)> = Vec::new();
        for (field, real) in found {
            let existing = self.slots().get(&(profile.id, field.role)).cloned();
            let planned_stand_in = match existing {
                Some(stand_in) => (stand_in, false),
                // The system had no random numbers, or the token cannot be copied: either way
                // there is no stand-in to give.
                None => (
                    shape::stand_in_for(&real, field).map_err(|_| Problem::UnusableToken)?,
                    true,
                ),
            };
            planned.push((field, real, planned_stand_in.0, planned_stand_in.1));
        }
        // The credential store first: a token that was not kept is not replaced in the answer.
        for (field, real, stand_in, _) in &planned {
            let role = field.role;
            let (stand_in, real) = (stand_in.clone(), real.clone());
            self.store(move |vault| vault.write(profile, role, &stand_in, &real))
                .await
                .map_err(|_| Problem::StoreUnavailable)?;
        }
        for (field, real, stand_in, is_new) in &planned {
            let slot = (field.role, field.scope);
            // A refresh gives the stand-in a new token without a moment in which it has none; a
            // slot the registry has lost (a forgotten login) is made again.
            let refreshed = !is_new
                && self
                    .inner
                    .registry
                    .set_real(stand_in, SecretValue::new(real.as_str()))
                    == Ok(true);
            if !refreshed {
                self.install(profile, slot, stand_in, real)
                    .map_err(|_| Problem::UnusableToken)?;
            }
            parsed.set_text(field.name, stand_in);
            tracing::info!(
                workspace = %self.inner.workspace,
                profile = profile.id,
                role = field.role.key(),
                new = *is_new,
                "kept a login's token and gave the workspace a stand-in"
            );
        }
        Ok(Some(Bytes::copy_from_slice(&parsed.render())))
    }
}

/// Why a login could not be forgotten completely.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ForgetError {
    /// The credential store did not delete a token.
    #[error("the operating system's credential store did not delete a saved login")]
    Store,
}

/// The answer of one token endpoint, being captured.
struct Capture {
    logins: Logins,
    profile: &'static Profile,
    endpoint: &'static Endpoint,
}

impl AnswerRewriter for Capture {
    fn wants(&mut self, head: &AnswerHead<'_>) -> bool {
        // Only a success answer has tokens; an error answer is the tool's to read.
        if !(200..300).contains(&head.status) || head.status == 204 {
            return false;
        }
        let identity = head
            .content_encoding
            .is_none_or(|e| e.trim().is_empty() || e.trim().eq_ignore_ascii_case("identity"));
        let small = head
            .content_length
            .is_none_or(|n| n <= MAX_EXCHANGE_BODY as u64);
        if TokenBody::reads(head.content_type) && identity && small {
            return true;
        }
        self.logins.notify(self.profile, Problem::UnexpectedAnswer);
        false
    }

    fn rewrite<'a>(
        &'a mut self,
        head: &'a AnswerHead<'a>,
        body: &'a [u8],
    ) -> puddle_proxy::BoxFuture<'a, Option<Bytes>> {
        Box::pin(async move {
            match self
                .logins
                .capture((self.profile, self.endpoint), body, head.content_type)
                .await
            {
                Ok(replaced) => replaced,
                Err(problem) => {
                    self.logins.notify(self.profile, problem);
                    None
                }
            }
        })
    }
}

impl ExchangeRewriter for Logins {
    fn begin(&self, host: &Host, method: &str, path: &str) -> Option<Exchange> {
        if !self.inner.enabled || method != "POST" {
            return None;
        }
        // The host first: most requests on a decrypted host are not to a token endpoint, and
        // only these pay for the path's canonical spelling.
        let mut on_host = self
            .inner
            .routes
            .iter()
            .filter(|route| route.host == *host)
            .peekable();
        on_host.peek()?;
        let path = canonical_path(path);
        let route = on_host.find(|route| route.path == path)?;
        let mut exchange = Exchange::new();
        if let Some(field) = route.endpoint.refresh_field {
            exchange = exchange.swapping(field);
        }
        Some(exchange.answered_by(Box::new(Capture {
            logins: self.clone(),
            profile: route.profile,
            endpoint: route.endpoint,
        })))
    }
}
