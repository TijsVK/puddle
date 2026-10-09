// SPDX-License-Identifier: GPL-3.0-or-later
//! The lists: which credentials to read, the in-memory cache, one read at a time per credential,
//! and the back-off when a host limits us.
//!
//! Nothing here runs on its own: a list is read when a screen asks for it, never on a timer, and
//! a list that could not be refreshed is served from the last good read with the reason beside
//! it. The lists live in memory only and go with the process.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use futures_util::future::{BoxFuture, join_all};
use puddle_secrets::{Credential, Fetch, SecretCache, SourceError, SourceSpec};
use puddle_store::{Clock, CredentialBinding, Identity, IdentityId};
use tokio::sync::{Mutex as AsyncMutex, Semaphore};

use crate::api::{Api, ApiReply, Authorization};
use crate::exchange::{Exchange, Remedy};
use crate::model::{ListState, Listed, Note, NoteKind, Problem, ProblemKind, Profile, SourceList};
use crate::{azure, github, limits};

/// Where the engine gets a token: the proxy's shared cache of secrets in the host.
pub trait Secrets: Send + Sync {
    /// The credential for `spec`, or why not. Never asks the user anything.
    fn get<'a>(&'a self, spec: &'a SourceSpec) -> BoxFuture<'a, Result<Credential, SourceError>>;

    /// Forgets what is cached for `spec`, so the next read asks its source again.
    fn invalidate(&self, spec: &SourceSpec);
}

impl<F: Fetch + 'static> Secrets for SecretCache<F> {
    fn get<'a>(&'a self, spec: &'a SourceSpec) -> BoxFuture<'a, Result<Credential, SourceError>> {
        Box::pin(SecretCache::get(self, spec))
    }

    fn invalidate(&self, spec: &SourceSpec) {
        SecretCache::invalidate(self, spec);
    }
}

/// Timings of the cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    /// How long a list counts as current without asking the host again.
    pub fresh_for: Duration,
    /// How long after a failed read a plain request does not try again (a refresh does).
    pub retry_after_failure: Duration,
    /// How soon after a read a refresh is answered from it instead of asking again.
    pub min_reload_gap: Duration,
    /// The time one credential's read may take, pages and all.
    pub deadline: Duration,
    /// Reads running at once, across credentials.
    pub concurrent_reads: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            fresh_for: Duration::from_mins(10),
            retry_after_failure: Duration::from_secs(30),
            min_reload_gap: Duration::from_secs(10),
            deadline: Duration::from_secs(25),
            concurrent_reads: 4,
        }
    }
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// Whether to ask the hosts again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Freshness {
    /// Serve what is cached; read what is missing or older than [`Config::fresh_for`].
    Cached,
    /// Read again now (a "Refresh"), unless the list was read a moment ago or the host said to
    /// wait.
    Reload,
}

/// What to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Read {
    /// Only this identity's credentials; `None` for every identity's.
    pub only: Option<IdentityId>,
    /// Whether to ask the hosts again.
    pub freshness: Freshness,
}

/// A profile read: what was found, and why the rest was not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileRead {
    /// What the host said (empty when it could not be asked).
    pub profile: Profile,
    /// Why the profile could not be read.
    pub problem: Option<Problem>,
}

/// One thing to read: a credential and, on Azure DevOps, an organisation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Target {
    source: SourceSpec,
    organisation: Option<String>,
}

/// What to do about one credential of one identity.
enum Plan {
    Read(Target),
    Cannot(Problem),
}

/// Whose list a row is.
struct Meta {
    identity: IdentityId,
    credential: usize,
    host: String,
    organisation: Option<String>,
}

/// A [`Plan`] with its cache slot.
enum Resolved {
    Read(Arc<Slot>),
    Cannot(Problem),
}

#[derive(Default)]
struct Entry {
    repos: Arc<[crate::model::Repository]>,
    notes: Vec<Note>,
    loaded_at: Option<u64>,
    failed_at: Option<u64>,
    problem: Option<Problem>,
    blocked_until: Option<u64>,
    strikes: u32,
    /// Counts finished reads, so a caller that waited its turn can see another one finished.
    generation: u64,
}

struct Slot {
    target: Target,
    /// Held for the whole of a read: one read per credential at a time.
    turn: AsyncMutex<()>,
    entry: Mutex<Entry>,
}

impl Slot {
    fn new(target: Target) -> Self {
        Self {
            target,
            turn: AsyncMutex::new(()),
            entry: Mutex::new(Entry::default()),
        }
    }

    fn entry(&self) -> MutexGuard<'_, Entry> {
        self.entry.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Which API a host is.
enum Kind {
    GitHub(github::Endpoint),
    Azure,
}

fn kind_of(host: &str, source: &SourceSpec) -> Result<Kind, Problem> {
    let host = host.to_ascii_lowercase();
    let via_gh = matches!(source, SourceSpec::Gh { .. });
    if host == azure::HOST {
        if via_gh {
            return Err(Problem::new(
                ProblemKind::Unsupported,
                "the GitHub CLI signs in to GitHub hosts, not to Azure DevOps; use Git Credential \
                 Manager or a pasted token",
            ));
        }
        return Ok(Kind::Azure);
    }
    github::endpoint(&host, via_gh)
        .map(Kind::GitHub)
        .ok_or_else(|| unsupported(&host))
}

fn unsupported(host: &str) -> Problem {
    Problem::new(
        ProblemKind::Unsupported,
        format!(
            "puddle lists repositories on GitHub and Azure DevOps; {host} is neither: enter the \
             address of its repository in the create form"
        ),
    )
}

/// The organisation a credential's own source is for, lower case: the one a pasted token belongs
/// to, the first segment of the path a Git credential is for.
fn source_organisation(source: &SourceSpec) -> Option<String> {
    match source {
        SourceSpec::Stored { scope, .. } => {
            scope.org.as_ref().map(|o| o.as_str().to_ascii_lowercase())
        }
        SourceSpec::GitCredential { path, .. } => {
            path.as_str().split('/').next().map(str::to_ascii_lowercase)
        }
        _ => None,
    }
}

/// The Azure DevOps organisations a credential names: the one its source is for and, unless it is a
/// pasted token (which belongs to one organisation), those it covers.
fn azure_organisations(binding: &CredentialBinding) -> BTreeSet<String> {
    let mut orgs: BTreeSet<String> = match &binding.source {
        SourceSpec::Stored { .. } => BTreeSet::new(),
        _ => binding
            .covers
            .owners
            .iter()
            .map(|o| o.as_str().to_owned())
            .collect(),
    };
    orgs.extend(source_organisation(&binding.source));
    orgs
}

fn plan(identities: &[Identity], only: Option<IdentityId>) -> Vec<(Meta, Plan)> {
    let mut rows = Vec::new();
    for identity in identities
        .iter()
        .filter(|i| only.is_none_or(|id| id == i.id))
    {
        for (credential, binding) in identity.credentials.iter().enumerate() {
            let host = binding.host.as_str().to_ascii_lowercase();
            let row = |organisation: Option<String>, plan: Plan| {
                (
                    Meta {
                        identity: identity.id,
                        credential,
                        host: host.clone(),
                        organisation,
                    },
                    plan,
                )
            };
            let scope = binding.source.scope();
            if !scope.host.as_str().eq_ignore_ascii_case(&host) {
                rows.push(row(
                    None,
                    Plan::Cannot(Problem::new(
                        ProblemKind::WrongTarget,
                        format!(
                            "this credential is for {}, not {host}; puddle does not send it there: edit \
                             the credential so its source and its host agree",
                            scope.host
                        ),
                    )),
                ));
                continue;
            }
            match kind_of(&host, &binding.source) {
                Err(problem) => rows.push(row(None, Plan::Cannot(problem))),
                Ok(Kind::GitHub(_)) => rows.push(row(
                    None,
                    Plan::Read(Target {
                        source: binding.source.clone(),
                        organisation: None,
                    }),
                )),
                Ok(Kind::Azure) => {
                    let orgs = azure_organisations(binding);
                    if orgs.is_empty() {
                        rows.push(row(None, Plan::Cannot(organisation_needed())));
                    }
                    for org in orgs {
                        rows.push(row(
                            Some(org.clone()),
                            Plan::Read(Target {
                                source: binding.source.clone(),
                                organisation: Some(org),
                            }),
                        ));
                    }
                }
            }
        }
    }
    rows
}

fn organisation_needed() -> Problem {
    Problem::new(
        ProblemKind::OrganisationNeeded,
        "Azure DevOps shows the organisations of an account only to a Microsoft Entra sign-in, \
         and puddle lists the organisations a credential names; add the organisation to what \
         this credential covers",
    )
}

/// What a list says about itself whatever the host answered.
fn standing_notes(source: &SourceSpec, kind: &Kind) -> Vec<Note> {
    if matches!(kind, Kind::GitHub(_)) && !matches!(source, SourceSpec::Stored { .. }) {
        return vec![Note::new(
            NoteKind::OrganisationsMayBeHidden,
            "organisations that restrict third-party apps or require single sign-on can be \
             missing until you approve this sign-in for them on GitHub",
        )];
    }
    Vec::new()
}

/// The lists. Cheap to share behind an [`Arc`].
pub struct Repos {
    api: Arc<dyn Api>,
    secrets: Arc<dyn Secrets>,
    clock: Arc<dyn Clock>,
    config: Config,
    slots: Mutex<HashMap<Target, Arc<Slot>>>,
    reads: Semaphore,
}

impl std::fmt::Debug for Repos {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Repos").finish_non_exhaustive()
    }
}

impl Repos {
    /// Lists read through `api`, with tokens from `secrets` and time from `clock`.
    #[must_use]
    pub fn new(api: Arc<dyn Api>, secrets: Arc<dyn Secrets>, clock: Arc<dyn Clock>) -> Self {
        Self::with_config(api, secrets, clock, Config::default())
    }

    /// As [`Repos::new`] with other timings.
    #[must_use]
    pub fn with_config(
        api: Arc<dyn Api>,
        secrets: Arc<dyn Secrets>,
        clock: Arc<dyn Clock>,
        config: Config,
    ) -> Self {
        Self {
            api,
            secrets,
            clock,
            reads: Semaphore::new(config.concurrent_reads.max(1)),
            config,
            slots: Mutex::new(HashMap::new()),
        }
    }

    fn slots(&self) -> MutexGuard<'_, HashMap<Target, Arc<Slot>>> {
        self.slots.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn slot(&self, target: Target) -> Arc<Slot> {
        let mut slots = self.slots();
        let slot = slots
            .entry(target)
            .or_insert_with_key(|target| Arc::new(Slot::new(target.clone())));
        Arc::clone(slot)
    }

    /// The lists of `identities`' credentials (one per credential, one per organisation on Azure
    /// DevOps), each with how current it is and why it could not be read. `read` says which
    /// identity and whether to ask the hosts again.
    ///
    /// Lists nobody refers to any more (an identity or credential that changed or went) are
    /// forgotten here, so pass every identity, with `read.only` to narrow what is read and
    /// returned.
    pub async fn lists(&self, identities: &[Identity], read: Read) -> Vec<SourceList> {
        let everything = plan(identities, None);
        let wanted: HashSet<&Target> = everything
            .iter()
            .filter_map(|(_, plan)| match plan {
                Plan::Read(target) => Some(target),
                Plan::Cannot(_) => None,
            })
            .collect();
        self.slots().retain(|target, _| wanted.contains(target));

        let rows = if read.only.is_some() {
            plan(identities, read.only)
        } else {
            everything
        };
        let resolved: Vec<(Meta, Resolved)> = rows
            .into_iter()
            .map(|(meta, plan)| {
                let resolved = match plan {
                    Plan::Cannot(problem) => Resolved::Cannot(problem),
                    Plan::Read(target) => Resolved::Read(self.slot(target)),
                };
                (meta, resolved)
            })
            .collect();
        let mut distinct: Vec<&Arc<Slot>> = Vec::new();
        for (_, resolved) in &resolved {
            if let Resolved::Read(slot) = resolved
                && !distinct.iter().any(|seen| Arc::ptr_eq(seen, slot))
            {
                distinct.push(slot);
            }
        }
        let force = read.freshness == Freshness::Reload;
        join_all(distinct.iter().map(|slot| self.refresh(slot, force))).await;

        let now = self.clock.now_ms();
        resolved
            .into_iter()
            .map(|(meta, resolved)| snapshot(meta, &resolved, now))
            .collect()
    }

    fn wants_read(&self, entry: &Entry, now: u64, force: bool) -> bool {
        if entry.blocked_until.is_some_and(|until| until > now) {
            return false;
        }
        if let Some(loaded) = entry.loaded_at {
            let age = now.saturating_sub(loaded);
            if force {
                return age >= millis(self.config.min_reload_gap);
            }
            if age < millis(self.config.fresh_for) {
                return false;
            }
        }
        let recently_failed = entry
            .failed_at
            .is_some_and(|at| now.saturating_sub(at) < millis(self.config.retry_after_failure));
        force || !recently_failed
    }

    async fn refresh(&self, slot: &Slot, force: bool) {
        let seen = slot.entry().generation;
        let _turn = slot.turn.lock().await;
        let strikes = {
            let entry = slot.entry();
            // Another caller read it while this one waited its turn.
            if entry.generation != seen || !self.wants_read(&entry, self.clock.now_ms(), force) {
                return;
            }
            entry.strikes
        };
        let outcome = {
            let _permit = self.reads.acquire().await;
            match tokio::time::timeout(self.config.deadline, self.read(&slot.target, strikes)).await
            {
                Ok(outcome) => outcome,
                Err(_) => Err(self.too_slow()),
            }
        };
        let now = self.clock.now_ms();
        let mut entry = slot.entry();
        entry.generation += 1;
        match outcome {
            Ok(listed) => entry.succeed(listed, now),
            Err(problem) => entry.fail(problem, now, &slot.target),
        }
    }

    fn too_slow(&self) -> Problem {
        Problem::unreachable(format!(
            "no answer within {} seconds",
            self.config.deadline.as_secs()
        ))
    }

    /// One read of one credential's list.
    async fn read(&self, target: &Target, strikes: u32) -> Result<Listed, Problem> {
        let kind = kind_of(target.source.scope().host.as_str(), &target.source)?;
        let credential = self
            .secrets
            .get(&target.source)
            .await
            .map_err(|err| Problem::from_source(&err))?;
        let stored = matches!(target.source, SourceSpec::Stored { .. });
        let result = match &kind {
            Kind::GitHub(endpoint) => {
                let exchange = self.exchange("GitHub", &target.source, limits::github, strikes);
                github::list(
                    &exchange,
                    endpoint,
                    &Authorization::Bearer(credential.secret),
                )
                .await
            }
            Kind::Azure => {
                let organisation = target.organisation.clone().unwrap_or_default();
                let mut exchange =
                    self.exchange("Azure DevOps", &target.source, limits::azure, strikes);
                exchange.missing = format!("organisation {organisation}");
                let authorization = azure::authorization(credential.secret);
                azure::list(&exchange, &organisation, &authorization).await
            }
        };
        if matches!(&result, Err(p) if p.kind == ProblemKind::TokenRejected) && !stored {
            // The host says the token is bad: the cached copy must not be served again.
            self.secrets.invalidate(&target.source);
        }
        let mut listed = result?;
        listed.notes.extend(standing_notes(&target.source, &kind));
        Ok(listed)
    }

    fn exchange(
        &self,
        who: &'static str,
        source: &SourceSpec,
        judge: fn(&ApiReply, u64, u32) -> limits::Verdict,
        strikes: u32,
    ) -> Exchange<'_> {
        Exchange {
            api: self.api.as_ref(),
            clock: self.clock.as_ref(),
            strikes,
            who,
            remedy: if matches!(source, SourceSpec::Stored { .. }) {
                Remedy::NewToken
            } else {
                Remedy::SignIn
            },
            judge,
            missing: "listing".to_owned(),
        }
    }

    /// Who a credential's account is, to prefill an identity: its author and the organisations to
    /// offer as coverage. Reads from the host (GitHub) or from the credential itself (Azure
    /// DevOps, whose profile only a Microsoft Entra sign-in may read).
    pub async fn profile(&self, source: &SourceSpec) -> ProfileRead {
        match self.read_profile(source).await {
            Ok(profile) => ProfileRead {
                profile,
                problem: None,
            },
            Err(problem) => ProfileRead {
                profile: Profile::default(),
                problem: Some(problem),
            },
        }
    }

    async fn read_profile(&self, source: &SourceSpec) -> Result<Profile, Problem> {
        let kind = kind_of(source.scope().host.as_str(), source)?;
        let endpoint = match &kind {
            Kind::GitHub(endpoint) => endpoint,
            Kind::Azure => return Ok(azure_profile(source)),
        };
        let slot = self.slot(Target {
            source: source.clone(),
            organisation: None,
        });
        let strikes = {
            let entry = slot.entry();
            if let Some(until) = entry
                .blocked_until
                .filter(|until| *until > self.clock.now_ms())
            {
                return Err(limited_until(until));
            }
            entry.strikes
        };
        let credential = self
            .secrets
            .get(source)
            .await
            .map_err(|err| Problem::from_source(&err))?;
        let mut exchange = self.exchange("GitHub", source, limits::github, strikes);
        "account".clone_into(&mut exchange.missing);
        let authorization = Authorization::Bearer(credential.secret);
        let result = match tokio::time::timeout(
            self.config.deadline,
            github::profile(&exchange, endpoint, &authorization),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(self.too_slow()),
        };
        match result {
            Ok(mut profile) => {
                profile.notes.extend(standing_notes(source, &kind));
                Ok(profile)
            }
            Err(problem) => {
                match problem.kind {
                    ProblemKind::RateLimited => {
                        let mut entry = slot.entry();
                        entry.strikes = entry.strikes.saturating_add(1);
                        entry.blocked_until = problem.retry_at;
                    }
                    ProblemKind::TokenRejected if !matches!(source, SourceSpec::Stored { .. }) => {
                        self.secrets.invalidate(source);
                    }
                    _ => {}
                }
                Err(problem)
            }
        }
    }
}

fn limited_until(until: u64) -> Problem {
    Problem {
        retry_at: Some(until),
        ..Problem::new(
            ProblemKind::RateLimited,
            "the host is limiting requests; puddle asks again once it allows",
        )
    }
}

/// An Azure DevOps credential's own answer: the organisation it names, and why the author is not
/// filled in.
fn azure_profile(source: &SourceSpec) -> Profile {
    let organisations = source_organisation(source).into_iter().collect();
    Profile {
        organisations,
        notes: vec![Note::new(
            NoteKind::AuthorUnavailable,
            "Azure DevOps lets only a Microsoft Entra sign-in read an account's profile, and \
             puddle does not read it yet: enter the author yourself",
        )],
        ..Profile::default()
    }
}

impl Entry {
    fn succeed(&mut self, listed: Listed, now: u64) {
        self.repos = listed.repos.into();
        self.notes = listed.notes;
        self.loaded_at = Some(now);
        self.failed_at = None;
        self.problem = None;
        self.strikes = 0;
        self.blocked_until = listed.spent_until.filter(|until| *until > now);
    }

    fn fail(&mut self, problem: Problem, now: u64, target: &Target) {
        self.failed_at = Some(now);
        let host = target.source.scope().host;
        if problem.kind == ProblemKind::RateLimited {
            self.strikes = self.strikes.saturating_add(1);
            self.blocked_until = problem.retry_at;
            tracing::warn!(%host, strikes = self.strikes, retry_at = ?problem.retry_at, "a git host is limiting requests; its repository list waits");
        } else {
            tracing::debug!(%host, kind = ?problem.kind, "a repository list could not be read");
        }
        self.problem = Some(problem);
    }
}

fn snapshot(meta: Meta, resolved: &Resolved, now: u64) -> SourceList {
    let mut list = SourceList {
        identity: meta.identity,
        credential: meta.credential,
        host: meta.host,
        organisation: meta.organisation,
        state: ListState::Unavailable,
        refreshed_at: None,
        retry_at: None,
        problem: None,
        notes: Vec::new(),
        repos: Arc::from([]),
    };
    match resolved {
        Resolved::Cannot(problem) => list.problem = Some(problem.clone()),
        Resolved::Read(slot) => {
            let entry = slot.entry();
            list.state = match (entry.loaded_at, &entry.problem) {
                (Some(_), None) => ListState::Ok,
                (Some(_), Some(_)) => ListState::Stale,
                (None, _) => ListState::Failed,
            };
            list.refreshed_at = entry.loaded_at;
            list.retry_at = entry.blocked_until.filter(|until| *until > now);
            list.problem.clone_from(&entry.problem);
            list.notes.clone_from(&entry.notes);
            if list.retry_at.is_some() && list.problem.is_none() {
                // A good list that cannot be refreshed yet: say why a refresh will wait.
                list.notes.push(Note::new(
                    NoteKind::HostLimitReached,
                    "the host's request limit for this hour is used up, so a refresh waits until it resets",
                ));
            }
            list.repos = Arc::clone(&entry.repos);
        }
    }
    list
}

#[cfg(test)]
mod tests {
    use puddle_secrets::{AccountName, HostName, OrgName, StoredId, TokenScope, UrlPath};

    use super::*;

    #[test]
    fn a_sources_own_organisation_is_the_pasted_tokens_or_the_git_credentials_path_and_no_other_has_one()
     {
        let host = HostName::new("dev.azure.com").unwrap();
        let stored = SourceSpec::Stored {
            id: StoredId::new("tok-1").unwrap(),
            scope: TokenScope {
                host: host.clone(),
                org: Some(OrgName::new("Acme").unwrap()),
            },
        };
        let git = SourceSpec::GitCredential {
            host: host.clone(),
            path: UrlPath::new("Contoso/Fabrikam").unwrap(),
            username: None,
        };
        let gh = SourceSpec::Gh {
            host,
            account: AccountName::new("me").unwrap(),
        };
        assert_eq!(source_organisation(&stored).as_deref(), Some("acme"));
        assert_eq!(source_organisation(&git).as_deref(), Some("contoso"));
        assert_eq!(source_organisation(&gh), None);
    }
}
