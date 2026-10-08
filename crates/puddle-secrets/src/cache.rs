// SPDX-License-Identifier: GPL-3.0-or-later
//! An in-memory cache with expiry, single flight and a stale grace. Nothing is written to disk.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use tokio::sync::broadcast;
use tokio::time::Instant;

use crate::error::SourceError;
use crate::sources::{Credential, Fetch};
use crate::spec::SourceSpec;

/// How long a value of one source kind is trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ttl {
    /// The value is served as is for this long; `None` means until it is invalidated.
    pub fresh: Option<Duration>,
    /// After `fresh`, a failed refresh keeps serving the old value this much longer.
    pub grace: Duration,
}

/// The expiry per source kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ttls {
    /// `gh`: 55 minutes, like the Docker sandboxes refresh.
    pub gh: Ttl,
    /// Git credential helpers: 30 minutes.
    pub git_credential: Ttl,
    /// Pasted tokens: until the user changes or removes them.
    pub stored: Ttl,
}

impl Default for Ttls {
    fn default() -> Self {
        let grace = Duration::from_mins(5);
        Self {
            gh: Ttl {
                fresh: Some(Duration::from_mins(55)),
                grace,
            },
            git_credential: Ttl {
                fresh: Some(Duration::from_mins(30)),
                grace,
            },
            stored: Ttl {
                fresh: None,
                grace: Duration::ZERO,
            },
        }
    }
}

impl Ttls {
    fn for_spec(&self, spec: &SourceSpec) -> Ttl {
        match spec {
            SourceSpec::Gh { .. } => self.gh,
            SourceSpec::GitCredential { .. } => self.git_credential,
            SourceSpec::Stored { .. } => self.stored,
        }
    }
}

/// A source needs the user to sign in. The proxy's 502 and the UI's "Sign in" notice come from
/// this; it names the source and nothing secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignInNeeded {
    /// The source that could not supply its secret.
    pub source: SourceSpec,
}

struct Held {
    credential: Credential,
    /// Past this the value is refreshed; `None` = never.
    refresh_at: Option<Instant>,
    /// Past this the old value is never served again; `None` = never.
    dead_at: Option<Instant>,
}

type Slot = Arc<tokio::sync::Mutex<Option<Held>>>;

/// Caches what a [`Fetch`] returns. One lookup per source at a time (a burst of requests is one
/// spawn); a refresh that fails keeps the old value until its grace ends, then fails.
pub struct SecretCache<F> {
    fetcher: F,
    ttls: Ttls,
    slots: Mutex<HashMap<SourceSpec, Slot>>,
    events: broadcast::Sender<SignInNeeded>,
}

/// A credential should be renewed this long before its source says it ends.
const RENEW_EARLY: Duration = Duration::from_mins(5);

impl<F: Fetch> SecretCache<F> {
    /// A cache over `fetcher` with the default expiry.
    pub fn new(fetcher: F) -> Self {
        Self::with_ttls(fetcher, Ttls::default())
    }

    /// A cache over `fetcher` with `ttls`.
    pub fn with_ttls(fetcher: F, ttls: Ttls) -> Self {
        let (events, _) = broadcast::channel(16);
        Self {
            fetcher,
            ttls,
            slots: Mutex::new(HashMap::new()),
            events,
        }
    }

    /// Sign-in notices, one per failed read that needs the user.
    pub fn subscribe(&self) -> broadcast::Receiver<SignInNeeded> {
        self.events.subscribe()
    }

    /// Drops what is held for `spec` (the user changed or removed it, or signed in).
    pub fn invalidate(&self, spec: &SourceSpec) {
        self.slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(spec);
    }

    /// The credential `spec` names: from the cache while fresh, else read again.
    ///
    /// # Errors
    /// The source's [`SourceError`] when it cannot supply a value and no earlier one is still
    /// allowed.
    pub async fn get(&self, spec: &SourceSpec) -> Result<Credential, SourceError> {
        let slot = {
            let mut slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
            Arc::clone(slots.entry(spec.clone()).or_default())
        };
        let mut held = slot.lock().await;
        let now = Instant::now();
        if let Some(h) = held.as_ref()
            && h.refresh_at.is_none_or(|at| now < at)
        {
            return Ok(h.credential.clone());
        }
        match self.fetcher.fetch(spec).await {
            Ok(fetched) => {
                let ttl = self.ttls.for_spec(spec);
                let mut refresh_at = ttl.fresh.map(|d| now + d);
                let mut dead_at = refresh_at.map(|at| at + ttl.grace);
                if let Some(valid) = fetched.valid_for {
                    let renew = now + valid.saturating_sub(RENEW_EARLY);
                    refresh_at = Some(refresh_at.map_or(renew, |at| at.min(renew)));
                    let end = now + valid;
                    dead_at = Some(dead_at.map_or(end, |at| at.min(end)));
                }
                let credential = fetched.credential.clone();
                *held = Some(Held {
                    credential: fetched.credential,
                    refresh_at,
                    dead_at,
                });
                Ok(credential)
            }
            Err(err) => {
                if let Some(h) = held.as_ref()
                    && h.dead_at.is_none_or(|at| now < at)
                {
                    tracing::warn!(source = %spec.describe(), "refresh failed, serving the earlier value");
                    return Ok(h.credential.clone());
                }
                *held = None;
                if err.needs_sign_in() {
                    let _ = self.events.send(SignInNeeded {
                        source: spec.clone(),
                    });
                }
                Err(err)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::future::Future;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::name::{AccountName, HostName, StoredId};
    use crate::secret::Secret;
    use crate::sources::Fetched;
    use crate::spec::TokenScope;

    /// Answers from a script, one entry per call, and counts the calls.
    struct Script {
        answers: Mutex<VecDeque<Result<Option<Duration>, SourceError>>>,
        calls: AtomicUsize,
    }

    impl Script {
        fn new(answers: Vec<Result<Option<Duration>, SourceError>>) -> Self {
            Self {
                answers: Mutex::new(answers.into()),
                calls: AtomicUsize::new(0),
            }
        }
        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl Fetch for &Script {
        fn fetch(
            &self,
            _: &SourceSpec,
        ) -> impl Future<Output = Result<Fetched, SourceError>> + Send {
            let n = self.calls.fetch_add(1, Ordering::SeqCst);
            let next = self
                .answers
                .lock()
                .unwrap()
                .pop_front()
                .expect("scripted answer");
            std::future::ready(next.map(|valid_for| Fetched {
                credential: Credential {
                    username: None,
                    secret: Arc::new(Secret::new(format!("v{n}"))),
                },
                valid_for,
            }))
        }
    }

    fn gh() -> SourceSpec {
        SourceSpec::Gh {
            host: HostName::new("github.com").unwrap(),
            account: AccountName::new("me").unwrap(),
        }
    }

    const MIN: Duration = Duration::from_secs(60);

    async fn value(cache: &SecretCache<&Script>, spec: &SourceSpec) -> Result<String, SourceError> {
        cache.get(spec).await.map(|c| c.secret.expose().to_owned())
    }

    #[tokio::test(start_paused = true)]
    async fn serves_from_memory_until_the_ttl_then_reads_again() {
        let script = Script::new(vec![Ok(None), Ok(None)]);
        let cache = SecretCache::new(&script);
        assert_eq!(value(&cache, &gh()).await.unwrap(), "v0");
        tokio::time::advance(54 * MIN).await;
        assert_eq!(value(&cache, &gh()).await.unwrap(), "v0");
        assert_eq!(script.calls(), 1);
        tokio::time::advance(2 * MIN).await;
        assert_eq!(value(&cache, &gh()).await.unwrap(), "v1");
        assert_eq!(script.calls(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_refresh_serves_the_old_value_until_the_grace_ends() {
        let script = Script::new(vec![
            Ok(None),
            Err(SourceError::Timeout(crate::Tool::Gh)),
            Err(SourceError::NotSignedIn),
        ]);
        let cache = SecretCache::new(&script);
        let mut events = cache.subscribe();
        assert_eq!(value(&cache, &gh()).await.unwrap(), "v0");
        tokio::time::advance(56 * MIN).await;
        assert_eq!(
            value(&cache, &gh()).await.unwrap(),
            "v0",
            "refresh failed, still in grace"
        );
        assert!(
            events.try_recv().is_err(),
            "no notice while an old value still works"
        );
        tokio::time::advance(5 * MIN).await;
        assert_eq!(
            value(&cache, &gh()).await.unwrap_err(),
            SourceError::NotSignedIn
        );
        assert_eq!(events.try_recv().unwrap().source, gh());
    }

    #[tokio::test(start_paused = true)]
    async fn a_token_that_expires_early_is_renewed_early() {
        let script = Script::new(vec![Ok(Some(20 * MIN)), Ok(Some(20 * MIN))]);
        let cache = SecretCache::new(&script);
        assert_eq!(value(&cache, &gh()).await.unwrap(), "v0");
        tokio::time::advance(14 * MIN).await;
        assert_eq!(value(&cache, &gh()).await.unwrap(), "v0");
        tokio::time::advance(2 * MIN).await;
        assert_eq!(value(&cache, &gh()).await.unwrap(), "v1");
    }

    #[tokio::test(start_paused = true)]
    async fn a_token_past_its_end_is_never_served_after_a_failed_refresh() {
        let script = Script::new(vec![
            Ok(Some(10 * MIN)),
            Err(SourceError::Timeout(crate::Tool::Git)),
        ]);
        let cache = SecretCache::new(&script);
        assert_eq!(value(&cache, &gh()).await.unwrap(), "v0");
        tokio::time::advance(11 * MIN).await;
        assert!(value(&cache, &gh()).await.is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn stored_values_never_expire_and_invalidate_drops_them() {
        let spec = SourceSpec::Stored {
            id: StoredId::new("a").unwrap(),
            scope: TokenScope {
                host: HostName::new("github.com").unwrap(),
                org: None,
            },
        };
        let script = Script::new(vec![Ok(None), Ok(None)]);
        let cache = SecretCache::new(&script);
        assert_eq!(value(&cache, &spec).await.unwrap(), "v0");
        tokio::time::advance(Duration::from_hours(720)).await;
        assert_eq!(value(&cache, &spec).await.unwrap(), "v0");
        cache.invalidate(&spec);
        assert_eq!(value(&cache, &spec).await.unwrap(), "v1");
    }

    #[tokio::test(start_paused = true)]
    async fn sources_are_cached_separately() {
        let other = SourceSpec::Gh {
            host: HostName::new("github.com").unwrap(),
            account: AccountName::new("you").unwrap(),
        };
        let script = Script::new(vec![Ok(None), Ok(None)]);
        let cache = SecretCache::new(&script);
        assert_eq!(value(&cache, &gh()).await.unwrap(), "v0");
        assert_eq!(value(&cache, &other).await.unwrap(), "v1");
        assert_eq!(value(&cache, &gh()).await.unwrap(), "v0");
    }
}
