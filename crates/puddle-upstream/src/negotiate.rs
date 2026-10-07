// SPDX-License-Identifier: GPL-3.0-or-later
//! Negotiate and NTLM sign-in to a proxy, as a [`ProxyAuth`] over a pluggable token source.
//!
//! This module is the protocol half and is portable: which scheme to speak, how a `407`
//! challenge becomes the next `Proxy-Authorization` value, how many legs, what happens when the
//! proxy refuses. The other half, producing the opaque tokens as the logged-on user, is a
//! [`TokenSource`]: Windows SSPI (`windows/sspi.rs`), later GSSAPI on Linux (T-148 L-2). A
//! source never asks for a password; if the OS has no ticket for the user the session fails.
//!
//! Behaviour (T-026 section 2a, T-033 S7):
//!
//! - **Negotiate is preferred over NTLM** when the proxy offers both.
//! - **Preemptive first leg.** Before any `407` (`offered` empty) a session starts on the scheme
//!   last seen for that proxy, else Negotiate, and its first token goes on the first request:
//!   a Kerberos ticket needs no challenge, and an NTLM Type 1 message saves the bare `407`.
//! - **Several legs on one connection** (NTLM: Type 1, then Type 3 after the challenge).
//! - A Negotiate token the proxy refuses, with only NTLM left on offer, restarts the session on
//!   NTLM once. A second refusal is an error, so a wrong sign-in never loops.
//! - Tokens and challenges are never logged or put in errors, only their scheme and length.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use crate::auth::{AuthError, AuthSession, AuthStep, ProxyAuth};
use crate::hop::ProxyAddr;

/// An HTTP authentication scheme this module speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Package {
    /// SPNEGO: Kerberos when the user has a ticket for the proxy, NTLM otherwise.
    Negotiate,
    /// NTLM alone.
    Ntlm,
}

impl Package {
    /// The scheme word in `Proxy-Authenticate` and `Proxy-Authorization`.
    #[must_use]
    pub fn word(self) -> &'static str {
        match self {
            Self::Negotiate => "Negotiate",
            Self::Ntlm => "NTLM",
        }
    }

    fn from_word(word: &str) -> Option<Self> {
        if word.eq_ignore_ascii_case("negotiate") {
            Some(Self::Negotiate)
        } else if word.eq_ignore_ascii_case("ntlm") {
            Some(Self::Ntlm)
        } else {
            None
        }
    }
}

/// One output of a security context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Leg {
    /// The token to send; empty when the context has nothing more to say.
    pub token: Vec<u8>,
    /// The context is established: no further challenge is expected.
    pub complete: bool,
}

/// A client-side security context for one proxy connection (an SSPI or GSSAPI context).
pub trait SecurityContext: Send + fmt::Debug {
    /// The next leg from the proxy's token (`None` for the first call).
    ///
    /// # Errors
    /// [`AuthError`] when the OS rejects the input or has no credentials.
    fn step(&mut self, input: Option<&[u8]>) -> Result<Leg, AuthError>;
}

/// Opens security contexts as the current user.
pub trait TokenSource: Send + Sync + fmt::Debug {
    /// A fresh context for `package` towards the service `spn` (`HTTP/<proxy host>`).
    ///
    /// # Errors
    /// [`AuthError`] when the package is unavailable or the user has no credentials.
    fn open(&self, package: Package, spn: &str) -> Result<Box<dyn SecurityContext>, AuthError>;
}

/// [`ProxyAuth`] for Negotiate and NTLM over a [`TokenSource`].
#[derive(Debug)]
pub struct NegotiateAuth {
    source: Arc<dyn TokenSource>,
    /// The scheme each proxy last challenged with, so the next connection starts on it.
    learned: Arc<Mutex<HashMap<ProxyAddr, Package>>>,
}

impl NegotiateAuth {
    /// Authentication through `source`.
    #[must_use]
    pub fn new(source: Arc<dyn TokenSource>) -> Self {
        Self {
            source,
            learned: Arc::default(),
        }
    }
}

impl ProxyAuth for NegotiateAuth {
    fn begin(
        &self,
        proxy: &ProxyAddr,
        offered: &[&str],
    ) -> Result<Option<Box<dyn AuthSession>>, AuthError> {
        let package = if offered.is_empty() {
            let learned = self.learned.lock().unwrap_or_else(PoisonError::into_inner);
            learned.get(proxy).copied().unwrap_or(Package::Negotiate)
        } else {
            let known: Vec<Package> = offered
                .iter()
                .filter_map(|w| Package::from_word(w))
                .collect();
            match prefer(&known) {
                Some(package) => package,
                None => return Ok(None),
            }
        };
        let spn = format!("HTTP/{}", proxy.host());
        let context = self.source.open(package, &spn)?;
        Ok(Some(Box::new(Session {
            source: Arc::clone(&self.source),
            learned: Arc::clone(&self.learned),
            proxy: proxy.clone(),
            spn,
            package,
            context,
            legs: 0,
            complete: false,
            tried: vec![package],
        })))
    }
}

fn prefer(known: &[Package]) -> Option<Package> {
    if known.contains(&Package::Negotiate) {
        Some(Package::Negotiate)
    } else if known.contains(&Package::Ntlm) {
        Some(Package::Ntlm)
    } else {
        None
    }
}

struct Session {
    source: Arc<dyn TokenSource>,
    learned: Arc<Mutex<HashMap<ProxyAddr, Package>>>,
    proxy: ProxyAddr,
    spn: String,
    package: Package,
    context: Box<dyn SecurityContext>,
    /// Tokens sent with the current package.
    legs: u32,
    /// The context reported itself established.
    complete: bool,
    /// Packages used so far, so a refusal restarts at most once per package.
    tried: Vec<Package>,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("proxy", &self.proxy)
            .field("package", &self.package)
            .field("legs", &self.legs)
            .finish_non_exhaustive()
    }
}

/// A scheme in a `Proxy-Authenticate` value, with its decoded token when it carries one.
#[derive(Debug, PartialEq, Eq)]
struct Offer {
    package: Package,
    token: Option<Vec<u8>>,
}

/// The schemes this module speaks in a `Proxy-Authenticate` value (one header, or several joined
/// by commas). Unknown schemes are skipped. A token that is not base64 is an error.
fn parse_challenge(value: &str) -> Result<Vec<Offer>, AuthError> {
    let mut offers = Vec::new();
    // Base64 never contains a comma, so a comma always starts the next challenge.
    for part in value.split(',') {
        let mut words = part.split_whitespace();
        let Some(package) = words.next().and_then(Package::from_word) else {
            continue;
        };
        let token = match words.next() {
            None => None,
            Some(text) => Some(STANDARD.decode(text).map_err(|_| {
                AuthError::Failed(format!("malformed {} challenge", package.word()))
            })?),
        };
        offers.push(Offer { package, token });
    }
    Ok(offers)
}

impl Session {
    fn restart(&mut self, package: Package) -> Result<(), AuthError> {
        self.context = self.source.open(package, &self.spn)?;
        self.package = package;
        self.tried.push(package);
        self.legs = 0;
        self.complete = false;
        Ok(())
    }

    fn refused(&self) -> AuthError {
        AuthError::Failed(format!(
            "the proxy refused the {} sign-in",
            self.package.word()
        ))
    }

    /// Picks what to feed the context from the proxy's offers: the token to answer, after
    /// switching package when the proxy asks for another one.
    fn input_from(&mut self, offers: &[Offer]) -> Result<Option<Vec<u8>>, AuthError> {
        if self.legs == 0 && !self.complete {
            // First token for this package. A 407 that names other schemes decides which.
            let wanted = prefer(&offers.iter().map(|o| o.package).collect::<Vec<_>>());
            match wanted {
                None => {
                    return Err(AuthError::Failed(
                        "no supported sign-in scheme offered".into(),
                    ));
                }
                Some(package) if package != self.package => self.restart(package)?,
                Some(_) => {}
            }
        }
        let mine = offers.iter().find(|o| o.package == self.package);
        match mine.and_then(|o| o.token.clone()) {
            Some(token) => Ok(Some(token)),
            None if self.legs == 0 => Ok(None),
            None => {
                // We already sent a token and the proxy asks again without one: refused.
                let fallback = offers
                    .iter()
                    .map(|o| o.package)
                    .find(|p| !self.tried.contains(p));
                match fallback {
                    Some(package) => {
                        self.restart(package)?;
                        Ok(None)
                    }
                    None => Err(self.refused()),
                }
            }
        }
    }
}

impl AuthSession for Session {
    fn step(&mut self, challenge: Option<&str>) -> Result<AuthStep, AuthError> {
        let input = match challenge {
            None => None,
            Some(value) => {
                let offers = parse_challenge(value)?;
                if offers.is_empty() {
                    return Err(AuthError::Failed(
                        "no supported sign-in scheme offered".into(),
                    ));
                }
                if self.complete {
                    return Err(self.refused());
                }
                let mut learned = self.learned.lock().unwrap_or_else(PoisonError::into_inner);
                if let Some(first) = prefer(&offers.iter().map(|o| o.package).collect::<Vec<_>>()) {
                    learned.insert(self.proxy.clone(), first);
                }
                drop(learned);
                self.input_from(&offers)?
            }
        };
        let leg = self.context.step(input.as_deref())?;
        self.complete = leg.complete;
        if leg.token.is_empty() {
            return if leg.complete {
                Ok(AuthStep::Done)
            } else {
                Err(AuthError::Failed(format!(
                    "{} produced no token",
                    self.package.word()
                )))
            };
        }
        self.legs += 1;
        tracing::debug!(
            proxy = %self.proxy,
            scheme = self.package.word(),
            leg = self.legs,
            token_len = leg.token.len(),
            "proxy sign-in leg"
        );
        Ok(AuthStep::Authorization(format!(
            "{} {}",
            self.package.word(),
            STANDARD.encode(&leg.token)
        )))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use proptest::prelude::*;

    use super::*;

    type Log = Arc<Mutex<Vec<(Package, Option<Vec<u8>>)>>>;

    /// How a scripted context behaves.
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    enum Mode {
        /// Type 1, then Type 3 once it sees a challenge.
        #[default]
        Ntlm,
        /// Kerberos-like on Negotiate: complete after the first token.
        OneShot,
        /// Type 1, then complete without a token (a mutual-auth acknowledgement).
        Ack,
        /// Every step fails.
        FailStep,
        /// Every step returns nothing and is not complete.
        Silent,
        /// The source cannot open a context at all.
        FailOpen,
    }

    #[derive(Debug)]
    struct Script {
        package: Package,
        calls: usize,
        log: Log,
        mode: Mode,
    }

    impl SecurityContext for Script {
        fn step(&mut self, input: Option<&[u8]>) -> Result<Leg, AuthError> {
            self.calls += 1;
            self.log
                .lock()
                .unwrap()
                .push((self.package, input.map(<[u8]>::to_vec)));
            let leg = |token: &[u8], complete| Leg {
                token: token.to_vec(),
                complete,
            };
            match (self.calls, self.mode) {
                (_, Mode::FailStep) => Err(AuthError::Failed("scripted failure".into())),
                (_, Mode::Silent) => Ok(leg(b"", false)),
                (1, Mode::OneShot) if self.package == Package::Negotiate => Ok(leg(b"krb", true)),
                (1, _) => Ok(leg(b"type1", false)),
                (2, Mode::Ack) => Ok(leg(b"", true)),
                (2, _) => Ok(leg(b"type3", true)),
                _ => Err(AuthError::Failed("scripted: too many calls".into())),
            }
        }
    }

    #[derive(Debug, Default)]
    struct Source {
        opened: AtomicUsize,
        mode: Mode,
        log: Log,
    }

    impl TokenSource for Source {
        fn open(&self, package: Package, spn: &str) -> Result<Box<dyn SecurityContext>, AuthError> {
            assert_eq!(spn, "HTTP/proxy.corp");
            if self.mode == Mode::FailOpen {
                return Err(AuthError::Failed("no credentials".into()));
            }
            self.opened.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(Script {
                package,
                calls: 0,
                log: Arc::clone(&self.log),
                mode: self.mode,
            }))
        }
    }

    fn auth(source: Source) -> (NegotiateAuth, Arc<Source>) {
        let source = Arc::new(source);
        (
            NegotiateAuth::new(Arc::clone(&source) as Arc<dyn TokenSource>),
            source,
        )
    }

    fn proxy() -> ProxyAddr {
        ProxyAddr::new("Proxy.Corp", 8080)
    }

    fn header(scheme: &str, token: &[u8]) -> String {
        format!("{scheme} {}", STANDARD.encode(token))
    }

    fn authorization(step: AuthStep) -> String {
        match step {
            AuthStep::Authorization(value) => value,
            other => panic!("expected a header, got {other:?}"),
        }
    }

    #[test]
    fn a_preemptive_negotiate_token_needs_no_challenge() {
        let (auth, _) = auth(Source {
            mode: Mode::OneShot,
            ..Source::default()
        });
        let mut session = auth.begin(&proxy(), &[]).unwrap().unwrap();
        assert_eq!(
            authorization(session.step(None).unwrap()),
            header("Negotiate", b"krb")
        );
    }

    #[test]
    fn ntlm_runs_three_legs() {
        let (auth, source) = auth(Source::default());
        let mut session = auth.begin(&proxy(), &["NTLM"]).unwrap().unwrap();
        assert_eq!(
            authorization(session.step(Some("NTLM")).unwrap()),
            header("NTLM", b"type1")
        );
        let type2 = header("NTLM", b"type2");
        assert_eq!(
            authorization(session.step(Some(&type2)).unwrap()),
            header("NTLM", b"type3")
        );
        let log = source.log.lock().unwrap();
        assert_eq!(log[0], (Package::Ntlm, None));
        assert_eq!(log[1], (Package::Ntlm, Some(b"type2".to_vec())));
    }

    #[test]
    fn negotiate_is_preferred_and_the_first_call_may_be_the_bare_407() {
        let (auth, source) = auth(Source::default());
        let mut session = auth
            .begin(&proxy(), &["NTLM", "Negotiate"])
            .unwrap()
            .unwrap();
        let sent = authorization(session.step(Some("Negotiate, NTLM")).unwrap());
        assert!(sent.starts_with("Negotiate "));
        assert_eq!(source.opened.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn the_scheme_the_407_names_decides_over_the_default() {
        // A preemptive session starts on Negotiate; the proxy then only speaks NTLM.
        let (auth, source) = auth(Source::default());
        let mut session = auth.begin(&proxy(), &[]).unwrap().unwrap();
        let sent = authorization(session.step(Some("NTLM")).unwrap());
        assert_eq!(sent, header("NTLM", b"type1"));
        assert_eq!(source.opened.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn a_refused_negotiate_token_restarts_on_ntlm_once() {
        let (auth, _) = auth(Source::default());
        let mut session = auth.begin(&proxy(), &[]).unwrap().unwrap();
        assert!(authorization(session.step(None).unwrap()).starts_with("Negotiate "));
        // 407 again, bare: the proxy did not take the token, and still offers NTLM.
        let sent = authorization(session.step(Some("Negotiate, NTLM")).unwrap());
        assert_eq!(sent, header("NTLM", b"type1"));
        // Refused again with nothing new to try.
        let err = session.step(Some("Negotiate, NTLM")).unwrap_err();
        assert!(err.to_string().contains("refused"), "{err}");
    }

    #[test]
    fn a_refusal_with_nothing_left_is_an_error_not_a_loop() {
        let (auth, _) = auth(Source {
            mode: Mode::OneShot,
            ..Source::default()
        });
        let mut session = auth.begin(&proxy(), &[]).unwrap().unwrap();
        session.step(None).unwrap();
        assert!(
            session
                .step(Some("Negotiate"))
                .unwrap_err()
                .to_string()
                .contains("refused")
        );
    }

    #[test]
    fn an_established_context_with_nothing_to_send_is_done() {
        let (auth, _) = auth(Source {
            mode: Mode::Ack,
            ..Source::default()
        });
        let mut session = auth.begin(&proxy(), &["NTLM"]).unwrap().unwrap();
        session.step(Some("NTLM")).unwrap();
        let type2 = header("NTLM", b"t2");
        assert_eq!(session.step(Some(&type2)).unwrap(), AuthStep::Done);
        // A 407 after completion is a refusal.
        assert!(session.step(Some(&type2)).is_err());
    }

    #[test]
    fn schemes_this_module_cannot_speak_are_not_offered_a_session() {
        let (auth, source) = auth(Source::default());
        assert!(auth.begin(&proxy(), &["Basic"]).unwrap().is_none());
        assert!(
            auth.begin(&proxy(), &["Basic", "Digest"])
                .unwrap()
                .is_none()
        );
        assert_eq!(source.opened.load(Ordering::SeqCst), 0);
        assert!(auth.begin(&proxy(), &["negotiate"]).unwrap().is_some());
    }

    #[test]
    fn a_challenge_without_a_known_scheme_is_an_error() {
        let (auth, _) = auth(Source::default());
        let mut session = auth.begin(&proxy(), &[]).unwrap().unwrap();
        assert!(session.step(Some("Basic realm=\"corp\"")).is_err());
    }

    #[test]
    fn a_challenge_that_is_not_base64_is_an_error_without_the_text() {
        let (auth, _) = auth(Source::default());
        let mut session = auth.begin(&proxy(), &["NTLM"]).unwrap().unwrap();
        session.step(Some("NTLM")).unwrap();
        let err = session.step(Some("NTLM not*base64!")).unwrap_err();
        assert!(!err.to_string().contains("base64!"), "{err}");
    }

    #[test]
    fn the_scheme_a_proxy_asked_for_starts_the_next_preemptive_session() {
        let (auth, source) = auth(Source::default());
        let mut first = auth.begin(&proxy(), &[]).unwrap().unwrap();
        first.step(Some("NTLM")).unwrap();
        let mut second = auth.begin(&proxy(), &[]).unwrap().unwrap();
        assert_eq!(
            authorization(second.step(None).unwrap()),
            header("NTLM", b"type1")
        );
        assert_eq!(source.log.lock().unwrap().last().unwrap().0, Package::Ntlm);
    }

    #[test]
    fn a_source_that_cannot_open_fails_begin_and_never_prompts() {
        let (auth, _) = auth(Source {
            mode: Mode::FailOpen,
            ..Source::default()
        });
        assert!(auth.begin(&proxy(), &[]).is_err());
        assert!(auth.begin(&proxy(), &["NTLM"]).is_err());
    }

    #[test]
    fn a_context_error_is_passed_up() {
        let (auth, _) = auth(Source {
            mode: Mode::FailStep,
            ..Source::default()
        });
        let mut session = auth.begin(&proxy(), &["NTLM"]).unwrap().unwrap();
        assert!(session.step(Some("NTLM")).is_err());
    }

    #[test]
    fn a_context_that_is_neither_done_nor_has_a_token_is_an_error() {
        let (auth, _) = auth(Source {
            mode: Mode::Silent,
            ..Source::default()
        });
        let mut session = auth.begin(&proxy(), &["NTLM"]).unwrap().unwrap();
        assert!(
            session
                .step(Some("NTLM"))
                .unwrap_err()
                .to_string()
                .contains("no token")
        );
    }

    #[test]
    fn tokens_stay_out_of_debug_output() {
        let (auth, _) = auth(Source::default());
        let mut session = auth.begin(&proxy(), &["NTLM"]).unwrap().unwrap();
        session.step(Some("NTLM")).unwrap();
        let shown = format!("{session:?} {auth:?}");
        assert!(!shown.contains("type1") && !shown.contains("dHlwZTE"));
    }

    #[test]
    fn parsing_reads_tokens_and_skips_other_schemes() {
        let value = format!(
            "Basic realm=\"x\", NTLM, Negotiate {}",
            STANDARD.encode(b"abc")
        );
        let offers = parse_challenge(&value).unwrap();
        assert_eq!(
            offers,
            vec![
                Offer {
                    package: Package::Ntlm,
                    token: None
                },
                Offer {
                    package: Package::Negotiate,
                    token: Some(b"abc".to_vec())
                },
            ]
        );
        assert_eq!(parse_challenge("").unwrap().len(), 0);
        assert_eq!(Package::Ntlm.word(), "NTLM");
    }

    proptest! {
        #[test]
        fn parsing_never_panics(text in ".*") {
            let _ = parse_challenge(&text);
        }

        #[test]
        fn a_token_round_trips_through_a_header(bytes in proptest::collection::vec(any::<u8>(), 1..200)) {
            let offers = parse_challenge(&header("NTLM", &bytes)).unwrap();
            prop_assert_eq!(offers.len(), 1);
            prop_assert_eq!(offers[0].token.as_deref(), Some(bytes.as_slice()));
        }
    }
}
