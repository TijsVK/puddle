// SPDX-License-Identifier: GPL-3.0-or-later
//! Basic authentication to an upstream proxy from credentials the user configured, and a list
//! that tries several [`ProxyAuth`] implementations in order (Basic after SSPI, say).
//!
//! The credentials are the only ones puddle ever holds for a proxy; they come from settings or
//! the OS credential store, never from a prompt in the proxy path. They are never logged: every
//! `Debug` shows names, not secrets.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;

use crate::auth::{AuthError, AuthSession, AuthStep, ProxyAuth};
use crate::hop::ProxyAddr;

/// A user name and password for one proxy (or the default for every proxy).
#[derive(Clone, PartialEq, Eq)]
pub struct Credentials {
    user: String,
    password: String,
}

impl Credentials {
    /// Credentials for `user`.
    #[must_use]
    pub fn new(user: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            user: user.into(),
            password: password.into(),
        }
    }

    /// The `Proxy-Authorization` value, `Basic base64(user:password)`.
    fn header(&self) -> String {
        format!(
            "Basic {}",
            BASE64.encode(format!("{}:{}", self.user, self.password))
        )
    }
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("user", &self.user)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// Basic authentication: answers a proxy's `407` that offers `Basic` with the configured
/// credentials for that proxy, else the default credentials.
///
/// A proxy that rejects the credentials is not asked again on the same exchange: the second
/// `407` ends the session with an error, so a wrong password costs one attempt, not a loop
/// (and not an account lockout).
#[derive(Debug, Default, Clone)]
pub struct BasicAuth {
    default: Option<Credentials>,
    per_proxy: HashMap<ProxyAddr, Credentials>,
}

impl BasicAuth {
    /// No credentials: [`ProxyAuth::begin`] never offers a session.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Credentials for every proxy without its own.
    #[must_use]
    pub fn with_default(mut self, credentials: Credentials) -> Self {
        self.default = Some(credentials);
        self
    }

    /// Credentials for `proxy` only.
    #[must_use]
    pub fn with_proxy(mut self, proxy: ProxyAddr, credentials: Credentials) -> Self {
        self.per_proxy.insert(proxy, credentials);
        self
    }
}

impl ProxyAuth for BasicAuth {
    fn begin(
        &self,
        proxy: &ProxyAddr,
        offered: &[&str],
    ) -> Result<Option<Box<dyn AuthSession>>, AuthError> {
        // Never preemptive: with nothing offered the proxy may not want credentials at all, and
        // a password must not go to a proxy that did not ask for Basic.
        if !offered.iter().any(|s| s.eq_ignore_ascii_case("basic")) {
            return Ok(None);
        }
        Ok(self
            .per_proxy
            .get(proxy)
            .or(self.default.as_ref())
            .map(|credentials| {
                Box::new(BasicSession {
                    header: credentials.header(),
                    sent: false,
                }) as Box<dyn AuthSession>
            }))
    }
}

struct BasicSession {
    header: String,
    sent: bool,
}

impl fmt::Debug for BasicSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BasicSession")
            .field("sent", &self.sent)
            .finish_non_exhaustive()
    }
}

impl AuthSession for BasicSession {
    fn step(&mut self, _challenge: Option<&str>) -> Result<AuthStep, AuthError> {
        if self.sent {
            return Err(AuthError::Failed(
                "the proxy rejected the configured credentials".into(),
            ));
        }
        self.sent = true;
        Ok(AuthStep::Authorization(self.header.clone()))
    }
}

/// Several [`ProxyAuth`] implementations tried in order: the first that offers a session for
/// the proxy and its offered schemes is used (SSPI first, then Basic from settings).
#[derive(Debug, Default, Clone)]
pub struct AuthList {
    members: Vec<Arc<dyn ProxyAuth>>,
}

impl AuthList {
    /// An empty list: no authentication.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds `auth` after the ones already in the list.
    #[must_use]
    pub fn with(mut self, auth: Arc<dyn ProxyAuth>) -> Self {
        self.members.push(auth);
        self
    }
}

impl ProxyAuth for AuthList {
    fn begin(
        &self,
        proxy: &ProxyAddr,
        offered: &[&str],
    ) -> Result<Option<Box<dyn AuthSession>>, AuthError> {
        for member in &self.members {
            if let Some(session) = member.begin(proxy, offered)? {
                return Ok(Some(session));
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proxy(port: u16) -> ProxyAddr {
        ProxyAddr::new("proxy.corp", port)
    }

    #[test]
    fn basic_answers_a_basic_challenge_once() {
        let auth = BasicAuth::new().with_default(Credentials::new("t165", "s3cret"));
        let mut session = auth.begin(&proxy(1), &["Basic"]).unwrap().unwrap();
        // base64("t165:s3cret")
        assert_eq!(
            session.step(Some("Basic realm=\"x\"")).unwrap(),
            AuthStep::Authorization("Basic dDE2NTpzM2NyZXQ=".into())
        );
        assert!(matches!(
            session.step(Some("Basic realm=\"x\"")),
            Err(AuthError::Failed(_))
        ));
    }

    #[test]
    fn basic_is_never_preemptive_and_needs_the_scheme_offered() {
        let auth = BasicAuth::new().with_default(Credentials::new("u", "p"));
        assert!(auth.begin(&proxy(1), &[]).unwrap().is_none());
        assert!(
            auth.begin(&proxy(1), &["NTLM", "Negotiate"])
                .unwrap()
                .is_none()
        );
        assert!(auth.begin(&proxy(1), &["bAsIc"]).unwrap().is_some());
    }

    #[test]
    fn a_proxy_without_credentials_gets_none_and_its_own_beats_the_default() {
        let auth = BasicAuth::new().with_proxy(proxy(1), Credentials::new("a", "b"));
        assert!(auth.begin(&proxy(2), &["Basic"]).unwrap().is_none());
        let both = auth.with_default(Credentials::new("d", "d"));
        let mut own = both.begin(&proxy(1), &["Basic"]).unwrap().unwrap();
        assert_eq!(
            own.step(None).unwrap(),
            AuthStep::Authorization(format!("Basic {}", BASE64.encode("a:b")))
        );
        let mut other = both.begin(&proxy(9), &["Basic"]).unwrap().unwrap();
        assert_eq!(
            other.step(None).unwrap(),
            AuthStep::Authorization(format!("Basic {}", BASE64.encode("d:d")))
        );
    }

    #[test]
    fn debug_never_shows_the_password() {
        let credentials = Credentials::new("user", "hunter2-canary");
        let auth = BasicAuth::new().with_default(credentials.clone());
        let session = auth.begin(&proxy(1), &["Basic"]).unwrap().unwrap();
        for text in [
            format!("{credentials:?}"),
            format!("{auth:?}"),
            format!("{session:?}"),
        ] {
            assert!(!text.contains("hunter2-canary"), "{text}");
            assert!(
                !text.contains(&BASE64.encode("user:hunter2-canary")),
                "{text}"
            );
        }
    }

    #[test]
    fn the_list_uses_the_first_member_that_helps() {
        let first = BasicAuth::new().with_proxy(proxy(1), Credentials::new("first", "1"));
        let second = BasicAuth::new().with_default(Credentials::new("second", "2"));
        let list = AuthList::new().with(Arc::new(first)).with(Arc::new(second));
        let mut a = list.begin(&proxy(1), &["Basic"]).unwrap().unwrap();
        assert_eq!(
            a.step(None).unwrap(),
            AuthStep::Authorization(format!("Basic {}", BASE64.encode("first:1")))
        );
        let mut b = list.begin(&proxy(2), &["Basic"]).unwrap().unwrap();
        assert_eq!(
            b.step(None).unwrap(),
            AuthStep::Authorization(format!("Basic {}", BASE64.encode("second:2")))
        );
        assert!(
            AuthList::new()
                .begin(&proxy(1), &["Basic"])
                .unwrap()
                .is_none()
        );
    }
}
