// SPDX-License-Identifier: GPL-3.0-or-later
//! The seam for authenticating to an upstream proxy (T-135 fills it: Windows SSPI Negotiate,
//! later GSSAPI Kerberos on Linux, T-148 L-2). Discovery names the proxy ([`ProxyAddr`]); this
//! trait turns a proxy's `407` challenge into the next `Proxy-Authorization` value, so the code
//! that connects (CONNECT, absolute-form HTTP) does not know which scheme or OS is behind it.
//!
//! Credentials never pass through this interface: an implementation signs in as the current user
//! (never a prompt) and holds whatever it needs itself.

use std::sync::Arc;

use crate::hop::ProxyAddr;

/// Why authentication could not continue.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AuthError {
    /// The proxy's challenge could not be answered (bad token, no ticket).
    #[error("proxy authentication failed: {0}")]
    Failed(String),
}

/// What to do after a `407` round trip.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthStep {
    /// Send the request again with this `Proxy-Authorization` header value.
    Authorization(String),
    /// Authentication is complete; nothing more to send.
    Done,
}

/// One authentication exchange with one proxy, possibly several legs on one connection (NTLM).
pub trait AuthSession: Send + std::fmt::Debug {
    /// The next step. `challenge` is the `Proxy-Authenticate` value of the latest `407` (when the
    /// proxy sent several headers they are joined with `, `, which HTTP allows), or `None` for
    /// the first leg (a preemptive Kerberos token needs no challenge).
    ///
    /// # Errors
    /// [`AuthError`] when the challenge cannot be answered.
    fn step(&mut self, challenge: Option<&str>) -> Result<AuthStep, AuthError>;
}

/// Starts authentication with a proxy.
pub trait ProxyAuth: Send + Sync + std::fmt::Debug {
    /// A session for `proxy` when this implementation speaks one of the `offered` schemes (the
    /// scheme words of the `Proxy-Authenticate` headers, such as `Negotiate`, `NTLM`, `Basic`;
    /// empty before the first `407`). `None` when it cannot help: the caller then reports the
    /// proxy's refusal as it is.
    ///
    /// # Errors
    /// [`AuthError`] when a session cannot be created.
    fn begin(
        &self,
        proxy: &ProxyAddr,
        offered: &[&str],
    ) -> Result<Option<Box<dyn AuthSession>>, AuthError>;
}

/// No authentication: every proxy is used as it is. The Unix implementation of [`system_auth`].
#[derive(Debug, Default, Clone, Copy)]
pub struct NoAuth;

impl ProxyAuth for NoAuth {
    fn begin(
        &self,
        _proxy: &ProxyAddr,
        _offered: &[&str],
    ) -> Result<Option<Box<dyn AuthSession>>, AuthError> {
        Ok(None)
    }
}

/// The authentication of the current platform: Windows SSPI Negotiate and NTLM as the logged-on
/// user (T-135). [`NoAuth`] elsewhere (T-148 L-2); a GSSAPI [`TokenSource`](crate::TokenSource) for
/// [`NegotiateAuth`](crate::NegotiateAuth) is the Linux follow-up.
#[must_use]
pub fn system_auth() -> Arc<dyn ProxyAuth> {
    #[cfg(windows)]
    {
        Arc::new(crate::negotiate::NegotiateAuth::new(Arc::new(
            crate::windows::SspiSource,
        )))
    }
    #[cfg(not(windows))]
    {
        Arc::new(NoAuth)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct Echo(u8);

    impl AuthSession for Echo {
        fn step(&mut self, challenge: Option<&str>) -> Result<AuthStep, AuthError> {
            self.0 += 1;
            match (self.0, challenge) {
                (1, None) => Ok(AuthStep::Authorization("Negotiate first".into())),
                (2, Some(c)) => Ok(AuthStep::Authorization(format!("Negotiate answer-{c}"))),
                (_, Some(_)) => Ok(AuthStep::Done),
                _ => Err(AuthError::Failed("unexpected".into())),
            }
        }
    }

    #[derive(Debug)]
    struct Fake;

    impl ProxyAuth for Fake {
        fn begin(
            &self,
            _proxy: &ProxyAddr,
            offered: &[&str],
        ) -> Result<Option<Box<dyn AuthSession>>, AuthError> {
            Ok(offered
                .is_empty()
                .then(|| Box::new(Echo(0)) as Box<dyn AuthSession>))
        }
    }

    #[test]
    fn no_auth_never_offers_a_session() {
        let proxy = ProxyAddr::new("p", 1);
        assert!(NoAuth.begin(&proxy, &[]).unwrap().is_none());
        assert!(NoAuth.begin(&proxy, &["Negotiate"]).unwrap().is_none());
        // Basic is never answered by any platform implementation: no password prompt exists.
        assert!(system_auth().begin(&proxy, &["Basic"]).unwrap().is_none());
        #[cfg(not(windows))]
        assert!(system_auth().begin(&proxy, &["NTLM"]).unwrap().is_none());
    }

    #[test]
    fn a_multi_leg_exchange_fits_the_trait() {
        let proxy = ProxyAddr::new("p", 1);
        let mut session = Fake.begin(&proxy, &[]).unwrap().unwrap();
        assert_eq!(
            session.step(None).unwrap(),
            AuthStep::Authorization("Negotiate first".into())
        );
        assert_eq!(
            session.step(Some("c")).unwrap(),
            AuthStep::Authorization("Negotiate answer-c".into())
        );
        assert_eq!(session.step(Some("d")).unwrap(), AuthStep::Done);
        let mut broken = Echo(5);
        assert!(broken.step(None).is_err());
        assert!(Fake.begin(&proxy, &["Basic"]).unwrap().is_none());
    }
}
