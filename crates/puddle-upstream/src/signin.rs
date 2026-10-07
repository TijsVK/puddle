// SPDX-License-Identifier: GPL-3.0-or-later
//! What the last sign-in to each upstream proxy came to, for the network-health report. Holds
//! scheme words and short messages only: never a token, a header value or a password.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::SystemTime;

use crate::hop::ProxyAddr;
use crate::redact::redact_text;

/// How a sign-in to a proxy ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignInOutcome {
    /// The proxy asked, and puddle answered.
    SignedIn,
    /// The proxy let the request through without asking.
    NotRequired,
    /// The proxy refused the credentials or the token, or asked too often.
    Failed,
    /// The proxy asks for something puddle has no way to give (a scheme it does not speak, or no
    /// configured password).
    Unsupported,
}

/// The latest sign-in attempt to one proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignIn {
    /// The proxy.
    pub proxy: ProxyAddr,
    /// The scheme word that was sent (`Negotiate`, `NTLM`, `Basic`); `None` when nothing was.
    pub scheme: Option<String>,
    /// How it ended.
    pub outcome: SignInOutcome,
    /// Why, in words, already cleaned of anything secret.
    pub detail: Option<String>,
    /// When.
    pub at: SystemTime,
}

#[derive(Debug, Default)]
pub(crate) struct SignInLog {
    latest: Mutex<HashMap<ProxyAddr, SignIn>>,
}

impl SignInLog {
    pub(crate) fn record(
        &self,
        proxy: &ProxyAddr,
        scheme: Option<String>,
        outcome: SignInOutcome,
        detail: Option<String>,
    ) {
        let entry = SignIn {
            proxy: proxy.clone(),
            scheme,
            outcome,
            detail: detail.map(|text| redact_text(&text)),
            at: SystemTime::now(),
        };
        self.latest
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(proxy.clone(), entry);
    }

    /// Newest first.
    pub(crate) fn all(&self) -> Vec<SignIn> {
        let mut all: Vec<SignIn> = self
            .latest
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .cloned()
            .collect();
        all.sort_by(|a, b| b.at.cmp(&a.at).then_with(|| a.proxy.cmp(&b.proxy)));
        all
    }
}
