// SPDX-License-Identifier: GPL-3.0-or-later
//! The environment that sends msb's image pulls through puddle's image-pull proxy (T-116, D-8
//! interim design).
//!
//! The msb SDK pulls inside puddle's process, with a registry client that takes its proxy only
//! from the environment (reqwest's system proxy: `HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY`,
//! `NO_PROXY`, either case; on Windows also the user's `WinINet` proxy when those are empty). msb
//! has no setting for it. So, like [`crate::RuntimeEnv`], this is a plan applied to the process
//! before any thread starts:
//!
//! - remove every proxy variable the user set (any case), and `REQUEST_METHOD` (with it set, the
//!   client ignores every proxy, httpoxy guard);
//! - set `HTTPS_PROXY` and `HTTP_PROXY` to the pull proxy's URL with its per-run token, and
//!   `NO_PROXY` to [`NO_PROXY_NONE`], a name nothing matches: an empty `NO_PROXY` would let the
//!   Windows proxy bypass list fill in, and a pull to a listed registry would skip puddle.
//!
//! Children puddle starts inherit the variables; they reach only the pull proxy, which needs the
//! token and connects only where the guard allows. The token is in the values only: `Debug`
//! shows the names.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::process::Command;

/// The `NO_PROXY` value puddle sets: one name under the reserved `.invalid` TLD (RFC 2606), so
/// no registry host matches and nothing bypasses the pull proxy.
pub const NO_PROXY_NONE: &str = "puddle.invalid";

/// The variables the registry client reads its proxy from, plus `REQUEST_METHOD`.
const PROXY_VARS: [&str; 5] = [
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "REQUEST_METHOD",
];

/// Whether `name` is one of the variables the plan removes, ASCII case-insensitively.
#[must_use]
pub fn is_proxy_variable(name: &OsStr) -> bool {
    let name = name.as_encoded_bytes();
    PROXY_VARS
        .iter()
        .any(|v| v.as_bytes().eq_ignore_ascii_case(name))
}

/// The environment changes that point the registry client at the pull proxy: variables to
/// remove, then variables to set. `Debug` never shows the proxy URL.
#[derive(Clone, PartialEq, Eq)]
pub struct PullProxyEnv {
    remove: Vec<OsString>,
    set: Vec<(&'static str, String)>,
}

impl PullProxyEnv {
    /// The plan for `proxy_url` (`http://puddle:<token>@127.0.0.1:<port>`, from the pull proxy),
    /// given the current environment `vars` (normally [`std::env::vars_os`]): every proxy
    /// variable in `vars` is removed, then `HTTPS_PROXY` and `HTTP_PROXY` are set to `proxy_url`
    /// and `NO_PROXY` to [`NO_PROXY_NONE`].
    #[must_use]
    pub fn plan(proxy_url: &str, vars: impl IntoIterator<Item = (OsString, OsString)>) -> Self {
        let mut remove: Vec<OsString> = vars
            .into_iter()
            .map(|(name, _)| name)
            .filter(|name| is_proxy_variable(name))
            .collect();
        remove.sort();
        remove.dedup();
        let set = vec![
            ("HTTPS_PROXY", proxy_url.to_owned()),
            ("HTTP_PROXY", proxy_url.to_owned()),
            ("NO_PROXY", NO_PROXY_NONE.to_owned()),
        ];
        Self { remove, set }
    }

    /// The variables removed (each user-set one, sorted).
    #[must_use]
    pub fn removed(&self) -> &[OsString] {
        &self.remove
    }

    /// The names set, in order: `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY`.
    #[must_use]
    pub fn set_names(&self) -> Vec<&'static str> {
        self.set.iter().map(|(name, _)| *name).collect()
    }

    /// The value set for `name`, if the plan sets it. It holds the token for the proxy variables.
    #[must_use]
    pub fn value(&self, name: &str) -> Option<&str> {
        self.set
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v.as_str())
    }

    /// Applies the plan to a child process.
    pub fn apply_to(&self, command: &mut Command) {
        for name in &self.remove {
            command.env_remove(name);
        }
        for (name, value) in &self.set {
            command.env(name, value);
        }
    }

    /// Applies the plan to puddle's own process, where the msb SDK pulls images.
    ///
    /// # Safety
    ///
    /// Changing the process environment is only sound while no other thread reads or writes it
    /// ([`std::env::set_var`]). Call this first thing in `main`, before the tokio runtime or any
    /// other thread starts (bind the pull proxy with its std listener first).
    #[expect(
        unsafe_code,
        reason = "the SDK's registry client only reads its proxy from the process environment"
    )]
    pub unsafe fn apply_to_process(&self) {
        for name in &self.remove {
            // SAFETY: the caller guarantees no other thread touches the environment (see # Safety).
            unsafe { std::env::remove_var(name) };
        }
        for (name, value) in &self.set {
            // SAFETY: as above.
            unsafe { std::env::set_var(name, value) };
        }
    }
}

impl fmt::Debug for PullProxyEnv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PullProxyEnv")
            .field("remove", &self.remove)
            .field("set", &self.set_names())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const URL: &str = "http://puddle:0123abcd@127.0.0.1:40000";

    fn vars(names: &[&str]) -> Vec<(OsString, OsString)> {
        names
            .iter()
            .map(|n| (OsString::from(n), OsString::from("http://corp-proxy:8080")))
            .collect()
    }

    #[test]
    fn every_proxy_variable_in_any_case_is_removed_and_nothing_else() {
        let env = PullProxyEnv::plan(
            URL,
            vars(&[
                "PATH",
                "http_proxy",
                "HTTPS_PROXY",
                "https_proxy",
                "All_Proxy",
                "no_proxy",
                "NO_PROXY",
                "REQUEST_METHOD",
                "FTP_PROXY",
                "MY_HTTPS_PROXY",
                "MSB_PATH",
            ]),
        );
        let removed: Vec<_> = env.removed().iter().map(|n| n.to_str().unwrap()).collect();
        assert_eq!(
            removed,
            [
                "All_Proxy",
                "HTTPS_PROXY",
                "NO_PROXY",
                "REQUEST_METHOD",
                "http_proxy",
                "https_proxy",
                "no_proxy"
            ]
        );
    }

    #[test]
    fn sets_both_proxies_to_the_url_and_a_no_proxy_nothing_matches() {
        let env = PullProxyEnv::plan(URL, vars(&[]));
        assert_eq!(env.set_names(), ["HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY"]);
        assert_eq!(env.value("HTTPS_PROXY"), Some(URL));
        assert_eq!(env.value("HTTP_PROXY"), Some(URL));
        assert_eq!(env.value("NO_PROXY"), Some("puddle.invalid"));
        assert_eq!(env.value("ALL_PROXY"), None);
    }

    #[test]
    fn debug_shows_names_but_never_the_url() {
        let env = PullProxyEnv::plan(URL, vars(&["https_proxy"]));
        let shown = format!("{env:?}");
        assert!(!shown.contains("0123abcd"), "{shown}");
        assert!(!shown.contains("127.0.0.1"), "{shown}");
        assert!(
            shown.contains("HTTPS_PROXY") && shown.contains("https_proxy"),
            "{shown}"
        );
    }

    #[test]
    fn a_child_gets_the_plan() {
        let env = PullProxyEnv::plan(URL, vars(&["http_proxy", "ALL_PROXY"]));
        let mut cmd = Command::new("true");
        env.apply_to(&mut cmd);
        let envs: Vec<(String, Option<String>)> = cmd
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect();
        for (name, value) in [
            ("HTTPS_PROXY", Some(URL)),
            ("HTTP_PROXY", Some(URL)),
            ("NO_PROXY", Some("puddle.invalid")),
        ] {
            assert!(
                envs.contains(&(name.to_owned(), value.map(str::to_owned))),
                "{name}: {envs:?}"
            );
        }
        assert!(envs.contains(&("ALL_PROXY".to_owned(), None)), "{envs:?}");
        if cfg!(not(windows)) {
            // Windows folds names: removing `http_proxy` and setting `HTTP_PROXY` is one entry.
            assert!(envs.contains(&("http_proxy".to_owned(), None)), "{envs:?}");
        }
    }
}
