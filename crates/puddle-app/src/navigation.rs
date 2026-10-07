// SPDX-License-Identifier: GPL-3.0-or-later
//! Where the main window may go.
//!
//! The main window shows puddle's own page from the API origin and nothing else. A link or
//! redirect that leaves that origin is cancelled in the window; a web address is then handed to
//! the default browser, called from Rust (the page never gets to call an opener). Anything that
//! is not a plain web address is dropped.

use url::Url;

/// Host names the webview itself answers on Windows (`http://<name>.localhost`): Tauri's
/// protocol handler serves them on any port, so they are never an address to open.
const WEBVIEW_HOSTS: [&str; 3] = ["tauri.localhost", "ipc.localhost", "asset.localhost"];

/// What to do with a navigation of the main window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Navigation {
    /// Let the window go there.
    Stay,
    /// Cancel it and open the address in the default browser.
    External,
    /// Cancel it and do nothing else.
    Refuse,
}

/// The origins the main window may stay on.
#[derive(Debug, Clone)]
pub struct OriginPolicy {
    api: Url,
    dev: Option<Url>,
}

impl OriginPolicy {
    /// A policy for the API's own origin, plus a development server's origin when `dev` is set.
    #[must_use]
    pub fn new(api: &Url, dev: Option<&Url>) -> Self {
        Self {
            api: api.clone(),
            dev: dev.cloned(),
        }
    }

    /// Classifies a navigation of the main window.
    #[must_use]
    pub fn classify(&self, target: &Url) -> Navigation {
        let origin = target.origin();
        if origin == self.api.origin() || self.dev.as_ref().is_some_and(|d| origin == d.origin()) {
            return Navigation::Stay;
        }
        if target.as_str() == "about:blank" {
            return Navigation::Stay;
        }
        let web = matches!(target.scheme(), "http" | "https");
        let webview_name = target
            .host_str()
            .is_some_and(|h| WEBVIEW_HOSTS.contains(&h.to_ascii_lowercase().as_str()));
        if web && !webview_name {
            Navigation::External
        } else {
            Navigation::Refuse
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> OriginPolicy {
        OriginPolicy::new(&Url::parse("http://127.0.0.1:4711/").unwrap(), None)
    }

    fn class(policy: &OriginPolicy, url: &str) -> Navigation {
        policy.classify(&Url::parse(url).unwrap())
    }

    #[test]
    fn the_api_origin_stays() {
        let p = policy();
        for url in [
            "http://127.0.0.1:4711/",
            "http://127.0.0.1:4711/inbox?x=1#y",
            "http://127.0.0.1:4711/_app/immutable/a.js",
            "about:blank",
            "blob:http://127.0.0.1:4711/2f1c",
        ] {
            assert_eq!(class(&p, url), Navigation::Stay, "{url}");
        }
    }

    #[test]
    fn another_origin_of_the_same_machine_is_external() {
        let p = policy();
        for url in [
            "http://127.0.0.1:4712/",
            "http://127.0.0.1/",
            "https://127.0.0.1:4711/",
            "http://localhost:4711/",
            "http://[::1]:4711/",
            "https://example.org/docs",
            "http://workspace.localhost:9000/",
            "http://127.0.0.1.example.org:4711/",
            "http://127.0.0.1:4711@example.org/",
        ] {
            assert_eq!(class(&p, url), Navigation::External, "{url}");
        }
    }

    #[test]
    fn the_webview_s_own_names_and_non_web_schemes_are_refused() {
        let p = policy();
        for url in [
            "http://tauri.localhost/index.html",
            "http://TAURI.localhost:4711/",
            "http://ipc.localhost/",
            "https://asset.localhost/x",
            "tauri://localhost/",
            "ipc://localhost/",
            "asset://localhost/x",
            "file:///c:/windows/win.ini",
            "javascript:alert(1)",
            "data:text/html,hi",
            "mailto:a@example.org",
            "ms-msdt:something",
            "about:srcdoc",
        ] {
            assert_eq!(class(&p, url), Navigation::Refuse, "{url}");
        }
    }

    #[test]
    fn a_development_server_stays_only_when_given() {
        let dev = Url::parse("http://localhost:5173/").unwrap();
        let with = OriginPolicy::new(&Url::parse("http://127.0.0.1:4711/").unwrap(), Some(&dev));
        assert_eq!(
            class(&with, "http://localhost:5173/inbox"),
            Navigation::Stay
        );
        assert_eq!(class(&with, "http://localhost:5174/"), Navigation::External);
        assert_eq!(
            class(&policy(), "http://localhost:5173/inbox"),
            Navigation::External
        );
    }
}
