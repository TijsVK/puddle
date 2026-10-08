// SPDX-License-Identifier: GPL-3.0-or-later
//! The main window: its label, its start-up script and how it is built.

use std::sync::Arc;

use tauri::webview::NewWindowResponse;
use tauri::{Manager, Runtime, WebviewUrl, WebviewWindow, WebviewWindowBuilder};
use url::Url;

use crate::navigation::{Navigation, OriginPolicy};

/// The main window's label. puddle's one capability file names this label and grants it nothing;
/// workspace windows get labels of their own (`vs-<workspace>`), never this one.
pub const MAIN_LABEL: &str = "main";

/// Hands a web address to the default browser. In the app this is the opener plugin called from
/// Rust; tests pass a recorder.
pub type OpenExternal = Arc<dyn Fn(&Url) + Send + Sync>;

/// The script that runs before the page's own scripts, in the main window's top-level frame only.
///
/// It sets `window.__PUDDLE__ = { token }`, the one way the SPA learns the API token (see `ui/src/lib/api/connection.ts`). The
/// property can't be reassigned or deleted by the page. The script does nothing unless the page's
/// origin is the API's, so a navigation that somehow got elsewhere would see no token.
#[must_use]
pub fn init_script(origin: &str, token: &str) -> String {
    // `serde_json` writes a string literal that is also a valid JavaScript string literal, so a
    // value with quotes, backslashes or line breaks stays inside it.
    let origin = serde_json::Value::from(origin);
    let token = serde_json::Value::from(token);
    format!(
        "(function () {{\n\
         \x20 if (window.location.origin !== {origin}) return;\n\
         \x20 Object.defineProperty(window, \"__PUDDLE__\", {{\n\
         \x20   value: Object.freeze({{ token: {token} }}),\n\
         \x20 }});\n\
         }})();\n"
    )
}

/// The navigation callback for the main window: keeps it on the allowed origins and sends web
/// addresses elsewhere to `open`.
pub fn navigation_handler(
    policy: OriginPolicy,
    open: OpenExternal,
) -> impl Fn(&Url) -> bool + Send + Sync + 'static {
    move |target| match policy.classify(target) {
        Navigation::Stay => true,
        Navigation::External => {
            open(target);
            false
        }
        Navigation::Refuse => {
            tracing::warn!(scheme = target.scheme(), "main window navigation refused");
            false
        }
    }
}

/// Opens the main window on `url` with the token handed over. Returns the existing window if
/// there is one. `debug_port` opens WebView2's DevTools Protocol on that port (Windows, for the
/// smoke test; ignored elsewhere).
///
/// # Errors
///
/// Whatever Tauri reports when the window can't be created.
pub fn open_main<R: Runtime, M: Manager<R>>(
    manager: &M,
    url: &Url,
    token: &str,
    dev_url: Option<&Url>,
    debug_port: Option<u16>,
    open: OpenExternal,
) -> tauri::Result<WebviewWindow<R>> {
    if let Some(existing) = manager.get_webview_window(MAIN_LABEL) {
        return Ok(existing);
    }
    let policy = OriginPolicy::new(url, dev_url);
    let start = dev_url.unwrap_or(url).clone();
    let origin = start.origin().ascii_serialization();
    let on_new_window_open = open.clone();
    let builder = WebviewWindowBuilder::new(manager, MAIN_LABEL, WebviewUrl::External(start))
        .title("puddle")
        .inner_size(1280.0, 800.0)
        .min_inner_size(900.0, 600.0)
        .initialization_script(init_script(&origin, token))
        .on_navigation(navigation_handler(policy.clone(), open))
        .on_new_window(move |target, _features| {
            // Never `Allow`: that is the webview's own pop-up, without our handlers.
            // `target="_blank"` links to the web go to the browser; the rest is dropped.
            if policy.classify(&target) == Navigation::External {
                on_new_window_open(&target);
            }
            NewWindowResponse::Deny
        });
    #[cfg(windows)]
    let builder = match debug_port {
        // WebView2 only takes this from the API (the environment variable is ignored once the
        // API sets arguments, which wry always does); the first two are wry's own defaults.
        Some(port) => builder.additional_browser_args(&format!(
            "--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection --remote-debugging-port={port} --remote-allow-origins=*"
        )),
        None => builder,
    };
    #[cfg(not(windows))]
    let _ = debug_port;
    builder.build()
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    fn recorder() -> (OpenExternal, Arc<Mutex<Vec<String>>>) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let open: OpenExternal = Arc::new(move |u: &Url| sink.lock().unwrap().push(u.to_string()));
        (open, seen)
    }

    #[test]
    fn the_script_sets_a_frozen_token_for_the_api_origin_only() {
        let script = init_script("http://127.0.0.1:4711", "abc123");
        assert!(script.contains("window.location.origin !== \"http://127.0.0.1:4711\""));
        assert!(script.contains("Object.freeze({ token: \"abc123\" })"));
        assert!(script.contains("Object.defineProperty(window, \"__PUDDLE__\""));
        assert_eq!(script.matches("abc123").count(), 1);
    }

    #[test]
    fn the_script_keeps_hostile_values_inside_their_string_literals() {
        let script = init_script("http://x/\"", "a\"b\\c\nd</script>");
        assert!(script.contains(r#"\"b\\c\nd</script>""#), "{script}");
        assert!(!script.contains("a\"b"), "{script}");
        assert!(script.contains(r#"!== "http://x/\"""#), "{script}");
    }

    #[test]
    fn the_handler_stays_opens_or_drops() {
        let api = Url::parse("http://127.0.0.1:4711/").unwrap();
        let (open, seen) = recorder();
        let handler = navigation_handler(OriginPolicy::new(&api, None), open);
        assert!(handler(&Url::parse("http://127.0.0.1:4711/inbox").unwrap()));
        assert!(seen.lock().unwrap().is_empty());
        assert!(!handler(&Url::parse("https://example.org/a").unwrap()));
        assert_eq!(*seen.lock().unwrap(), ["https://example.org/a"]);
        assert!(!handler(&Url::parse("file:///etc/passwd").unwrap()));
        assert!(!handler(&Url::parse("http://tauri.localhost/").unwrap()));
        assert_eq!(seen.lock().unwrap().len(), 1);
    }

    #[test]
    fn the_main_window_opens_once_on_the_api_origin() {
        let app = tauri::test::mock_app();
        let url = Url::parse("http://127.0.0.1:4711/").unwrap();
        let (open, _) = recorder();
        let first = open_main(&app, &url, "t", None, None, open.clone()).unwrap();
        assert_eq!(first.label(), MAIN_LABEL);
        assert_eq!(first.url().unwrap(), url);
        let second = open_main(&app, &url, "t", None, None, open).unwrap();
        assert_eq!(second.label(), MAIN_LABEL);
        assert_eq!(app.webview_windows().len(), 1);
    }

    #[test]
    fn a_development_server_replaces_the_start_page() {
        let app = tauri::test::mock_app();
        let api = Url::parse("http://127.0.0.1:4711/").unwrap();
        let dev = Url::parse("http://localhost:5173/").unwrap();
        let (open, _) = recorder();
        let window = open_main(&app, &api, "t", Some(&dev), None, open).unwrap();
        assert_eq!(window.url().unwrap(), dev);
    }
}
