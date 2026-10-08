// SPDX-License-Identifier: GPL-3.0-or-later
//! Wiring: plugins, the backend and the main window, and the exit hook.

use std::path::PathBuf;
use std::sync::Arc;

use tauri::{AppHandle, Manager, RunEvent, Runtime};
use tauri_plugin_opener::OpenerExt;
use url::Url;

use crate::backend::{Backend, BackendError};
use crate::window::{MAIN_LABEL, OpenExternal, open_main};

/// Why the shell didn't start or ended badly.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ShellError {
    /// The in-process backend didn't start.
    #[error("the backend didn't start: {0}")]
    Backend(#[from] BackendError),
    /// Tauri failed.
    #[error("the window system failed: {0}")]
    Tauri(#[from] tauri::Error),
}

/// How a run differs from the defaults. Development conveniences only; a release build ignores
/// the environment.
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// Port for the API on `127.0.0.1`; 0 picks a free one.
    pub port: u16,
    /// Where to write the connection file (`PUDDLE_CONNECTION_FILE`), so `npm run dev` in `ui/`
    /// can proxy to this backend.
    pub connection_file: Option<PathBuf>,
    /// A development server for the page (`PUDDLE_APP_UI_URL`, e.g. `http://localhost:5173/`),
    /// shown in the window instead of the API's own page. The token is handed to it as well.
    pub dev_url: Option<Url>,
    /// A port for WebView2's DevTools Protocol (`PUDDLE_APP_DEBUG_PORT`), which the smoke test
    /// drives the window through. Windows only.
    pub debug_port: Option<u16>,
}

impl Options {
    /// The options the environment asks for (debug builds only).
    #[must_use]
    pub fn from_env() -> Self {
        if cfg!(debug_assertions) {
            Self {
                port: 0,
                connection_file: std::env::var_os("PUDDLE_CONNECTION_FILE").map(PathBuf::from),
                dev_url: std::env::var("PUDDLE_APP_UI_URL")
                    .ok()
                    .and_then(|v| Url::parse(&v).ok()),
                debug_port: std::env::var("PUDDLE_APP_DEBUG_PORT")
                    .ok()
                    .and_then(|v| v.parse().ok()),
            }
        } else {
            Self::default()
        }
    }
}

/// Tauri's context for the app: `tauri.conf.json`, the capabilities and the ACL manifest.
#[must_use]
pub fn context<R: Runtime>() -> tauri::Context<R> {
    tauri::generate_context!()
}

/// Adds the plugins every build has (all but single-instance, which only the real app can have:
/// it talks to the desktop's message bus). None of them is granted to any window.
pub fn with_plugins<R: Runtime>(builder: tauri::Builder<R>) -> tauri::Builder<R> {
    builder
        .plugin(tauri_plugin_window_state::Builder::default().build())
        .plugin(tauri_plugin_opener::init())
}

/// Brings the main window to the front (a second launch asks for this).
pub fn focus_main<R: Runtime>(app: &AppHandle<R>) {
    if let Some(window) = app.get_webview_window(MAIN_LABEL) {
        // Both can fail if the window is being closed; there is nothing to do about that.
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

/// Hands an address to the default browser through the opener plugin.
fn opener<R: Runtime>(app: &AppHandle<R>) -> OpenExternal {
    let app = app.clone();
    Arc::new(move |url: &Url| {
        if let Err(err) = app.opener().open_url(url.as_str(), None::<&str>) {
            tracing::warn!(%err, "could not open the default browser");
        }
    })
}

/// Starts the backend and opens the main window, then keeps the backend for the exit hook.
///
/// # Errors
///
/// [`ShellError`] if the backend or the window can't start.
pub fn start<R: Runtime>(app: &AppHandle<R>, options: &Options) -> Result<(), ShellError> {
    let backend = tauri::async_runtime::block_on(Backend::start(options.port))?;
    if let Some(file) = &options.connection_file {
        backend.write_connection_file(file)?;
    }
    open_main(
        app,
        backend.url(),
        backend.token(),
        options.dev_url.as_ref(),
        options.debug_port,
        opener(app),
    )?;
    tracing::info!(url = %backend.url(), "main window open");
    app.manage(backend);
    Ok(())
}

/// The exit hook: stops the backend. The workspace quit sequence will go in front.
pub fn stop<R: Runtime>(app: &AppHandle<R>) {
    if let Some(backend) = app.try_state::<Backend>() {
        tauri::async_runtime::block_on(backend.shutdown());
    }
}

/// Runs the app until it quits. Closing the main window quits (that will change to hiding to the
/// tray).
///
/// # Errors
///
/// [`ShellError`] if the app can't start.
pub fn run(options: &Options) -> Result<(), ShellError> {
    // The first subscriber wins; a second `run` in one process (tests) keeps the first.
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .try_init();
    let options = options.clone();
    // Single-instance first: a second launch must end before anything else starts.
    let builder =
        tauri::Builder::default().plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            focus_main(app);
        }));
    let app = with_plugins(builder)
        .setup(move |app| {
            start(app.handle(), &options)?;
            Ok(())
        })
        .build(context())?;
    app.run(|handle, event| {
        if matches!(event, RunEvent::Exit) {
            stop(handle);
        }
    });
    Ok(())
}

#[cfg(all(test, feature = "fixture"))]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "helpers outside #[test] fns run only in tests; a panic is how a test fails"
    )]

    use tauri::test::{MockRuntime, mock_builder};

    use super::*;
    use crate::backend::tests::get;

    fn app() -> tauri::App<MockRuntime> {
        with_plugins(mock_builder()).build(context()).unwrap()
    }

    #[test]
    fn start_opens_the_main_window_on_the_backend_and_stop_ends_the_backend() {
        let app = app();
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("api.json");
        let options = Options {
            connection_file: Some(file.clone()),
            ..Options::default()
        };
        start(app.handle(), &options).unwrap();

        let backend = app.state::<Backend>();
        let window = app.get_webview_window(MAIN_LABEL).unwrap();
        assert_eq!(&window.url().unwrap(), backend.url());
        assert!(file.exists());

        let rt = tokio::runtime::Runtime::new().unwrap();
        let reply = rt.block_on(get(&backend, "/api/pending", Some(backend.token())));
        assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");

        stop(app.handle());
        let port = backend.url().port().unwrap();
        assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_err());
        // The hook can run again (a second Exit event, or no backend at all).
        stop(app.handle());
    }

    #[test]
    fn stop_without_a_backend_does_nothing() {
        stop(app().handle());
    }

    #[test]
    fn focusing_without_a_main_window_does_nothing_and_with_one_succeeds() {
        let app = app();
        focus_main(app.handle());
        start(app.handle(), &Options::default()).unwrap();
        focus_main(app.handle());
        stop(app.handle());
    }

    #[test]
    fn a_failed_start_leaves_no_window() {
        let app = app();
        let taken = tauri::async_runtime::block_on(Backend::start(0)).unwrap();
        let options = Options {
            port: taken.url().port().unwrap(),
            ..Options::default()
        };
        let err = start(app.handle(), &options).unwrap_err();
        assert!(matches!(err, ShellError::Backend(_)), "{err}");
        assert!(app.get_webview_window(MAIN_LABEL).is_none());
        tauri::async_runtime::block_on(taken.shutdown());
    }

    #[test]
    fn the_defaults_pick_a_free_port_and_ask_for_nothing() {
        let options = Options::default();
        assert_eq!(options.port, 0);
        assert!(options.connection_file.is_none() && options.dev_url.is_none());
        assert!(options.debug_port.is_none());
        assert_eq!(Options::from_env().port, 0);
    }
}
