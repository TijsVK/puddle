// SPDX-License-Identifier: GPL-3.0-or-later
//! The backend the window talks to: puddle-api, in this process.
//!
//! Until the real host is wired in (store, proxy, lifecycle, the same entry point as the `puddle`
//! daemon) the backend is the fixture: the real router on in-memory services with one seeded
//! pending request. [`Backend`] is the seam: the shell only needs the origin, the token, the
//! event hub (the tray and notifications will subscribe to it) and a shutdown.

use std::path::Path;
use std::sync::Arc;

use puddle_api::{ConnectionFileError, ConnectionInfo, EventHub, RunningApi, ServeError};
use tokio::sync::Mutex;
use url::Url;

/// Why the backend didn't start.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BackendError {
    /// This build has no backend to run (built without the `fixture` feature).
    #[error(
        "this build has no backend: build with the `fixture` feature (the real wiring is not built yet)"
    )]
    Missing,
    /// The API couldn't listen.
    #[error(transparent)]
    Serve(#[from] ServeError),
    /// The fixture's store couldn't be opened or seeded.
    #[error("cannot set up the fixture: {0}")]
    Fixture(String),
    /// The token couldn't be made, or the connection file couldn't be written.
    #[error(transparent)]
    Connection(#[from] ConnectionFileError),
    /// The API reported an address that isn't a URL.
    #[error("the API's address is not a URL: {0}")]
    Url(#[from] url::ParseError),
}

/// A running in-process backend.
pub struct Backend {
    info: ConnectionInfo,
    url: Url,
    events: Arc<EventHub>,
    running: Mutex<Option<RunningApi>>,
}

impl std::fmt::Debug for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Backend")
            .field("url", &self.url)
            .finish_non_exhaustive()
    }
}

impl Backend {
    /// Starts the backend this build has, listening on `127.0.0.1:<port>` (0 picks a free port).
    ///
    /// # Errors
    ///
    /// [`BackendError`] if there is no backend in this build or it can't start.
    pub async fn start(port: u16) -> Result<Self, BackendError> {
        #[cfg(feature = "fixture")]
        {
            crate::fixture::start(port).await
        }
        #[cfg(not(feature = "fixture"))]
        {
            let _ = port;
            Err(BackendError::Missing)
        }
    }

    pub(crate) fn new(
        info: ConnectionInfo,
        events: Arc<EventHub>,
        running: RunningApi,
    ) -> Result<Self, BackendError> {
        Ok(Self {
            url: Url::parse(&info.url)?,
            info,
            events,
            running: Mutex::new(Some(running)),
        })
    }

    /// The API's origin, `http://127.0.0.1:<port>/`: the address of the main window.
    #[must_use]
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// The API token, to hand to the main window's start-up script. Never log it.
    #[must_use]
    pub fn token(&self) -> &str {
        self.info.token.expose()
    }

    /// The event hub: whatever emits events into it reaches the SPA's stream, and Rust code (the
    /// tray and notifications) can subscribe through the API's types.
    #[must_use]
    pub fn events(&self) -> &Arc<EventHub> {
        &self.events
    }

    /// Writes the connection file, so `npm run dev` in `ui/` (and the CLI) can reach this
    /// backend. Development only: the shell itself never reads it.
    ///
    /// # Errors
    ///
    /// [`BackendError::Connection`] if the file can't be written.
    pub fn write_connection_file(&self, path: &Path) -> Result<(), BackendError> {
        Ok(self.info.write(path)?)
    }

    /// Stops the backend: the shutdown hook. Today it ends the API server; the sandbox quit
    /// sequence will go (close sandbox windows, browser-mode cleanup, stop every sandbox)
    /// in front of it. Safe to call twice.
    pub async fn shutdown(&self) {
        let running = self.running.lock().await.take();
        if let Some(running) = running {
            running.shutdown().await;
        }
    }
}

#[cfg(all(test, feature = "fixture"))]
pub(crate) mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "helpers outside #[test] fns run only in tests; a panic is how a test fails"
    )]

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    use super::*;

    /// One HTTP/1.1 GET over loopback; returns the whole reply as text.
    pub(crate) async fn get(backend: &Backend, path: &str, token: Option<&str>) -> String {
        let addr = (
            backend.url().host_str().unwrap().to_owned(),
            backend.url().port().unwrap(),
        );
        let mut stream = TcpStream::connect(addr.clone()).await.unwrap();
        let auth = token.map_or(String::new(), |t| format!("Authorization: Bearer {t}\r\n"));
        let host = format!("{}:{}", backend.url().host_str().unwrap(), addr.1);
        let request =
            format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n{auth}Connection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).await.unwrap();
        String::from_utf8_lossy(&reply).into_owned()
    }

    #[tokio::test]
    async fn the_fixture_serves_the_api_on_loopback_with_its_token() {
        let backend = Backend::start(0).await.unwrap();
        assert_eq!(backend.url().host_str(), Some("127.0.0.1"));
        assert_ne!(backend.url().port(), Some(0));
        assert_eq!(backend.token().len(), 64);

        let with = get(&backend, "/api/pending", Some(backend.token())).await;
        assert!(with.starts_with("HTTP/1.1 200"), "{with}");
        assert!(with.contains("registry.example.org"), "{with}");

        let without = get(&backend, "/api/pending", None).await;
        assert!(without.starts_with("HTTP/1.1 401"), "{without}");
        backend.shutdown().await;
    }

    #[tokio::test]
    async fn shutdown_stops_listening_and_can_be_called_twice() {
        let backend = Backend::start(0).await.unwrap();
        let port = backend.url().port().unwrap();
        backend.shutdown().await;
        backend.shutdown().await;
        assert!(TcpStream::connect(("127.0.0.1", port)).await.is_err());
    }

    #[tokio::test]
    async fn the_connection_file_names_this_backend() {
        let backend = Backend::start(0).await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("api.json");
        backend.write_connection_file(&file).unwrap();
        let read = ConnectionInfo::read(&file).unwrap();
        assert_eq!(read.url, backend.url().as_str().trim_end_matches('/'));
        assert_eq!(read.token.expose(), backend.token());
        backend.shutdown().await;
        assert!(format!("{backend:?}").contains("127.0.0.1"));
        assert!(!format!("{backend:?}").contains(backend.token()));
    }

    #[tokio::test]
    async fn two_backends_get_their_own_ports_and_tokens() {
        let a = Backend::start(0).await.unwrap();
        let b = Backend::start(0).await.unwrap();
        assert_ne!(a.url(), b.url());
        assert_ne!(a.token(), b.token());
        a.shutdown().await;
        b.shutdown().await;
    }

    #[tokio::test]
    async fn a_taken_port_is_reported() {
        let a = Backend::start(0).await.unwrap();
        let err = Backend::start(a.url().port().unwrap()).await.unwrap_err();
        assert!(matches!(err, BackendError::Serve(_)), "{err:?}");
        a.shutdown().await;
    }
}
