// SPDX-License-Identifier: GPL-3.0-or-later
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code: a panic is how a test fails"
)]
//! Its own test binary: the log capture is the process-wide default, which the other tests must not share.

mod common;

use std::fmt::Write;
use std::sync::Arc;

use common::{CANARY, Fakes};
use puddle_secrets::{
    AccountName, Fetch, HostName, MemoryStore, SourceSpec, Sources, StoredId, TokenScope,
    ToolPaths, UrlPath,
};

fn sources(gh: Option<std::path::PathBuf>, git: Option<std::path::PathBuf>) -> Sources {
    Sources::new(ToolPaths::new(gh, git), Arc::new(MemoryStore::new()))
}

fn gh_spec() -> SourceSpec {
    SourceSpec::Gh {
        host: HostName::new("github.com").unwrap(),
        account: AccountName::new("me").unwrap(),
    }
}

fn git_spec(path: &str) -> SourceSpec {
    SourceSpec::GitCredential {
        host: HostName::new("dev.azure.com").unwrap(),
        path: UrlPath::new(path).unwrap(),
        username: None,
    }
}

fn stored_spec(id: &str) -> SourceSpec {
    SourceSpec::Stored {
        id: StoredId::new(id).unwrap(),
        scope: TokenScope {
            host: HostName::new("dev.azure.com").unwrap(),
            org: None,
        },
    }
}

/// A secret that every layer must keep out of logs and error text, whatever fails.
#[tokio::test]
async fn no_secret_reaches_logs_errors_or_debug_output() {
    use std::sync::Mutex;
    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Capture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl MakeWriter<'_> for Capture {
        type Writer = Capture;
        fn make_writer(&self) -> Capture {
            self.clone()
        }
    }

    let capture = Capture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(capture.clone())
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let fakes = Fakes::new();
    let gh = fakes.install("gh", &format!("[]\nstdout={CANARY} spaced\\n\n"));
    let git = fakes.install(
        "git",
        &format!("[]\nstdout=protocol=https\\nhost=x.com\\npath=o\\npassword={CANARY}\\n\n"),
    );
    let src = sources(Some(gh), Some(git));
    let mut shown = String::new();
    for spec in [gh_spec(), git_spec("org"), stored_spec("zz")] {
        let err = src.fetch(&spec).await.unwrap_err();
        write!(shown, "{err} {err:?} {spec:?} {}", spec.describe()).unwrap();
    }
    let good = Fakes::new();
    let ok = good.install("gh", &format!("[]\nstdout={CANARY}\\n\n"));
    let got = sources(Some(ok), None).fetch(&gh_spec()).await.unwrap();
    write!(shown, "{got:?}").unwrap();

    let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    assert!(
        logs.contains("reading a secret"),
        "the capture works: {logs}"
    );
    assert!(!logs.contains(CANARY), "{logs}");
    assert!(!shown.contains(CANARY), "{shown}");
}
