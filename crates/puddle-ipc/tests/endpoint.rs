// SPDX-License-Identifier: GPL-3.0-or-later
//! Endpoints end to end on the host's real IPC (named pipes on Windows, Unix sockets elsewhere).
#![expect(
    clippy::unwrap_used,
    reason = "helpers run outside #[test] but only in tests"
)]

use std::collections::HashSet;
use std::time::Duration;

use puddle_ipc::{Connection, IpcError, IpcRoot, Listener, connect};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

const WAIT: Duration = Duration::from_secs(20);

fn root() -> IpcRoot {
    IpcRoot::new().unwrap()
}

/// Accepts connections forever and echoes each one until the client goes away. Clients read
/// back exactly what they sent and then drop the connection: named pipes have no half-close
/// (see `shutdown_half_closes_only_on_unix`), so an echo can't wait for EOF on Windows.
fn spawn_echo(mut listener: Listener) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let Ok(mut conn) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let (mut r, mut w) = tokio::io::split(&mut conn);
                // Ends with EOF (Unix) or a broken pipe (Windows) when the client drops.
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    })
}

async fn roundtrip(conn: &mut Connection, payload: &[u8]) -> Vec<u8> {
    conn.write_all(payload).await.unwrap();
    let mut back = vec![0u8; payload.len()];
    conn.read_exact(&mut back).await.unwrap();
    back
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_reaches_the_listener_and_data_flows_both_ways() {
    let root = root();
    let mut listener = root.listen().unwrap();
    let path = listener.endpoint().path().to_path_buf();

    let client = tokio::spawn(async move {
        let mut c = connect(&path).await.unwrap();
        c.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        c.read_exact(&mut buf).await.unwrap();
        buf
    });
    let mut server = timeout(WAIT, listener.accept()).await.unwrap().unwrap();
    let mut buf = [0u8; 4];
    server.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");
    server.write_all(b"pong").await.unwrap();
    server.flush().await.unwrap();
    assert_eq!(&client.await.unwrap(), b"pong");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_listen_gets_its_own_unguessable_endpoint() {
    let root = root();
    let listeners: Vec<Listener> = (0..8).map(|_| root.listen().unwrap()).collect();
    let names: HashSet<_> = listeners.iter().map(|l| l.endpoint().clone()).collect();
    assert_eq!(names.len(), listeners.len());
    for l in &listeners {
        let file = l.endpoint().path().file_name().unwrap().to_str().unwrap();
        let hex: String = file.chars().filter(char::is_ascii_hexdigit).collect();
        // 128 random bits for a pipe (shared namespace), 64 in a private Unix directory.
        assert!(hex.len() >= if cfg!(windows) { 32 } else { 16 }, "{file}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ho2_binding_a_name_that_exists_is_refused_and_leaves_the_owner_alone() {
    let root = root();
    let endpoint = root.endpoint().unwrap();
    let first = root.bind(&endpoint).unwrap();
    let echo = spawn_echo(first);

    let err = root.bind(&endpoint).unwrap_err();
    assert!(matches!(err, IpcError::NameTaken { .. }), "{err}");
    assert!(err.to_string().contains(&endpoint.to_string()), "{err}");

    // The first owner still serves.
    let mut c = connect(endpoint.path()).await.unwrap();
    assert_eq!(roundtrip(&mut c, b"still mine").await, b"still mine");
    echo.abort();
}

#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ho2_a_pipe_squatted_by_another_creator_is_refused() {
    use tokio::net::windows::named_pipe::ServerOptions;
    let root = root();
    let endpoint = root.endpoint().unwrap();
    // The squatter: a plain pipe at puddle's name, created first, default DACL.
    let _squatter = ServerOptions::new().create(endpoint.path()).unwrap();
    let err = root.bind(&endpoint).unwrap_err();
    assert!(matches!(err, IpcError::NameTaken { .. }), "{err}");
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ho2_a_path_squatted_by_a_file_or_socket_is_refused() {
    let root = root();
    let endpoint = root.endpoint().unwrap();
    let _squatter = std::os::unix::net::UnixListener::bind(endpoint.path()).unwrap();
    let err = root.bind(&endpoint).unwrap_err();
    assert!(matches!(err, IpcError::NameTaken { .. }), "{err}");

    let endpoint = root.endpoint().unwrap();
    std::fs::write(endpoint.path(), b"").unwrap();
    let err = root.bind(&endpoint).unwrap_err();
    assert!(matches!(err, IpcError::NameTaken { .. }), "{err}");
    std::fs::remove_file(endpoint.path()).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_burst_of_256_parallel_clients_all_get_through() {
    let root = root();
    let listener = root.listen().unwrap();
    let path = listener.endpoint().path().to_path_buf();
    let echo = spawn_echo(listener);

    let clients: Vec<_> = (0..256u32)
        .map(|i| {
            let path = path.clone();
            tokio::spawn(async move {
                let mut c = connect(&path).await?;
                let msg = format!("client {i}").into_bytes();
                let back = roundtrip(&mut c, &msg).await;
                assert_eq!(back, msg);
                Ok::<(), IpcError>(())
            })
        })
        .collect();
    let mut failures = Vec::new();
    for c in clients {
        if let Err(e) = timeout(WAIT, c).await.unwrap().unwrap() {
            failures.push(e.to_string());
        }
    }
    assert!(
        failures.is_empty(),
        "{} failed: {failures:?}",
        failures.len()
    );
    echo.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vectored_writes_arrive_in_order() {
    let root = root();
    let listener = root.listen().unwrap();
    let path = listener.endpoint().path().to_path_buf();
    let echo = spawn_echo(listener);

    let mut c = connect(&path).await.unwrap();
    assert_eq!(
        tokio::io::AsyncWrite::is_write_vectored(&c),
        cfg!(unix),
        "unix streams write vectored, pipes don't"
    );
    let parts = [std::io::IoSlice::new(b"ab"), std::io::IoSlice::new(b"cd")];
    // A partial write is legal; finish whatever is left with write_all.
    let n = c.write_vectored(&parts).await.unwrap();
    assert!(n > 0);
    c.write_all(&b"abcd"[n..]).await.unwrap();
    c.flush().await.unwrap();
    let mut back = [0u8; 4];
    c.read_exact(&mut back).await.unwrap();
    assert_eq!(&back, b"abcd");
    echo.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_large_transfer_arrives_intact() {
    let root = root();
    let listener = root.listen().unwrap();
    let path = listener.endpoint().path().to_path_buf();
    let echo = spawn_echo(listener);

    let payload: Vec<u8> = (0..8 * 1024 * 1024u32).map(|i| (i % 251) as u8).collect();
    let mut c = connect(&path).await.unwrap();
    let (mut r, mut w) = tokio::io::split(&mut c);
    let outgoing = payload.clone();
    let ((), back) = tokio::join!(
        async move {
            w.write_all(&outgoing).await.unwrap();
        },
        async move {
            let mut back = vec![0u8; 8 * 1024 * 1024];
            r.read_exact(&mut back).await.unwrap();
            back
        }
    );
    assert_eq!(back.len(), payload.len());
    assert_eq!(back, payload);
    echo.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn closing_the_listener_closes_the_endpoint() {
    let root = root();
    // Repeated: the Windows race this pins (an aborted acceptor's instance still listening
    // after `close`) shows only now and then.
    for _ in 0..50 {
        let listener = root.listen().unwrap();
        let endpoint = listener.endpoint().clone();
        listener.close().await;
        let err = connect(endpoint.path()).await.unwrap_err();
        assert!(matches!(err, IpcError::NotFound { .. }), "{err}");
        // The name is free again for puddle (not for anyone else: it was random).
        root.bind(&endpoint).unwrap().close().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_half_closes_only_on_unix() {
    // Pinned so protocols over these endpoints (SSH bridge, T-114) frame their own end: on a
    // named pipe `shutdown` is a no-op and the peer sees EOF only when the handle closes.
    let root = root();
    let mut listener = root.listen().unwrap();
    let path = listener.endpoint().path().to_path_buf();
    let client = tokio::spawn(async move {
        let mut c = connect(&path).await.unwrap();
        c.write_all(b"a").await.unwrap();
        c.shutdown().await.unwrap();
        let after = c.write_all(b"b").await;
        assert_eq!(after.is_ok(), cfg!(windows), "{after:?}");
        let mut done = [0u8; 1];
        c.read_exact(&mut done).await.unwrap();
    });
    let mut server = timeout(WAIT, listener.accept()).await.unwrap().unwrap();
    let mut got = Vec::new();
    if cfg!(windows) {
        let mut two = [0u8; 2];
        server.read_exact(&mut two).await.unwrap();
        got.extend_from_slice(&two);
    } else {
        server.read_to_end(&mut got).await.unwrap(); // EOF after "a"
    }
    assert_eq!(got, if cfg!(windows) { &b"ab"[..] } else { &b"a"[..] });
    server.write_all(b"k").await.unwrap();
    client.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connecting_to_nothing_is_not_found() {
    let root = root();
    let endpoint = root.endpoint().unwrap();
    let err = connect(endpoint.path()).await.unwrap_err();
    assert!(matches!(err, IpcError::NotFound { .. }), "{err}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accept_is_cancel_safe() {
    let root = root();
    let mut listener = root.listen().unwrap();
    // A cancelled accept with no client waiting loses nothing...
    assert!(
        timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err()
    );
    // ...and the next client is still accepted.
    let path = listener.endpoint().path().to_path_buf();
    let client = tokio::spawn(async move { connect(&path).await.unwrap() });
    timeout(WAIT, listener.accept()).await.unwrap().unwrap();
    client.await.unwrap();
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};

    fn mode(path: &std::path::Path) -> u32 {
        std::fs::symlink_metadata(path)
            .unwrap()
            .permissions()
            .mode()
            & 0o7777
    }

    #[tokio::test]
    async fn ho1_socket_is_0600_in_a_0700_dir() {
        let root = root();
        let listener = root.listen().unwrap();
        let sock = listener.endpoint().path();
        assert_eq!(mode(root.dir()), 0o700);
        assert_eq!(mode(sock), 0o600);
        assert!(
            std::fs::symlink_metadata(sock)
                .unwrap()
                .file_type()
                .is_socket()
        );
        assert_eq!(sock.parent(), Some(root.dir()));
    }

    #[tokio::test]
    async fn the_mode_holds_under_a_permissive_umask_and_parent() {
        // A world-writable parent (like /tmp without the sticky bit) doesn't widen anything.
        let parent = IpcRoot::new_in(&std::env::temp_dir()).unwrap();
        std::fs::set_permissions(parent.dir(), std::fs::Permissions::from_mode(0o777)).unwrap();
        let root = IpcRoot::new_in(parent.dir()).unwrap();
        let listener = root.listen().unwrap();
        assert_eq!(mode(root.dir()), 0o700);
        assert_eq!(mode(listener.endpoint().path()), 0o600);
        drop(listener);
        drop(root);
        std::fs::set_permissions(parent.dir(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[tokio::test]
    async fn an_endpoint_from_another_root_is_refused() {
        let a = root();
        let b = root();
        let err = a.bind(&b.endpoint().unwrap()).unwrap_err();
        assert!(matches!(err, IpcError::ForeignEndpoint { .. }), "{err}");
    }

    #[tokio::test]
    async fn socket_file_and_dir_are_removed_when_dropped() {
        let root = root();
        let dir = root.dir().to_path_buf();
        let listener = root.listen().unwrap();
        let sock = listener.endpoint().path().to_path_buf();
        drop(root); // the listener keeps the dir alive
        assert!(dir.is_dir());
        drop(listener);
        assert!(!sock.exists());
        assert!(!dir.exists());
    }

    #[tokio::test]
    async fn too_long_a_parent_is_refused_with_the_limit() {
        // Deep enough that <parent>/puddle-<32>/<32>.sock passes the sun_path limit.
        let mut parent = std::env::temp_dir();
        let base = IpcRoot::new_in(&parent).unwrap();
        parent = base.dir().join("d".repeat(60));
        std::fs::create_dir(&parent).unwrap();
        let root = IpcRoot::new_in(&parent).unwrap();
        let err = root.listen().unwrap_err();
        assert!(matches!(err, IpcError::PathTooLong { .. }), "{err}");
        drop(root);
        std::fs::remove_dir(&parent).unwrap();
    }

    #[tokio::test]
    async fn a_bind_failure_other_than_a_taken_name_is_an_io_error() {
        let root = root();
        let endpoint = root.endpoint().unwrap();
        std::fs::set_permissions(root.dir(), std::fs::Permissions::from_mode(0o500)).unwrap();
        let err = root.bind(&endpoint).unwrap_err();
        std::fs::set_permissions(root.dir(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(err, IpcError::Io { op: "bind", .. }), "{err}");
    }

    #[tokio::test]
    async fn a_socket_file_removed_early_does_not_upset_the_drop() {
        let root = root();
        let listener = root.listen().unwrap();
        std::fs::remove_file(listener.endpoint().path()).unwrap();
        drop(listener);
        assert_eq!(std::fs::read_dir(root.dir()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn a_client_without_permission_is_denied() {
        // Same user, but the socket's write bit removed: connect needs it, so this exercises
        // the AccessDenied path a different user would hit.
        let root = root();
        let listener = root.listen().unwrap();
        let sock = listener.endpoint().path();
        std::fs::set_permissions(sock, std::fs::Permissions::from_mode(0o000)).unwrap();
        let err = connect(sock).await.unwrap_err();
        assert!(matches!(err, IpcError::AccessDenied { .. }), "{err}");
    }
}
