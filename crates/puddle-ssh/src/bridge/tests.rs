// SPDX-License-Identifier: GPL-3.0-or-later
//! The relay's end-of-stream rules on in-memory streams (the endpoint and pipe versions are in
//! `tests/`).

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{DuplexStream, ReadBuf, duplex};
use tokio::time::timeout;

use super::*;
use crate::{HELLO, refusal_line};

const WAIT: Duration = Duration::from_secs(30);

/// A deterministic byte at stream offset `i` (not periodic in any small power of two, so a lost,
/// doubled or reordered chunk shows).
fn pattern_byte(seed: u8, i: u64) -> u8 {
    let x = i.wrapping_mul(2_654_435_761).wrapping_add(u64::from(seed));
    (x ^ (x >> 13)).to_le_bytes()[0]
}

async fn write_pattern<W: AsyncWrite + Unpin>(w: &mut W, seed: u8, len: u64) {
    let mut buf = vec![0_u8; 50_000];
    let mut off = 0_u64;
    while off < len {
        let n = usize::try_from((len - off).min(buf.len() as u64)).unwrap();
        for (j, b) in buf[..n].iter_mut().enumerate() {
            *b = pattern_byte(seed, off + j as u64);
        }
        w.write_all(&buf[..n]).await.unwrap();
        off += n as u64;
    }
}

/// Reads to EOF and checks every byte against the pattern; returns the length.
async fn read_pattern<R: AsyncRead + Unpin>(r: &mut R, seed: u8) -> u64 {
    let mut buf = vec![0_u8; 70_001];
    let mut off = 0_u64;
    loop {
        let n = r.read(&mut buf).await.unwrap();
        if n == 0 {
            return off;
        }
        for (j, b) in buf[..n].iter().enumerate() {
            assert_eq!(
                *b,
                pattern_byte(seed, off + j as u64),
                "byte {}",
                off + j as u64
            );
        }
        off += n as u64;
    }
}

/// The three streams around a relay: what the test holds for `ssh`'s stdin and stdout, and the
/// server's end.
struct Rig {
    stdin: DuplexStream,
    stdout: DuplexStream,
    server: DuplexStream,
}

/// The streams, with the endpoint's hello already sent.
async fn rig() -> (Rig, DuplexStream, DuplexStream, DuplexStream) {
    let (stdin, relay_in) = duplex(256 * 1024);
    let (relay_out, stdout) = duplex(256 * 1024);
    let (relay_server, mut server) = duplex(256 * 1024);
    server.write_all(HELLO.as_bytes()).await.unwrap();
    (
        Rig {
            stdin,
            stdout,
            server,
        },
        relay_in,
        relay_out,
        relay_server,
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn large_transfers_both_ways_at_once_arrive_intact() {
    const LEN: u64 = 64 * 1024 * 1024;
    let (rig, i, o, s) = rig().await;
    let relay = tokio::spawn(relay(i, o, s));
    let Rig {
        mut stdin,
        mut stdout,
        server,
    } = rig;
    let (mut server_rd, mut server_wr) = tokio::io::split(server);
    let client_sends = async move {
        write_pattern(&mut stdin, 1, LEN).await;
        stdin.shutdown().await.unwrap();
    };
    // Like an SSH server: it sends while it receives, and closes only after the client's end.
    let server = async move {
        let ((), got) = tokio::join!(
            write_pattern(&mut server_wr, 2, LEN),
            read_pattern(&mut server_rd, 1)
        );
        server_wr.shutdown().await.unwrap();
        got
    };
    let ((), server_got, client_got) = timeout(WAIT * 4, async {
        tokio::join!(client_sends, server, read_pattern(&mut stdout, 2))
    })
    .await
    .unwrap();
    assert_eq!((server_got, client_got), (LEN, LEN));
    let report = relay.await.unwrap().unwrap();
    assert_eq!(report.end, SessionEnd::ServerClosed);
    assert_eq!((report.sent, report.received), (LEN, LEN));
    assert!(report.input_ended);
}

#[tokio::test]
async fn client_eof_half_closes_and_the_server_can_still_answer() {
    let (mut rig, i, o, s) = rig().await;
    let relay = tokio::spawn(relay(i, o, s));
    rig.stdin.write_all(b"request").await.unwrap();
    rig.stdin.shutdown().await.unwrap();
    // The server sees the request, then the end of the client's input...
    let mut got = Vec::new();
    timeout(WAIT, rig.server.read_to_end(&mut got))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got, b"request");
    // ...and its answer still reaches the client, followed by EOF.
    rig.server.write_all(b"SSH-2.0-answer").await.unwrap();
    drop(rig.server);
    let mut out = Vec::new();
    timeout(WAIT, rig.stdout.read_to_end(&mut out))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(out, b"SSH-2.0-answer");
    let report = relay.await.unwrap().unwrap();
    assert_eq!(report.end, SessionEnd::ServerClosed);
    assert_eq!((report.sent, report.received), (7, 14));
    assert!(report.input_ended);
}

#[tokio::test]
async fn server_eof_ends_the_session_while_the_input_stays_open() {
    let (mut rig, i, o, s) = rig().await;
    let relay = tokio::spawn(relay(i, o, s));
    rig.stdin.write_all(b"partial").await.unwrap();
    let mut first = [0_u8; 7];
    rig.server.read_exact(&mut first).await.unwrap();
    rig.server.write_all(b"SSH-2.0-bye\r\n").await.unwrap();
    rig.server.shutdown().await.unwrap();
    // stdin is still open and silent: the relay must end anyway.
    let report = timeout(WAIT, relay).await.unwrap().unwrap().unwrap();
    assert_eq!(report.end, SessionEnd::ServerClosed);
    assert!(!report.input_ended);
    assert_eq!((report.sent, report.received), (7, 13));
    let mut out = Vec::new();
    timeout(WAIT, rig.stdout.read_to_end(&mut out))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(out, b"SSH-2.0-bye\r\n");
    // The relay dropped its end: the server sees the close too.
    let mut rest = Vec::new();
    rig.server.read_to_end(&mut rest).await.unwrap();
    assert_eq!(rest, b"");
    drop(rig.stdin);
}

#[tokio::test]
async fn server_gone_while_the_client_keeps_sending_ends_the_session() {
    let (rig, i, o, s) = rig().await;
    let Rig {
        mut stdin,
        mut stdout,
        server,
    } = rig;
    let relay = tokio::spawn(relay(i, o, s));
    let sender = tokio::spawn(async move {
        // Keeps sending until the relay stops reading.
        let chunk = vec![7_u8; 32 * 1024];
        while stdin.write_all(&chunk).await.is_ok() {}
    });
    drop(server);
    let report = timeout(WAIT, relay).await.unwrap().unwrap().unwrap();
    assert_eq!(report.end, SessionEnd::ServerClosed);
    assert_eq!(report.received, 0);
    let mut out = Vec::new();
    stdout.read_to_end(&mut out).await.unwrap();
    assert_eq!(out, b"");
    timeout(WAIT, sender).await.unwrap().unwrap();
}

#[tokio::test]
async fn client_gone_ends_the_session_and_closes_the_server_stream() {
    let (rig, i, o, s) = rig().await;
    let Rig {
        stdin,
        stdout,
        mut server,
    } = rig;
    drop(stdout);
    let relay = tokio::spawn(relay(i, o, s));
    server.write_all(b"SSH-2.0-x\r\n").await.unwrap();
    let report = timeout(WAIT, relay).await.unwrap().unwrap().unwrap();
    assert_eq!(report.end, SessionEnd::ClientGone);
    assert_eq!(report.received, 0);
    let mut rest = Vec::new();
    timeout(WAIT, server.read_to_end(&mut rest))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rest, b"");
    drop(stdin);
}

#[tokio::test]
async fn client_gone_mid_session_is_reported() {
    let (rig, i, o, s) = rig().await;
    let Rig {
        stdin,
        mut stdout,
        mut server,
    } = rig;
    let relay = tokio::spawn(relay(i, o, s));
    server.write_all(b"SSH-2.0-x\r\n").await.unwrap();
    let mut banner = [0_u8; 11];
    stdout.read_exact(&mut banner).await.unwrap();
    drop(stdout);
    server.write_all(b"more").await.unwrap();
    let report = timeout(WAIT, relay).await.unwrap().unwrap().unwrap();
    assert_eq!(report.end, SessionEnd::ClientGone);
    assert_eq!(report.received, 11);
    drop(stdin);
}

#[tokio::test]
async fn a_refusal_is_an_error_and_nothing_reaches_the_client() {
    let (mut rig, i, o, s) = rig().await;
    let relay = tokio::spawn(relay(i, o, s));
    rig.server
        .write_all(refusal_line("workspace \"a\": workspace is not running").as_bytes())
        .await
        .unwrap();
    drop(rig.server);
    let err = timeout(WAIT, relay).await.unwrap().unwrap().unwrap_err();
    assert!(
        matches!(&err, BridgeError::Refused { reason } if reason == "workspace \"a\": workspace is not running"),
        "{err:?}"
    );
    assert_eq!(err.to_string(), "workspace \"a\": workspace is not running");
    let mut out = Vec::new();
    rig.stdout.read_to_end(&mut out).await.unwrap();
    assert!(out.is_empty(), "{out:?}");
}

/// A stream whose reads fail and whose writes succeed.
struct Broken;

impl AsyncRead for Broken {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::from(io::ErrorKind::ConnectionReset)))
    }
}

impl AsyncWrite for Broken {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn a_server_read_error_is_reported() {
    let (_stdin, i) = duplex(64);
    let (o, _stdout) = duplex(64);
    let err = relay(i, o, Broken).await.unwrap_err();
    assert!(matches!(err, BridgeError::ServerRead(_)), "{err:?}");
    assert_eq!(err.to_string(), "the connection to the workspace broke");
}

#[tokio::test]
async fn a_server_read_error_mid_session_is_reported() {
    /// Sends a hello and a banner, then fails.
    struct BannerThenBroken(Vec<u8>);
    impl AsyncRead for BannerThenBroken {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.0.is_empty() {
                return Poll::Ready(Err(io::Error::from(io::ErrorKind::ConnectionReset)));
            }
            let n = self.0.len().min(buf.remaining());
            buf.put_slice(&self.0[..n]);
            self.0.drain(..n);
            Poll::Ready(Ok(()))
        }
    }
    impl AsyncWrite for BannerThenBroken {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    let (_stdin, i) = duplex(64);
    let (o, mut stdout) = duplex(64);
    let mut bytes = HELLO.as_bytes().to_vec();
    bytes.extend_from_slice(b"SSH-2.0-x\r\n");
    let err = relay(i, o, BannerThenBroken(bytes)).await.unwrap_err();
    assert!(matches!(err, BridgeError::ServerRead(_)), "{err:?}");
    let mut banner = [0_u8; 11];
    stdout.read_exact(&mut banner).await.unwrap();
    assert_eq!(&banner, b"SSH-2.0-x\r\n");
}

#[tokio::test]
async fn a_client_input_error_counts_as_the_end_of_input() {
    let (o, mut stdout) = duplex(1024);
    let (relay_server, mut server) = duplex(1024);
    let relay = tokio::spawn(relay(Broken, o, relay_server));
    server.write_all(HELLO.as_bytes()).await.unwrap();
    let mut got = Vec::new();
    timeout(WAIT, server.read_to_end(&mut got))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got, b"");
    server.write_all(b"SSH-2.0-x").await.unwrap();
    drop(server);
    let report = relay.await.unwrap().unwrap();
    assert!(report.input_ended);
    assert_eq!(report.received, 9);
    let mut out = Vec::new();
    stdout.read_to_end(&mut out).await.unwrap();
    assert_eq!(out, b"SSH-2.0-x");
}

#[tokio::test]
async fn a_server_that_stops_reading_doesnt_stop_its_output() {
    // Writes to the server block (it reads nothing) while its output keeps coming.
    let (mut stdin, i) = duplex(1 << 20);
    let (o, mut stdout) = duplex(1 << 20);
    let (relay_server, mut server) = duplex(1024);
    server.write_all(HELLO.as_bytes()).await.unwrap();
    let relay = tokio::spawn(relay(i, o, relay_server));
    stdin.write_all(&vec![1_u8; 512 * 1024]).await.unwrap();
    let (server_rd, mut server_wr) = tokio::io::split(server);
    let writer = tokio::spawn(async move {
        write_pattern(&mut server_wr, 3, 4 * 1024 * 1024).await;
        server_wr.shutdown().await.unwrap();
    });
    assert_eq!(
        timeout(WAIT, read_pattern(&mut stdout, 3)).await.unwrap(),
        4 * 1024 * 1024
    );
    writer.await.unwrap();
    drop(server_rd);
    let report = timeout(WAIT, relay).await.unwrap().unwrap().unwrap();
    assert_eq!(report.end, SessionEnd::ServerClosed);
    drop(stdin);
}

#[tokio::test(start_paused = true)]
async fn an_idle_session_is_never_timed_out() {
    let (mut rig, i, o, s) = rig().await;
    let relay = tokio::spawn(relay(i, o, s));
    rig.server.write_all(b"SSH-2.0-x\r\n").await.unwrap();
    let mut banner = [0_u8; 11];
    rig.stdout.read_exact(&mut banner).await.unwrap();
    // Fifteen idle minutes (a paused clock jumps them) and more: nothing ends the session.
    tokio::time::sleep(Duration::from_mins(15)).await;
    tokio::time::sleep(Duration::from_hours(24)).await;
    assert!(!relay.is_finished());
    rig.stdin.write_all(b"ping").await.unwrap();
    let mut request = [0_u8; 4];
    rig.server.read_exact(&mut request).await.unwrap();
    rig.server.write_all(b"pong").await.unwrap();
    let mut answer = [0_u8; 4];
    rig.stdout.read_exact(&mut answer).await.unwrap();
    assert_eq!((&request, &answer), (b"ping", b"pong"));
    drop(rig.server);
    relay.await.unwrap().unwrap();
}

#[tokio::test(start_paused = true)]
async fn an_endpoint_that_never_says_hello_is_given_up_on() {
    let (_stdin, i) = duplex(64);
    let (o, mut stdout) = duplex(64);
    let (relay_server, _server) = duplex(64);
    let err = relay(i, o, relay_server).await.unwrap_err();
    assert!(
        matches!(err, BridgeError::NoAnswer { waited } if waited == HELLO_TIMEOUT),
        "{err:?}"
    );
    assert!(
        err.to_string()
            .starts_with("the SSH endpoint did not answer within 10s")
    );
    let mut out = Vec::new();
    stdout.read_to_end(&mut out).await.unwrap();
    assert_eq!(out, b"");
}

#[tokio::test]
async fn something_other_than_puddle_is_not_relayed() {
    for answer in [&b"SSH-2.0-OpenSSH_9.9\r\n"[..], b"puddle-ssh/2\r\n", b"pud"] {
        let (_stdin, i) = duplex(64);
        let (o, mut stdout) = duplex(64);
        let (relay_server, mut server) = duplex(64);
        server.write_all(answer).await.unwrap();
        drop(server);
        let err = relay(i, o, relay_server).await.unwrap_err();
        assert!(matches!(err, BridgeError::NotPuddle), "{answer:?}: {err:?}");
        let mut out = Vec::new();
        stdout.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"");
    }
}
