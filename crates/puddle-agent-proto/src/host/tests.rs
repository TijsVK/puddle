// SPDX-License-Identifier: GPL-3.0-or-later
use std::time::Duration;

use futures_util::StreamExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_yamux::{Control, Session};

use super::*;
use crate::control::PREAMBLE;
use crate::kind::StreamKind;
use crate::yamux::client_config;

const WAIT: Duration = Duration::from_secs(5);

struct ChanSink(mpsc::UnboundedSender<Event>);

impl EventSink for ChanSink {
    fn emit(&self, event: Event) {
        // The receiver outlives every session in these tests.
        let _ = self.0.send(event);
    }
}

/// Echoes a stream back, first byte included.
struct Echo;

impl StreamHandler for Echo {
    async fn handle(&self, mut stream: GuestStream) {
        let mut buf = Vec::new();
        if stream.read_to_end(&mut buf).await.is_ok() {
            let _ = stream.write_all(&buf).await;
            let _ = stream.shutdown().await;
        }
    }
}

struct Harness {
    control: Control,
    server: JoinHandle<Result<(), SessionError>>,
    events: mpsc::UnboundedReceiver<Event>,
    _driver: JoinHandle<()>,
}

fn name() -> SandboxName {
    SandboxName::new("box").unwrap()
}

fn start_with(config: HostConfig) -> Harness {
    let (guest, host) = tokio::io::duplex(1 << 20);
    let (tx, events) = mpsc::unbounded_channel();
    let server = tokio::spawn(serve_session(
        host,
        name(),
        Arc::new(ChanSink(tx)),
        Arc::new(Echo),
        config,
    ));
    let mut client = Session::new_client(guest, client_config());
    let control = client.control();
    let driver = tokio::spawn(async move { while client.next().await.is_some() {} });
    Harness {
        control,
        server,
        events,
        _driver: driver,
    }
}

fn start() -> Harness {
    start_with(HostConfig::default())
}

impl Harness {
    async fn control_stream(&mut self) -> StreamHandle {
        let mut s = self.control.open_stream().await.unwrap();
        s.write_all(PREAMBLE).await.unwrap();
        s
    }

    async fn next_event(&mut self) -> Event {
        tokio::time::timeout(WAIT, self.events.recv())
            .await
            .expect("no event in time")
            .expect("sink closed")
    }

    async fn close(mut self) -> Result<(), SessionError> {
        self.control.close().await;
        tokio::time::timeout(WAIT, self.server)
            .await
            .unwrap()
            .unwrap()
    }
}

async fn send(stream: &mut StreamHandle, msg: &AgentMessage) {
    stream.write_all(&msg.to_line().unwrap()).await.unwrap();
}

#[tokio::test]
async fn a_proxied_stream_reaches_the_handler_with_its_first_byte() {
    let mut h = start();
    let mut s = h.control.open_stream().await.unwrap();
    s.write_all(b"CONNECT example.test:443 HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    s.shutdown().await.unwrap();
    let mut back = Vec::new();
    s.read_to_end(&mut back).await.unwrap();
    assert_eq!(back, b"CONNECT example.test:443 HTTP/1.1\r\n\r\n");
    h.close().await.unwrap();
}

#[tokio::test]
async fn oom_kills_on_the_control_stream_become_events_for_the_routes_sandbox() {
    let mut h = start();
    let mut c = h.control_stream().await;
    send(&mut c, &AgentMessage::hello()).await;
    send(
        &mut c,
        &AgentMessage::oom_kill(Some(2406), Some("tail".into())),
    )
    .await;
    send(&mut c, &AgentMessage::oom_kill(None, None)).await;
    send(
        &mut c,
        &AgentMessage::oom_kill(Some(9), Some("evil\u{1b}[2J".into())),
    )
    .await;
    assert_eq!(h.next_event().await, Event::oom_kill(name(), 2406, "tail"));
    assert_eq!(
        h.next_event().await,
        Event::oom_kill(name(), 0, UNKNOWN_PROCESS)
    );
    let Event::OomKill { process, .. } = h.next_event().await else {
        panic!("wrong event");
    };
    assert_eq!(process, "evil?[2J");
    h.close().await.unwrap();
}

#[tokio::test]
async fn unknown_and_invalid_messages_are_skipped_and_later_ones_still_count() {
    let mut h = start();
    let mut c = h.control_stream().await;
    c.write_all(b"{\"type\":\"future_thing\"}\nnot json\n{\"type\":\"hello\",\"agent_version\":\"\\u0007x\",\"protocol\":9}\n")
        .await
        .unwrap();
    send(&mut c, &AgentMessage::oom_kill(Some(1), Some("a".into()))).await;
    assert_eq!(h.next_event().await, Event::oom_kill(name(), 1, "a"));
    h.close().await.unwrap();
}

#[tokio::test]
async fn a_second_control_stream_on_a_session_is_refused_while_the_first_is_open() {
    let mut h = start();
    let mut first = h.control_stream().await;
    send(&mut first, &AgentMessage::hello()).await;
    // Let the host register the first stream before the second arrives.
    send(&mut first, &AgentMessage::oom_kill(Some(1), None)).await;
    assert_eq!(h.next_event().await, Event::oom_kill(name(), 1, "unknown"));

    let mut second = h.control_stream().await;
    send(&mut second, &AgentMessage::oom_kill(Some(2), None)).await;
    let mut buf = [0u8; 1];
    // The host dropped the second stream without a shutdown: a reset, not data.
    assert!(second.read(&mut buf).await.is_err());

    send(&mut first, &AgentMessage::oom_kill(Some(3), None)).await;
    assert_eq!(h.next_event().await, Event::oom_kill(name(), 3, "unknown"));

    // After the first one closes, a new control stream is accepted (agent reconnect).
    first.shutdown().await.unwrap();
    drop(first);
    let mut third = h.control_stream().await;
    let mut accepted = false;
    for pid in 4..200 {
        if third
            .write_all(&AgentMessage::oom_kill(Some(pid), None).to_line().unwrap())
            .await
            .is_err()
        {
            third = h.control_stream().await;
            continue;
        }
        if let Ok(Some(Event::OomKill { pid: got, .. })) =
            tokio::time::timeout(Duration::from_millis(50), h.events.recv()).await
        {
            assert!(got >= 4);
            accepted = true;
            break;
        }
    }
    assert!(
        accepted,
        "a control stream after the first closed was refused"
    );
    h.close().await.unwrap();
}

#[tokio::test]
async fn a_control_stream_with_a_bad_preamble_is_dropped() {
    let mut h = start();
    let mut s = h.control.open_stream().await.unwrap();
    s.write_all(b"\0puddle-kontrol/1\n").await.unwrap();
    send(&mut s, &AgentMessage::oom_kill(Some(1), None)).await;
    let mut buf = [0u8; 1];
    assert!(s.read(&mut buf).await.is_err());
    assert!(h.events.try_recv().is_err());
    h.close().await.unwrap();
}

#[tokio::test]
async fn reserved_and_malformed_stream_kinds_are_closed() {
    let mut h = start();
    for preamble in [
        StreamKind::Connect.preamble(),
        StreamKind::SshAgent.preamble(),
        b"\0puddle-control/2\n",
        b"\0no newline in sixty-four bytes .................................................",
    ] {
        let mut s = h.control.open_stream().await.unwrap();
        s.write_all(preamble).await.unwrap();
        let mut buf = [0u8; 1];
        assert!(s.read(&mut buf).await.is_err(), "{preamble:?}");
    }
    h.close().await.unwrap();
}

#[tokio::test]
async fn an_over_long_control_line_ends_the_control_stream() {
    let mut h = start();
    let mut c = h.control_stream().await;
    c.write_all(&vec![b'x'; MAX_LINE + 1]).await.unwrap();
    let mut buf = [0u8; 1];
    assert!(c.read(&mut buf).await.is_err());
    h.close().await.unwrap();
}

#[tokio::test]
async fn control_messages_over_the_rate_limit_are_dropped() {
    let mut h = start_with(HostConfig {
        control_burst: 5,
        control_per_second: 1,
        ..HostConfig::default()
    });
    let mut c = h.control_stream().await;
    for pid in 0..50 {
        send(&mut c, &AgentMessage::oom_kill(Some(pid), None)).await;
    }
    c.shutdown().await.unwrap();
    let mut got = 0;
    while let Ok(Some(_)) = tokio::time::timeout(Duration::from_millis(300), h.events.recv()).await
    {
        got += 1;
    }
    assert!((5..=7).contains(&got), "{got} events got through");
    h.close().await.unwrap();
}

#[tokio::test]
async fn a_connection_that_is_not_yamux_is_refused() {
    let (mut guest, host) = tokio::io::duplex(64);
    let server = tokio::spawn(serve_session(
        host,
        name(),
        Arc::new(puddle_types::NullSink),
        Arc::new(Echo),
        HostConfig::default(),
    ));
    guest.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
    let err = server.await.unwrap().unwrap_err();
    assert!(matches!(err, SessionError::NotYamux(b'G')), "{err}");
    assert!(err.to_string().contains("0x47"));
}

#[tokio::test(start_paused = true)]
async fn a_silent_connection_times_out() {
    let serve = |host| {
        serve_session(
            host,
            name(),
            Arc::new(puddle_types::NullSink),
            Arc::new(Echo),
            HostConfig {
                first_byte_timeout: Duration::from_secs(1),
                ..HostConfig::default()
            },
        )
    };
    let (guest, host) = tokio::io::duplex(64);
    let result = serve(host).await;
    drop(guest);
    assert!(matches!(result, Err(SessionError::Timeout(_))));
    // A connection closed before any byte is a clean end.
    let (guest, host) = tokio::io::duplex(64);
    drop(guest);
    assert!(serve(host).await.is_ok());
}

#[tokio::test]
async fn a_failing_connection_is_an_io_error() {
    struct Broken;
    impl AsyncRead for Broken {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
        }
    }
    impl AsyncWrite for Broken {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    let result = serve_session(
        Broken,
        name(),
        Arc::new(puddle_types::NullSink),
        Arc::new(Echo),
        HostConfig::default(),
    )
    .await;
    assert!(matches!(result, Err(SessionError::Io(_))));
}

#[test]
fn rate_limit_refills_at_its_rate_up_to_the_burst() {
    let t0 = Instant::now();
    let mut limit = RateLimit::new(2, 4, t0);
    assert!(limit.allow(t0));
    assert!(limit.allow(t0));
    assert!(!limit.allow(t0));
    assert_eq!(limit.suppressed, 1);
    // A quarter second buys one message at 4/s.
    assert!(limit.allow(t0 + Duration::from_millis(250)));
    assert!(!limit.allow(t0 + Duration::from_millis(250)));
    // A long pause refills to the burst, not beyond.
    let later = t0 + Duration::from_secs(60);
    assert!(limit.allow(later));
    assert!(limit.allow(later));
    assert!(!limit.allow(later));
}

#[test]
fn guest_text_for_logs_is_cut_and_cleaned() {
    assert_eq!(clean("a\u{7}b", 10), "a?b");
    assert_eq!(clean(&"v".repeat(100), MAX_VERSION_CHARS).len(), 64);
}
