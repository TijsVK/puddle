// SPDX-License-Identifier: GPL-3.0-or-later
//! I test: an OOM kill in the (fake) guest kernel becomes one `Event::OomKill` on the host.
#![cfg(unix)]
#![expect(
    clippy::unwrap_used,
    unreachable_pub,
    reason = "helpers outside #[test] fns, and the shared harness module, run only in tests"
)]

mod common;

use std::io::Write;
use std::time::Duration;

use puddle_agent::config::OomSources;
use puddle_types::Event;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[tokio::test]
async fn a_guest_oom_kill_becomes_one_event_on_the_hosts_sink_within_2_s() {
    let mut rig = common::rig("oom", |dir| {
        std::fs::write(dir.join("vmstat"), "oom_kill 0\n").unwrap();
        std::fs::write(dir.join("kmsg"), "").unwrap();
        Some(OomSources {
            vmstat: dir.join("vmstat"),
            kmsg: dir.join("kmsg"),
            poll: Duration::from_millis(50),
            grace: Duration::from_millis(300),
        })
    })
    .await;
    let (vmstat, kmsg) = (rig.dir.0.join("vmstat"), rig.dir.0.join("kmsg"));

    // A normal run: no event.
    assert_eq!(
        common::next_event(&mut rig.events, Duration::from_millis(500)).await,
        None
    );

    std::fs::write(&vmstat, "oom_kill 1\n").unwrap();
    std::fs::OpenOptions::new()
        .append(true)
        .open(&kmsg)
        .unwrap()
        .write_all(b"3,9,9,-;Out of memory: Killed process 31337 (python3) total-vm:1048576kB, anon-rss:524288kB\n")
        .unwrap();
    let event = common::next_event(&mut rig.events, Duration::from_secs(2))
        .await
        .expect("no event within 2 s");
    assert_eq!(event, Event::oom_kill(common::sandbox(), 31337, "python3"));
    // Exactly one: the counter increase was matched to the log line.
    assert_eq!(
        common::next_event(&mut rig.events, Duration::from_millis(800)).await,
        None
    );

    // The host restarts (puddle restarted, sessions gone): the next kill still arrives, on a
    // control stream the agent reopened.
    rig.restart_host().await;
    std::fs::write(&vmstat, "oom_kill 2\n").unwrap();
    std::fs::OpenOptions::new()
        .append(true)
        .open(&kmsg)
        .unwrap()
        .write_all(b"3,10,10,-;Out of memory: Killed process 4040 (node) total-vm:1kB\n")
        .unwrap();
    let event = common::next_event(&mut rig.events, Duration::from_secs(5))
        .await
        .expect("no event after the host restart");
    assert_eq!(event, Event::oom_kill(common::sandbox(), 4040, "node"));

    // The agent still relays: the host answers a CONNECT to a closed port with 502.
    let gone = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap();
    let mut conn = TcpStream::connect(rig.agent.local_addr()).await.unwrap();
    conn.write_all(format!("CONNECT {gone} HTTP/1.1\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut reply = Vec::new();
    conn.read_to_end(&mut reply).await.unwrap();
    assert!(
        reply.starts_with(b"HTTP/1.1 502"),
        "{:?}",
        String::from_utf8_lossy(&reply)
    );
}
