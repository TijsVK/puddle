// SPDX-License-Identifier: GPL-3.0-or-later
//! I test with a real Linux bridge (T-099): the built agent binary runs in its own network
//! namespace (`unshare -n`), where the test script creates, deletes and re-creates a bridge that
//! owns `172.17.0.1`, the way dockerd's `docker0` comes and goes. It checks with `ss` what the
//! agent really listens on, and that a client on the bridge address gets through to the host
//! endpoint (this process, over a Unix socket) and its echo server.
//!
//! Needs `unshare` with either unprivileged user namespaces or passwordless `sudo`; the test
//! fails, not skips, when neither works.
#![cfg(target_os = "linux")]
#![expect(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    unreachable_pub,
    reason = "helpers outside #[test] fns, and the shared harness module, run only in tests"
)]

#[expect(dead_code, reason = "shared harness; this test uses part of it")]
mod common;

use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::process::Command;

/// Runs inside the new namespace. Exit codes name the step that failed.
const SCRIPT: &str = r#"
set -u
step() { echo "STEP $*"; }
fail() { echo "FAIL $*"; ss -ltn; exit 1; }
mount -t sysfs sysfs /sys || fail "sysfs"
ip link set lo up
"$AGENT" &
agent=$!
trap 'kill $agent 2>/dev/null' EXIT

# listeners on the proxy port, as "addr:port" lines
listeners() { ss -ltnH 'sport = :3128' | awk '{print $4}' | sort; }
wait_for() { # wait_for <what> <command...>
  what=$1; shift
  for _ in $(seq 1 100); do "$@" && return 0; sleep 0.05; done
  fail "timeout waiting for $what"
}
loopback_up() { [ "$(listeners)" = "127.0.0.1:3128" ]; }
bridge_up() { listeners | grep -qx "172.17.0.1:3128"; }
bridge_down() { ! bridge_up; }
echo_via_bridge() {
  timeout 5 bash -c '
    exec 3<>/dev/tcp/172.17.0.1/3128
    printf "CONNECT %s HTTP/1.1\r\n\r\n" "$ECHO" >&3
    read -r -t 3 status <&3; read -r -t 3 blank <&3
    case $status in "HTTP/1.1 200"*) ;; *) exit 1;; esac
    printf "ping\n" >&3; read -r -t 3 line <&3
    [ "$line" = ping ]'
}
make_bridge() {
  ip link add "$1" type bridge && ip addr add 172.17.0.1/16 dev "$1" && ip link set "$1" up
}

wait_for "the loopback listener" loopback_up
step "no-bridge: only loopback listens"
sleep 0.5
[ "$(listeners)" = "127.0.0.1:3128" ] || fail "listening before the bridge exists: $(listeners)"

# An address on a dummy (not a bridge) interface must not open a listener either.
ip link add d0 type dummy && ip addr add 172.17.0.1/16 dev d0 && ip link set d0 up
step "dummy: an interface that is not a bridge"
sleep 0.5
[ "$(listeners)" = "127.0.0.1:3128" ] || fail "listening on a non-bridge: $(listeners)"
ip link del d0

for round in 1 2 3; do
  make_bridge "br-t$round" || fail "make_bridge $round"
  wait_for "the bridge listener (round $round)" bridge_up
  step "up $round: $(listeners | tr '\n' ' ')"
  [ "$(listeners)" = "$(printf '127.0.0.1:3128\n172.17.0.1:3128')" ] || fail "wrong listeners: $(listeners)"
  wait_for "a tunnel through the bridge (round $round)" echo_via_bridge
  step "relay $round"
  ip link del "br-t$round" || fail "del $round"
  wait_for "the bridge listener to close (round $round)" bridge_down
  step "down $round: $(listeners | tr '\n' ' ')"
  loopback_up || fail "loopback listener lost"
done
step "done"
"#;

/// The command prefix that gives a root-like shell in a new network namespace with its own
/// `/sys`: unprivileged first, then passwordless `sudo`.
async fn namespace_runner() -> Vec<&'static str> {
    for runner in [
        vec!["unshare", "-Urnm"],
        vec!["sudo", "-n", "unshare", "-nm"],
    ] {
        let ok = Command::new(runner[0])
            .args(&runner[1..])
            .args([
                "sh",
                "-c",
                "mount -t sysfs sysfs /sys && ip link add t0 type bridge",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .is_ok_and(|s| s.success());
        if ok {
            return runner;
        }
    }
    panic!(
        "no way to create a network namespace with a bridge: need `unshare -Urnm` or passwordless `sudo unshare -nm`"
    );
}

#[tokio::test]
async fn a_real_bridge_that_comes_goes_and_returns_is_followed_by_the_agent_binary() {
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut conn, _) = echo.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = conn.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
                let _ = w.shutdown().await;
            });
        }
    });
    let dir = common::TempDir::new("realbr");
    let socket = dir.0.join("route.sock");
    let (tx, _events) = tokio::sync::mpsc::unbounded_channel();
    let host = common::start_host(&socket, Arc::new(common::ChanSink(tx)));
    // Give the (possibly root) agent in the namespace access to the socket's directory.
    std::fs::set_permissions(&dir.0, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();

    let runner = namespace_runner().await;
    let output = tokio::time::timeout(
        Duration::from_secs(90),
        Command::new(runner[0])
            .args(&runner[1..])
            // `env` sets the variables inside the namespace: `sudo` would drop them.
            .arg("env")
            .arg(format!("AGENT={}", env!("CARGO_BIN_EXE_puddle-agent")))
            .arg(format!("ECHO={echo_addr}"))
            .arg(format!("PUDDLE_AGENT_TARGET=unix://{}", socket.display()))
            .args(["PUDDLE_AGENT_OOM=0", "PUDDLE_AGENT_BRIDGE_POLL_MS=20"])
            .args(["bash", "-c", SCRIPT])
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("the namespace script did not finish in 90 s")
    .unwrap();
    host.abort();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("STEP done"),
        "script failed\n--- stdout\n{stdout}\n--- stderr\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    for marker in [
        "STEP no-bridge",
        "STEP dummy",
        "STEP up 1",
        "STEP relay 1",
        "STEP down 1",
        "STEP up 3",
        "STEP relay 3",
        "STEP down 3",
    ] {
        assert!(stdout.contains(marker), "missing {marker}\n{stdout}");
    }
}
