// SPDX-License-Identifier: GPL-3.0-or-later
//! `puddle-agent connect <host> <port> [<name>]`: the command `ssh` runs as its `ProxyCommand`
//! (`%h %p %n`) in a sandbox.
//!
//! `ssh` talks to it over stdin and stdout, and the command carries that connection to the proxy
//! through the agent's listener as a `CONNECT`. SSH is not supported yet: the command reads the
//! client's identification line first, and when it is SSH (`SSH-2.0-...`, on any port) it says so
//! in the request ([`puddle_agent_proto::ssh::PROTOCOL_HEADER`]) and sends the line along, so the
//! proxy refuses it at once without asking about the destination, whatever it is. The refusal
//! goes to stderr, which `ssh` passes on to its own, so the user, `git` and tools that run `ssh`
//! show it.
//!
//! Anything that is not SSH is carried as it is: the command is a plain `CONNECT` helper for a
//! client that is not.
//!
//! `<name>` (the host name as typed, before `HostName`) is accepted and unused until SSH is.
//! `ssh` ignores the exit status of its `ProxyCommand`: only what the command printed matters.

use std::fmt::Write as _;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use puddle_agent_proto::ssh::{BANNER_MIN, PROTOCOL_HEADER, SSH, is_banner};
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
    copy_bidirectional, join,
};
use tokio::net::TcpStream;
use tokio::time::Instant;

use crate::config::Config;

/// Usage text.
pub const USAGE: &str = "usage: puddle-agent connect <host> <port> [<name>]";

/// Longest response head read from the proxy.
const MAX_HEAD: u64 = 16 * 1024;

/// Most of a refusal's body that is shown.
const MAX_BODY: usize = 4 * 1024;

/// The destination `ssh` asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    host: String,
    port: u16,
}

impl Request {
    /// Reads `<host> <port> [<name>]`.
    ///
    /// # Errors
    ///
    /// The usage text, or what is wrong with the host or port.
    pub fn parse<S: AsRef<str>>(args: &[S]) -> Result<Self, String> {
        let (host, port) = match args {
            [host, port] | [host, port, _] => (host.as_ref(), port.as_ref()),
            _ => return Err(USAGE.to_owned()),
        };
        let port = port
            .parse::<u16>()
            .ok()
            .filter(|p| *p != 0)
            .ok_or_else(|| format!("bad port {port:?}\n{USAGE}"))?;
        // `ssh user@[2001:db8::1]` hands the brackets on.
        let host = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .filter(|h| h.parse::<Ipv6Addr>().is_ok())
            .unwrap_or(host);
        let plain =
            |b: u8| b.is_ascii_graphic() && !matches!(b, b'/' | b'@' | b'?' | b'#' | b'[' | b']');
        if host.is_empty() || host.len() > 253 || !host.bytes().all(plain) {
            return Err(format!(
                "bad host {:?}\n{USAGE}",
                host.chars().take(64).collect::<String>()
            ));
        }
        Ok(Self {
            host: host.to_owned(),
            port,
        })
    }

    /// `host:port` as a `CONNECT` target (an IPv6 address in brackets).
    fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// Where the proxy is and how long each step may take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settings {
    /// The agent's proxy listener.
    pub proxy: SocketAddr,
    /// How long to wait for the client's first bytes before treating it as no SSH client.
    pub first_bytes: Duration,
    /// How long the proxy may take to answer (it connects to the destination first).
    pub answer: Duration,
}

impl Settings {
    /// The agent's own settings (`PUDDLE_AGENT_LISTEN`), with the usual timeouts.
    #[must_use]
    pub fn from_config(config: &Config) -> Self {
        let mut proxy = config.listen;
        if proxy.ip().is_unspecified() {
            proxy.set_ip(Ipv4Addr::LOCALHOST.into());
        }
        Self {
            proxy,
            first_bytes: Duration::from_secs(2),
            answer: Duration::from_secs(60),
        }
    }
}

/// How the command ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// The connection was carried until either side closed it.
    Done,
    /// It was refused or could not be made; the reason is on stderr.
    Failed,
}

impl Exit {
    /// The process exit status: 255, as `ssh` itself uses for a failed connection.
    #[must_use]
    pub fn code(self) -> u8 {
        match self {
            Self::Done => 0,
            Self::Failed => 255,
        }
    }
}

/// Carries `stdin` and `stdout` to `request`'s destination through the proxy, or says on `stderr`
/// why it can't.
pub async fn run<I, O, E>(
    settings: &Settings,
    request: &Request,
    mut stdin: I,
    stdout: O,
    stderr: &mut E,
) -> Exit
where
    I: AsyncRead + Unpin,
    O: AsyncWrite + Unpin,
    E: AsyncWrite + Unpin,
{
    let first = peek(&mut stdin, settings.first_bytes).await;
    let mut stdout = stdout;
    match open(settings, request, &first).await {
        Ok(Opened::Tunnel { mut conn, rest }) => {
            let mut both = join(stdin, &mut stdout);
            let carried = async {
                both.write_all(&rest).await?;
                copy_bidirectional(&mut both, &mut conn).await
            };
            match carried.await {
                Ok(_) => Exit::Done,
                Err(err) => {
                    tracing::debug!(error = %err, "connection ended with an error");
                    Exit::Failed
                }
            }
        }
        Ok(Opened::Refused(text)) => {
            say(stderr, &text).await;
            Exit::Failed
        }
        Err(err) => {
            let authority = request.authority();
            let proxy = settings.proxy;
            say(
                stderr,
                &format!("puddle-agent connect: {authority} through {proxy}: {err}\n"),
            )
            .await;
            Exit::Failed
        }
    }
}

/// What the proxy answered.
enum Opened {
    /// `200`: the tunnel is open; `rest` is what the proxy sent behind its answer.
    Tunnel { conn: TcpStream, rest: Vec<u8> },
    /// Anything else: the proxy's own text.
    Refused(String),
}

/// Reads what the client sends first: up to [`BANNER_MIN`] bytes, as long as they arrive within
/// `limit`. An empty answer is a client that waits for the server (or a closed stdin).
async fn peek<I: AsyncRead + Unpin>(stdin: &mut I, limit: Duration) -> Vec<u8> {
    let deadline = Instant::now() + limit;
    let mut seen = Vec::new();
    let mut chunk = [0u8; 256];
    while seen.len() < BANNER_MIN {
        match tokio::time::timeout_at(deadline, stdin.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => seen.extend_from_slice(chunk.get(..n).unwrap_or_default()),
            _ => break,
        }
    }
    seen
}

/// Sends the `CONNECT` (with the client's first bytes right behind it) and reads the answer.
async fn open(settings: &Settings, request: &Request, first: &[u8]) -> io::Result<Opened> {
    let authority = request.authority();
    let mut head = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if is_banner(first) {
        let _ = write!(head, "{PROTOCOL_HEADER}: {SSH}\r\n");
    }
    head.push_str("\r\n");
    let mut out = head.into_bytes();
    out.extend_from_slice(first);
    let mut reader = BufReader::new(TcpStream::connect(settings.proxy).await?);
    reader.get_mut().write_all(&out).await?;
    let (status, body) = tokio::time::timeout(settings.answer, read_answer(&mut reader))
        .await
        .map_err(|_| io::ErrorKind::TimedOut)??;
    if status == 200 {
        let rest = reader.buffer().to_vec();
        return Ok(Opened::Tunnel {
            conn: reader.into_inner(),
            rest,
        });
    }
    let text = String::from_utf8_lossy(&body).trim_end().to_owned();
    Ok(Opened::Refused(if text.is_empty() {
        format!("puddle: the proxy answered {status}\n")
    } else {
        format!("{text}\n")
    }))
}

/// The status of the proxy's answer and, for anything but `200`, its body.
async fn read_answer<R: AsyncBufRead + Unpin>(reader: &mut R) -> io::Result<(u16, Vec<u8>)> {
    let mut head = Vec::new();
    let mut limited = reader.take(MAX_HEAD);
    loop {
        let before = head.len();
        limited.read_until(b'\n', &mut head).await?;
        if head.len() == before {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the proxy closed the connection",
            ));
        }
        if head.ends_with(b"\r\n\r\n") || head.ends_with(b"\n\n") {
            break;
        }
    }
    let text = String::from_utf8_lossy(&head).into_owned();
    let mut lines = text.lines();
    let status = lines
        .next()
        .and_then(|line| line.split(' ').nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "the proxy's answer is not HTTP")
        })?;
    if status == 200 {
        return Ok((status, Vec::new()));
    }
    let length = lines
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.trim().parse::<usize>().ok())
        .map_or(MAX_BODY, |n| n.min(MAX_BODY));
    let mut body = Vec::new();
    reader.take(length as u64).read_to_end(&mut body).await?;
    Ok((status, body))
}

/// Writes `text` to `stderr`; a stderr that is gone is nobody to tell.
async fn say<E: AsyncWrite + Unpin>(stderr: &mut E, text: &str) {
    let _ = stderr.write_all(text.as_bytes()).await;
    let _ = stderr.flush().await;
}

#[cfg(test)]
mod tests {
    use tokio::net::TcpListener;

    use super::*;

    fn request(host: &str, port: u16) -> Request {
        Request::parse(&[host, &port.to_string()]).unwrap()
    }

    #[test]
    fn a_request_is_a_host_a_port_and_an_optional_name() {
        let r = Request::parse(&["github.com", "22"]).unwrap();
        assert_eq!(r.authority(), "github.com:22");
        assert_eq!(
            Request::parse(&["ssh.github.com", "443", "gh"])
                .unwrap()
                .authority(),
            "ssh.github.com:443"
        );
        assert_eq!(request("::1", 22).authority(), "[::1]:22");
        assert_eq!(request("[2001:db8::1]", 22).authority(), "[2001:db8::1]:22");
        assert_eq!(request("203.0.113.7", 2222).authority(), "203.0.113.7:2222");
    }

    #[test]
    fn anything_else_is_a_usage_error() {
        let long = "a".repeat(254);
        for args in [
            vec![],
            vec!["h"],
            vec!["h", "22", "n", "extra"],
            vec!["h", "0"],
            vec!["h", "65536"],
            vec!["h", "x"],
            vec!["", "22"],
            vec!["a b", "22"],
            vec!["a/b", "22"],
            vec!["u@h", "22"],
            vec!["h\r\nx: y", "22"],
            vec!["[::1", "22"],
            vec!["[not-an-address]", "22"],
            vec!["[::1]x", "22"],
            vec![long.as_str(), "22"],
        ] {
            let err = Request::parse(&args).unwrap_err();
            assert!(err.contains(USAGE), "{args:?}: {err}");
        }
    }

    #[test]
    fn the_proxy_is_the_agents_listener_and_a_wildcard_means_loopback() {
        let default = Settings::from_config(&Config::default());
        assert_eq!(default.proxy, "127.0.0.1:3128".parse().unwrap());
        let wildcard = Config {
            listen: "0.0.0.0:4000".parse().unwrap(),
            ..Config::default()
        };
        assert_eq!(
            Settings::from_config(&wildcard).proxy,
            "127.0.0.1:4000".parse().unwrap()
        );
    }

    #[test]
    fn failing_is_255_as_ssh_does() {
        assert_eq!(Exit::Done.code(), 0);
        assert_eq!(Exit::Failed.code(), 255);
    }

    /// A proxy that reads one request head, hands it to the test, and answers `reply`.
    async fn proxy(reply: &'static [u8]) -> (SocketAddr, tokio::sync::oneshot::Receiver<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut conn, _) = listener.accept().await.unwrap();
            let mut seen = Vec::new();
            let mut buf = [0u8; 1024];
            while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = conn.read(&mut buf).await.unwrap();
                assert_ne!(n, 0, "the client closed before its request");
                seen.extend_from_slice(&buf[..n]);
            }
            // Give a client that sends its first bytes behind the head time to do so.
            tokio::time::sleep(Duration::from_millis(50)).await;
            let _ = tx.send(seen);
            conn.write_all(reply).await.unwrap();
            if reply.starts_with(b"HTTP/1.1 200") {
                // A tunnel to an echo server.
                let (mut r, mut w) = conn.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            }
        });
        (addr, rx)
    }

    fn settings(proxy: SocketAddr) -> Settings {
        Settings {
            proxy,
            first_bytes: Duration::from_millis(300),
            answer: Duration::from_secs(5),
        }
    }

    /// Runs the command with `input` on stdin; returns the exit, stdout and stderr.
    async fn go(settings: &Settings, request: &Request, input: &[u8]) -> (Exit, String, String) {
        let (mut ssh, stdin) = tokio::io::duplex(4096);
        let (stdout, mut out) = tokio::io::duplex(4096);
        let mut stderr = Vec::new();
        ssh.write_all(input).await.unwrap();
        ssh.shutdown().await.unwrap();
        let exit = run(settings, request, stdin, stdout, &mut stderr).await;
        let mut printed = Vec::new();
        out.read_to_end(&mut printed).await.unwrap();
        (
            exit,
            String::from_utf8(printed).unwrap(),
            String::from_utf8(stderr).unwrap(),
        )
    }

    #[tokio::test]
    async fn an_ssh_client_is_announced_with_its_banner_behind_the_head_and_the_refusal_is_printed()
    {
        let (addr, seen) = proxy(
            b"HTTP/1.1 403 Forbidden\r\ncontent-length: 34\r\nx-puddle-blocked: ssh_unsupported\r\n\r\npuddle: SSH is not supported yet\n\n",
        )
        .await;
        let (exit, stdout, stderr) = go(
            &settings(addr),
            &request("github.com", 22),
            b"SSH-2.0-OpenSSH_10.0p2\r\n",
        )
        .await;
        assert_eq!(exit, Exit::Failed);
        assert_eq!(stdout, "", "nothing a client could mistake for a server");
        assert_eq!(stderr, "puddle: SSH is not supported yet\n");
        let head = String::from_utf8(seen.await.unwrap()).unwrap();
        assert_eq!(
            head,
            "CONNECT github.com:22 HTTP/1.1\r\nHost: github.com:22\r\nx-puddle-protocol: ssh\r\n\r\nSSH-2.0-OpenSSH_10.0p2\r\n"
        );
    }

    #[tokio::test]
    async fn anything_else_is_carried_both_ways_with_no_announcement() {
        let (addr, seen) =
            proxy(b"HTTP/1.1 200 Connection Established\r\n\r\nserver says hi\n").await;
        let (mut client, stdin) = tokio::io::duplex(64);
        let (stdout, mut out) = tokio::io::duplex(64);
        let mut stderr = Vec::new();
        let task = tokio::spawn(async move {
            let exit = run(
                &settings(addr),
                &request("db.test", 5432),
                stdin,
                stdout,
                &mut stderr,
            )
            .await;
            (exit, stderr)
        });
        client.write_all(b"hello").await.unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;
        client.write_all(b" later").await.unwrap();
        client.shutdown().await.unwrap();
        let (exit, stderr) = task.await.unwrap();
        assert_eq!((exit, stderr.as_slice()), (Exit::Done, &b""[..]));
        // What the proxy sent behind its answer comes first, then the echo of the later upload;
        // the first bytes went with the request.
        let mut printed = Vec::new();
        out.read_to_end(&mut printed).await.unwrap();
        assert_eq!(printed, b"server says hi\n later");
        let head = String::from_utf8(seen.await.unwrap()).unwrap();
        assert_eq!(
            head,
            "CONNECT db.test:5432 HTTP/1.1\r\nHost: db.test:5432\r\n\r\nhello"
        );
    }

    #[tokio::test]
    async fn an_ssh_client_that_went_away_ends_the_command_with_a_failure() {
        // The proxy opens the tunnel and sends something behind its answer; stdout is gone.
        let (addr, _) = proxy(b"HTTP/1.1 200 Connection Established\r\n\r\nserver says hi\n").await;
        let (_ssh, stdin) = tokio::io::duplex(64);
        let (stdout, out) = tokio::io::duplex(64);
        drop(out);
        let mut stderr = Vec::new();
        let exit = run(
            &settings(addr),
            &request("db.test", 5432),
            stdin,
            stdout,
            &mut stderr,
        )
        .await;
        assert_eq!(exit, Exit::Failed);
    }

    #[tokio::test]
    async fn a_client_that_waits_for_the_server_is_carried_too() {
        // Nothing on stdin within the first-bytes time: no banner, so no announcement.
        let (addr, seen) = proxy(b"HTTP/1.1 200 Connection Established\r\n\r\n").await;
        let (mut keep, stdin) = tokio::io::duplex(64);
        let (stdout, mut out) = tokio::io::duplex(64);
        let mut stderr = Vec::new();
        let task = tokio::spawn(async move {
            let exit = run(
                &settings(addr),
                &request("smtp.test", 25),
                stdin,
                stdout,
                &mut stderr,
            )
            .await;
            (exit, stderr)
        });
        tokio::time::sleep(Duration::from_millis(500)).await;
        keep.write_all(b"EHLO x\r\n").await.unwrap();
        keep.shutdown().await.unwrap();
        let (exit, stderr) = task.await.unwrap();
        assert_eq!((exit, stderr.as_slice()), (Exit::Done, &b""[..]));
        let mut echoed = Vec::new();
        out.read_to_end(&mut echoed).await.unwrap();
        assert_eq!(echoed, b"EHLO x\r\n");
        let head = String::from_utf8(seen.await.unwrap()).unwrap();
        assert!(!head.contains("x-puddle-protocol"), "{head}");
    }

    #[tokio::test]
    async fn a_refusal_without_a_body_names_the_status() {
        let (addr, _) = proxy(b"HTTP/1.1 502 Bad Gateway\r\ncontent-length: 0\r\n\r\n").await;
        let (exit, _, stderr) = go(&settings(addr), &request("a.test", 22), b"x").await;
        assert_eq!(exit, Exit::Failed);
        assert_eq!(stderr, "puddle: the proxy answered 502\n");
    }

    #[tokio::test]
    async fn a_body_without_a_length_is_read_to_its_end_and_a_long_one_is_cut() {
        let (addr, _) = proxy(b"HTTP/1.1 403 Forbidden\r\n\r\npuddle: no length\n").await;
        let (_, _, stderr) = go(&settings(addr), &request("a.test", 22), b"x").await;
        assert_eq!(stderr, "puddle: no length\n");
        let long = format!(
            "HTTP/1.1 403 Forbidden\r\ncontent-length: 10000\r\n\r\n{}",
            "x".repeat(10_000)
        );
        let (addr, _) = proxy(Box::leak(long.into_bytes().into_boxed_slice())).await;
        let (_, _, stderr) = go(&settings(addr), &request("a.test", 22), b"x").await;
        assert_eq!(
            stderr.len(),
            MAX_BODY + 1,
            "cut at {MAX_BODY} bytes, plus the newline"
        );
    }

    #[tokio::test]
    async fn trouble_with_the_proxy_is_said_on_stderr() {
        // Nothing listens.
        let gone = {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            listener.local_addr().unwrap()
        };
        let (exit, stdout, stderr) = go(&settings(gone), &request("a.test", 22), b"x").await;
        assert_eq!((exit, stdout.as_str()), (Exit::Failed, ""));
        assert!(
            stderr.starts_with(&format!("puddle-agent connect: a.test:22 through {gone}: ")),
            "{stderr}"
        );
        // An answer that is not HTTP, one that ends early, and one that never comes.
        for (reply, why) in [
            (&b"SSH-2.0-what\r\n\r\n"[..], "not HTTP"),
            (b"HTTP/1.1 4", "closed the connection"),
        ] {
            let (addr, _) = proxy(Box::leak(reply.to_vec().into_boxed_slice())).await;
            let (exit, _, stderr) = go(&settings(addr), &request("a.test", 22), b"x").await;
            assert_eq!(exit, Exit::Failed);
            assert!(stderr.contains(why), "{why}: {stderr}");
        }
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let silent = listener.local_addr().unwrap();
        let silent_proxy = tokio::spawn(async move {
            // Takes the connection and never answers, until the client gives up.
            let (mut conn, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            while conn.read(&mut buf).await.unwrap_or(0) > 0 {}
        });
        let quick = Settings {
            answer: Duration::from_millis(150),
            ..settings(silent)
        };
        let (exit, _, stderr) = go(&quick, &request("a.test", 22), b"x").await;
        assert_eq!(exit, Exit::Failed);
        assert!(stderr.contains("timed out"), "{stderr}");
        silent_proxy.await.unwrap();
    }
}
