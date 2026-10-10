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
//! What is inside the workspace is not outbound and is not sent to the proxy: the command
//! looks the destination up itself and, when every address it names is loopback or inside a
//! `--local-net` (the container bridge), dials that address directly and carries the connection.
//! It is decided by the address, never by the name: a DNS name that starts with `127.` resolves
//! to whatever its zone says and goes to the proxy unless that is local. The address that was
//! checked is the one dialled.
//!
//! `<name>` (the host name as typed, before `HostName`) is accepted and unused until SSH is.
//! `ssh` ignores the exit status of its `ProxyCommand`: only what the command printed matters.

use std::fmt::Write as _;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
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
pub const USAGE: &str =
    "usage: puddle-agent connect [--local-net <address>/<bits>]... <host> <port> [<name>]";

/// Longest response head read from the proxy.
const MAX_HEAD: u64 = 16 * 1024;

/// Most of a refusal's body that is shown.
const MAX_BODY: usize = 4 * 1024;

/// The destination `ssh` asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    host: String,
    port: u16,
    local: Vec<LocalNet>,
}

/// An IPv4 network whose addresses are inside the workspace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LocalNet {
    base: u32,
    mask: u32,
}

impl LocalNet {
    fn parse(text: &str) -> Option<Self> {
        let (address, bits) = text.split_once('/')?;
        let bits = bits.parse::<u32>().ok().filter(|b| (1..=32).contains(b))?;
        let mask = u32::MAX << (32 - bits);
        Some(Self {
            base: u32::from(address.parse::<Ipv4Addr>().ok()?) & mask,
            mask,
        })
    }

    fn contains(self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & self.mask == self.base
    }
}

impl Request {
    /// Whether `ip` is inside the workspace: loopback (0.0.0.0 and :: reach it too) or inside a
    /// `--local-net`.
    fn is_local(&self, ip: IpAddr) -> bool {
        match ip.to_canonical() {
            IpAddr::V4(v4) => {
                v4.is_loopback() || v4.is_unspecified() || self.local.iter().any(|n| n.contains(v4))
            }
            IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
        }
    }
}

impl Request {
    /// Reads `[--local-net <address>/<bits>]... <host> <port> [<name>]`.
    ///
    /// # Errors
    ///
    /// The usage text, or what is wrong with the host or port.
    pub fn parse<S: AsRef<str>>(args: &[S]) -> Result<Self, String> {
        let mut args: Vec<&str> = args.iter().map(AsRef::as_ref).collect();
        let mut local = Vec::new();
        while let ["--local-net", net, ..] = args.as_slice() {
            local
                .push(LocalNet::parse(net).ok_or_else(|| format!("bad network {net:?}\n{USAGE}"))?);
            args.drain(..2);
        }
        let (host, port) = match args.as_slice() {
            [host, port] | [host, port, _] => (*host, *port),
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
            local,
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

/// How a destination name becomes addresses: `None` when it can't be looked up in time.
pub type Lookup =
    fn(String, u16, Duration) -> Pin<Box<dyn Future<Output = Option<Vec<IpAddr>>> + Send>>;

/// The system resolver, giving up after `limit`.
pub fn system_lookup(
    host: String,
    port: u16,
    limit: Duration,
) -> Pin<Box<dyn Future<Output = Option<Vec<IpAddr>>> + Send>> {
    Box::pin(async move {
        let found = tokio::time::timeout(limit, tokio::net::lookup_host((host.as_str(), port)))
            .await
            .ok()?
            .ok()?;
        Some(found.map(|a| a.ip()).collect())
    })
}

/// Where the proxy is and how long each step may take.
#[derive(Debug, Clone, Copy)]
pub struct Settings {
    /// The agent's proxy listener.
    pub proxy: SocketAddr,
    /// How long to wait for the client's first bytes before treating it as no SSH client.
    pub first_bytes: Duration,
    /// How long the proxy may take to answer (it connects to the destination first).
    pub answer: Duration,
    /// How long to wait for the destination's name to resolve; a name that doesn't in time is
    /// not local.
    pub lookup_limit: Duration,
    /// Resolves destination names.
    pub lookup: Lookup,
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
            lookup_limit: Duration::from_secs(2),
            lookup: system_lookup,
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
    let mut stdout = stdout;
    if let Some(addresses) = inside_the_workspace(settings, request).await {
        return direct(&addresses, request.port, stdin, &mut stdout, stderr).await;
    }
    let first = peek(&mut stdin, settings.first_bytes).await;
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

/// The destination's addresses when every one of them is inside the workspace, else `None`.
async fn inside_the_workspace(settings: &Settings, request: &Request) -> Option<Vec<IpAddr>> {
    let addresses = match request.host.parse::<IpAddr>() {
        Ok(ip) => vec![ip],
        Err(_) => {
            (settings.lookup)(request.host.clone(), request.port, settings.lookup_limit).await?
        }
    };
    (!addresses.is_empty() && addresses.iter().all(|ip| request.is_local(*ip))).then_some(addresses)
}

/// Carries the connection to one of `addresses`, which were checked, without the proxy.
async fn direct<I, O, E>(
    addresses: &[IpAddr],
    port: u16,
    stdin: I,
    stdout: &mut O,
    stderr: &mut E,
) -> Exit
where
    I: AsyncRead + Unpin,
    O: AsyncWrite + Unpin,
    E: AsyncWrite + Unpin,
{
    let mut failure = String::new();
    for ip in addresses {
        // An IPv4-mapped IPv6 address (::ffff:127.0.0.1) is local by `is_local`; dial its IPv4
        // form, since Windows refuses to connect to the mapped one (os error 10049).
        match TcpStream::connect(SocketAddr::new(ip.to_canonical(), port)).await {
            Ok(conn) => return carry_until_the_server_closes(conn, stdin, stdout).await,
            Err(err) => failure = format!("puddle-agent connect: {ip} port {port}: {err}\n"),
        }
    }
    say(stderr, &failure).await;
    Exit::Failed
}

/// Carries both directions until the server is done. The client's own end is no signal: `stdout`
/// is a pipe that stays open until this process exits, so a client waiting for the server to
/// close would never close its side first.
async fn carry_until_the_server_closes<I, O>(conn: TcpStream, mut stdin: I, mut stdout: O) -> Exit
where
    I: AsyncRead + Unpin,
    O: AsyncWrite + Unpin,
{
    let (mut from_server, mut to_server) = conn.into_split();
    let down = async {
        tokio::io::copy(&mut from_server, &mut stdout).await?;
        stdout.flush().await
    };
    let up = async {
        tokio::io::copy(&mut stdin, &mut to_server).await?;
        to_server.shutdown().await
    };
    tokio::pin!(down, up);
    let ended: io::Result<()> = async {
        tokio::select! {
            down = &mut down => down,
            up = &mut up => {
                up?;
                down.await
            }
        }
    }
    .await;
    match ended {
        Ok(()) => Exit::Done,
        Err(err) => {
            tracing::debug!(error = %err, "connection ended with an error");
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

    /// No name resolves: the unit tests never ask a resolver.
    fn no_names(
        _: String,
        _: u16,
        _: Duration,
    ) -> Pin<Box<dyn Future<Output = Option<Vec<IpAddr>>> + Send>> {
        Box::pin(async { None })
    }

    fn settings(proxy: SocketAddr) -> Settings {
        Settings {
            proxy,
            first_bytes: Duration::from_millis(300),
            answer: Duration::from_secs(5),
            lookup_limit: Duration::from_secs(1),
            lookup: no_names,
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

    /// A few names with fixed answers, the rest do not resolve.
    fn names(
        host: String,
        _: u16,
        _: Duration,
    ) -> Pin<Box<dyn Future<Output = Option<Vec<IpAddr>>> + Send>> {
        let ip = |text: &str| text.parse::<IpAddr>().unwrap();
        Box::pin(async move {
            match host.as_str() {
                "app.test" => Some(vec![ip("127.0.0.1")]),
                "bridge.test" => Some(vec![ip("172.17.0.5")]),
                // A DNS name that starts with 127. is just a name: its zone says where it goes.
                "127.0.0.1.nip.test" | "127.evil.test" => Some(vec![ip("203.0.113.9")]),
                "mixed.test" => Some(vec![ip("127.0.0.1"), ip("203.0.113.9")]),
                "empty.test" => Some(vec![]),
                _ => None,
            }
        })
    }

    fn bridge_request(host: &str, port: u16) -> Request {
        Request::parse(&["--local-net", "172.17.0.0/16", host, &port.to_string()]).unwrap()
    }

    #[test]
    fn the_workspace_is_loopback_and_the_listed_networks_by_address() {
        let r = bridge_request("h", 22);
        for local in [
            "127.0.0.1",
            "127.255.0.9",
            "::1",
            "::ffff:127.0.0.1",
            "0.0.0.0",
            "::",
            "172.17.0.5",
            "172.17.255.255",
        ] {
            assert!(r.is_local(local.parse().unwrap()), "{local}");
        }
        for outside in [
            "203.0.113.9",
            "172.18.0.5",
            "172.16.255.255",
            "10.0.0.1",
            "2001:db8::1",
            "fe80::1",
            "::ffff:203.0.113.9",
        ] {
            assert!(!r.is_local(outside.parse().unwrap()), "{outside}");
        }
        // Without a network listed only loopback is inside.
        assert!(!request("h", 22).is_local("172.17.0.5".parse().unwrap()));
    }

    #[test]
    fn networks_are_checked_when_parsed() {
        let r = Request::parse(&[
            "--local-net",
            "10.1.2.3/8",
            "--local-net",
            "192.168.0.0/16",
            "h",
            "22",
            "n",
        ])
        .unwrap();
        assert!(r.is_local("10.200.0.1".parse().unwrap()));
        assert!(r.is_local("192.168.9.9".parse().unwrap()));
        assert!(!r.is_local("192.169.0.1".parse().unwrap()));
        assert!(
            Request::parse(&["--local-net", "0.0.0.0/32", "h", "22"])
                .unwrap()
                .is_local("0.0.0.0".parse().unwrap())
        );
        for bad in [
            "172.17.0.0",
            "172.17.0.0/0",
            "172.17.0.0/33",
            "nope/16",
            "172.17.0.0/x",
            "::1/64",
        ] {
            let err = Request::parse(&["--local-net", bad, "h", "22"]).unwrap_err();
            assert!(
                err.contains("bad network") && err.contains(USAGE),
                "{bad}: {err}"
            );
        }
        assert!(Request::parse(&["--local-net"]).is_err());
    }

    /// An echo server on loopback; the port.
    async fn echo() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (mut conn, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let (mut r, mut w) = conn.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        port
    }

    /// A proxy address nobody listens on: a connection that goes there fails loudly.
    async fn no_proxy() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap()
    }

    #[tokio::test]
    async fn an_address_inside_the_workspace_is_dialled_directly_and_never_asked_of_the_proxy() {
        let port = echo().await;
        let direct = Settings {
            lookup: names,
            ..settings(no_proxy().await)
        };
        // A literal address, and a name that resolves to loopback.
        for host in ["127.0.0.1", "::ffff:127.0.0.1", "app.test"] {
            let (exit, stdout, stderr) =
                go(&direct, &bridge_request(host, port), b"SSH-2.0-x\r\n").await;
            assert_eq!(
                (exit, stdout.as_str(), stderr.as_str()),
                (Exit::Done, "SSH-2.0-x\r\n", ""),
                "{host}"
            );
        }
    }

    #[tokio::test]
    async fn a_dns_name_that_starts_with_127_goes_to_the_proxy_unless_it_resolves_inside() {
        for host in [
            "127.0.0.1.nip.test",
            "127.evil.test",
            "mixed.test",
            "empty.test",
            "nowhere.test",
        ] {
            let (addr, seen) =
                proxy(b"HTTP/1.1 403 Forbidden\r\ncontent-length: 3\r\n\r\nno\n").await;
            let through = Settings {
                lookup: names,
                ..settings(addr)
            };
            let (exit, _, stderr) = go(&through, &bridge_request(host, 22), b"SSH-2.0-x\r\n").await;
            assert_eq!((exit, stderr.as_str()), (Exit::Failed, "no\n"), "{host}");
            let head = String::from_utf8(seen.await.unwrap()).unwrap();
            assert!(
                head.starts_with(&format!("CONNECT {host}:22 HTTP/1.1")),
                "{head}"
            );
        }
    }

    #[tokio::test]
    async fn a_local_destination_that_refuses_is_said_on_stderr() {
        let closed = {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            listener.local_addr().unwrap().port()
        };
        let direct = Settings {
            lookup: names,
            ..settings(no_proxy().await)
        };
        let (exit, stdout, stderr) = go(&direct, &bridge_request("app.test", closed), b"x").await;
        assert_eq!((exit, stdout.as_str()), (Exit::Failed, ""));
        assert!(
            stderr.starts_with(&format!("puddle-agent connect: 127.0.0.1 port {closed}: ")),
            "{stderr}"
        );
    }

    #[tokio::test]
    async fn a_direct_connection_whose_client_went_away_fails() {
        let port = echo().await;
        let direct = Settings {
            lookup: names,
            ..settings(no_proxy().await)
        };
        let (mut ssh, stdin) = tokio::io::duplex(64);
        let (stdout, out) = tokio::io::duplex(64);
        drop(out);
        ssh.write_all(b"x").await.unwrap();
        let mut stderr = Vec::new();
        let request = bridge_request("127.0.0.1", port);
        let exit = run(&direct, &request, stdin, stdout, &mut stderr).await;
        assert_eq!(exit, Exit::Failed);
    }

    #[tokio::test]
    async fn the_system_resolver_answers_with_addresses_and_gives_none_for_a_name_it_cannot_find() {
        let limit = Duration::from_secs(10);
        let found = system_lookup("localhost".to_owned(), 22, limit)
            .await
            .unwrap();
        assert!(found.iter().all(IpAddr::is_loopback), "{found:?}");
        assert_eq!(
            system_lookup("bad host.invalid".to_owned(), 22, limit).await,
            None
        );
    }
}
