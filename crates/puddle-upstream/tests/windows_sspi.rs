// SPDX-License-Identifier: GPL-3.0-or-later
//! Windows only: puddle's SSPI sign-in against a fake corporate proxy whose server side
//! is Windows' own SSPI (`AcceptSecurityContext`). So the tokens are checked by the real NTLM and
//! Negotiate packages, as the logged-on user of the runner, instead of by a stand-in that
//! "accepts anything" (Squid's `ntlm_fake_auth` sends a Type 2 Windows rejects).
//!
//! Not covered here: real Kerberos (needs a domain controller); the proxy's side of an
//! AD identity (the runner is a local account, so Negotiate settles on NTLM inside SPNEGO).
#![cfg(windows)]
#![expect(
    unsafe_code,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::undocumented_unsafe_blocks,
    clippy::print_stderr,
    reason = "a test fake of the SSPI server side; a panic is how a test helper fails"
)]

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::ptr;
use std::sync::{Arc, Mutex};
use std::thread;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use puddle_upstream::{AuthStep, ProxyAddr, ProxyAuth, system_auth};
use windows_sys::Win32::Foundation::{SEC_E_OK, SEC_I_CONTINUE_NEEDED};
use windows_sys::Win32::Security::Authentication::Identity::{
    ASC_REQ_ALLOCATE_MEMORY, ASC_REQ_CONNECTION, AcceptSecurityContext, AcquireCredentialsHandleW,
    DeleteSecurityContext, FreeContextBuffer, FreeCredentialsHandle, QueryContextAttributesW,
    SECBUFFER_TOKEN, SECBUFFER_VERSION, SECPKG_ATTR_NAMES, SECPKG_CRED_INBOUND,
    SECURITY_NATIVE_DREP, SecBuffer, SecBufferDesc, SecPkgContext_NamesW,
};
use windows_sys::Win32::Security::Credentials::SecHandle;

/// Serialises the fake server's own SSPI calls (the code under test has its own lock).
static SERVER_LOCK: Mutex<()> = Mutex::new(());

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// One server-side SSPI context for one connection.
struct ServerContext {
    credential: SecHandle,
    context: SecHandle,
    started: bool,
}

impl ServerContext {
    fn new(package: &str) -> Self {
        let name = wide(package);
        let mut credential = SecHandle {
            dwLower: 0,
            dwUpper: 0,
        };
        let mut expiry = 0i64;
        let _guard = SERVER_LOCK.lock().unwrap();
        let status = unsafe {
            AcquireCredentialsHandleW(
                ptr::null(),
                name.as_ptr(),
                SECPKG_CRED_INBOUND,
                ptr::null(),
                ptr::null(),
                None,
                ptr::null(),
                &raw mut credential,
                &raw mut expiry,
            )
        };
        assert_eq!(status, SEC_E_OK, "server credentials for {package}");
        Self {
            credential,
            context: SecHandle {
                dwLower: 0,
                dwUpper: 0,
            },
            started: false,
        }
    }

    /// Feeds the client's token; returns the reply token, whether the context is complete, and
    /// the authenticated user once it is.
    fn accept(&mut self, token: &[u8]) -> Result<(Vec<u8>, Option<String>), i32> {
        let mut input = SecBuffer {
            cbBuffer: u32::try_from(token.len()).unwrap(),
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: token.as_ptr().cast_mut().cast(),
        };
        let input_desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: 1,
            pBuffers: &raw mut input,
        };
        let mut output = SecBuffer {
            cbBuffer: 0,
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: ptr::null_mut(),
        };
        let mut output_desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: 1,
            pBuffers: &raw mut output,
        };
        let (mut attributes, mut expiry) = (0u32, 0i64);
        let context: *mut SecHandle = &raw mut self.context;
        let _guard = SERVER_LOCK.lock().unwrap();
        let status = unsafe {
            AcceptSecurityContext(
                &raw const self.credential,
                if self.started { context } else { ptr::null() },
                &raw const input_desc,
                ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_CONNECTION,
                SECURITY_NATIVE_DREP,
                context,
                &raw mut output_desc,
                &raw mut attributes,
                &raw mut expiry,
            )
        };
        let reply = if output.pvBuffer.is_null() {
            Vec::new()
        } else {
            let bytes = unsafe {
                std::slice::from_raw_parts(output.pvBuffer.cast::<u8>(), output.cbBuffer as usize)
            }
            .to_vec();
            unsafe { FreeContextBuffer(output.pvBuffer) };
            bytes
        };
        if status != SEC_E_OK && status != SEC_I_CONTINUE_NEEDED {
            return Err(status);
        }
        self.started = true;
        if status == SEC_I_CONTINUE_NEEDED {
            return Ok((reply, None));
        }
        let mut names = SecPkgContext_NamesW {
            sUserName: ptr::null_mut(),
        };
        let query = unsafe {
            QueryContextAttributesW(
                &raw const self.context,
                SECPKG_ATTR_NAMES,
                (&raw mut names).cast(),
            )
        };
        assert_eq!(query, SEC_E_OK, "the authenticated user name");
        let mut length = 0;
        while unsafe { *names.sUserName.add(length) } != 0 {
            length += 1;
        }
        let user = String::from_utf16_lossy(unsafe {
            std::slice::from_raw_parts(names.sUserName, length)
        });
        unsafe { FreeContextBuffer(names.sUserName.cast()) };
        Ok((reply, Some(user)))
    }
}

impl Drop for ServerContext {
    fn drop(&mut self) {
        unsafe {
            if self.started {
                DeleteSecurityContext(&raw const self.context);
            }
            FreeCredentialsHandle(&raw const self.credential);
        }
    }
}

/// What the fake proxy does.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Behaviour {
    /// Verify tokens with SSPI.
    Verify,
    /// Refuse every token: a bare `407` again.
    Reject,
    /// Answer a token with well-formed base64 that is not a token.
    Garbage,
}

#[derive(Default)]
struct Observed {
    /// Per connection: did its first request already carry `Proxy-Authorization`?
    first_had_auth: Vec<bool>,
    /// Per connection: how many requests it carried.
    requests: Vec<usize>,
    /// The users SSPI authenticated.
    users: Vec<String>,
}

struct FakeProxy {
    port: u16,
    observed: Arc<Mutex<Observed>>,
}

fn read_head(reader: &mut BufReader<TcpStream>) -> Option<Vec<String>> {
    let mut lines = Vec::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).ok()? == 0 {
            return None;
        }
        let line = line.trim_end().to_owned();
        if line.is_empty() {
            return Some(lines);
        }
        lines.push(line);
    }
}

fn serve(stream: TcpStream, schemes: &[&str], behaviour: Behaviour, observed: &Mutex<Observed>) {
    let mut writer = stream.try_clone().unwrap();
    let mut reader = BufReader::new(stream);
    let mut context: Option<ServerContext> = None;
    let mut requests = 0usize;
    let mut first_had_auth = None;
    while let Some(head) = read_head(&mut reader) {
        requests += 1;
        let auth = head.iter().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("proxy-authorization")
                .then(|| value.trim().to_owned())
        });
        first_had_auth.get_or_insert(auth.is_some());
        let challenge_all = || {
            schemes.iter().fold(String::new(), |mut all, scheme| {
                all.push_str("Proxy-Authenticate: ");
                all.push_str(scheme);
                all.push_str("\r\n");
                all
            })
        };
        let response = match auth.as_deref().and_then(|v| v.split_once(' ')) {
            None => format!(
                "HTTP/1.1 407 Proxy Authentication Required\r\n{}Content-Length: 0\r\n\r\n",
                challenge_all()
            ),
            Some((scheme, _)) if !schemes.iter().any(|s| s.eq_ignore_ascii_case(scheme)) => {
                format!(
                    "HTTP/1.1 407 Proxy Authentication Required\r\n{}Content-Length: 0\r\n\r\n",
                    challenge_all()
                )
            }
            Some((scheme, blob)) => match behaviour {
                Behaviour::Reject => format!(
                    "HTTP/1.1 407 Proxy Authentication Required\r\n{}Content-Length: 0\r\n\r\n",
                    challenge_all()
                ),
                Behaviour::Garbage => format!(
                    "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: {scheme} {}\r\nContent-Length: 0\r\n\r\n",
                    STANDARD.encode(b"this is not a security token at all, not even close")
                ),
                Behaviour::Verify => {
                    let token = STANDARD.decode(blob).unwrap();
                    let ctx = context.get_or_insert_with(|| ServerContext::new(scheme));
                    match ctx.accept(&token) {
                        Err(status) => {
                            eprintln!("fake proxy: AcceptSecurityContext 0x{status:08x}");
                            "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n".to_owned()
                        }
                        Ok((reply, None)) => format!(
                            "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: {scheme} {}\r\nContent-Length: 0\r\n\r\n",
                            STANDARD.encode(reply)
                        ),
                        Ok((_, Some(user))) => {
                            observed.lock().unwrap().users.push(user);
                            "HTTP/1.1 200 Connection established\r\n\r\n".to_owned()
                        }
                    }
                }
            },
        };
        if writer.write_all(response.as_bytes()).is_err() {
            break;
        }
    }
    let mut seen = observed.lock().unwrap();
    seen.first_had_auth.push(first_had_auth.unwrap_or(false));
    seen.requests.push(requests);
}

fn fake_proxy(schemes: &'static [&'static str], behaviour: Behaviour) -> FakeProxy {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let observed = Arc::new(Mutex::new(Observed::default()));
    let shared = Arc::clone(&observed);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { return };
            let shared = Arc::clone(&shared);
            thread::spawn(move || serve(stream, schemes, behaviour, &shared));
        }
    });
    FakeProxy { port, observed }
}

/// What the client side saw on one CONNECT.
#[derive(Debug)]
struct Outcome {
    status: u16,
    /// Tokens sent (`Proxy-Authorization` headers).
    legs: usize,
}

/// The loop the 407 handling runs, on one connection: send, read, answer a 407 with the
/// session's next header. `preemptive` starts a session before the first request.
fn connect_through(
    port: u16,
    auth: &dyn ProxyAuth,
    preemptive: bool,
    offered_override: Option<&[&str]>,
) -> Result<Outcome, String> {
    let proxy = ProxyAddr::new("127.0.0.1", port);
    let stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let mut writer = stream.try_clone().unwrap();
    let mut reader = BufReader::new(stream);
    let mut session = None;
    let mut authorization: Option<String> = None;
    let mut legs = 0;
    if preemptive {
        let mut s = auth
            .begin(&proxy, &[])
            .map_err(|e| e.to_string())?
            .ok_or("no session")?;
        match s.step(None).map_err(|e| e.to_string())? {
            AuthStep::Authorization(value) => authorization = Some(value),
            _ => return Err("preemptive step gave no header".into()),
        }
        session = Some(s);
    }
    loop {
        let header = authorization.take().map_or_else(String::new, |value| {
            legs += 1;
            format!("Proxy-Authorization: {value}\r\n")
        });
        let request =
            format!("CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n{header}\r\n");
        writer.write_all(request.as_bytes()).unwrap();
        let head = read_head(&mut reader).ok_or("connection closed")?;
        let status: u16 = head[0].split(' ').nth(1).unwrap().parse().unwrap();
        if status != 407 {
            return Ok(Outcome { status, legs });
        }
        let challenges: Vec<String> = head
            .iter()
            .filter_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("proxy-authenticate")
                    .then(|| value.trim().to_owned())
            })
            .collect();
        let joined = challenges.join(", ");
        if session.is_none() {
            let words: Vec<&str> = challenges
                .iter()
                .filter_map(|c| c.split_whitespace().next())
                .collect();
            let offered = offered_override.unwrap_or(&words);
            session = auth.begin(&proxy, offered).map_err(|e| e.to_string())?;
            if session.is_none() {
                return Ok(Outcome { status, legs });
            }
        }
        match session
            .as_mut()
            .unwrap()
            .step(Some(&joined))
            .map_err(|e| e.to_string())?
        {
            AuthStep::Authorization(value) => authorization = Some(value),
            AuthStep::Done => return Ok(Outcome { status, legs }),
            _ => return Err("unknown step".into()),
        }
    }
}

fn current_user() -> String {
    std::env::var("USERNAME").unwrap().to_lowercase()
}

fn assert_signed_in_as_this_user(proxy: &FakeProxy, count: usize) {
    let seen = proxy.observed.lock().unwrap();
    assert_eq!(
        seen.users.len(),
        count,
        "authenticated users: {:?}",
        seen.users
    );
    for user in &seen.users {
        let name = user.rsplit('\\').next().unwrap().to_lowercase();
        assert_eq!(name, current_user(), "SSPI authenticated {user}");
    }
}

#[test]
fn negotiate_is_sent_on_the_first_request_and_signs_in_as_the_logged_on_user() {
    let proxy = fake_proxy(&["Negotiate", "NTLM"], Behaviour::Verify);
    let outcome = connect_through(proxy.port, system_auth().as_ref(), true, None).unwrap();
    assert_eq!(outcome.status, 200, "{outcome:?}");
    // SPNEGO on a local account wraps the NTLM exchange: two tokens, three if the package asks
    // for an acknowledgement leg.
    assert!((2..=3).contains(&outcome.legs), "{outcome:?}");
    assert_signed_in_as_this_user(&proxy, 1);
    thread::sleep(std::time::Duration::from_millis(200));
    assert_eq!(proxy.observed.lock().unwrap().first_had_auth, vec![true]);
}

#[test]
fn ntlm_takes_three_legs_on_one_connection() {
    let proxy = fake_proxy(&["NTLM"], Behaviour::Verify);
    let outcome = connect_through(proxy.port, system_auth().as_ref(), false, None).unwrap();
    assert_eq!(outcome.status, 200, "{outcome:?}");
    assert_eq!(outcome.legs, 2, "Type 1 and Type 3: {outcome:?}");
    assert_signed_in_as_this_user(&proxy, 1);
    thread::sleep(std::time::Duration::from_millis(200));
    let seen = proxy.observed.lock().unwrap();
    assert_eq!(seen.requests, vec![3], "bare request, Type 1, Type 3");
    assert_eq!(seen.first_had_auth, vec![false]);
}

#[test]
fn negotiate_is_preferred_when_both_are_offered_without_a_preemptive_token() {
    let proxy = fake_proxy(&["NTLM", "Negotiate"], Behaviour::Verify);
    let outcome = connect_through(proxy.port, system_auth().as_ref(), false, None).unwrap();
    assert_eq!(outcome.status, 200, "{outcome:?}");
    assert_signed_in_as_this_user(&proxy, 1);
}

#[test]
fn a_proxy_that_asks_for_a_password_gets_no_session_and_no_prompt() {
    let proxy = fake_proxy(&["Basic realm=\"corp\""], Behaviour::Verify);
    let outcome = connect_through(proxy.port, system_auth().as_ref(), false, None).unwrap();
    assert_eq!(outcome.status, 407);
    assert_eq!(outcome.legs, 0);
}

#[test]
fn a_proxy_that_refuses_the_token_ends_in_an_error_not_a_loop() {
    let proxy = fake_proxy(&["NTLM"], Behaviour::Reject);
    let err = connect_through(proxy.port, system_auth().as_ref(), false, None).unwrap_err();
    assert!(err.contains("refused"), "{err}");
}

#[test]
fn a_garbage_challenge_is_an_error_naming_only_the_status() {
    let proxy = fake_proxy(&["NTLM"], Behaviour::Garbage);
    let err = connect_through(proxy.port, system_auth().as_ref(), false, None).unwrap_err();
    assert!(err.contains("InitializeSecurityContext 0x"), "{err}");
}

/// With the logged-on user: without the lock, parallel handshakes failed 12 of 30.
#[test]
fn thirty_parallel_handshakes_all_succeed() {
    let proxy = fake_proxy(&["NTLM"], Behaviour::Verify);
    let auth = system_auth();
    for _round in 0..2 {
        let handles: Vec<_> = (0..30)
            .map(|_| {
                let auth = Arc::clone(&auth);
                let port = proxy.port;
                thread::spawn(move || connect_through(port, auth.as_ref(), false, None))
            })
            .collect();
        for handle in handles {
            let outcome = handle.join().unwrap().unwrap();
            assert_eq!(outcome.status, 200, "{outcome:?}");
        }
    }
    assert_signed_in_as_this_user(&proxy, 60);
}
