// SPDX-License-Identifier: GPL-3.0-or-later
//! Recognising an SSH client by the first bytes it sends.
//!
//! An SSH client starts with its identification line (RFC 4253 section 4.2):
//! `SSH-<protocol version>-<software version>`, whatever the port. That line, not the port,
//! tells the proxy a connection is SSH: `ssh.github.com:443` is SSH and some other service on
//! port 22 is not.
//!
//! A tool that carries an SSH client's bytes to the proxy (the agent's `connect` command, the
//! `ssh` `ProxyCommand`) puts [`PROTOCOL_HEADER`]: [`SSH`] on its `CONNECT` once it has seen the
//! line, so the proxy can refuse before it decides anything about the destination. The proxy also
//! looks at the first bytes itself ([`is_banner`]) for a client that sends them with the `CONNECT`
//! or inside an established tunnel.
//!
//! The header only ever makes the proxy stricter: a guest that sets it wrongly gets its own
//! connection refused, and no connection is allowed because of it.

/// The request header that says the tunnel will carry SSH.
pub const PROTOCOL_HEADER: &str = "x-puddle-protocol";

/// The value of [`PROTOCOL_HEADER`] for SSH.
pub const SSH: &str = "ssh";

/// Fewest bytes [`is_banner`] needs: `SSH-` and the first digit of the protocol version.
pub const BANNER_MIN: usize = 5;

/// Whether `bytes` begin an SSH identification line: `SSH-` followed by a digit.
///
/// Fewer than [`BANNER_MIN`] bytes never match; a caller that has less reads on first.
///
/// ```
/// use puddle_agent_proto::ssh::is_banner;
/// assert!(is_banner(b"SSH-2.0-OpenSSH_9.6\r\n"));
/// assert!(is_banner(b"SSH-1.99-libssh2_1.11.0"));
/// assert!(!is_banner(b"SSH-"));
/// assert!(!is_banner(b"\x16\x03\x01\x02\x00"));
/// assert!(!is_banner(b"GET / HTTP/1.1\r\n"));
/// ```
#[must_use]
pub fn is_banner(bytes: &[u8]) -> bool {
    bytes.starts_with(b"SSH-") && bytes.get(4).is_some_and(u8::is_ascii_digit)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn real_client_identification_lines_match() {
        for line in [
            &b"SSH-2.0-OpenSSH_10.0p2 Debian-7\r\n"[..],
            b"SSH-2.0-libssh2_1.11.1\r\n",
            b"SSH-2.0-Go\r\n",
            b"SSH-2.0-paramiko_3.4.0\r\n",
            b"SSH-1.99-OpenSSH_3.9\r\n",
            b"SSH-2.0-x",
        ] {
            assert!(is_banner(line), "{}", String::from_utf8_lossy(line));
        }
    }

    #[test]
    fn other_traffic_and_near_misses_do_not() {
        for bytes in [
            &b""[..],
            b"S",
            b"SSH-",
            b"SSH-x",
            b"ssh-2.0-lower",
            b" SSH-2.0-x",
            b"SSH2.0-x",
            b"puddle: SSH-2.0 is not\r\n",
            b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc",
            b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
            b"CONNECT a.test:22 HTTP/1.1\r\n",
        ] {
            assert!(!is_banner(bytes), "{}", String::from_utf8_lossy(bytes));
        }
    }

    proptest! {
        #[test]
        fn matching_never_panics_and_needs_the_prefix(
            bytes in proptest::collection::vec(any::<u8>(), 0..16)
        ) {
            if is_banner(&bytes) {
                prop_assert!(bytes.starts_with(b"SSH-"));
            }
        }

        #[test]
        fn any_line_that_starts_like_a_banner_matches(
            digit in b'0'..=b'9',
            rest in proptest::collection::vec(any::<u8>(), 0..64)
        ) {
            let mut line = vec![b'S', b'S', b'H', b'-', digit];
            line.extend(rest);
            prop_assert!(is_banner(&line));
        }
    }
}
