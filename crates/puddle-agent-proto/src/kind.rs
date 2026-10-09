// SPDX-License-Identifier: GPL-3.0-or-later
//! Stream kinds: what a yamux stream that isn't a proxied connection carries.
//!
//! One vsock route carries everything (a smaller surface than a route per feature).
//! A proxied connection starts with its HTTP request line; every other stream starts with a
//! preamble line `\0puddle-<kind>/<version>\n`. The leading `0x00` can't start an HTTP request
//! line, so the first byte tells the two apart.
//!
//! | Kind | Opened by | State |
//! |---|---|---|
//! | `control` v1 | agent | served: [`crate::AgentMessage`] lines, guest → host |
//! | `resolve` v1 | agent | served: one name lookup per stream ([`crate::resolve`]), for the guest's stub DNS |
//! | `connect` | agent | reserved: a raw connection to a named destination (`puddle-agent connect`, the `ssh` `ProxyCommand`, goes through the agent's listener as a `CONNECT` for now: [`crate::ssh`]) |
//! | `ssh-agent` | agent | reserved: filtered SSH agent / signing |
//! | `host-control` | host | reserved: [`crate::control::HostMessage`] lines, host → guest |
//!
//! The host closes a stream of a reserved or unknown kind, or an unsupported version, with a
//! logged reason.
//!
//! ```
//! use puddle_agent_proto::kind::{parse_preamble, StreamKind};
//! assert_eq!(StreamKind::Control.preamble(), b"\0puddle-control/1\n");
//! assert_eq!(parse_preamble(b"\0puddle-control/1\n"), Ok((StreamKind::Control, 1)));
//! ```

/// Longest preamble line the host reads, newline included.
pub const MAX_PREAMBLE: usize = 64;

/// A stream kind with a registered name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum StreamKind {
    /// The agent's reports to the host.
    Control,
    /// One name lookup for the guest's stub DNS: a query line, an answer line.
    Resolve,
    /// Reserved: a raw connection to a named destination.
    Connect,
    /// Reserved: the guest side of a filtered SSH agent.
    SshAgent,
    /// Reserved: host → guest messages on a host-opened stream.
    HostControl,
}

impl StreamKind {
    /// Every registered kind.
    pub const ALL: [Self; 5] = [
        Self::Control,
        Self::Resolve,
        Self::Connect,
        Self::SshAgent,
        Self::HostControl,
    ];

    /// The kind's name in the preamble.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Control => "control",
            Self::Resolve => "resolve",
            Self::Connect => "connect",
            Self::SshAgent => "ssh-agent",
            Self::HostControl => "host-control",
        }
    }

    /// The version this build speaks.
    #[must_use]
    pub const fn version(self) -> u32 {
        1
    }

    /// The preamble that opens a stream of this kind at [`StreamKind::version`].
    #[must_use]
    pub const fn preamble(self) -> &'static [u8] {
        match self {
            Self::Control => b"\0puddle-control/1\n",
            Self::Resolve => b"\0puddle-resolve/1\n",
            Self::Connect => b"\0puddle-connect/1\n",
            Self::SshAgent => b"\0puddle-ssh-agent/1\n",
            Self::HostControl => b"\0puddle-host-control/1\n",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.name() == name)
    }
}

/// A preamble the host can't use.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PreambleError {
    /// Not `\0puddle-<kind>/<version>\n`.
    #[error("malformed stream preamble")]
    Malformed,
    /// A kind this build doesn't know (cut to 32 characters, control characters replaced).
    #[error("unknown stream kind {0:?}")]
    UnknownKind(String),
}

/// Parses a preamble line (newline included) into its kind and version.
///
/// # Errors
///
/// [`PreambleError::Malformed`] for anything not shaped like a preamble, or
/// [`PreambleError::UnknownKind`] for an unregistered kind.
pub fn parse_preamble(line: &[u8]) -> Result<(StreamKind, u32), PreambleError> {
    let body = line
        .strip_prefix(b"\0puddle-")
        .and_then(|l| l.strip_suffix(b"\n"))
        .ok_or(PreambleError::Malformed)?;
    let body = std::str::from_utf8(body).map_err(|_| PreambleError::Malformed)?;
    let (name, version) = body.rsplit_once('/').ok_or(PreambleError::Malformed)?;
    let version = version.parse().map_err(|_| PreambleError::Malformed)?;
    let kind = StreamKind::from_name(name).ok_or_else(|| {
        PreambleError::UnknownKind(
            name.chars()
                .take(32)
                .map(|c| if c.is_control() { '?' } else { c })
                .collect(),
        )
    })?;
    Ok((kind, version))
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn every_kind_round_trips_through_its_preamble() {
        for kind in StreamKind::ALL {
            let p = kind.preamble();
            assert!(p.len() <= MAX_PREAMBLE);
            assert_eq!(p.first(), Some(&0));
            assert_eq!(parse_preamble(p), Ok((kind, kind.version())));
        }
    }

    #[test]
    fn unknown_kinds_and_bad_shapes_are_errors() {
        assert_eq!(
            parse_preamble(b"\0puddle-telepathy/1\n"),
            Err(PreambleError::UnknownKind("telepathy".into()))
        );
        assert_eq!(
            parse_preamble(b"\0puddle-\x07x/1\n"),
            Err(PreambleError::UnknownKind("?x".into()))
        );
        for bad in [
            &b""[..],
            b"\0puddle-control/1",
            b"\0puddle-control\n",
            b"\0puddle-control/x\n",
            b"puddle-control/1\n",
            b"\0puddle-\xff/1\n",
        ] {
            assert_eq!(
                parse_preamble(bad),
                Err(PreambleError::Malformed),
                "{bad:?}"
            );
        }
        assert_eq!(
            parse_preamble(b"\0puddle-control/2\n"),
            Ok((StreamKind::Control, 2))
        );
    }

    proptest! {
        #[test]
        fn any_bytes_parse_or_fail_without_panicking(bytes in proptest::collection::vec(any::<u8>(), 0..80)) {
            let _ = parse_preamble(&bytes);
        }
    }
}
