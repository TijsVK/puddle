// SPDX-License-Identifier: GPL-3.0-or-later
//! The control stream: one yamux stream per session on which the agent reports to the host.
//!
//! The agent opens it like any other stream and writes [`PREAMBLE`], then one JSON
//! [`AgentMessage`] per line (`\n`-terminated, at most [`MAX_LINE`] bytes including the newline).
//! Data flows guest → host only. The first message is [`AgentMessage::Hello`].
//!
//! Host → guest messages will use the same line format on a host-opened `host-control` stream
//! ([`HostMessage`], [`crate::kind::StreamKind::HostControl`]); none are defined yet.
//!
//! ```
//! use puddle_agent_proto::AgentMessage;
//! let line = AgentMessage::oom_kill(Some(42), Some("node".into())).to_line().unwrap();
//! assert_eq!(line, b"{\"type\":\"oom_kill\",\"pid\":42,\"process\":\"node\"}\n");
//! assert_eq!(AgentMessage::from_line(&line).unwrap(), AgentMessage::oom_kill(Some(42), Some("node".into())));
//! ```

use std::io;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufRead, AsyncBufReadExt};

/// Bytes that open a control stream ([`crate::kind::StreamKind::Control`] v1).
pub const PREAMBLE: &[u8] = crate::kind::StreamKind::Control.preamble();

/// The control protocol version, sent in [`AgentMessage::Hello`]. Bump it on a change the other
/// side must know about; adding a message type is not one (unknown types are ignored).
pub const PROTOCOL_VERSION: u32 = 1;

/// Longest control line the host accepts, newline included. A longer line ends the stream.
pub const MAX_LINE: usize = 4096;

/// One message from the agent to the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum AgentMessage {
    /// Sent first on every control stream.
    Hello {
        /// The agent's version (puddle's version at build time).
        agent_version: String,
        /// [`PROTOCOL_VERSION`] of the agent.
        protocol: u32,
    },
    /// The guest kernel's OOM killer ended a process.
    ///
    /// `pid` and `process` are missing when the agent saw the kill counter in `/proc/vmstat` go up
    /// but no matching `Killed process` line in the kernel log.
    OomKill {
        /// The killed process's id in the guest.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pid: Option<u32>,
        /// The killed process's name (`comm`) as the kernel printed it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        process: Option<String>,
    },
    /// A message type this side doesn't know (from a newer agent). Ignored.
    #[serde(other)]
    Unknown,
}

impl AgentMessage {
    /// A [`AgentMessage::Hello`] for this build.
    #[must_use]
    pub fn hello() -> Self {
        Self::Hello {
            agent_version: puddle_types::VERSION.to_owned(),
            protocol: PROTOCOL_VERSION,
        }
    }

    /// An [`AgentMessage::OomKill`].
    #[must_use]
    pub fn oom_kill(pid: Option<u32>, process: Option<String>) -> Self {
        Self::OomKill { pid, process }
    }

    /// The message as one control line, newline included.
    ///
    /// # Errors
    ///
    /// [`LineError::TooLong`] if it doesn't fit in [`MAX_LINE`] (a process name can't make it
    /// that long; the check keeps the agent within what the host accepts).
    pub fn to_line(&self) -> Result<Vec<u8>, LineError> {
        let mut line = serde_json::to_vec(self).map_err(|e| LineError::Json(e.to_string()))?;
        line.push(b'\n');
        if line.len() > MAX_LINE {
            return Err(LineError::TooLong);
        }
        Ok(line)
    }

    /// Parses one control line (with or without its newline).
    ///
    /// # Errors
    ///
    /// [`LineError::Json`] if the line isn't a JSON object with a string `type`.
    pub fn from_line(line: &[u8]) -> Result<Self, LineError> {
        let line = line.strip_suffix(b"\n").unwrap_or(line);
        serde_json::from_slice(line).map_err(|e| LineError::Json(e.to_string()))
    }
}

/// One message from the host to the agent, on a `host-control` stream. Reserved: no messages are
/// defined yet (T-020 C-6: extension-host cleanup, idle cache drop, CA rotation are candidates).
/// An agent ignores types it doesn't know.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum HostMessage {
    /// A message type this side doesn't know. Ignored.
    #[serde(other)]
    Unknown,
}

/// A control line that can't be written or read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LineError {
    /// Longer than [`MAX_LINE`].
    #[error("control line longer than {MAX_LINE} bytes")]
    TooLong,
    /// Not a valid message.
    #[error("invalid control message: {0}")]
    Json(String),
}

/// Reads one `\n`-terminated line of at most `max` bytes (newline included) into `line`, which is
/// cleared first. Returns `Ok(false)` at a clean end of stream with no partial line.
///
/// # Errors
///
/// The reader's I/O errors; [`io::ErrorKind::InvalidData`] when the line runs past `max` bytes;
/// [`io::ErrorKind::UnexpectedEof`] when the stream ends inside a line.
pub async fn read_line<R>(reader: &mut R, line: &mut Vec<u8>, max: usize) -> io::Result<bool>
where
    R: AsyncBufRead + Unpin + ?Sized,
{
    line.clear();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return if line.is_empty() {
                Ok(false)
            } else {
                Err(io::ErrorKind::UnexpectedEof.into())
            };
        }
        let (take, done) = match available.iter().position(|&b| b == b'\n') {
            Some(i) => (i + 1, true),
            None => (available.len(), false),
        };
        if line.len() + take > max {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                LineError::TooLong,
            ));
        }
        line.extend_from_slice(available.get(..take).unwrap_or_default());
        reader.consume(take);
        if done {
            return Ok(true);
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn hello_carries_this_builds_version_and_protocol() {
        let line = AgentMessage::hello().to_line().unwrap();
        let text = String::from_utf8(line).unwrap();
        assert_eq!(
            text,
            format!(
                "{{\"type\":\"hello\",\"agent_version\":\"{}\",\"protocol\":1}}\n",
                puddle_types::VERSION
            )
        );
    }

    #[test]
    fn an_unnamed_oom_kill_has_no_pid_or_process_fields() {
        let line = AgentMessage::oom_kill(None, None).to_line().unwrap();
        assert_eq!(line, b"{\"type\":\"oom_kill\"}\n");
        assert_eq!(
            AgentMessage::from_line(&line).unwrap(),
            AgentMessage::oom_kill(None, None)
        );
    }

    #[test]
    fn unknown_types_and_fields_parse_as_unknown_or_are_ignored() {
        assert_eq!(
            AgentMessage::from_line(b"{\"type\":\"cpu_pressure\",\"x\":1}").unwrap(),
            AgentMessage::Unknown
        );
        assert_eq!(
            AgentMessage::from_line(b"{\"type\":\"oom_kill\",\"pid\":3,\"extra\":true}").unwrap(),
            AgentMessage::oom_kill(Some(3), None)
        );
    }

    #[test]
    fn garbage_is_an_error_not_a_panic() {
        for bad in [
            &b""[..],
            b"{",
            b"[]",
            b"{\"pid\":1}",
            b"{\"type\":7}",
            b"{\"type\":\"oom_kill\",\"pid\":-1}",
            b"\xff\xfe",
        ] {
            assert!(
                matches!(AgentMessage::from_line(bad), Err(LineError::Json(_))),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn a_message_too_long_for_the_host_is_refused_by_the_writer() {
        let long = AgentMessage::oom_kill(Some(1), Some("x".repeat(MAX_LINE)));
        assert_eq!(long.to_line(), Err(LineError::TooLong));
        assert!(LineError::TooLong.to_string().contains("4096"));
    }

    async fn lines(input: &[u8], max: usize) -> Vec<io::Result<Vec<u8>>> {
        let mut reader = tokio::io::BufReader::with_capacity(3, input);
        let mut out = Vec::new();
        let mut line = Vec::new();
        loop {
            match read_line(&mut reader, &mut line, max).await {
                Ok(true) => out.push(Ok(line.clone())),
                Ok(false) => return out,
                Err(e) => {
                    out.push(Err(e));
                    return out;
                }
            }
        }
    }

    #[tokio::test]
    async fn read_line_splits_on_newlines_across_buffer_refills() {
        let got = lines(b"ab\ncdefg\n\n", 16).await;
        let got: Vec<_> = got.into_iter().map(Result::unwrap).collect();
        assert_eq!(got, [&b"ab\n"[..], b"cdefg\n", b"\n"]);
    }

    #[tokio::test]
    async fn read_line_refuses_a_line_past_the_limit() {
        let got = lines(b"abc\nabcdefgh\n", 5).await;
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].as_ref().unwrap(), b"abc\n");
        assert_eq!(
            got[1].as_ref().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        // Exactly at the limit is fine.
        assert_eq!(lines(b"abcd\n", 5).await[0].as_ref().unwrap(), b"abcd\n");
    }

    #[tokio::test]
    async fn read_line_reports_a_stream_cut_inside_a_line() {
        let got = lines(b"ok\npartial", 64).await;
        assert_eq!(
            got[1].as_ref().unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn host_messages_of_any_type_are_ignored_for_now() {
        let msg: HostMessage = serde_json::from_slice(b"{\"type\":\"drop_caches\"}").unwrap();
        assert_eq!(msg, HostMessage::Unknown);
    }

    proptest! {
        #[test]
        fn any_bytes_parse_or_fail_without_panicking(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
            let _ = AgentMessage::from_line(&bytes);
        }

        #[test]
        fn oom_kill_lines_round_trip(pid in proptest::option::of(any::<u32>()), name in proptest::option::of(".{0,64}")) {
            let msg = AgentMessage::oom_kill(pid, name);
            let line = msg.to_line().unwrap();
            prop_assert_eq!(line.split(|&b| b == b'\n').count(), 2);
            prop_assert_eq!(AgentMessage::from_line(&line).unwrap(), msg);
        }
    }
}
