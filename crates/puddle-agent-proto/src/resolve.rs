// SPDX-License-Identifier: GPL-3.0-or-later
//! The `resolve` stream: the guest's stub DNS asks the host about one name.
//!
//! The agent opens a stream per lookup and writes [`PREAMBLE`], then one JSON [`ResolveQuery`]
//! line. The host answers with one JSON [`ResolveAnswer`] line and closes the stream. Lines are
//! `\n`-terminated and bounded ([`MAX_QUERY_LINE`], [`MAX_ANSWER_LINE`]).
//!
//! The host decides with the sandbox's rules and never writes a pending row for a lookup:
//!
//! - a name the rules allow is looked up on the host, and the answer says whether the guest should
//!   get a stand-in address for it ([`ResolveAnswer::StandIn`]) or `NXDOMAIN`;
//! - a name that isn't allowed gets a stand-in **without any lookup**, so DNS is no channel out
//!   and the connect that follows produces the deny or pending row;
//! - `SRV`, `TXT` and `MX` records are returned for allowed names only.
//!
//! ```
//! use puddle_agent_proto::resolve::{RecordType, ResolveQuery};
//! let q = ResolveQuery::new("example.com", RecordType::A);
//! assert_eq!(q.to_line().unwrap(), b"{\"name\":\"example.com\",\"type\":\"A\"}\n");
//! ```

use std::io;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

use crate::control::read_line;

/// Bytes that open a resolve stream ([`crate::kind::StreamKind::Resolve`] v1).
pub const PREAMBLE: &[u8] = crate::kind::StreamKind::Resolve.preamble();

/// Longest query line the host reads, newline included.
pub const MAX_QUERY_LINE: usize = 512;

/// Longest answer line the agent reads, newline included.
pub const MAX_ANSWER_LINE: usize = 16 * 1024;

/// Most records one answer carries; the host cuts a longer list.
pub const MAX_RECORDS: usize = 16;

/// Longest host name the protocol carries (the DNS limit).
pub const MAX_NAME: usize = 253;

/// The record types the stub forwards. Address queries (`A`) are answered with stand-ins;
/// `AAAA` and every other type never leave the guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
#[non_exhaustive]
pub enum RecordType {
    /// An address: the answer says whether the guest gets a stand-in.
    A,
    /// Service records (`mongodb+srv`, Kerberos).
    Srv,
    /// Text records.
    Txt,
    /// Mail exchangers.
    Mx,
}

/// One lookup, from the agent to the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolveQuery {
    /// The name asked for, lower case, without a trailing dot. Untrusted: the host normalises it.
    pub name: String,
    /// The record type.
    #[serde(rename = "type")]
    pub rtype: RecordType,
}

impl ResolveQuery {
    /// A query for `name`.
    #[must_use]
    pub fn new(name: impl Into<String>, rtype: RecordType) -> Self {
        Self {
            name: name.into(),
            rtype,
        }
    }

    /// The query as a line, newline included.
    ///
    /// # Errors
    ///
    /// [`ResolveError::TooLong`] when the line passes [`MAX_QUERY_LINE`].
    pub fn to_line(&self) -> Result<Vec<u8>, ResolveError> {
        let mut line =
            serde_json::to_vec(self).map_err(|err| ResolveError::Invalid(err.to_string()))?;
        line.push(b'\n');
        if line.len() > MAX_QUERY_LINE {
            return Err(ResolveError::TooLong);
        }
        Ok(line)
    }

    /// Parses a query line (with or without its newline).
    ///
    /// # Errors
    ///
    /// [`ResolveError::Invalid`] for anything that isn't a query.
    pub fn from_line(line: &[u8]) -> Result<Self, ResolveError> {
        let line = line.strip_suffix(b"\n").unwrap_or(line);
        serde_json::from_slice(line).map_err(|err| ResolveError::Invalid(err.to_string()))
    }
}

/// Why the host says a name gets a stand-in. For logs and tests; the guest sees the same stand-in
/// for every reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum StandInReason {
    /// Allowed, and the host resolved it.
    Resolves,
    /// Allowed, but the host can't resolve it and the company proxy will: the proxy decides.
    ViaUpstream,
    /// No rule allows it (denied or pending): never looked up. The connect decides.
    NotAllowed,
    /// The name is blocked by itself or by every address it resolves to: the connect says why.
    Blocked,
}

/// One record of an [`ResolveAnswer::Records`] answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Record {
    /// A service record.
    Srv {
        /// Priority.
        priority: u16,
        /// Weight.
        weight: u16,
        /// Port.
        port: u16,
        /// Target host name.
        target: String,
    },
    /// A text record.
    Txt {
        /// The character strings.
        strings: Vec<String>,
    },
    /// A mail exchanger.
    Mx {
        /// Preference.
        preference: u16,
        /// Exchanger host name.
        exchange: String,
    },
}

/// The host's answer to a [`ResolveQuery`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
#[non_exhaustive]
pub enum ResolveAnswer {
    /// Answer an `A` query with a stand-in address.
    StandIn {
        /// Why.
        why: StandInReason,
        /// Seconds the answer may be cached.
        ttl: u32,
    },
    /// The name doesn't exist (`NXDOMAIN`).
    NoSuchName {
        /// Seconds the answer may be cached.
        ttl: u32,
    },
    /// The name exists but has nothing of this type (`NODATA`).
    NoData {
        /// Seconds the answer may be cached.
        ttl: u32,
    },
    /// Records for an `SRV`, `TXT` or `MX` query.
    Records {
        /// The records, at most [`MAX_RECORDS`].
        records: Vec<Record>,
        /// Seconds the answer may be cached.
        ttl: u32,
    },
    /// The host couldn't answer now (policy unreadable, busy, timed out): the guest gets
    /// `SERVFAIL` and may retry.
    Unavailable,
    /// An answer this build doesn't know. Treated as [`ResolveAnswer::Unavailable`].
    #[serde(other)]
    Unknown,
}

impl ResolveAnswer {
    /// The answer as a line, newline included.
    ///
    /// # Errors
    ///
    /// [`ResolveError::TooLong`] when the line passes [`MAX_ANSWER_LINE`].
    pub fn to_line(&self) -> Result<Vec<u8>, ResolveError> {
        let mut line =
            serde_json::to_vec(self).map_err(|err| ResolveError::Invalid(err.to_string()))?;
        line.push(b'\n');
        if line.len() > MAX_ANSWER_LINE {
            return Err(ResolveError::TooLong);
        }
        Ok(line)
    }

    /// Parses an answer line (with or without its newline).
    ///
    /// # Errors
    ///
    /// [`ResolveError::Invalid`] for anything that isn't an answer.
    pub fn from_line(line: &[u8]) -> Result<Self, ResolveError> {
        let line = line.strip_suffix(b"\n").unwrap_or(line);
        serde_json::from_slice(line).map_err(|err| ResolveError::Invalid(err.to_string()))
    }
}

/// A lookup that failed on the wire.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ResolveError {
    /// The line is longer than its limit.
    #[error("resolve line too long")]
    TooLong,
    /// The line isn't valid.
    #[error("invalid resolve message: {0}")]
    Invalid(String),
    /// The stream ended before an answer.
    #[error("resolve stream ended before an answer")]
    NoAnswer,
    /// The stream failed.
    #[error("resolve stream i/o: {0}")]
    Io(#[from] io::Error),
    /// No answer within the limit.
    #[error("no resolve answer within {0:?}")]
    Timeout(Duration),
}

/// Asks the host one question on a fresh stream (the agent side): writes the preamble and the
/// query, reads the answer line.
///
/// # Errors
///
/// [`ResolveError`] for a failed stream, a missing or invalid answer, or no answer within `limit`.
pub async fn ask<S>(
    stream: S,
    query: &ResolveQuery,
    limit: Duration,
) -> Result<ResolveAnswer, ResolveError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let line = query.to_line()?;
    let mut stream = BufReader::new(stream);
    let exchange = async {
        let mut request = PREAMBLE.to_vec();
        request.extend_from_slice(&line);
        stream.write_all(&request).await?;
        stream.flush().await?;
        let mut answer = Vec::with_capacity(128);
        if !read_line(&mut stream, &mut answer, MAX_ANSWER_LINE)
            .await
            .map_err(|err| {
                if err.kind() == io::ErrorKind::InvalidData {
                    ResolveError::TooLong
                } else {
                    ResolveError::Io(err)
                }
            })?
        {
            return Err(ResolveError::NoAnswer);
        }
        ResolveAnswer::from_line(&answer)
    };
    tokio::time::timeout(limit, exchange)
        .await
        .map_err(|_| ResolveError::Timeout(limit))?
}

/// Reads one query line (the host side, after the preamble).
///
/// # Errors
///
/// [`ResolveError`] for a stream that fails, ends or sends a line over [`MAX_QUERY_LINE`] or
/// anything that isn't a query.
pub async fn read_query<R>(reader: &mut R) -> Result<ResolveQuery, ResolveError>
where
    R: AsyncBufReadExt + AsyncReadExt + Unpin,
{
    let mut line = Vec::with_capacity(96);
    match read_line(reader, &mut line, MAX_QUERY_LINE).await {
        Ok(true) => ResolveQuery::from_line(&line),
        Ok(false) => Err(ResolveError::NoAnswer),
        Err(err) if err.kind() == io::ErrorKind::InvalidData => Err(ResolveError::TooLong),
        Err(err) => Err(ResolveError::Io(err)),
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn a_query_round_trips_and_keeps_its_wire_shape() {
        let q = ResolveQuery::new("_mongodb._tcp.db.example.net", RecordType::Srv);
        let line = q.to_line().unwrap();
        assert_eq!(
            line,
            b"{\"name\":\"_mongodb._tcp.db.example.net\",\"type\":\"SRV\"}\n"
        );
        assert_eq!(ResolveQuery::from_line(&line).unwrap(), q);
    }

    #[test]
    fn every_answer_round_trips() {
        let answers = [
            ResolveAnswer::StandIn {
                why: StandInReason::ViaUpstream,
                ttl: 30,
            },
            ResolveAnswer::NoSuchName { ttl: 5 },
            ResolveAnswer::NoData { ttl: 5 },
            ResolveAnswer::Records {
                records: vec![
                    Record::Srv {
                        priority: 1,
                        weight: 2,
                        port: 27017,
                        target: "shard0.example.net".into(),
                    },
                    Record::Txt {
                        strings: vec!["a=b".into()],
                    },
                    Record::Mx {
                        preference: 10,
                        exchange: "mx.example.net".into(),
                    },
                ],
                ttl: 60,
            },
            ResolveAnswer::Unavailable,
        ];
        for a in answers {
            assert_eq!(ResolveAnswer::from_line(&a.to_line().unwrap()).unwrap(), a);
        }
    }

    #[test]
    fn an_answer_type_from_the_future_is_unknown_not_an_error() {
        assert_eq!(
            ResolveAnswer::from_line(b"{\"result\":\"teleport\",\"x\":1}\n").unwrap(),
            ResolveAnswer::Unknown
        );
    }

    #[test]
    fn garbage_and_overlong_lines_are_errors() {
        assert!(matches!(
            ResolveQuery::from_line(b"hello\n"),
            Err(ResolveError::Invalid(_))
        ));
        assert!(matches!(
            ResolveQuery::from_line(b"{\"name\":\"x\",\"type\":\"AAAA\"}\n"),
            Err(ResolveError::Invalid(_))
        ));
        let long = ResolveQuery::new("a".repeat(MAX_QUERY_LINE), RecordType::A);
        assert!(matches!(long.to_line(), Err(ResolveError::TooLong)));
        let many = ResolveAnswer::Records {
            records: vec![
                Record::Txt {
                    strings: vec!["x".repeat(1000)]
                };
                MAX_RECORDS + 1
            ],
            ttl: 1,
        };
        assert!(matches!(many.to_line(), Err(ResolveError::TooLong)));
    }

    #[tokio::test]
    async fn ask_writes_the_preamble_and_the_query_and_reads_the_answer() {
        let (client, mut server) = tokio::io::duplex(4096);
        let host = tokio::spawn(async move {
            let mut reader = BufReader::new(&mut server);
            let mut preamble = vec![0u8; PREAMBLE.len()];
            reader.read_exact(&mut preamble).await.unwrap();
            assert_eq!(preamble, PREAMBLE);
            let q = read_query(&mut reader).await.unwrap();
            assert_eq!(q, ResolveQuery::new("example.com", RecordType::A));
            let answer = ResolveAnswer::NoSuchName { ttl: 9 }.to_line().unwrap();
            server.write_all(&answer).await.unwrap();
        });
        let got = ask(
            client,
            &ResolveQuery::new("example.com", RecordType::A),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        assert_eq!(got, ResolveAnswer::NoSuchName { ttl: 9 });
        host.await.unwrap();
    }

    #[tokio::test]
    async fn ask_fails_on_a_closed_stream_a_bad_answer_a_long_answer_and_silence() {
        let q = ResolveQuery::new("example.com", RecordType::A);
        let limit = Duration::from_millis(200);

        let (client, server) = tokio::io::duplex(4096);
        drop(server);
        assert!(ask(client, &q, limit).await.is_err());

        let (client, mut server) = tokio::io::duplex(4096);
        server.write_all(b"nonsense\n").await.unwrap();
        assert!(matches!(
            ask(client, &q, limit).await,
            Err(ResolveError::Invalid(_))
        ));

        let (client, mut server) = tokio::io::duplex(64 * 1024);
        server
            .write_all(&vec![b'x'; MAX_ANSWER_LINE + 10])
            .await
            .unwrap();
        assert!(matches!(
            ask(client, &q, limit).await,
            Err(ResolveError::TooLong)
        ));

        let (client, _silent) = tokio::io::duplex(4096);
        assert!(matches!(
            ask(client, &q, limit).await,
            Err(ResolveError::Timeout(_))
        ));

        let (client, mut server) = tokio::io::duplex(4096);
        server.shutdown().await.unwrap();
        assert!(matches!(
            ask(client, &q, limit).await,
            Err(ResolveError::NoAnswer)
        ));
    }

    #[tokio::test]
    async fn read_query_refuses_a_long_line_and_a_closed_stream() {
        let overlong = vec![b'x'; MAX_QUERY_LINE + 1];
        let mut long = BufReader::new(&overlong[..]);
        assert!(matches!(
            read_query(&mut long).await,
            Err(ResolveError::TooLong)
        ));
        let mut empty = BufReader::new(&b""[..]);
        assert!(matches!(
            read_query(&mut empty).await,
            Err(ResolveError::NoAnswer)
        ));
        let mut cut = BufReader::new(&b"{\"name\""[..]);
        assert!(matches!(
            read_query(&mut cut).await,
            Err(ResolveError::Io(_))
        ));
    }

    proptest! {
        #[test]
        fn any_bytes_parse_or_fail_without_panicking(bytes in proptest::collection::vec(any::<u8>(), 0..600)) {
            let _ = ResolveQuery::from_line(&bytes);
            let _ = ResolveAnswer::from_line(&bytes);
        }
    }
}
