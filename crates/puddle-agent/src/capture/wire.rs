// SPDX-License-Identifier: GPL-3.0-or-later
//! The DNS messages the stub speaks: a strict parser for queries from the guest (hostile input)
//! and a builder for the answers. Only what the stub needs: one question, no name compression in
//! queries, `A`/`SRV`/`TXT`/`MX` answers, an `OPT` echo for `EDNS(0)`.

use std::net::Ipv4Addr;

/// `A`.
pub const TYPE_A: u16 = 1;
/// `MX`.
pub const TYPE_MX: u16 = 15;
/// `TXT`.
pub const TYPE_TXT: u16 = 16;
/// `SRV`.
pub const TYPE_SRV: u16 = 33;
const TYPE_OPT: u16 = 41;
/// The Internet class, the only one the stub answers.
pub const CLASS_IN: u16 = 1;

/// Longest query message the stub reads (over TCP a client may send up to this).
pub const MAX_QUERY: usize = 4096;
/// The payload size the stub advertises and the most it sends over UDP when the client allows it.
pub const EDNS_PAYLOAD: u16 = 1232;
/// The classic UDP limit, for clients without `EDNS(0)`.
const PLAIN_UDP: usize = 512;

/// A response code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rcode {
    /// No error.
    NoError,
    /// The query was malformed.
    FormErr,
    /// The server failed; the client may retry.
    ServFail,
    /// The name doesn't exist.
    NxDomain,
    /// The opcode isn't supported.
    NotImp,
    /// The server refuses to answer.
    Refused,
}

impl Rcode {
    /// The code in the header.
    #[must_use]
    pub const fn code(self) -> u16 {
        match self {
            Self::NoError => 0,
            Self::FormErr => 1,
            Self::ServFail => 2,
            Self::NxDomain => 3,
            Self::NotImp => 4,
            Self::Refused => 5,
        }
    }
}

/// The name in a question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryName {
    /// Letters, digits, `-` and `_` only, lower-cased, no trailing dot (the root is empty).
    Plain(String),
    /// Anything else (escape characters, non-ASCII bytes, spaces).
    Odd,
}

/// A parsed query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    /// The message id, echoed in the answer.
    pub id: u16,
    /// The question's name.
    pub name: QueryName,
    /// The question's type.
    pub qtype: u16,
    /// The question's class.
    pub qclass: u16,
    /// Whether the client set "recursion desired" (echoed).
    pub recursion_desired: bool,
    /// The payload size the client advertised in an `OPT` record, if it sent one.
    pub edns_payload: Option<u16>,
    /// The question section as received (name in the client's letter case), echoed in the answer.
    question: Vec<u8>,
}

/// Why a message isn't answered as a normal query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    /// Not a query, or too short to have an id: dropped without an answer.
    Drop,
    /// Answered with this code and no records.
    Answer {
        /// The message id.
        id: u16,
        /// The code.
        rcode: Rcode,
        /// The recursion-desired bit, echoed.
        recursion_desired: bool,
    },
}

/// Parses `msg` as a query: exactly one question, opcode 0, no compression in the question.
///
/// # Errors
///
/// [`Reject`] says whether to drop the message or answer it with an error code.
pub fn parse_query(msg: &[u8]) -> Result<Query, Reject> {
    let word = |at: usize| be16(msg, at).ok_or(Reject::Drop);
    let (id, flags, questions) = (word(0)?, word(2)?, word(4)?);
    let (answer_count, authority_count, additional_count) = (word(6)?, word(8)?, word(10)?);
    if flags & 0x8000 != 0 {
        return Err(Reject::Drop);
    }
    let recursion_desired = flags & 0x0100 != 0;
    let answer = |rcode| Reject::Answer {
        id,
        rcode,
        recursion_desired,
    };
    if (flags >> 11) & 0xF != 0 {
        return Err(answer(Rcode::NotImp));
    }
    if questions != 1 || answer_count != 0 || authority_count != 0 {
        return Err(answer(Rcode::FormErr));
    }
    let (name, mut at) = read_name(msg, 12).ok_or_else(|| answer(Rcode::FormErr))?;
    let (qtype, qclass) = be16(msg, at)
        .zip(be16(msg, at + 2))
        .ok_or_else(|| answer(Rcode::FormErr))?;
    at += 4;
    let question = msg.get(12..at).unwrap_or_default().to_vec();
    let edns_payload = edns_payload(msg, at, additional_count);
    Ok(Query {
        id,
        name,
        qtype,
        qclass,
        recursion_desired,
        edns_payload,
        question,
    })
}

/// The big-endian 16-bit word at `at`.
fn be16(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*bytes.get(at)?, *bytes.get(at + 1)?]))
}

/// Reads an uncompressed name at `start`; returns it and the offset after it. A compression
/// pointer, a label over 63 bytes, or a name over 255 bytes is a malformed question.
fn read_name(msg: &[u8], start: usize) -> Option<(QueryName, usize)> {
    let mut at = start;
    let mut name = String::new();
    let mut plain = true;
    loop {
        let len = usize::from(*msg.get(at)?);
        at += 1;
        if len == 0 {
            break;
        }
        if len > 63 || at - start > 255 {
            return None;
        }
        let label = msg.get(at..at + len)?;
        at += len;
        if !name.is_empty() {
            name.push('.');
        }
        for &b in label {
            if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' {
                name.push(char::from(b.to_ascii_lowercase()));
            } else {
                plain = false;
            }
        }
    }
    let name = if plain {
        QueryName::Plain(name)
    } else {
        QueryName::Odd
    };
    Some((name, at))
}

/// The `OPT` record's advertised payload size among the `arcount` additional records at `at`.
/// A malformed additional section is ignored: the question is what matters.
fn edns_payload(msg: &[u8], mut at: usize, additional_count: u16) -> Option<u16> {
    for _ in 0..additional_count.min(8) {
        // Owner name: the root (0), a pointer (2 bytes) or labels.
        loop {
            let len = usize::from(*msg.get(at)?);
            if len == 0 {
                at += 1;
                break;
            }
            if len & 0xC0 == 0xC0 {
                at += 2;
                break;
            }
            at += 1 + len;
        }
        let (rtype, class, rdlen) = (
            be16(msg, at)?,
            be16(msg, at + 2)?,
            usize::from(be16(msg, at + 8)?),
        );
        if rtype == TYPE_OPT {
            return Some(class.max(512));
        }
        at += 10 + rdlen;
    }
    None
}

/// The data of one answer record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rdata {
    /// An address.
    A(Ipv4Addr),
    /// A service record.
    Srv {
        /// Priority.
        priority: u16,
        /// Weight.
        weight: u16,
        /// Port.
        port: u16,
        /// Target name (plain, no trailing dot).
        target: String,
    },
    /// Text strings.
    Txt(Vec<String>),
    /// A mail exchanger.
    Mx {
        /// Preference.
        preference: u16,
        /// Exchanger name (plain, no trailing dot).
        exchange: String,
    },
}

/// One record in the answer or additional section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// The owner: `None` is the question's name, else a plain name.
    pub owner: Option<String>,
    /// Seconds to live.
    pub ttl: u32,
    /// The data.
    pub data: Rdata,
}

/// Builds the response to `query`. Over UDP (`udp`), a response that doesn't fit what the client
/// allows keeps its question and sets "truncated", so the client retries over TCP.
#[must_use]
pub fn respond(
    query: &Query,
    rcode: Rcode,
    answers: &[Record],
    additional: &[Record],
    udp: bool,
) -> Vec<u8> {
    let full = build(query, rcode, answers, additional, false);
    let limit = query
        .edns_payload
        .map_or(PLAIN_UDP, |p| usize::from(p.min(EDNS_PAYLOAD)));
    if udp && full.len() > limit {
        return build(query, rcode, &[], &[], true);
    }
    full
}

/// A response for a message that isn't a normal query (`FORMERR`, `NOTIMP`): the header only.
#[must_use]
pub fn error_response(id: u16, rcode: Rcode, recursion_desired: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(12);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&flags(rcode, recursion_desired, false).to_be_bytes());
    out.extend_from_slice(&[0; 8]);
    out
}

fn flags(rcode: Rcode, recursion_desired: bool, truncated: bool) -> u16 {
    // QR and RA set; the stub is not authoritative.
    0x8080 | (u16::from(recursion_desired) << 8) | (u16::from(truncated) << 9) | rcode.code()
}

fn build(
    query: &Query,
    rcode: Rcode,
    answers: &[Record],
    additional: &[Record],
    truncated: bool,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(96);
    out.extend_from_slice(&query.id.to_be_bytes());
    out.extend_from_slice(&flags(rcode, query.recursion_desired, truncated).to_be_bytes());
    let opt = usize::from(query.edns_payload.is_some());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&count(answers.len()).to_be_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&count(additional.len() + opt).to_be_bytes());
    out.extend_from_slice(&query.question);
    for record in answers.iter().chain(additional) {
        put_record(&mut out, record);
    }
    if opt == 1 {
        // The root name, type OPT, our payload size as the class, no extended flags, no options.
        out.push(0);
        out.extend_from_slice(&TYPE_OPT.to_be_bytes());
        out.extend_from_slice(&EDNS_PAYLOAD.to_be_bytes());
        out.extend_from_slice(&[0; 6]);
    }
    out
}

fn count(n: usize) -> u16 {
    u16::try_from(n).unwrap_or(u16::MAX)
}

fn put_record(out: &mut Vec<u8>, record: &Record) {
    match &record.owner {
        // A pointer to the question's name at offset 12.
        None => out.extend_from_slice(&[0xC0, 0x0C]),
        Some(owner) => put_name(out, owner),
    }
    let (rtype, rdata) = match &record.data {
        Rdata::A(ip) => (TYPE_A, ip.octets().to_vec()),
        Rdata::Srv {
            priority,
            weight,
            port,
            target,
        } => {
            let mut data = Vec::with_capacity(8 + target.len());
            for n in [priority, weight, port] {
                data.extend_from_slice(&n.to_be_bytes());
            }
            put_name(&mut data, target);
            (TYPE_SRV, data)
        }
        Rdata::Txt(strings) => {
            let mut data = Vec::new();
            for s in strings {
                if s.is_empty() {
                    data.push(0);
                }
                // A character-string is at most 255 bytes: longer text is split.
                for chunk in s.as_bytes().chunks(255) {
                    data.push(u8::try_from(chunk.len()).unwrap_or(255));
                    data.extend_from_slice(chunk);
                }
            }
            (TYPE_TXT, data)
        }
        Rdata::Mx {
            preference,
            exchange,
        } => {
            let mut data = preference.to_be_bytes().to_vec();
            put_name(&mut data, exchange);
            (TYPE_MX, data)
        }
    };
    out.extend_from_slice(&rtype.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    out.extend_from_slice(&record.ttl.to_be_bytes());
    out.extend_from_slice(&count(rdata.len()).to_be_bytes());
    out.extend_from_slice(&rdata);
}

/// A name as labels. The caller passes only plain names (labels of 1 to 63 bytes).
fn put_name(out: &mut Vec<u8>, name: &str) {
    for label in name.split('.').filter(|l| !l.is_empty()) {
        let bytes = label
            .as_bytes()
            .get(..label.len().min(63))
            .unwrap_or_default();
        out.push(u8::try_from(bytes.len()).unwrap_or(63));
        out.extend_from_slice(bytes);
    }
    out.push(0);
}

#[cfg(test)]
pub(crate) mod tests;
