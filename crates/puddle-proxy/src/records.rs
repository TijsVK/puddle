// SPDX-License-Identifier: GPL-3.0-or-later
//! `SRV`, `TXT` and `MX` lookups for names the rules allow (the guest's stub DNS forwards them;
//! `mongodb+srv` and Kerberos need them). Address lookups go through [`crate::Resolver`].
//!
//! The lookups use the host's own DNS configuration, like the address resolver does, so a name
//! the host can't resolve has no records here either; the answer is then `NODATA` or `NXDOMAIN`
//! and the guest's client reports it as it would on any network that lacks the record.

use std::time::Duration;

use hickory_resolver::TokioResolver;
use hickory_resolver::proto::rr::{RData, RecordType as DnsType};
use puddle_agent_proto::resolve::{MAX_RECORDS, Record, RecordType};

use crate::destination::BoxFuture;

/// Shortest and longest time an answer may be cached by the guest.
const TTL_RANGE: (u32, u32) = (5, 300);

/// Longest TXT string kept, and most TXT bytes in one answer.
const MAX_TXT_BYTES: usize = 8 * 1024;

/// The records found for a name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Records {
    /// The records, at most [`MAX_RECORDS`].
    pub records: Vec<Record>,
    /// How long the answer may be cached.
    pub ttl: Duration,
}

/// Why a record lookup has no records.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RecordError {
    /// The name doesn't exist.
    #[error("no such name")]
    NoSuchName,
    /// The name exists, with no record of this type.
    #[error("no records of this type")]
    NoData,
    /// The lookup failed (no server, timeout, malformed answer).
    #[error("lookup failed: {0}")]
    Failed(String),
}

/// Looks up `SRV`, `TXT` and `MX` records of an allowed name. Tests fake it;
/// [`SystemRecords`] asks the host's DNS servers.
pub trait RecordResolver: Send + Sync {
    /// The records of type `rtype` for `fqdn`: lower case, no trailing dot, labels of letters,
    /// digits, `-` and `_` only (the proxy has checked it).
    fn records<'a>(
        &'a self,
        fqdn: &'a str,
        rtype: RecordType,
    ) -> BoxFuture<'a, Result<Records, RecordError>>;
}

/// The host's DNS configuration (`/etc/resolv.conf`, the Windows adapter settings), read at each
/// lookup so a network change is picked up.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemRecords;

impl RecordResolver for SystemRecords {
    fn records<'a>(
        &'a self,
        fqdn: &'a str,
        rtype: RecordType,
    ) -> BoxFuture<'a, Result<Records, RecordError>> {
        Box::pin(async move {
            let dns_type = match rtype {
                RecordType::Srv => DnsType::SRV,
                RecordType::Txt => DnsType::TXT,
                RecordType::Mx => DnsType::MX,
                _ => return Err(RecordError::NoData),
            };
            let resolver: TokioResolver = TokioResolver::builder_tokio()
                .and_then(hickory_resolver::ResolverBuilder::build)
                .map_err(|err| RecordError::Failed(err.to_string()))?;
            // The trailing dot makes it a single query: no search-domain guesses.
            let lookup = resolver
                .lookup(format!("{fqdn}."), dns_type)
                .await
                .map_err(|err| {
                    if err.is_nx_domain() {
                        RecordError::NoSuchName
                    } else if err.is_no_records_found() {
                        RecordError::NoData
                    } else {
                        RecordError::Failed(err.to_string())
                    }
                })?;
            let mut records = Vec::new();
            let mut ttl = TTL_RANGE.1;
            let mut txt_bytes = 0;
            for answer in lookup.answers() {
                if records.len() >= MAX_RECORDS {
                    break;
                }
                let record = match &answer.data {
                    RData::SRV(srv) => {
                        target_name(&srv.target.to_ascii()).map(|target| Record::Srv {
                            priority: srv.priority,
                            weight: srv.weight,
                            port: srv.port,
                            target,
                        })
                    }
                    RData::MX(mx) => {
                        target_name(&mx.exchange.to_ascii()).map(|exchange| Record::Mx {
                            preference: mx.preference,
                            exchange,
                        })
                    }
                    RData::TXT(txt) => {
                        let strings: Vec<String> = txt
                            .txt_data
                            .iter()
                            .map(|s| String::from_utf8_lossy(s).into_owned())
                            .collect();
                        txt_bytes += strings.iter().map(String::len).sum::<usize>();
                        (txt_bytes <= MAX_TXT_BYTES).then_some(Record::Txt { strings })
                    }
                    _ => None,
                };
                if let Some(record) = record {
                    ttl = ttl.min(answer.ttl);
                    records.push(record);
                }
            }
            if records.is_empty() {
                return Err(RecordError::NoData);
            }
            let ttl = ttl.clamp(TTL_RANGE.0, TTL_RANGE.1);
            Ok(Records {
                records,
                ttl: Duration::from_secs(u64::from(ttl)),
            })
        })
    }
}

/// A record's target as the protocol carries it: lower case, no trailing dot. `None` for the root
/// (an SRV target of `.` means "no service") and for anything that isn't a plain host name.
fn target_name(ascii: &str) -> Option<String> {
    let name = ascii
        .strip_suffix('.')
        .unwrap_or(ascii)
        .to_ascii_lowercase();
    valid_fqdn(&name).then_some(name)
}

/// Whether `name` is a syntactically plain name: labels of 1-63 letters, digits, `-` or `_`,
/// at most 253 characters in all.
pub(crate) fn valid_fqdn(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= puddle_agent_proto::resolve::MAX_NAME
        && name.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_names_are_valid_and_everything_else_is_not() {
        for ok in [
            "a",
            "example.com",
            "_mongodb._tcp.c0.example.net",
            "xn--bcher-kva.example",
            "a-b.c-d",
        ] {
            assert!(valid_fqdn(ok), "{ok}");
        }
        for bad in [
            "",
            ".",
            "a..b",
            "a.b.",
            "Upper.example",
            "sp ace.example",
            "esc\u{1b}.example",
            "bücher.example",
            "star*.example",
            &"a".repeat(64),
            &format!(
                "{}.{}.{}.{}",
                "a".repeat(63),
                "b".repeat(63),
                "c".repeat(63),
                "d".repeat(63)
            ),
        ] {
            assert!(!valid_fqdn(bad), "{bad:?}");
        }
    }

    #[test]
    fn record_targets_are_cleaned_and_the_root_is_dropped() {
        assert_eq!(
            target_name("Shard0.Example.NET."),
            Some("shard0.example.net".into())
        );
        assert_eq!(target_name("."), None);
        assert_eq!(target_name("bad name.example."), None);
    }

    #[tokio::test]
    async fn an_address_type_is_no_data_for_the_record_resolver() {
        let err = SystemRecords
            .records("example.com", RecordType::A)
            .await
            .unwrap_err();
        assert_eq!(err, RecordError::NoData);
    }
}
