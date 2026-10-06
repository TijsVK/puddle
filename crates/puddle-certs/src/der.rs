// SPDX-License-Identifier: GPL-3.0-or-later
//! Just enough DER to select roots: issuer, subject, `notAfter`, public key and common name of an
//! X.509 certificate. Input is the host's own certificate stores, but any bytes are handled
//! without panicking (property test below).

/// What a certificate that can't be read lacks, for the skipped list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("not an X.509 certificate: {0}")]
pub(crate) struct Malformed(pub(crate) &'static str);

/// The fields root selection uses. Names and the key are the raw DER (tag included), so equal
/// bytes mean equal names, as in the chain engines' own issuer matching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CertFields<'a> {
    pub(crate) issuer: &'a [u8],
    pub(crate) subject: &'a [u8],
    pub(crate) spki: &'a [u8],
    /// Seconds since the Unix epoch.
    pub(crate) not_after: i64,
    pub(crate) subject_cn: Option<String>,
}

const SEQUENCE: u8 = 0x30;
const SET: u8 = 0x31;
const INTEGER: u8 = 0x02;
const OID: u8 = 0x06;
const UTC_TIME: u8 = 0x17;
const GENERALIZED_TIME: u8 = 0x18;
const VERSION: u8 = 0xa0;
/// 2.5.4.3, `commonName`.
const OID_CN: &[u8] = &[0x55, 0x04, 0x03];

/// One TLV: its tag, its contents, and the input after it.
struct Tlv<'a> {
    tag: u8,
    contents: &'a [u8],
    whole: &'a [u8],
    rest: &'a [u8],
}

fn tlv(input: &[u8]) -> Result<Tlv<'_>, Malformed> {
    let (&tag, after_tag) = input.split_first().ok_or(Malformed("truncated"))?;
    if tag & 0x1f == 0x1f {
        return Err(Malformed("multi-byte tag"));
    }
    let (&first, after_len) = after_tag.split_first().ok_or(Malformed("truncated"))?;
    let (len, body) = if first < 0x80 {
        (usize::from(first), after_len)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 {
            return Err(Malformed("unsupported length"));
        }
        let (bytes, body) = after_len
            .split_at_checked(n)
            .ok_or(Malformed("truncated"))?;
        let len = bytes
            .iter()
            .fold(0_usize, |acc, &b| (acc << 8) | usize::from(b));
        (len, body)
    };
    let (contents, rest) = body.split_at_checked(len).ok_or(Malformed("truncated"))?;
    let header = input.len() - body.len();
    let whole = input.get(..header + len).ok_or(Malformed("truncated"))?;
    Ok(Tlv {
        tag,
        contents,
        whole,
        rest,
    })
}

fn expect<'a>(input: &'a [u8], tag: u8, what: &'static str) -> Result<Tlv<'a>, Malformed> {
    let t = tlv(input)?;
    if t.tag == tag {
        Ok(t)
    } else {
        Err(Malformed(what))
    }
}

/// Reads `der` (one certificate).
pub(crate) fn parse(der: &[u8]) -> Result<CertFields<'_>, Malformed> {
    let cert = expect(der, SEQUENCE, "no certificate sequence")?;
    if !cert.rest.is_empty() {
        return Err(Malformed("trailing bytes"));
    }
    let tbs = expect(cert.contents, SEQUENCE, "no tbsCertificate")?;
    let mut rest = tbs.contents;
    if rest.first() == Some(&VERSION) {
        rest = tlv(rest)?.rest;
    }
    let serial = expect(rest, INTEGER, "no serial number")?;
    let algorithm = expect(serial.rest, SEQUENCE, "no signature algorithm")?;
    let issuer = expect(algorithm.rest, SEQUENCE, "no issuer")?;
    let validity = expect(issuer.rest, SEQUENCE, "no validity")?;
    let subject = expect(validity.rest, SEQUENCE, "no subject")?;
    let spki = expect(subject.rest, SEQUENCE, "no public key")?;

    let not_before = tlv(validity.contents)?;
    let not_after = tlv(not_before.rest)?;
    Ok(CertFields {
        issuer: issuer.whole,
        subject: subject.whole,
        spki: spki.whole,
        not_after: time(&not_after)?,
        subject_cn: common_name(subject.contents),
    })
}

/// `UTCTime` (`YYMMDDHHMMSSZ`, 1950–2049) or `GeneralizedTime` (`YYYYMMDDHHMMSSZ`) as Unix
/// seconds.
fn time(t: &Tlv<'_>) -> Result<i64, Malformed> {
    let digits = |s: &[u8]| -> Result<i64, Malformed> {
        s.iter().try_fold(0_i64, |acc, &b| {
            if b.is_ascii_digit() {
                Ok(acc * 10 + i64::from(b - b'0'))
            } else {
                Err(Malformed("bad time"))
            }
        })
    };
    let (year, rest) = match (t.tag, t.contents.len()) {
        (UTC_TIME, 13) => {
            let (yy, rest) = t.contents.split_at(2);
            let yy = digits(yy)?;
            (if yy < 50 { 2000 + yy } else { 1900 + yy }, rest)
        }
        (GENERALIZED_TIME, 15) => {
            let (yyyy, rest) = t.contents.split_at(4);
            (digits(yyyy)?, rest)
        }
        _ => return Err(Malformed("bad time")),
    };
    let field = |i: usize| {
        rest.get(i..i + 2)
            .ok_or(Malformed("bad time"))
            .and_then(digits)
    };
    let (month, day, hour, minute, second) =
        (field(0)?, field(2)?, field(4)?, field(6)?, field(8)?);
    if rest.get(10) != Some(&b'Z')
        || !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return Err(Malformed("bad time"));
    }
    Ok(days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second)
}

/// Days since 1970-01-01 of a proleptic Gregorian date (H. Hinnant's algorithm).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The first `commonName` in a Name's contents, for display; control characters become `?`.
fn common_name(mut rdns: &[u8]) -> Option<String> {
    while !rdns.is_empty() {
        let set = expect(rdns, SET, "").ok()?;
        rdns = set.rest;
        let mut atvs = set.contents;
        while !atvs.is_empty() {
            let atv = expect(atvs, SEQUENCE, "").ok()?;
            atvs = atv.rest;
            let oid = expect(atv.contents, OID, "").ok()?;
            if oid.contents != OID_CN {
                continue;
            }
            let value = tlv(oid.rest).ok()?;
            let text = match value.tag {
                // BMPString: UTF-16BE.
                0x1e => String::from_utf16_lossy(
                    &value
                        .contents
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|c| u16::from_be_bytes(*c))
                        .collect::<Vec<_>>(),
                ),
                _ => String::from_utf8_lossy(value.contents).into_owned(),
            };
            return Some(
                text.chars()
                    .map(|c| if c.is_control() { '?' } else { c })
                    .collect(),
            );
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn cert(cn: &str, not_after: (i32, u8, u8)) -> Vec<u8> {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn);
        params
            .distinguished_name
            .push(rcgen::DnType::OrganizationName, "Example Corp");
        params.not_after = rcgen::date_time_ymd(not_after.0, not_after.1, not_after.2);
        let key = rcgen::KeyPair::generate().unwrap();
        params.self_signed(&key).unwrap().der().to_vec()
    }

    #[test]
    fn reads_names_key_validity_and_common_name() {
        let der = cert("Example Corp Root CA", (2040, 6, 30));
        let f = parse(&der).unwrap();
        assert_eq!(f.issuer, f.subject, "self-signed");
        assert_eq!(f.subject.first(), Some(&SEQUENCE));
        assert_eq!(f.spki.first(), Some(&SEQUENCE));
        assert_eq!(f.subject_cn.as_deref(), Some("Example Corp Root CA"));
        // 2040-06-30T00:00:00Z
        assert_eq!(f.not_after, 2_224_627_200);
        // rcgen writes GeneralizedTime from 2050 on.
        let late = cert("Late", (2051, 1, 1));
        assert_eq!(parse(&late).unwrap().not_after, 2_556_143_999 + 1);
    }

    #[test]
    fn civil_dates_match_known_epochs() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
        assert_eq!(days_from_civil(1950, 1, 1), -7305);
        assert_eq!(days_from_civil(2024, 2, 29), 19_782);
    }

    #[test]
    fn times_parse_in_both_forms_and_refuse_garbage() {
        let t = |tag: u8, s: &str| {
            let mut v = vec![tag, u8::try_from(s.len()).unwrap()];
            v.extend_from_slice(s.as_bytes());
            let parsed = tlv(&v).unwrap();
            time(&parsed)
        };
        assert_eq!(t(UTC_TIME, "700101000000Z"), Ok(0));
        assert_eq!(t(UTC_TIME, "491231235959Z"), Ok(2_524_607_999));
        assert_eq!(t(UTC_TIME, "500101000000Z"), Ok(-631_152_000));
        assert_eq!(t(GENERALIZED_TIME, "20500101000000Z"), Ok(2_524_608_000));
        for bad in [
            "700101000000+",
            "7001010000000",
            "701301000000Z",
            "70010100000aZ",
        ] {
            assert!(t(UTC_TIME, bad).is_err(), "{bad}");
        }
        assert!(t(GENERALIZED_TIME, "700101000000Z").is_err());
        assert!(t(INTEGER, "700101000000Z").is_err());
    }

    #[test]
    fn refuses_truncated_trailing_and_odd_encodings() {
        let der = cert("X", (2040, 1, 1));
        assert!(parse(&der[..der.len() - 1]).is_err());
        let mut trailing = der.clone();
        trailing.push(0);
        assert_eq!(parse(&trailing), Err(Malformed("trailing bytes")));
        assert_eq!(parse(&[]), Err(Malformed("truncated")));
        assert_eq!(parse(&[0x1f, 0x00]), Err(Malformed("multi-byte tag")));
        assert_eq!(parse(&[0x30, 0x80]), Err(Malformed("unsupported length")));
        assert_eq!(
            parse(&[0x30, 0x85, 1, 1, 1, 1, 1]),
            Err(Malformed("unsupported length"))
        );
        assert_eq!(
            parse(&[0x02, 0x00]),
            Err(Malformed("no certificate sequence"))
        );
        assert_eq!(parse(&[0x30, 0x00]), Err(Malformed("truncated")));
        assert_eq!(
            parse(&[0x30, 0x02, 0x02, 0x00]),
            Err(Malformed("no tbsCertificate"))
        );
    }

    #[test]
    fn common_name_handles_bmp_controls_and_absence() {
        // SET { SEQ { OID cn, BMPString "A" } }
        let bmp = [
            0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x03, 0x1e, 0x02, 0x00, 0x41,
        ];
        assert_eq!(common_name(&bmp).as_deref(), Some("A"));
        // An odd byte count: the trailing byte is dropped.
        let odd = [
            0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x1e, 0x03, 0x00, 0x41, 0x00,
        ];
        assert_eq!(common_name(&odd).as_deref(), Some("A"));
        let two = [
            0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x1e, 0x04, 0x00, 0x41, 0x00,
            0x62,
        ];
        assert_eq!(common_name(&two).as_deref(), Some("Ab"));
        let ctl = [
            0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x02, b'a', 0x0a,
        ];
        assert_eq!(common_name(&ctl).as_deref(), Some("a?"));
        // Only an O attribute.
        let org = [
            0x31, 0x0a, 0x30, 0x08, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x01, b'o',
        ];
        assert_eq!(common_name(&org), None);
        // A value that runs past its SET.
        let short = [0x31, 0x05, 0x30, 0x09, 0x06, 0x03, 0x55];
        assert_eq!(common_name(&short), None);
    }

    proptest! {
        #[test]
        fn any_bytes_parse_or_fail_without_panicking(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
            let _ = parse(&bytes);
            let _ = common_name(&bytes);
        }

        #[test]
        fn a_corrupted_certificate_never_panics(index in 0_usize..400, value in any::<u8>()) {
            let mut der = cert("Corrupt", (2040, 1, 1));
            if let Some(b) = der.get_mut(index) {
                *b = value;
            }
            let _ = parse(&der);
        }
    }
}
