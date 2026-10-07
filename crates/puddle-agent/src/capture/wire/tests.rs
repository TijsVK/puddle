// SPDX-License-Identifier: GPL-3.0-or-later
use proptest::prelude::*;

use super::*;

/// A query message the way a resolver sends it.
pub(crate) fn query_bytes(id: u16, name: &str, qtype: u16, edns: Option<u16>) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(&id.to_be_bytes());
    m.extend_from_slice(&0x0100u16.to_be_bytes());
    m.extend_from_slice(&[0, 1, 0, 0, 0, 0]);
    m.extend_from_slice(&[0, u8::from(edns.is_some())]);
    for label in name.split('.').filter(|l| !l.is_empty()) {
        m.push(u8::try_from(label.len()).unwrap());
        m.extend_from_slice(label.as_bytes());
    }
    m.push(0);
    m.extend_from_slice(&qtype.to_be_bytes());
    m.extend_from_slice(&CLASS_IN.to_be_bytes());
    if let Some(payload) = edns {
        m.push(0);
        m.extend_from_slice(&TYPE_OPT.to_be_bytes());
        m.extend_from_slice(&payload.to_be_bytes());
        m.extend_from_slice(&[0; 6]);
    }
    m
}

fn word(m: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([m[at], m[at + 1]])
}

#[test]
fn a_resolvers_query_parses_with_its_name_lower_cased_and_its_question_kept() {
    let msg = query_bytes(0xBEEF, "WwW.Example.COM", TYPE_A, None);
    let q = parse_query(&msg).unwrap();
    assert_eq!(q.id, 0xBEEF);
    assert_eq!(q.name, QueryName::Plain("www.example.com".into()));
    assert_eq!((q.qtype, q.qclass), (TYPE_A, CLASS_IN));
    assert!(q.recursion_desired);
    assert_eq!(q.edns_payload, None);
    // The answer echoes the question in the client's own letter case (0x20 randomisation).
    let response = respond(&q, Rcode::NoError, &[], &[], true);
    assert_eq!(
        &response[12..12 + q.question.len()],
        &msg[12..12 + q.question.len()]
    );
}

#[test]
fn the_root_is_an_empty_plain_name_and_a_service_name_keeps_its_underscores() {
    let q = parse_query(&query_bytes(1, ".", TYPE_A, None)).unwrap();
    assert_eq!(q.name, QueryName::Plain(String::new()));
    let q = parse_query(&query_bytes(
        1,
        "_mongodb._tcp.db.example.net",
        TYPE_SRV,
        None,
    ))
    .unwrap();
    assert_eq!(
        q.name,
        QueryName::Plain("_mongodb._tcp.db.example.net".into())
    );
}

#[test]
fn odd_bytes_in_a_name_make_it_odd_not_an_error() {
    let mut msg = query_bytes(1, "ab.example", TYPE_A, None);
    msg[13] = 0x1B; // an escape character inside the first label
    assert_eq!(parse_query(&msg).unwrap().name, QueryName::Odd);
    let mut msg = query_bytes(1, "ab.example", TYPE_A, None);
    msg[13] = 0xFF;
    assert_eq!(parse_query(&msg).unwrap().name, QueryName::Odd);
}

#[test]
fn edns_is_noticed_and_echoed_with_our_payload_size() {
    let q = parse_query(&query_bytes(7, "example.com", TYPE_A, Some(4096))).unwrap();
    assert_eq!(q.edns_payload, Some(4096));
    let response = respond(&q, Rcode::NoError, &[], &[], false);
    assert_eq!(word(&response, 10), 1, "one additional record: the OPT");
    let opt = &response[response.len() - 11..];
    assert_eq!(opt[0], 0);
    assert_eq!(word(opt, 1), TYPE_OPT);
    assert_eq!(word(opt, 3), EDNS_PAYLOAD);
    let plain = parse_query(&query_bytes(7, "example.com", TYPE_A, None)).unwrap();
    assert_eq!(
        word(&respond(&plain, Rcode::NoError, &[], &[], false), 10),
        0
    );
    // A payload below 512 is raised to 512.
    let tiny = parse_query(&query_bytes(7, "example.com", TYPE_A, Some(10))).unwrap();
    assert_eq!(tiny.edns_payload, Some(512));
}

#[test]
fn the_a_answer_points_back_at_the_question_name() {
    let q = parse_query(&query_bytes(9, "example.com", TYPE_A, None)).unwrap();
    let answer = Record {
        owner: None,
        ttl: 60,
        data: Rdata::A(Ipv4Addr::new(198, 18, 0, 2)),
    };
    let r = respond(&q, Rcode::NoError, &[answer], &[], true);
    assert_eq!(word(&r, 0), 9);
    assert_eq!(word(&r, 2) & 0x800F, 0x8000, "a response, no error");
    assert_eq!(word(&r, 2) & 0x0080, 0x0080, "recursion available");
    assert_eq!((word(&r, 4), word(&r, 6)), (1, 1));
    let tail = &r[r.len() - 16..];
    assert_eq!(&tail[..2], &[0xC0, 0x0C]);
    assert_eq!(word(tail, 2), TYPE_A);
    assert_eq!(&tail[4..8], &[0, 1, 0, 0]);
    assert_eq!(&tail[8..10], &[0, 60]);
    assert_eq!(&tail[10..12], &[0, 4]);
    assert_eq!(&tail[12..], &[198, 18, 0, 2]);
}

#[test]
fn srv_mx_and_txt_records_are_encoded_with_plain_names_and_split_strings() {
    let q = parse_query(&query_bytes(9, "example.com", TYPE_SRV, None)).unwrap();
    let records = [
        Record {
            owner: None,
            ttl: 30,
            data: Rdata::Srv {
                priority: 1,
                weight: 2,
                port: 27017,
                target: "s0.example.com".into(),
            },
        },
        Record {
            owner: None,
            ttl: 30,
            data: Rdata::Mx {
                preference: 10,
                exchange: "mx.example.com".into(),
            },
        },
        Record {
            owner: None,
            ttl: 30,
            data: Rdata::Txt(vec!["a=b".into(), String::new(), "x".repeat(300)]),
        },
    ];
    let r = respond(&q, Rcode::NoError, &records, &[], false);
    assert_eq!(word(&r, 6), 3);
    let body = &r[12 + q.question.len()..];
    // SRV: pointer, type, class, ttl, rdlength, 3 words, name `s0.example.com`.
    assert_eq!(word(body, 2), TYPE_SRV);
    assert_eq!(word(body, 10), 6 + 16);
    assert_eq!(&body[12..18], &[0, 1, 0, 2, 0x69, 0x89]);
    assert_eq!(&body[18..21], &[2, b's', b'0']);
    // TXT: one 3-byte string, one empty, 300 bytes split 255 + 45.
    let txt = &body[body.len() - (2 + 10 + 4 + 1 + 1 + 255 + 1 + 45)..];
    assert_eq!(word(txt, 2), TYPE_TXT);
    assert_eq!(
        &txt[12..],
        {
            let mut v = vec![3, b'a', b'=', b'b', 0, 255];
            v.extend_from_slice(&[b'x'; 255]);
            v.push(45);
            v.extend_from_slice(&[b'x'; 45]);
            v
        }
        .as_slice()
    );
}

#[test]
fn a_udp_answer_that_does_not_fit_is_truncated_to_its_question_and_tcp_gets_it_whole() {
    let q = parse_query(&query_bytes(9, "example.com", TYPE_TXT, None)).unwrap();
    let big = Record {
        owner: None,
        ttl: 30,
        data: Rdata::Txt(vec!["y".repeat(900)]),
    };
    let udp = respond(&q, Rcode::NoError, std::slice::from_ref(&big), &[], true);
    assert_eq!(word(&udp, 2) & 0x0200, 0x0200, "TC set");
    assert_eq!(word(&udp, 6), 0);
    assert!(udp.len() <= 512);
    let tcp = respond(&q, Rcode::NoError, std::slice::from_ref(&big), &[], false);
    assert_eq!(word(&tcp, 2) & 0x0200, 0);
    assert_eq!(word(&tcp, 6), 1);
    // With EDNS 1232 it still doesn't fit, with 4096 advertised the stub caps at 1232.
    let q = parse_query(&query_bytes(9, "example.com", TYPE_TXT, Some(4096))).unwrap();
    let huge = Record {
        owner: None,
        ttl: 30,
        data: Rdata::Txt(vec!["y".repeat(1500)]),
    };
    assert_eq!(
        word(&respond(&q, Rcode::NoError, &[huge], &[], true), 2) & 0x0200,
        0x0200
    );
}

#[test]
fn messages_that_are_not_plain_queries_are_dropped_or_answered_with_an_error() {
    // Too short, or a response: dropped.
    assert_eq!(parse_query(&[0; 11]), Err(Reject::Drop));
    let mut response = query_bytes(1, "example.com", TYPE_A, None);
    response[2] |= 0x80;
    assert_eq!(parse_query(&response), Err(Reject::Drop));
    // An update opcode: NOTIMP.
    let mut update = query_bytes(5, "example.com", TYPE_A, None);
    update[2] |= 5 << 3;
    assert_eq!(
        parse_query(&update),
        Err(Reject::Answer {
            id: 5,
            rcode: Rcode::NotImp,
            recursion_desired: true
        })
    );
    // Two questions, an answer section, a compression pointer in the name, a cut question,
    // a label over 63 bytes: FORMERR.
    let mut two = query_bytes(6, "example.com", TYPE_A, None);
    two[5] = 2;
    let mut with_answer = query_bytes(6, "example.com", TYPE_A, None);
    with_answer[7] = 1;
    let mut pointer = query_bytes(6, "example.com", TYPE_A, None);
    pointer[12] = 0xC0;
    let cut = query_bytes(6, "example.com", TYPE_A, None)[..16].to_vec();
    let mut long_label = query_bytes(6, "example.com", TYPE_A, None);
    long_label[12] = 64;
    for bad in [two, with_answer, pointer, cut, long_label] {
        assert_eq!(
            parse_query(&bad),
            Err(Reject::Answer {
                id: 6,
                rcode: Rcode::FormErr,
                recursion_desired: true
            })
        );
    }
}

#[test]
fn a_name_over_255_bytes_is_a_malformed_question() {
    let label = "a".repeat(63);
    let name = format!("{label}.{label}.{label}.{label}.{label}");
    let msg = query_bytes(3, &name, TYPE_A, None);
    assert!(matches!(
        parse_query(&msg),
        Err(Reject::Answer {
            rcode: Rcode::FormErr,
            ..
        })
    ));
}

#[test]
fn an_error_response_is_a_bare_header_with_the_query_id() {
    let r = error_response(0x1234, Rcode::FormErr, true);
    assert_eq!(r.len(), 12);
    assert_eq!(word(&r, 0), 0x1234);
    assert_eq!(word(&r, 2) & 0x800F, 0x8001);
}

#[test]
fn a_broken_additional_section_does_not_hide_the_question() {
    let mut msg = query_bytes(2, "example.com", TYPE_A, None);
    msg[11] = 3; // claims three additional records, has none
    let q = parse_query(&msg).unwrap();
    assert_eq!(q.edns_payload, None);
    // An additional record whose fixed part is cut.
    let mut msg = query_bytes(2, "example.com", TYPE_A, Some(1232));
    msg.truncate(msg.len() - 4);
    assert_eq!(parse_query(&msg).unwrap().edns_payload, None);
    // A non-OPT additional record is skipped on the way to the OPT.
    let mut msg = query_bytes(2, "example.com", TYPE_A, None);
    msg[11] = 2;
    msg.extend_from_slice(&[0, 0, 16, 0, 1, 0, 0, 0, 0, 0, 2, 0xAA, 0xBB]);
    msg.extend_from_slice(&[0, 0, 41, 0x10, 0x00, 0, 0, 0, 0, 0, 0]);
    assert_eq!(parse_query(&msg).unwrap().edns_payload, Some(4096));
}

proptest! {
    #[test]
    fn any_bytes_parse_or_are_rejected_without_panicking(bytes in proptest::collection::vec(any::<u8>(), 0..600)) {
        if let Ok(q) = parse_query(&bytes) {
            let _ = respond(&q, Rcode::NoError, &[], &[], true);
        }
    }

    #[test]
    fn a_mutated_valid_query_never_panics(
        name in "[a-z0-9-]{1,20}(\\.[a-z0-9-]{1,20}){0,4}",
        flips in proptest::collection::vec((0usize..80, any::<u8>()), 0..6),
        edns in proptest::option::of(any::<u16>()),
    ) {
        let mut msg = query_bytes(1, &name, TYPE_A, edns);
        for (at, byte) in flips {
            if let Some(slot) = msg.get_mut(at) {
                *slot = byte;
            }
        }
        if let Ok(q) = parse_query(&msg) {
            let r = respond(&q, Rcode::NoError, &[], &[], true);
            prop_assert!(r.len() >= 12);
        }
    }
}
