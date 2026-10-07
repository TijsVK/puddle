// SPDX-License-Identifier: GPL-3.0-or-later
use std::fmt::Write as _;

use super::*;

fn ip(s: &str) -> Ipv4Addr {
    s.parse().unwrap()
}

fn dir() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

#[test]
fn a_name_keeps_its_address_and_two_names_never_share_one() {
    let t = StandIns::in_memory();
    let a = t.address_for("a.example").unwrap();
    let b = t.address_for("b.example").unwrap();
    assert_ne!(a, b);
    assert_eq!(t.address_for("a.example").unwrap(), a);
    assert_eq!(t.name_for(a).as_deref(), Some("a.example"));
    assert_eq!(t.name_for(b).as_deref(), Some("b.example"));
    assert_eq!(t.len(), 2);
}

#[test]
fn addresses_start_after_the_stub_and_stay_in_the_range() {
    let t = StandIns::in_memory();
    assert_eq!(t.address_for("first.example").unwrap(), ip("198.18.0.2"));
    assert_eq!(t.address_for("second.example").unwrap(), ip("198.18.0.3"));
    assert!(in_range(ip("198.18.0.1")));
    assert!(in_range(ip("198.19.255.254")));
    assert!(!in_range(ip("198.17.255.255")));
    assert!(!in_range(ip("198.20.0.0")));
    assert!(!in_range(ip("10.0.0.1")));
    // The stub's own address, the network and the broadcast address are never stand-ins.
    for special in [
        "198.18.0.0",
        "198.18.0.1",
        "198.19.255.255",
        "198.20.0.1",
        "8.8.8.8",
    ] {
        assert_eq!(t.name_for(ip(special)), None, "{special}");
        assert!(t.hold(ip(special)).is_none(), "{special}");
    }
    assert_eq!(CAPACITY, 131_069);
    assert_eq!(address(LAST), ip("198.19.255.254"));
}

#[test]
fn an_address_nobody_was_given_has_no_name() {
    let t = StandIns::in_memory();
    t.address_for("a.example").unwrap();
    assert_eq!(t.name_for(ip("198.18.0.9")), None);
}

#[test]
#[expect(
    clippy::many_single_char_names,
    reason = "a, b, c, d are the addresses of a.example .. d.example"
)]
fn when_the_range_is_full_the_least_recently_used_address_is_reused() {
    let t = StandIns::open_with_capacity(None, 3);
    let a = t.address_for("a.example").unwrap();
    let b = t.address_for("b.example").unwrap();
    let c = t.address_for("c.example").unwrap();
    // `a` is used again, so `b` is the oldest.
    assert_eq!(t.address_for("a.example").unwrap(), a);
    let d = t.address_for("d.example").unwrap();
    assert_eq!(d, b, "the oldest address goes to the new name");
    assert_eq!(t.name_for(b).as_deref(), Some("d.example"));
    assert_eq!(t.name_for(a).as_deref(), Some("a.example"));
    assert_eq!(t.name_for(c).as_deref(), Some("c.example"));
    assert_eq!(t.len(), 3);
    // Looking an address up is a use, too.
    let _ = t.name_for(a);
    let _ = t.name_for(d);
    assert_eq!(t.address_for("e.example").unwrap(), c);
}

#[test]
fn an_address_with_a_live_connection_is_never_reused() {
    let t = StandIns::open_with_capacity(None, 2);
    let a = t.address_for("a.example").unwrap();
    let b = t.address_for("b.example").unwrap();
    let held = t.hold(a).unwrap();
    assert_eq!(held.name(), "a.example");
    // `a` is the oldest but held: `b` is given away instead.
    assert_eq!(t.address_for("c.example").unwrap(), b);
    assert_eq!(t.name_for(a).as_deref(), Some("a.example"));
    // With both held there is nothing to give.
    let _held_c = t.hold(b).unwrap();
    assert_eq!(t.address_for("d.example"), Err(Exhausted));
    // Releasing makes the address available again.
    drop(held);
    assert_eq!(t.address_for("d.example").unwrap(), a);
}

#[test]
fn holds_count_and_release_one_by_one() {
    let t = StandIns::open_with_capacity(None, 1);
    let a = t.address_for("a.example").unwrap();
    let one = t.hold(a).unwrap();
    let two = t.hold(a).unwrap();
    drop(one);
    assert_eq!(t.address_for("b.example"), Err(Exhausted));
    drop(two);
    assert_eq!(t.address_for("b.example").unwrap(), a);
}

#[test]
fn the_table_survives_a_restart_with_the_same_addresses() {
    let d = dir();
    let path = d.path().join("run/puddle/dns-table");
    let first = StandIns::open(&path);
    let a = first.address_for("api.example.com").unwrap();
    let b = first.address_for("cdn.example.com").unwrap();
    drop(first);
    let second = StandIns::open(&path);
    assert_eq!(second.len(), 2);
    assert_eq!(second.name_for(a).as_deref(), Some("api.example.com"));
    assert_eq!(second.address_for("cdn.example.com").unwrap(), b);
    // New names carry on after the loaded ones.
    let c = second.address_for("new.example.com").unwrap();
    assert_ne!(c, a);
    assert_ne!(c, b);
    drop(second);
    let third = StandIns::open(&path);
    assert_eq!(third.name_for(c).as_deref(), Some("new.example.com"));
}

#[test]
fn a_reused_address_is_remembered_with_its_new_name() {
    let d = dir();
    let path = d.path().join("table");
    let first = StandIns::open_with_capacity(Some(&path), 2);
    let a = first.address_for("a.example").unwrap();
    first.address_for("b.example").unwrap();
    let c = first.address_for("c.example").unwrap();
    assert_eq!(c, a);
    drop(first);
    let second = StandIns::open_with_capacity(Some(&path), 2);
    assert_eq!(second.name_for(a).as_deref(), Some("c.example"));
    assert_eq!(second.len(), 2);
    assert_eq!(second.address_for("c.example").unwrap(), a);
}

#[test]
fn freed_addresses_below_the_highest_loaded_one_are_used_before_new_ones() {
    let d = dir();
    let path = d.path().join("table");
    fs::write(&path, "198.18.0.9 late.example\n").unwrap();
    let t = StandIns::open(&path);
    assert_eq!(t.address_for("x.example").unwrap(), ip("198.18.0.2"));
    assert_eq!(t.address_for("y.example").unwrap(), ip("198.18.0.3"));
    assert_eq!(
        t.name_for(ip("198.18.0.9")).as_deref(),
        Some("late.example")
    );
}

#[test]
fn bad_lines_in_the_file_are_skipped() {
    let d = dir();
    let path = d.path().join("table");
    let mut text = String::new();
    for line in [
        "198.18.0.5 good.example",
        "not-an-ip bad.example",
        "198.18.0.6",
        "198.18.0.1 stub.example",
        "198.18.0.0 network.example",
        "198.19.255.255 broadcast.example",
        "8.8.8.8 outside.example",
        "198.18.0.7 UPPER.example",
        "198.18.0.8 sp ace.example",
        "198.18.0.9 esc\u{1b}.example",
        "",
    ] {
        text.push_str(line);
        text.push('\n');
    }
    fs::write(&path, text).unwrap();
    let t = StandIns::open(&path);
    assert_eq!(t.len(), 1);
    assert_eq!(
        t.name_for(ip("198.18.0.5")).as_deref(),
        Some("good.example")
    );
}

#[test]
fn a_name_moved_to_another_address_in_the_file_has_one_address() {
    let d = dir();
    let path = d.path().join("table");
    fs::write(&path, "198.18.0.5 a.example\n198.18.0.6 a.example\n").unwrap();
    let t = StandIns::open(&path);
    assert_eq!(t.len(), 1);
    assert_eq!(t.address_for("a.example").unwrap(), ip("198.18.0.6"));
    assert_eq!(t.name_for(ip("198.18.0.5")), None);
}

#[test]
fn a_file_with_many_replaced_lines_is_rewritten_on_start() {
    let d = dir();
    let path = d.path().join("table");
    let mut text = String::new();
    for i in 0..3000 {
        writeln!(text, "198.18.0.5 name{i}.example").unwrap();
    }
    fs::write(&path, text).unwrap();
    let t = StandIns::open(&path);
    assert_eq!(t.len(), 1);
    assert_eq!(
        fs::read_to_string(&path).unwrap(),
        "198.18.0.5 name2999.example\n"
    );
    // And it still appends.
    t.address_for("next.example").unwrap();
    assert_eq!(fs::read_to_string(&path).unwrap().lines().count(), 2);
}

#[test]
fn a_file_that_grows_through_reuse_is_compacted_while_running() {
    let d = dir();
    let path = d.path().join("table");
    let t = StandIns::open_with_capacity(Some(&path), 2);
    for i in 0..1500 {
        t.address_for(&format!("n{i}.example")).unwrap();
    }
    let lines = fs::read_to_string(&path).unwrap().lines().count();
    assert!(lines < 1100, "{lines} lines");
    drop(t);
    let again = StandIns::open_with_capacity(Some(&path), 2);
    assert_eq!(again.len(), 2);
    assert!(again.address_for("n1499.example").is_ok());
}

#[test]
fn a_table_file_that_cannot_be_used_costs_only_persistence() {
    let d = dir();
    // The "file" is a directory: reading and appending both fail.
    let t = StandIns::open(d.path());
    let a = t.address_for("a.example").unwrap();
    assert_eq!(t.name_for(a).as_deref(), Some("a.example"));
    // A parent that is a file: the folder can't be created.
    let blocker = d.path().join("blocker");
    fs::write(&blocker, "x").unwrap();
    let t = StandIns::open(&blocker.join("sub/table"));
    assert!(t.address_for("a.example").is_ok());
}

#[test]
fn a_hundred_thousand_names_fit_and_stay_distinct() {
    let t = StandIns::in_memory();
    let mut seen = std::collections::HashSet::new();
    for i in 0..100_000 {
        let a = t.address_for(&format!("rand{i}.example.net")).unwrap();
        assert!(seen.insert(a));
    }
    assert_eq!(t.len(), 100_000);
    // Past the end, memory stays flat: the count caps at the capacity.
    for i in 100_000..CAPACITY + 5_000 {
        t.address_for(&format!("rand{i}.example.net")).unwrap();
    }
    assert_eq!(t.len(), CAPACITY);
}
