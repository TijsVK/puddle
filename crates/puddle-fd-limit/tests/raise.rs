// SPDX-License-Identifier: GPL-3.0-or-later
//! The real system call, in a process of its own (one test per binary: the limit is per process).
#![cfg(unix)]

use puddle_fd_limit::Reach;
use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};

#[test]
fn a_low_soft_limit_is_raised_and_the_process_can_then_hold_that_many_sockets() {
    // Start from the 1024 that most systems give a process, as the product's processes do.
    let hard = getrlimit(Resource::Nofile).maximum;
    let low = Rlimit {
        current: Some(1024),
        maximum: hard,
    };
    if setrlimit(Resource::Nofile, low).is_err() {
        return;
    }
    let limit = puddle_fd_limit::raise_open_file_limit(Reach::Soft);
    assert_eq!(limit.before, Some(1024));
    assert_eq!(getrlimit(Resource::Nofile).current, limit.soft);
    assert!(
        limit.soft > Some(1024) || hard.is_some_and(|h| h <= 1024),
        "{limit}"
    );

    if limit.allows(3000) {
        let held: Vec<_> = (0..2500)
            .map(|_| std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
            .collect();
        assert_eq!(held.len(), 2500);
    }
    // A second call finds nothing to do and changes nothing.
    assert_eq!(
        puddle_fd_limit::raise_open_file_limit(Reach::Soft).before,
        limit.soft
    );

    // The kernel's default for a first process: soft 1024, hard 4096 (this cannot be undone
    // without privilege, so it comes last). Asking for the hard limit too gets a million with the
    // privilege and the 4096 without.
    let default = Rlimit {
        current: Some(1024),
        maximum: Some(4096),
    };
    if setrlimit(Resource::Nofile, default).is_err() {
        return;
    }
    let both = puddle_fd_limit::raise_open_file_limit(Reach::HardToo);
    assert_eq!(both.before, Some(1024));
    assert!(both.soft >= Some(4096), "{both}");
}
