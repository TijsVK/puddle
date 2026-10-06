// SPDX-License-Identifier: GPL-3.0-or-later
//! The guest's IPv4 interface addresses through `getifaddrs(3)` (Linux only). With `vsock` the
//! only `unsafe` in the agent: std has no interface listing, and the bridge watcher
//! ([`crate::bridge`]) must know which interface owns an address.
#![expect(
    unsafe_code,
    reason = "getifaddrs and if_nametoindex through libc; std has no interface listing"
)]

use std::ffi::CStr;
use std::io;
use std::net::Ipv4Addr;

use crate::bridge::{IfAddr, Interfaces};

/// The real interface list.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Getifaddrs;

/// Frees the list `getifaddrs` allocated.
struct List(*mut libc::ifaddrs);

impl Drop for List {
    fn drop(&mut self) {
        // SAFETY: the pointer came from a successful getifaddrs and is freed exactly once.
        unsafe { libc::freeifaddrs(self.0) };
    }
}

impl Interfaces for Getifaddrs {
    fn ipv4(&self) -> io::Result<Vec<IfAddr>> {
        let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
        // SAFETY: `head` is a valid out-pointer; on success the kernel-allocated list is owned
        // by `List` below.
        if unsafe { libc::getifaddrs(&raw mut head) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let list = List(head);
        let mut out = Vec::new();
        let mut cursor = list.0;
        while !cursor.is_null() {
            // SAFETY: `cursor` is a non-null node of the list `list` owns, alive until it drops.
            let entry = unsafe { &*cursor };
            cursor = entry.ifa_next;
            if entry.ifa_addr.is_null() || entry.ifa_name.is_null() {
                continue;
            }
            // SAFETY: a non-null `ifa_addr` points at a sockaddr whose family field is readable.
            let family = unsafe { (*entry.ifa_addr).sa_family };
            if libc::c_int::from(family) != libc::AF_INET {
                continue;
            }
            // SAFETY: AF_INET addresses are `sockaddr_in`, which `ifa_addr` points at.
            let raw = unsafe {
                (*entry.ifa_addr.cast::<libc::sockaddr_in>())
                    .sin_addr
                    .s_addr
            };
            // SAFETY: `ifa_name` is a NUL-terminated string owned by the list.
            let name = unsafe { CStr::from_ptr(entry.ifa_name) };
            // SAFETY: `name` is a valid NUL-terminated string.
            let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
            if index == 0 {
                // The interface vanished between the two calls.
                continue;
            }
            out.push(IfAddr {
                name: name.to_string_lossy().into_owned(),
                index,
                addr: Ipv4Addr::from(u32::from_be(raw)),
            });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_loopback_interface_is_listed_with_its_address() {
        let all = Getifaddrs.ipv4().unwrap();
        let lo = all
            .iter()
            .find(|i| i.addr == Ipv4Addr::LOCALHOST)
            .expect("127.0.0.1 is on some interface");
        assert!(lo.index > 0);
        assert_ne!(lo.name, "");
    }
}
