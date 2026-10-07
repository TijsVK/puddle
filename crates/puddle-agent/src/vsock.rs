// SPDX-License-Identifier: GPL-3.0-or-later
//! `AF_VSOCK` connect with a raised socket buffer (Linux guest only). The only `unsafe` in the
//! agent: std and tokio have no vsock sockets, and the buffer must be set before `connect`.
//!
//! **Why the buffer:** since Linux 6.12.68 (the CVE-2026-23086 fix) a guest sends at most
//! min(peer `buf_alloc`, own `buf_alloc`) unacknowledged bytes, and its own `buf_alloc` defaults to
//! 256 KiB. msb's vsock device sends a standalone credit update only after the host has consumed
//! 4 MiB, which a 256 KiB window never reaches, so every guest-to-host stream stalled after
//! 256 KiB in flight. With our buffer above 8 MiB the window is the host's 8 MiB and its 4 MiB
//! updates arrive. The transport copies the buffer size into `buf_alloc` at connect, so it must
//! be set first.
#![expect(
    unsafe_code,
    reason = "AF_VSOCK socket, setsockopt and connect through libc; std and tokio have no vsock"
)]

use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

/// `SO_VM_SOCKETS_BUFFER_SIZE` from `linux/vm_sockets.h` (not in the libc crate).
const SO_VM_SOCKETS_BUFFER_SIZE: libc::c_int = 0;
/// `SO_VM_SOCKETS_BUFFER_MAX_SIZE` from `linux/vm_sockets.h`.
const SO_VM_SOCKETS_BUFFER_MAX_SIZE: libc::c_int = 2;
/// Size of the `u64` these options take.
const U64_LEN: libc::socklen_t = 8;

/// A new, unconnected `AF_VSOCK` stream socket.
fn socket() -> io::Result<OwnedFd> {
    // SAFETY: socket(2) takes no pointers; a negative return is checked below.
    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a descriptor socket(2) just returned; nothing else owns or refers to it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn set_u64(fd: BorrowedFd<'_>, option: libc::c_int, value: u64) -> io::Result<()> {
    // SAFETY: `optval` points at a live `u64` for the duration of the call and `optlen` is its size.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::AF_VSOCK,
            option,
            (&raw const value).cast(),
            U64_LEN,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn get_u64(fd: BorrowedFd<'_>, option: libc::c_int) -> io::Result<u64> {
    let mut value: u64 = 0;
    let mut len = U64_LEN;
    // SAFETY: `optval` points at a live, writable `u64` and `optlen` at its size; the kernel
    // writes at most `len` bytes.
    let rc = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::AF_VSOCK,
            option,
            (&raw mut value).cast(),
            &raw mut len,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(value)
}

/// Sets the socket's vsock buffer to `bytes` (max first, since the size is clamped to the max)
/// and returns the `(size, max)` the kernel reports back.
fn set_buffer(fd: BorrowedFd<'_>, bytes: u64) -> io::Result<(u64, u64)> {
    set_u64(fd, SO_VM_SOCKETS_BUFFER_MAX_SIZE, bytes)?;
    set_u64(fd, SO_VM_SOCKETS_BUFFER_SIZE, bytes)?;
    Ok((
        get_u64(fd, SO_VM_SOCKETS_BUFFER_SIZE)?,
        get_u64(fd, SO_VM_SOCKETS_BUFFER_MAX_SIZE)?,
    ))
}

/// Connects to `cid:port` with the socket buffer raised to `buffer` bytes (`0` = kernel
/// default). Blocking: call it from `spawn_blocking`.
///
/// The connected socket is returned as a [`std::net::TcpStream`], which only issues `read`,
/// `write` and `shutdown` on it, all of which a vsock stream supports.
///
/// # Errors
///
/// Socket creation, the buffer options, or `connect` failing.
pub(crate) fn connect(cid: u32, port: u32, buffer: u64) -> io::Result<std::net::TcpStream> {
    let fd = socket()?;
    if buffer > 0 {
        let (size, max) = set_buffer(fd.as_fd(), buffer)
            .map_err(|e| io::Error::new(e.kind(), format!("vsock buffer {buffer}: {e}")))?;
        tracing::debug!(size, max, "vsock buffer set");
    }
    // SAFETY: `sockaddr_vm` is a plain C struct for which all-zero bytes are a valid value.
    let mut addr: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
    addr.svm_family = libc::sa_family_t::try_from(libc::AF_VSOCK)
        .map_err(|_| io::Error::other("AF_VSOCK out of range"))?;
    addr.svm_cid = cid;
    addr.svm_port = port;
    let len = libc::socklen_t::try_from(size_of::<libc::sockaddr_vm>())
        .map_err(|_| io::Error::other("sockaddr_vm size out of range"))?;
    // SAFETY: `addr` is a live, initialised `sockaddr_vm` and `len` is its exact size.
    let rc = unsafe { libc::connect(fd.as_raw_fd(), (&raw const addr).cast(), len) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(std::net::TcpStream::from(fd))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A vsock socket, or `None` where the kernel has no `AF_VSOCK` (the test then has nothing to
    /// check; CI runners have it).
    fn vsock() -> Option<OwnedFd> {
        match socket() {
            Ok(fd) => Some(fd),
            Err(err) => {
                eprintln!("skipped: no AF_VSOCK here ({err})");
                None
            }
        }
    }

    #[test]
    fn the_buffer_is_raised_past_the_hosts_window() {
        let Some(fd) = vsock() else { return };
        let got = set_buffer(fd.as_fd(), 16 << 20).unwrap();
        // 16 MiB > msb's 8 MiB, so the send window becomes the host's and its 4 MiB updates arrive.
        assert_eq!(got, (16 << 20, 16 << 20));
    }

    #[test]
    fn the_kernel_default_is_256_kib_without_the_fix() {
        let Some(fd) = vsock() else { return };
        assert_eq!(
            get_u64(fd.as_fd(), SO_VM_SOCKETS_BUFFER_SIZE).unwrap(),
            256 * 1024
        );
    }

    #[test]
    fn a_bad_option_is_an_error_not_a_panic() {
        let Some(fd) = vsock() else { return };
        assert!(set_u64(fd.as_fd(), 9999, 1).is_err());
        assert!(get_u64(fd.as_fd(), 9999).is_err());
    }

    #[test]
    fn connecting_to_nobody_fails_cleanly() {
        if vsock().is_none() {
            return;
        }
        // CID 1 is the local loopback; nothing listens on this port.
        assert!(connect(1, 0x7fff_fff0, 16 << 20).is_err());
        assert!(connect(1, 0x7fff_fff0, 0).is_err());
    }
}
