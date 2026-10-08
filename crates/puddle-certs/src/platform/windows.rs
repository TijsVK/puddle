// SPDX-License-Identifier: GPL-3.0-or-later
//! `CryptoAPI` store reading. All of the crate's `unsafe` is in this module.

use std::ffi::c_void;

use windows_sys::Win32::Foundation::{
    CRYPT_E_NOT_FOUND, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS, GetLastError,
    SetLastError,
};
use windows_sys::Win32::Security::Cryptography::{
    CERT_CONTEXT, CERT_STORE_OPEN_EXISTING_FLAG, CERT_STORE_PROV_PHYSICAL_W,
    CERT_STORE_PROV_SYSTEM_W, CERT_STORE_READONLY_FLAG, CERT_SYSTEM_STORE_CURRENT_USER,
    CERT_SYSTEM_STORE_LOCAL_MACHINE, CertCloseStore, CertEnumCertificatesInStore, CertOpenStore,
    HCERTSTORE,
};

use crate::store::{Location, Physical, StoreError, StoreName, StoreSnapshot, StoreSource};

// Store locations windows-sys doesn't define (wincrypt.h: location id << 16).
const CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY: u32 = 7 << 16;
const CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY: u32 = 8 << 16;
const CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE: u32 = 9 << 16;

/// Why a store didn't open.
enum OpenError {
    /// It doesn't exist (no policy pushed, nothing ever added): an empty store.
    Missing,
    /// Anything else, with the OS error code.
    Failed(u32),
}

pub(super) fn read(sources: &[StoreSource]) -> Result<StoreSnapshot, StoreError> {
    let mut snapshot = StoreSnapshot::new();
    for &source in sources {
        match Store::open(source) {
            Ok(store) => {
                let (certificates, failure) = store.certificates();
                let read = certificates.len();
                for der in certificates {
                    snapshot.add(source, der);
                }
                if let Some(code) = failure {
                    let reason =
                        format!("reading stopped after {read} certificates: os error {code:#x}");
                    // A `Disallowed` store cut short would trust what the machine distrusts.
                    if source.store == StoreName::Disallowed {
                        return Err(StoreError::DisallowedUnreadable {
                            store: source,
                            reason,
                        });
                    }
                    snapshot.note_unreadable(source, reason);
                }
            }
            Err(OpenError::Missing) => {}
            Err(OpenError::Failed(code)) if source.store == StoreName::Disallowed => {
                return Err(StoreError::DisallowedUnreadable {
                    store: source,
                    reason: format!("os error {code:#x}"),
                });
            }
            Err(OpenError::Failed(code)) => {
                snapshot.note_unreadable(source, format!("os error {code:#x}"));
            }
        }
    }
    Ok(snapshot)
}

/// What `CertOpenStore` needs for `source`: provider, flags and the UTF-16 store name.
fn open_args(source: StoreSource) -> (windows_sys::core::PCSTR, u32, Vec<u16>) {
    let name = match source.store {
        StoreName::Root => "Root",
        StoreName::Intermediate => "CA",
        StoreName::Disallowed => "Disallowed",
    };
    let (provider, location, name) = match (source.location, source.physical) {
        (location, Physical::Default) => (
            CERT_STORE_PROV_PHYSICAL_W,
            system_location(location),
            format!("{name}\\.Default"),
        ),
        (Location::LocalMachine, Physical::GroupPolicy) => (
            CERT_STORE_PROV_SYSTEM_W,
            CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY,
            name.to_owned(),
        ),
        (Location::CurrentUser, Physical::GroupPolicy) => (
            CERT_STORE_PROV_SYSTEM_W,
            CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY,
            name.to_owned(),
        ),
        (_, Physical::Enterprise) => (
            CERT_STORE_PROV_SYSTEM_W,
            CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE,
            name.to_owned(),
        ),
        (location, Physical::Logical) => (
            CERT_STORE_PROV_SYSTEM_W,
            system_location(location),
            name.to_owned(),
        ),
    };
    let flags = location | CERT_STORE_READONLY_FLAG | CERT_STORE_OPEN_EXISTING_FLAG;
    (provider, flags, name.encode_utf16().chain([0]).collect())
}

fn system_location(location: Location) -> u32 {
    match location {
        Location::LocalMachine => CERT_SYSTEM_STORE_LOCAL_MACHINE,
        Location::CurrentUser => CERT_SYSTEM_STORE_CURRENT_USER,
    }
}

/// An open, read-only store, closed on drop.
struct Store(HCERTSTORE);

impl Store {
    #[expect(unsafe_code, reason = "CryptoAPI store handle")]
    fn open(source: StoreSource) -> Result<Self, OpenError> {
        let (provider, flags, name) = open_args(source);
        // SAFETY: `name` is a NUL-terminated UTF-16 string that outlives the call; the provider
        // constants are the documented system/physical providers, which take exactly that as
        // `pvPara`; encoding type and provider handle 0 are the documented defaults.
        let handle =
            unsafe { CertOpenStore(provider, 0, 0, flags, name.as_ptr().cast::<c_void>()) };
        if handle.is_null() {
            // SAFETY: no preconditions; reads this thread's last error right after the call.
            let code = unsafe { GetLastError() };
            #[expect(clippy::cast_sign_loss, reason = "HRESULT bit pattern compared as u32")]
            let not_found = code == ERROR_FILE_NOT_FOUND
                || code == ERROR_PATH_NOT_FOUND
                || code == CRYPT_E_NOT_FOUND as u32;
            return Err(if not_found {
                OpenError::Missing
            } else {
                OpenError::Failed(code)
            });
        }
        Ok(Self(handle))
    }

    /// Every certificate in the store, DER, copied out, and the OS error code when the
    /// enumeration ended in a failure instead of at the end of the store (the certificates read
    /// before it are returned).
    #[expect(unsafe_code, reason = "CryptoAPI certificate enumeration")]
    fn certificates(&self) -> (Vec<Vec<u8>>, Option<u32>) {
        let mut ctx: *const CERT_CONTEXT = std::ptr::null();
        drain(
            || {
                // SAFETY: no preconditions; clears this thread's last error so that what is read
                // after a null return is this call's.
                unsafe { SetLastError(ERROR_SUCCESS) };
                // SAFETY: `self.0` is an open store; `ctx` is null or the context the previous
                // call returned, which this call frees (CertEnumCertificatesInStore's contract).
                // The drain stops on null, so no context is leaked or used after it was freed.
                ctx = unsafe { CertEnumCertificatesInStore(self.0, ctx) };
                if ctx.is_null() {
                    return None;
                }
                // SAFETY: a non-null context from the enumeration is valid until the next call;
                // `pbCertEncoded` points at `cbCertEncoded` bytes owned by it, copied out here.
                Some(unsafe {
                    let c = &*ctx;
                    std::slice::from_raw_parts(c.pbCertEncoded, c.cbCertEncoded as usize).to_vec()
                })
            },
            // SAFETY: no preconditions; reads this thread's last error right after the null return.
            || unsafe { GetLastError() },
        )
    }
}

/// Collects what `next` yields. When it yields `None`, `last_error` says why: `CRYPT_E_NOT_FOUND`
/// (or no error at all) is the end of the store, anything else a read failure, whose code is
/// returned beside the certificates read so far (a null return alone cannot tell the two apart).
fn drain(
    mut next: impl FnMut() -> Option<Vec<u8>>,
    last_error: impl FnOnce() -> u32,
) -> (Vec<Vec<u8>>, Option<u32>) {
    let mut out = Vec::new();
    while let Some(der) = next() {
        out.push(der);
    }
    let code = last_error();
    #[expect(clippy::cast_sign_loss, reason = "HRESULT bit pattern compared as u32")]
    let end_of_store = code == ERROR_SUCCESS || code == CRYPT_E_NOT_FOUND as u32;
    (out, (!end_of_store).then_some(code))
}

impl Drop for Store {
    #[expect(unsafe_code, reason = "CryptoAPI store handle")]
    fn drop(&mut self) {
        // SAFETY: `self.0` came from a successful CertOpenStore and is closed exactly once.
        // Flags 0: contexts handed out were all freed by the enumeration.
        let _ = unsafe { CertCloseStore(self.0, 0) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SOURCES;

    #[test]
    fn open_args_pick_the_physical_or_location_store() {
        let name = |v: &[u16]| String::from_utf16(v.strip_suffix(&[0]).unwrap()).unwrap();
        let (p, f, n) = open_args(SOURCES[0]);
        assert_eq!(
            (p, name(&n)),
            (CERT_STORE_PROV_PHYSICAL_W, "Root\\.Default".to_owned())
        );
        assert_eq!(f & 0xffff_0000, CERT_SYSTEM_STORE_LOCAL_MACHINE);
        let (p, f, n) = open_args(SOURCES[4]);
        assert_eq!((p, name(&n)), (CERT_STORE_PROV_SYSTEM_W, "Root".to_owned()));
        assert_eq!(f & 0xffff_0000, CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY);
        let (_, f, n) = open_args(SOURCES[7]);
        assert_eq!(name(&n), "CA");
        assert_eq!(f & 0xffff_0000, CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE);
        let (p, f, n) = open_args(SOURCES[11]);
        assert_eq!(
            (p, name(&n)),
            (CERT_STORE_PROV_SYSTEM_W, "Disallowed".to_owned())
        );
        assert_eq!(f & 0xffff_0000, CERT_SYSTEM_STORE_CURRENT_USER);
        assert_ne!(f & CERT_STORE_READONLY_FLAG, 0);
    }

    #[test]
    fn the_end_of_a_store_is_not_an_error_but_any_other_stop_is() {
        let from = |items: Vec<Vec<u8>>| {
            let mut items = items.into_iter();
            move || items.next()
        };
        #[expect(clippy::cast_sign_loss, reason = "HRESULT bit pattern compared as u32")]
        let not_found = CRYPT_E_NOT_FOUND as u32;
        let (read, failure) = drain(from(vec![vec![1], vec![2]]), || not_found);
        assert_eq!((read.len(), failure), (2, None));
        let (read, failure) = drain(from(vec![vec![1]]), || ERROR_SUCCESS);
        assert_eq!(
            (read.len(), failure),
            (1, None),
            "no error recorded is the end"
        );
        let (read, failure) = drain(from(vec![vec![1], vec![2], vec![3]]), || 0x5);
        assert_eq!(
            (read.len(), failure),
            (3, Some(0x5)),
            "access denied is a failure"
        );
    }

    #[test]
    fn every_source_reads_without_error() {
        let snapshot = read(&SOURCES).unwrap();
        // A Windows host always has some machine roots (.Default holds the OS's own).
        assert!(
            snapshot.certs().iter().any(|c| c.source == SOURCES[0]),
            "no LocalMachine\\Root\\.Default certificates"
        );
        assert!(
            snapshot.unreadable().is_empty(),
            "{:?}",
            snapshot.unreadable()
        );
    }
}
