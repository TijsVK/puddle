// SPDX-License-Identifier: GPL-3.0-or-later
//! `CryptoAPI` store reading. All of the crate's `unsafe` is in this module.

use std::ffi::c_void;

use windows_sys::Win32::Foundation::{
    CRYPT_E_NOT_FOUND, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, GetLastError,
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
                for der in store.certificates() {
                    snapshot.add(source, der);
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

    /// Every certificate in the store, DER, copied out.
    #[expect(unsafe_code, reason = "CryptoAPI certificate enumeration")]
    fn certificates(&self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut ctx: *const CERT_CONTEXT = std::ptr::null();
        loop {
            // SAFETY: `self.0` is an open store; `ctx` is null or the context the previous call
            // returned, which this call frees (CertEnumCertificatesInStore's contract). The loop
            // ends on null, so no context is leaked or used after it was freed.
            ctx = unsafe { CertEnumCertificatesInStore(self.0, ctx) };
            if ctx.is_null() {
                break;
            }
            // SAFETY: a non-null context from the enumeration is valid until the next call;
            // `pbCertEncoded` points at `cbCertEncoded` bytes owned by it, copied out here.
            let der = unsafe {
                let c = &*ctx;
                std::slice::from_raw_parts(c.pbCertEncoded, c.cbCertEncoded as usize).to_vec()
            };
            out.push(der);
        }
        out
    }
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
