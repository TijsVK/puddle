// SPDX-License-Identifier: GPL-3.0-or-later
//! Corporate root sync (W1, T-110; design T-026 §2b, D-24, D-11).
//!
//! Behind a TLS-inspecting corporate proxy, every HTTPS call in the guest fails unless the guest
//! trusts the company's root. puddle copies every root an admin or the user deliberately added
//! on the Windows host into the guest at boot, next to (never instead of) the image's own roots.
//!
//! | Step | Piece |
//! |---|---|
//! | read the host stores (`Root`/`CA` `.Default`, `.GroupPolicy`, `.Enterprise`; `Disallowed`) | [`read_host_stores`] → [`StoreSnapshot`] |
//! | select: roots, intermediates they issued, minus Disallowed (by certificate or key), minus expired, each once | [`CorporateRoots::select`] |
//! | guest files, env and boot step, together with puddle's own CAs ([`puddle_ca::TrustBundle`]) | [`GuestTrust`] |
//!
//! In the guest, `boot.sh` writes the files, runs `update-ca-certificates` when one of them
//! changed (the system store, for curl, git, apt, Go, .NET, Python `ssl`), then runs the step
//! (`guest/ca-bundle.sh`), which writes `/etc/puddle/ca-bundle.pem`: the image's bundle plus
//! the extra CAs, each certificate once, rewritten only when it changed. `SSL_CERT_FILE`,
//! `REQUESTS_CA_BUNDLE` and `CURL_CA_BUNDLE` point at that bundle, `NODE_EXTRA_CA_CERTS` at the
//! extra CAs alone (Node adds them to its own roots).
//!
//! ```no_run
//! use std::time::SystemTime;
//! use puddle_ca::TrustBundle;
//! use puddle_certs::{CorporateRoots, GuestTrust, read_host_stores};
//!
//! let roots = CorporateRoots::select(&read_host_stores()?, SystemTime::now());
//! let trust = GuestTrust::new(&roots, &TrustBundle::new());
//! // BootPlan::builder(..).files(trust.guest_files()).env(&trust.env()), plus
//! // .step(path) for trust.boot_step().
//! # Ok::<(), puddle_certs::StoreError>(())
//! ```
#![cfg_attr(not(windows), forbid(unsafe_code))]

mod der;
mod guest;
mod platform;
mod select;
mod store;

pub use guest::{
    BUNDLE_STEP_PATH, BUNDLE_STEP_SH, CA_BUNDLE_PATH, EXTRA_CAS_PATH, GuestTrust, HOST_CA_DIR,
};
pub use select::{CertKind, CorporateRoots, Fingerprint, SkipReason, SkippedCert, SyncedCert};
pub use store::{
    HostCert, Location, Physical, SOURCES, StoreError, StoreName, StoreSnapshot, StoreSource,
    UnreadableStore, read_host_stores,
};
