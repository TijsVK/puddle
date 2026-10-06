// SPDX-License-Identifier: GPL-3.0-or-later
//! Reading the host's certificate stores: `CryptoAPI` on Windows, nothing elsewhere (only Windows
//! has the admin- and user-added root stores puddle syncs).

use crate::store::{StoreError, StoreSnapshot, StoreSource};

#[cfg(windows)]
mod windows;

/// Reads `sources` into a snapshot (see [`crate::read_host_stores`]).
#[cfg(windows)]
pub(crate) fn read(sources: &[StoreSource]) -> Result<StoreSnapshot, StoreError> {
    windows::read(sources)
}

/// No Windows stores on this host: an empty snapshot.
#[cfg(not(windows))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "same signature as the Windows reader"
)]
pub(crate) fn read(sources: &[StoreSource]) -> Result<StoreSnapshot, StoreError> {
    let _ = sources;
    Ok(StoreSnapshot::new())
}
