// SPDX-License-Identifier: GPL-3.0-or-later
//! The destination guard (MWE plan W2, T-132): which destinations a sandbox may reach, decided
//! before any connection. Pure policy, no network I/O; the proxy (`puddle-proxy`) calls it.
//!
//! | Stage | Item | What |
//! |---|---|---|
//! | name | [`normalise_host`], [`Target`] | strict normal form: lower case, IDNA to ASCII, LDH labels, canonical IP literals; non-canonical numbers refused |
//! | name | [`NetPolicy::check_target`] | literals and `localhost`/metadata names blocked before the rules, so a block never becomes a pending row |
//! | address | [`classify_ip`], [`AddressClass`] | public, a [`LocalCategory`] (with the rule that put it there), or one of puddle's own endpoints |
//! | address | [`NetPolicy::check_address`], [`AddressVerdict`] | allow, exact-allow only (toggle on), or block naming the toggle |
//! | settings | [`LocalAccess`], [`LocalAccessSource`] | one sandbox's toggles and "wildcards reach local addresses", from `puddle-settings` |
//! | endpoints | [`PuddleEndpoints`], [`EndpointKind`] | the registry every puddle listener joins when it binds (D-26) |
//! | message | [`block_message`] | the `403` text: what was found and which toggle would allow it |
//!
//! The rules it applies:
//!
//! - **D-1:** local destinations are not forbidden, only off by default: one toggle per
//!   [`LocalCategory`], with a global default and a per-sandbox override.
//! - **D-37:** a toggle only *permits* its category; the destination still needs an allow rule
//!   or an approval.
//! - **D-44 / R-14:** with the toggle on, only an **exact** allow (of the name, or of the
//!   address itself) reaches a local address; a wildcard (suffix) allow doesn't, unless
//!   "wildcards reach local addresses" is on ([`AddressVerdict::ExactOnly`]).
//! - **D-26:** puddle's own listeners are their own class, blocked whatever the toggles say.
//! - A blocked request names the toggle that would allow it ([`block_message`]).
#![forbid(unsafe_code)]

mod access;
mod classify;
mod endpoints;
mod guard;
mod name;

pub use access::{LocalAccess, LocalAccessSource};
pub use classify::{AddressClass, classify_ip};
pub use endpoints::{EndpointKind, HostAddrs, OwnAddresses, PuddleEndpoints, Registration};
pub use guard::{AddressVerdict, NetPolicy, block_message};
pub use name::{MAX_RAW_HOST_LEN, NameError, Target, normalise_host};
pub use puddle_types::LocalCategory;
