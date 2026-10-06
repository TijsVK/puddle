// SPDX-License-Identifier: GPL-3.0-or-later
//! Egress proxy: the only way out of a sandbox (MWE plan W2).
//!
//! Every guest connection reaches the host as a yamux stream on the sandbox's route (a per-sandbox
//! named pipe or Unix socket, `puddle-ipc`), carried by the guest agent (`puddle-agent-proto`).
//! [`Proxy::serve_route`] accepts the agent's sessions on that route; each proxied stream goes
//! through these steps:
//!
//! 1. **Head**: at most 64 KiB (`431` over it) within [`ProxyConfig::head_timeout`] (`408`).
//! 2. **Target**: `CONNECT host:port` or an absolute-form `http://` request; the host is
//!    normalised into a [`puddle_types::Host`] (`puddle_netpolicy::normalise_host`: IDNA, LDH,
//!    canonical IPs); anything else is a `400`. A literal address or a name that is blocked by
//!    itself (toggle off, puddle's own endpoint) is refused here, before the rules.
//! 3. **Decision**: the [`puddle_types::Policy`] decides on the name before it is resolved
//!    (R-10). Deny, pending and blocked are a `403` that says which, with an
//!    `x-puddle-decision` header (and `x-puddle-pending: <id>` / `x-puddle-blocked: <reason>`);
//!    a policy error is a `503`: the proxy fails closed.
//! 4. **Addresses**: an allowed name is resolved once; every address goes through the
//!    [`AddressCheck`] (`puddle_netpolicy::NetPolicy`: address classes, local toggles, puddle's
//!    own endpoints) and only an address that passed is connected to. A local address needs its
//!    toggle on and an exact allow of the name or of the address itself, unless "wildcards
//!    reach local addresses" is on (R-14, D-44); a block names the toggle that would allow it.
//! 5. **Relay**: `CONNECT` is spliced both ways, an abort on either side reaching the other as a
//!    reset (T-048); a plain-HTTP request is forwarded once with `Host` rewritten to the checked
//!    target and its body framed exactly, so nothing unchecked rides along.
//!
//! The sandbox is the route's, never anything the guest says (HO-3). Each sandbox has a cap on
//! open connections and each route on agent sessions ([`ProxyConfig`]), far above what real tools
//! open (D-2).
//!
//! # Features
//!
//! - `testing`: in-memory doubles ([`testing::StaticPolicy`], [`testing::AnyAddress`],
//!   [`testing::StaticResolver`]) for tests. Never use them in product code.
#![forbid(unsafe_code)]

mod destination;
mod http;
mod proxy;
mod route;
mod target;
#[cfg(feature = "testing")]
pub mod testing;

pub use destination::{AddressCheck, AddressVerdict, BoxFuture, Resolver, SystemResolver};
pub use proxy::{Proxy, ProxyConfig, SandboxHandler};
pub use route::Route;
