// SPDX-License-Identifier: GPL-3.0-or-later
//! Egress proxy: the only way out of a sandbox.
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
//!    reach local addresses" is on (R-14); a block names the toggle that would allow it.
//! 5. **Relay**: `CONNECT` is spliced both ways, an abort on either side reaching the other as a
//!    reset; a plain-HTTP request is forwarded once with `Host` rewritten to the checked
//!    target and its body framed exactly, so nothing unchecked rides along.
//!    A tunnel that carries plain HTTP (Node `fetch` and Yarn Berry send `http://` as
//!    `CONNECT host:80`) is decided and relayed like any tunnel; only its first request line is
//!    read, for the audit.
//! 6. **Audit**: every request that got as far as a destination ends as one
//!    [`puddle_types::ConnectionEvent`] (decision, reason, rule or pending row, address connected
//!    to, method and path of a plain-HTTP request or of a tunnel's first HTTP request, bytes each
//!    way) handed to the
//!    [`puddle_types::ConnectionLog`] set with [`Proxy::with_connection_log`] (the store, R-24).
//!
//! The sandbox is the route's, never anything the guest says. Each sandbox has a cap on
//! open connections and each route on agent sessions ([`ProxyConfig`]), far above what real tools
//! open.
//!
//! [`PullProxy`] is the other way out: the loopback listener for puddle's own image pulls
//!, with a per-run token instead of a route, and the address guard without the rules.
//!
//! # Features
//!
//! - `testing`: in-memory doubles ([`testing::StaticPolicy`], [`testing::AnyAddress`],
//!   [`testing::StaticResolver`], [`testing::CollectingConnectionLog`]) for tests. Never use
//!   them in product code.
#![forbid(unsafe_code)]

mod counted;
mod destination;
mod http;
mod proxy;
mod pull;
mod route;
mod tap;
mod target;
#[cfg(feature = "testing")]
pub mod testing;
mod upstream;

pub use destination::{AddressCheck, AddressVerdict, BoxFuture, Resolver, SystemResolver};
pub use proxy::{Proxy, ProxyConfig, SandboxHandler};
pub use pull::{ProxyUrl, PullProxy, PullRoute, PullToken, default_pull_access};
pub use route::Route;
pub use upstream::Upstream;
