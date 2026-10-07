// SPDX-License-Identifier: GPL-3.0-or-later
//! Capture for tools that ignore the proxy settings.
//!
//! A client that doesn't use `HTTPS_PROXY` resolves a name and connects to the answer. The agent
//! answers the name itself ([`dns`]) with a *stand-in* address from `198.18.0.0/15`
//! ([`table`]), after asking the host whether the name is worth one. The connection to that
//! address is then redirected to the agent, which looks the name up in the table again and
//! sends `CONNECT name:port` to the host's proxy, exactly as an explicit proxy client would, so
//! the rules, the toggles and the audit see the name.
//!
//! - [`dns`]: the stub DNS server, its cache and its `resolve` lookups on the host;
//! - [`wire`]: the DNS messages it reads and writes;
//! - [`table`]: stand-in address ⇄ name, kept across agent restarts;
//! - [`names`]: which names are answered locally.

pub mod dns;
pub mod names;
pub mod table;
pub mod wire;
