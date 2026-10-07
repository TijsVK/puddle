// SPDX-License-Identifier: GPL-3.0-or-later
//! The way out of the host once a connection has been admitted: straight to a checked
//! address, or along the route the company's proxy settings give ([`puddle_upstream::Chain`]).
//!
//! Admission (rules, address guard, IP rules) has already happened by the time this runs, and
//! nothing here widens it: `DIRECT` connects to an admitted address only, and a proxy is told the
//! destination's name only when every address the name resolved to was admitted (otherwise it is
//! sent an admitted address). A name this host cannot resolve at all may go to the company proxy
//! by name when [`Upstream::with_resolve_via_upstream`] is on (the default), because in some
//! networks only the proxy resolves internet names; there is no address to guard then, and the
//! audit says so (no `resolved_ip`).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use puddle_upstream::{Chain, ChainError, Destination, Form, Request, Scheme, Secret};
use tokio::net::TcpStream;

use crate::proxy::{Refusal, connect_first};
use crate::target::Target;

/// The company proxy route in front of the host's connections.
#[derive(Debug, Clone)]
pub struct Upstream {
    chain: Arc<Chain>,
    resolve_via_upstream: bool,
}

impl Upstream {
    /// Connects along `chain`.
    #[must_use]
    pub fn new(chain: Arc<Chain>) -> Self {
        Self {
            chain,
            resolve_via_upstream: true,
        }
    }

    /// Whether an allowed name this host cannot resolve is sent to the company proxy by name
    /// (default: yes). Off, such a request is a `502` as without a proxy.
    #[must_use]
    pub fn with_resolve_via_upstream(mut self, on: bool) -> Self {
        self.resolve_via_upstream = on;
        self
    }

    pub(crate) fn resolves_unknown_names(&self) -> bool {
        self.resolve_via_upstream
    }
}

/// What admission let through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Admitted {
    /// The addresses that passed the guard and the IP rules. Empty only for a name this host
    /// could not resolve.
    pub(crate) addrs: Vec<SocketAddr>,
    /// Whether a proxy may be told the name: every resolved address passed (or the name is a
    /// literal, or unresolved here).
    pub(crate) name_ok: bool,
}

impl Admitted {
    pub(crate) fn checked(addrs: Vec<SocketAddr>, name_ok: bool) -> Self {
        Self { addrs, name_ok }
    }

    pub(crate) fn unresolved() -> Self {
        Self {
            addrs: Vec::new(),
            name_ok: true,
        }
    }
}

/// How a plain-HTTP request must be written to a proxy.
#[derive(Debug)]
pub(crate) struct ProxyForm {
    /// `host:port` for the absolute URI.
    pub(crate) authority: String,
    /// A `Proxy-Authorization` value for the request.
    pub(crate) authorization: Option<Secret>,
}

/// A connection out.
#[derive(Debug)]
pub(crate) struct Out {
    pub(crate) stream: TcpStream,
    /// The address of the destination connected to (directly, or sent to a proxy).
    pub(crate) addr: Option<SocketAddr>,
    /// The hop used, for the audit; `None` without an upstream configured.
    pub(crate) hop: Option<String>,
    /// Set for a proxy hop.
    pub(crate) via: Option<ProxyForm>,
}

/// Connects out for `target`: `tunnel` for `CONNECT`, else a plain-HTTP request.
pub(crate) async fn connect_out(
    upstream: Option<&Upstream>,
    target: &Target,
    tunnel: bool,
    admitted: &Admitted,
    connect_timeout: Duration,
) -> Result<Out, Refusal> {
    let Some(upstream) = upstream else {
        return match connect_first(&admitted.addrs, connect_timeout).await {
            Ok((stream, addr)) => Ok(Out {
                stream,
                addr: Some(addr),
                hop: None,
                via: None,
            }),
            Err(err) => {
                tracing::info!(host = %target.host, port = target.port, error = %err, "upstream connect failed");
                Err(Refusal::new(
                    "502 Bad Gateway",
                    format!("could not connect to {}:{}", target.host, target.port),
                ))
            }
        };
    };
    let scheme = if tunnel { Scheme::Https } else { Scheme::Http };
    let destination = Destination::new(scheme, &target.host.to_string(), target.port);
    let form = if tunnel { Form::Tunnel } else { Form::Absolute };
    let request = Request::new(&destination, form, &admitted.addrs).name_ok(admitted.name_ok);
    match upstream.chain.connect(&request).await {
        Ok(connected) => {
            let addr = connected.addr.or_else(|| {
                if admitted.name_ok {
                    None
                } else {
                    connected
                        .authority
                        .as_deref()
                        .and_then(|a| a.parse::<SocketAddr>().ok())
                }
            });
            let hop = Some(connected.hop.to_string());
            tracing::debug!(host = %target.host, port = target.port, hop = ?hop, "connected");
            let via = connected.authority.map(|authority| ProxyForm {
                authority,
                authorization: connected.authorization,
            });
            Ok(Out {
                stream: connected.stream,
                addr,
                hop,
                via,
            })
        }
        Err(err) => Err(refusal(&err, target)),
    }
}

/// The guest-facing refusal for a failed chain. It never names the company proxy (the log does):
/// the guest learns what to ask its administrator, not where the proxy is.
fn refusal(err: &ChainError, target: &Target) -> Refusal {
    let host = &target.host;
    let port = target.port;
    tracing::info!(%host, port, error = %err, "upstream route failed");
    match err {
        ChainError::Refused { status, reason, .. } => {
            let (code, text) = if *status == 403 {
                ("403 Forbidden", "refused")
            } else {
                ("502 Bad Gateway", "answered with an error for")
            };
            Refusal::new(
                code,
                format!("the company proxy {text} {host}:{port} ({status} {reason})"),
            )
            .header("x-puddle-blocked-by", "upstream")
        }
        ChainError::AuthRequired { schemes, .. } => Refusal::new(
            "502 Bad Gateway",
            format!(
                "the company proxy requires sign-in that puddle cannot provide (it offers {})",
                schemes.join(", ")
            ),
        )
        .header("x-puddle-blocked-by", "upstream-auth"),
        ChainError::AuthFailed { .. } => Refusal::new(
            "502 Bad Gateway",
            "signing in to the company proxy failed; check the proxy credentials in puddle",
        )
        .header("x-puddle-blocked-by", "upstream-auth"),
        _ => Refusal::new(
            "502 Bad Gateway",
            format!("could not connect to {host}:{port} (no route to it works)"),
        ),
    }
}
