// SPDX-License-Identifier: GPL-3.0-or-later
//! Connections puddle makes for itself: telemetry upload, downloads, anything the
//! host program fetches. They take the same route and authentication as a sandbox's traffic.
//!
//! Unlike a guest's request there is nothing to guard: the destination is a fixed endpoint of
//! puddle's own choosing, so every resolved address counts as checked. A name that cannot be
//! resolved here is left to the company's proxy, as for a guest. TLS goes on top of the returned
//! stream with [`crate::tls_connect`] (the platform verifier plus the corporate roots).

use std::net::SocketAddr;

use crate::chain::{Chain, ChainError, Connected, Form, Request};
use crate::hop::Destination;

/// Connects puddle itself to `destination` over `chain`.
///
/// # Errors
/// [`ChainError`], as for [`Chain::connect`].
pub async fn connect(
    chain: &Chain,
    destination: &Destination,
    form: Form,
) -> Result<Connected, ChainError> {
    let resolved: Vec<SocketAddr> = match tokio::net::lookup_host((
        destination.host(),
        destination.port(),
    ))
    .await
    {
        Ok(addrs) => addrs.collect(),
        Err(err) => {
            tracing::debug!(host = destination.host(), error = %err, "host-side lookup failed; the proxy may resolve it");
            Vec::new()
        }
    };
    let request = Request::new(destination, form, &resolved).name_ok(true);
    chain.connect(&request).await
}
