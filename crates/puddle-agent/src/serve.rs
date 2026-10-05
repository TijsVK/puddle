// SPDX-License-Identifier: GPL-3.0-or-later
//! The proxy listener inside the guest: every accepted connection becomes one yamux stream to
//! the host, spliced so an abort stays an abort (T-048). The agent doesn't parse the request;
//! the host proxy does.

use std::sync::Arc;
use std::time::Duration;

use puddle_agent_proto::relay::splice;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;

use crate::upstream::Upstream;

/// Pause after a failed accept (e.g. out of file descriptors) so the loop doesn't spin.
const ACCEPT_PAUSE: Duration = Duration::from_millis(50);

/// Accepts guest connections forever. Connection tasks are owned here and end with it.
pub async fn serve(listener: TcpListener, upstream: Arc<Upstream>) {
    let mut conns = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((client, _)) => {
                    conns.spawn(connection(client, Arc::clone(&upstream)));
                }
                Err(err) => {
                    tracing::warn!(error = %err, "accept failed");
                    tokio::time::sleep(ACCEPT_PAUSE).await;
                }
            },
            Some(_) = conns.join_next(), if !conns.is_empty() => {}
        }
    }
}

async fn connection(mut client: TcpStream, upstream: Arc<Upstream>) {
    let mut stream = match upstream.open().await {
        Ok(stream) => stream,
        Err(err) => {
            tracing::warn!(error = %err, "no stream to the host; connection reset");
            // A reset, so the client sees a failure rather than an empty response.
            let _ = client.set_zero_linger();
            return;
        }
    };
    if let Err(err) = splice(&mut client, &mut stream).await {
        // The stream is dropped without a shutdown below, which resets it on the host side.
        tracing::debug!(error = %err, "guest connection ended with an error");
    }
}
