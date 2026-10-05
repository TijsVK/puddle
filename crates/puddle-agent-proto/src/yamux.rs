// SPDX-License-Identifier: GPL-3.0-or-later
//! yamux settings shared by the agent (client) and the host (server).

use std::time::Duration;

use tokio_yamux::Config;

/// Receive window per stream, both directions: 16 MiB.
///
/// With the agent's vsock buffer raised past msb's 8 MiB (T-004, `puddle-agent`'s vsock module),
/// this window sets per-stream speed only; a single 1 GiB upload went from 68 to 334 MiB/s when it
/// went from 256 KiB back to 16 MiB.
pub const STREAM_WINDOW: u32 = 16 * 1024 * 1024;

/// Streams the host lets wait for its accept loop. A parallel restore or `docker pull` opens
/// hundreds at once; the default of 256 would refuse some.
pub const ACCEPT_BACKLOG: usize = 4096;

/// The host's keepalive ping interval: a liveness check only, it plays no part in flow control.
pub const KEEPALIVE: Duration = Duration::from_secs(30);

/// First byte of every yamux frame (protocol version 0). An HTTP request line starts with a
/// letter, so the host can tell a yamux session from anything else by this byte.
pub const VERSION_BYTE: u8 = 0;

/// The agent's session settings.
#[must_use]
pub fn client_config() -> Config {
    client_config_with_window(STREAM_WINDOW)
}

/// The agent's session settings with another receive window (`PUDDLE_AGENT_WINDOW`, for
/// experiments). yamux needs at least 256 KiB; smaller values are raised to that.
#[must_use]
pub fn client_config_with_window(window: u32) -> Config {
    Config {
        max_stream_window_size: window.max(tokio_yamux::config::INITIAL_STREAM_WINDOW),
        ..Config::default()
    }
}

/// The host's session settings.
#[must_use]
pub fn server_config() -> Config {
    Config {
        accept_backlog: ACCEPT_BACKLOG,
        max_stream_window_size: STREAM_WINDOW,
        enable_keepalive: true,
        keepalive_interval: KEEPALIVE,
        ..Config::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_sides_use_the_16_mib_window() {
        assert_eq!(client_config().max_stream_window_size, STREAM_WINDOW);
        assert_eq!(server_config().max_stream_window_size, STREAM_WINDOW);
        assert_eq!(server_config().accept_backlog, ACCEPT_BACKLOG);
        assert!(server_config().enable_keepalive);
    }

    #[test]
    fn a_window_below_the_yamux_minimum_is_raised() {
        assert_eq!(
            client_config_with_window(1).max_stream_window_size,
            256 * 1024
        );
        assert_eq!(
            client_config_with_window(32 << 20).max_stream_window_size,
            32 << 20
        );
    }
}
