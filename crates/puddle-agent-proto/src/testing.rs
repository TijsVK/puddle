// SPDX-License-Identifier: GPL-3.0-or-later
//! Test helpers (feature `testing`). Never use them in product code: [`AllowAll`] has no policy.

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use crate::host::{GuestStream, StreamHandler};
use crate::relay::splice;

/// Longest request head [`AllowAll`] reads.
const MAX_HEAD: usize = 64 * 1024;

/// A [`StreamHandler`] that serves every `CONNECT host:port` by connecting to it and splicing, the
/// way the real proxy does once a request is allowed: an abort on either side reaches the other
/// as a reset. Anything else gets `405`; a failed connect gets `502`.
#[derive(Debug, Clone, Copy, Default)]
pub struct AllowAll;

impl StreamHandler for AllowAll {
    async fn handle(&self, stream: GuestStream) {
        let mut reader = BufReader::new(stream);
        let Some(target) = read_connect(&mut reader).await else {
            refuse(reader.get_mut(), b"405 Method Not Allowed").await;
            return;
        };
        let Ok(mut server) = TcpStream::connect(&target).await else {
            refuse(reader.get_mut(), b"502 Bad Gateway").await;
            return;
        };
        let early = reader.buffer().to_vec();
        let mut guest = reader.into_inner();
        if guest
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .is_err()
            || server.write_all(&early).await.is_err()
        {
            return;
        }
        // On an error both ends reset: `splice` sets zero linger on the server socket, and the
        // guest stream is dropped without a shutdown.
        let _ = splice(&mut server, &mut guest).await;
    }
}

/// Sends an error response and closes the stream cleanly. A refusal is a normal end: dropping
/// the stream without the shutdown would reset it, and the reset can reach the client before the
/// response does.
async fn refuse(guest: &mut GuestStream, status: &[u8]) {
    let response = [
        &b"HTTP/1.1 "[..],
        status,
        b"\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
    ]
    .concat();
    if guest.write_all(&response).await.is_ok() {
        let _ = guest.shutdown().await;
    }
}

/// Reads a request head and returns the authority of a `CONNECT`, or `None`.
async fn read_connect(reader: &mut BufReader<GuestStream>) -> Option<String> {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let before = head.len();
        let n = reader.read_until(b'\n', &mut head).await.ok()?;
        if n == 0 || head.len() > MAX_HEAD || head.len() == before {
            return None;
        }
    }
    let text = std::str::from_utf8(&head).ok()?;
    let mut parts = text.lines().next()?.split(' ');
    match (parts.next(), parts.next()) {
        (Some("CONNECT"), Some(authority)) => Some(authority.to_owned()),
        _ => None,
    }
}
