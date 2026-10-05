// SPDX-License-Identifier: GPL-3.0-or-later
//! The agent's side of the control stream: hello first, then every report from the OOM watch.
//! A failed write reopens the stream (on a new session if the old one died) and resends.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use puddle_agent_proto::AgentMessage;
use puddle_agent_proto::control::PREAMBLE;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tokio_yamux::StreamHandle;

use crate::upstream::Upstream;

/// First wait before reopening a failed control stream; it doubles up to [`MAX_BACKOFF`].
const FIRST_BACKOFF: Duration = Duration::from_millis(100);
/// Longest wait between attempts.
const MAX_BACKOFF: Duration = Duration::from_secs(5);

/// Keeps a control stream open and writes every message from `reports` to it. Returns when
/// `reports` closes.
pub async fn run(upstream: Arc<Upstream>, mut reports: mpsc::Receiver<AgentMessage>) {
    let mut pending: Option<AgentMessage> = None;
    let mut backoff = FIRST_BACKOFF;
    loop {
        let mut stream = match open(&upstream).await {
            Ok(stream) => {
                backoff = FIRST_BACKOFF;
                stream
            }
            Err(err) => {
                tracing::warn!(error = %err, retry_ms = backoff.as_millis(), "control stream to the host failed");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
                continue;
            }
        };
        loop {
            let msg = match pending.take() {
                Some(msg) => msg,
                None => match reports.recv().await {
                    Some(msg) => msg,
                    None => return,
                },
            };
            if let Err(err) = write(&mut stream, &msg).await {
                tracing::info!(error = %err, "control stream lost, reopening");
                pending = Some(msg);
                break;
            }
        }
    }
}

async fn open(upstream: &Upstream) -> io::Result<StreamHandle> {
    let mut stream = upstream.open().await?;
    stream.write_all(PREAMBLE).await?;
    write(&mut stream, &AgentMessage::hello()).await?;
    Ok(stream)
}

async fn write(stream: &mut StreamHandle, msg: &AgentMessage) -> io::Result<()> {
    let line = msg
        .to_line()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    stream.write_all(&line).await?;
    stream.flush().await
}
