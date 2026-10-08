// SPDX-License-Identifier: GPL-3.0-or-later
//! What the endpoint says before SSH starts: a hello, then the SSH banner or a refusal line.
//!
//! On accept the endpoint at once writes [`HELLO`] (the bridge strips it; `ssh` never sees it),
//! so the bridge can bound its wait for a live puddle instead of hanging on an endpoint nobody
//! serves. Then an SSH server speaks first (`SSH-2.0-…`), so the next bytes are either that
//! banner or, when puddle refuses the client (sandbox stopped, boot failed), one line
//! `puddle-refused: <reason>\r\n` followed by a close. The bridge prints the reason instead of
//! leaving `ssh` with a bare "connection closed".
//!
//! The reason can carry guest output (a failed boot hook's stderr), so both ends make it one
//! line of printable text with a length cap: the endpoint before writing, the bridge again
//! before printing.

use tokio::io::{AsyncRead, AsyncReadExt as _};

/// The first bytes the endpoint sends on every connection.
pub const HELLO: &str = "puddle-ssh/1\r\n";

/// What a refusal line starts with. No SSH identification line does.
pub const REFUSAL_PREFIX: &str = "puddle-refused: ";

/// The longest reason kept, in characters.
const REASON_LIMIT: usize = 1024;

/// The most bytes the bridge reads looking for the end of a refusal line.
const LINE_LIMIT: usize = REFUSAL_PREFIX.len() + REASON_LIMIT * 4 + 2;

/// `reason` as one line of printable text: control and invisible formatting characters
/// (newlines, escape sequences, bidi overrides) become spaces, runs of spaces collapse, and it
/// is cut at 1024 characters.
#[must_use]
pub fn sanitize_reason(reason: &str) -> String {
    let mut out = String::with_capacity(reason.len().min(REASON_LIMIT));
    let mut count = 0;
    let mut pending_space = false;
    for c in reason.chars() {
        if c.is_control() || is_invisible_format(c) || c.is_whitespace() {
            pending_space = !out.is_empty();
            continue;
        }
        if pending_space {
            if count + 1 >= REASON_LIMIT {
                break;
            }
            out.push(' ');
            count += 1;
            pending_space = false;
        }
        if count >= REASON_LIMIT {
            break;
        }
        out.push(c);
        count += 1;
    }
    out
}

/// Characters that change how text displays without being visible: zero-width marks, bidi
/// embeddings, overrides and isolates, the BOM.
fn is_invisible_format(c: char) -> bool {
    matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{206F}' | '\u{FEFF}')
}

/// The line the endpoint writes to a refused client.
#[must_use]
pub fn refusal_line(reason: &str) -> String {
    format!("{REFUSAL_PREFIX}{}\r\n", sanitize_reason(reason))
}

/// What the first bytes from the endpoint were.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Head {
    /// A refusal, with its sanitised reason.
    Refused(String),
    /// Anything else: these bytes (possibly empty, at end of stream) go to the client as they
    /// are, followed by the rest of the stream.
    Pass(Vec<u8>),
}

/// Reads just enough of `server` to tell a refusal line from anything else.
pub(crate) async fn read_head<R: AsyncRead + Unpin>(server: &mut R) -> std::io::Result<Head> {
    let prefix = REFUSAL_PREFIX.as_bytes();
    let mut head = Vec::new();
    let mut chunk = [0_u8; 512];
    // Until the bytes so far can't be a refusal, or are the whole prefix.
    while head.len() < prefix.len() {
        let n = server.read(&mut chunk).await?;
        let Some(got) = chunk.get(..n).filter(|g| !g.is_empty()) else {
            return Ok(Head::Pass(head));
        };
        head.extend_from_slice(got);
        let common = head.len().min(prefix.len());
        if head.get(..common) != prefix.get(..common) {
            return Ok(Head::Pass(head));
        }
    }
    // A refusal: read to the end of the line (or the limit, or the end of the stream).
    while !head.contains(&b'\n') && head.len() < LINE_LIMIT {
        let n = server.read(&mut chunk).await?;
        let Some(got) = chunk.get(..n).filter(|g| !g.is_empty()) else {
            break;
        };
        head.extend_from_slice(got);
    }
    let rest = head.get(prefix.len()..).unwrap_or_default();
    let line = rest.split(|b| *b == b'\n').next().unwrap_or_default();
    Ok(Head::Refused(sanitize_reason(&String::from_utf8_lossy(
        line,
    ))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt as _;

    #[test]
    fn reasons_become_one_printable_line() {
        assert_eq!(
            sanitize_reason("boot hook exited with status 1:\nline two\r\n\tthree"),
            "boot hook exited with status 1: line two three"
        );
        assert_eq!(
            sanitize_reason("\x1b[2J\x1b]0;evil\x07gone"),
            "[2J ]0;evil gone"
        );
        assert_eq!(sanitize_reason("a\u{202E}b\u{200B}c\u{FEFF}"), "a b c");
        assert_eq!(
            sanitize_reason("  leading and trailing  \n"),
            "leading and trailing"
        );
        assert_eq!(sanitize_reason(""), "");
    }

    #[test]
    fn reasons_are_capped() {
        let long = "é".repeat(5000);
        let s = sanitize_reason(&long);
        assert_eq!(s.chars().count(), REASON_LIMIT);
        let spaced = "ab ".repeat(1000);
        assert!(sanitize_reason(&spaced).chars().count() <= REASON_LIMIT);
        assert!(!sanitize_reason(&spaced).ends_with(' '));
    }

    #[test]
    fn the_line_has_the_prefix_and_crlf() {
        assert_eq!(
            refusal_line("workspace \"a\": workspace is not running\n"),
            "puddle-refused: workspace \"a\": workspace is not running\r\n"
        );
    }

    /// Hands out its bytes one per read.
    struct Trickle(std::collections::VecDeque<u8>);

    impl AsyncRead for Trickle {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            if let Some(b) = self.0.pop_front() {
                buf.put_slice(&[b]);
            }
            std::task::Poll::Ready(Ok(()))
        }
    }

    async fn head_of(bytes: &[u8], chunked: bool) -> Head {
        if chunked {
            return read_head(&mut Trickle(bytes.iter().copied().collect()))
                .await
                .unwrap();
        }
        let (mut client, mut server) = tokio::io::duplex(64 * 1024);
        server.write_all(bytes).await.unwrap();
        drop(server);
        read_head(&mut client).await.unwrap()
    }

    #[tokio::test]
    async fn an_ssh_banner_passes_after_the_first_byte_that_differs() {
        assert_eq!(
            head_of(b"SSH-2.0-x\r\n", false).await,
            Head::Pass(b"SSH-2.0-x\r\n".to_vec())
        );
        assert_eq!(
            head_of(b"SSH-2.0-x\r\n", true).await,
            Head::Pass(b"S".to_vec())
        );
        // Shares a start with the prefix, then differs.
        assert_eq!(head_of(b"pudX", true).await, Head::Pass(b"pudX".to_vec()));
    }

    #[tokio::test]
    async fn end_of_stream_passes_what_came() {
        assert_eq!(head_of(b"", false).await, Head::Pass(Vec::new()));
        assert_eq!(head_of(b"pud", true).await, Head::Pass(b"pud".to_vec()));
    }

    #[tokio::test]
    async fn a_refusal_is_read_to_its_line_end_in_any_chunking() {
        let line = refusal_line("workspace is not running");
        for chunked in [false, true] {
            assert_eq!(
                head_of(line.as_bytes(), chunked).await,
                Head::Refused("workspace is not running".into())
            );
        }
        // No line end before the stream ends: what came is the reason.
        assert_eq!(
            head_of(b"puddle-refused: cut", true).await,
            Head::Refused("cut".into())
        );
        // Only the first line counts; the rest is hostile noise.
        assert_eq!(
            head_of(b"puddle-refused: one\r\n\x1b[31mtwo\n", false).await,
            Head::Refused("one".into())
        );
    }

    #[tokio::test]
    async fn a_refusal_without_a_line_end_stops_at_the_limit() {
        let (mut client, mut server) = tokio::io::duplex(1 << 16);
        server.write_all(REFUSAL_PREFIX.as_bytes()).await.unwrap();
        // Keeps the stream open and never sends a newline.
        server.write_all(&vec![b'x'; LINE_LIMIT]).await.unwrap();
        let Head::Refused(reason) = read_head(&mut client).await.unwrap() else {
            panic!("not a refusal");
        };
        assert_eq!(reason.len(), REASON_LIMIT);
        drop(server);
    }
}
