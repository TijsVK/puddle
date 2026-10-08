// SPDX-License-Identifier: GPL-3.0-or-later
//! WebSocket through a terminated connection (RFC 6455 over HTTP/1.1 `Upgrade`, RFC 8441 over
//! HTTP/2 extended `CONNECT`).
//!
//! The proxy checks and injects the handshake request like any other request. When the server
//! agrees (`101` on HTTP/1.1, `2xx` on HTTP/2), the two connections become a byte pipe: what the
//! frames mean is none of the proxy's business.

use ::http::header::{HeaderMap, HeaderName, HeaderValue};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};

/// The GUID RFC 6455 §1.3 mixes into the key.
const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// A fresh `Sec-WebSocket-Key` (16 random bytes, base64).
pub(crate) fn new_key() -> Option<String> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).ok()?;
    Some(STANDARD.encode(bytes))
}

/// The `Sec-WebSocket-Accept` a server answers `key` with.
pub(crate) fn accept_for(key: &str) -> String {
    let mut input = Vec::with_capacity(key.len() + GUID.len());
    input.extend_from_slice(key.as_bytes());
    input.extend_from_slice(GUID.as_bytes());
    let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &input);
    STANDARD.encode(digest.as_ref())
}

/// The headers of the server's handshake answer worth passing to the guest: what is end to end
/// (`Sec-WebSocket-Protocol`, `-Extensions`, `-Accept`, cookies), not the connection management
/// the proxy writes itself.
pub(crate) fn answer_headers(
    headers: &HeaderMap,
    keep_accept: bool,
) -> Vec<(HeaderName, HeaderValue)> {
    headers
        .iter()
        .filter(|(name, _)| {
            !matches!(
                name.as_str(),
                "connection"
                    | "upgrade"
                    | "keep-alive"
                    | "proxy-connection"
                    | "proxy-authenticate"
                    | "te"
                    | "trailer"
                    | "transfer-encoding"
                    | "content-length"
            ) && (keep_accept || **name != HeaderName::from_static("sec-websocket-accept"))
        })
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect()
}

/// Whether `headers` ask for a WebSocket upgrade on HTTP/1.1: `Connection: upgrade` with exactly
/// one `Upgrade: websocket`.
pub(crate) fn is_upgrade_request(connection_tokens: &[String], upgrade_values: &[&str]) -> bool {
    connection_tokens.iter().any(|token| token == "upgrade")
        && matches!(upgrade_values, [one] if one.trim().eq_ignore_ascii_case("websocket"))
}

/// Pipes the guest's side to the server's until either ends.
pub(crate) async fn splice<G>(guest: &mut G, upstream: Upgraded)
where
    G: AsyncRead + AsyncWrite + Unpin,
{
    let mut upstream = TokioIo::new(upstream);
    let _ = tokio::io::copy_bidirectional(guest, &mut upstream)
        .await
        .inspect_err(|err| tracing::debug!(error = %err, "WebSocket ended with an error"));
}

/// The header `name` of `headers` as text, if there is exactly one.
pub(crate) fn single<'a>(headers: &'a HeaderMap, name: &HeaderName) -> Option<&'a str> {
    let mut all = headers.get_all(name).iter();
    let first = all.next()?;
    if all.next().is_some() {
        return None;
    }
    first.to_str().ok()
}

/// `Sec-WebSocket-Version` the proxy can translate (RFC 6455 §4.1).
pub(crate) fn version_ok(headers: &HeaderMap) -> bool {
    single(headers, &HeaderName::from_static("sec-websocket-version")) == Some("13")
}

/// Whether the answer's `Sec-WebSocket-Accept` is the one for `key`.
pub(crate) fn accept_matches(headers: &HeaderMap, key: &str) -> bool {
    single(headers, &HeaderName::from_static("sec-websocket-accept"))
        .is_some_and(|got| got == accept_for(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_accept_key_is_the_one_of_rfc_6455() {
        // RFC 6455 §1.3's example.
        assert_eq!(
            accept_for("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn only_a_single_websocket_upgrade_with_the_connection_token_counts() {
        let upgrade = vec!["keep-alive".to_owned(), "upgrade".to_owned()];
        assert!(is_upgrade_request(&upgrade, &["WebSocket"]));
        assert!(!is_upgrade_request(&upgrade, &["websocket", "h2c"]));
        assert!(!is_upgrade_request(&upgrade, &["h2c"]));
        assert!(!is_upgrade_request(
            &["keep-alive".to_owned()],
            &["websocket"]
        ));
        assert!(!is_upgrade_request(&upgrade, &[]));
    }

    #[test]
    fn a_new_key_is_sixteen_random_bytes_in_base64() {
        let a = new_key().unwrap();
        let b = new_key().unwrap();
        assert_eq!(STANDARD.decode(&a).unwrap().len(), 16);
        assert_ne!(a, b);
    }

    #[test]
    fn the_answer_keeps_end_to_end_headers_only() {
        let mut headers = HeaderMap::new();
        headers.insert(
            ::http::header::CONNECTION,
            HeaderValue::from_static("Upgrade"),
        );
        headers.insert(
            ::http::header::UPGRADE,
            HeaderValue::from_static("websocket"),
        );
        headers.insert("sec-websocket-accept", HeaderValue::from_static("x"));
        headers.insert("sec-websocket-protocol", HeaderValue::from_static("chat"));
        let kept: Vec<_> = answer_headers(&headers, false)
            .into_iter()
            .map(|(n, _)| n.to_string())
            .collect();
        assert_eq!(kept, ["sec-websocket-protocol"]);
        assert_eq!(answer_headers(&headers, true).len(), 2);
    }

    #[test]
    fn a_header_is_single_only_when_it_has_exactly_one_text_value() {
        let mut headers = HeaderMap::new();
        let name = HeaderName::from_static("sec-websocket-protocol");
        assert_eq!(single(&headers, &name), None);
        headers.append(name.clone(), "chat".parse().unwrap());
        assert_eq!(single(&headers, &name), Some("chat"));
        headers.append(name.clone(), "superchat".parse().unwrap());
        assert_eq!(single(&headers, &name), None);
    }
}
