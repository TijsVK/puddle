// SPDX-License-Identifier: GPL-3.0-or-later
//! gRPC through a terminated HTTP/2 connection, with a tonic server behind it: unary calls,
//! error statuses (trailers), bidirectional streaming that must not be buffered, and credentials.
#![expect(
    clippy::unwrap_used,
    reason = "helpers outside #[test] functions fail the test by panicking"
)]
mod terminate_support;

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::StreamExt as _;
use http_body_util::BodyExt as _;
use terminate_support::h2_rig::{H2Guest, H2Server, Handler};
use terminate_support::{CANARY, Pki, RigBuilder};
use tonic::codegen::Service;
use tonic::server::{Grpc, StreamingService, UnaryService};
use tonic::{Request, Response, Status, Streaming};
use tonic_prost::ProstCodec;

#[derive(Clone, PartialEq, prost::Message)]
struct Msg {
    #[prost(string, tag = "1")]
    text: String,
    #[prost(bytes = "vec", tag = "2")]
    blob: Vec<u8>,
}

fn msg(text: &str) -> Msg {
    Msg {
        text: text.to_owned(),
        blob: Vec::new(),
    }
}

type Seen = Arc<Mutex<Vec<(String, Option<String>)>>>;

/// The server: `/t.Echo/Unary` answers with the text upper-cased (or an error status for
/// `fail`), `/t.Echo/Bidi` answers each message as it arrives.
#[derive(Clone)]
struct Echo {
    seen: Seen,
}

struct UnaryEcho;

impl UnaryService<Msg> for UnaryEcho {
    type Response = Msg;
    type Future = Pin<Box<dyn Future<Output = Result<Response<Msg>, Status>> + Send>>;

    fn call(&mut self, request: Request<Msg>) -> Self::Future {
        Box::pin(async move {
            let request = request.into_inner();
            if request.text == "fail" {
                return Err(Status::not_found("no such thing"));
            }
            Ok(Response::new(Msg {
                text: request.text.to_uppercase(),
                blob: request.blob,
            }))
        })
    }
}

struct BidiEcho;

impl StreamingService<Msg> for BidiEcho {
    type Response = Msg;
    type ResponseStream = Pin<Box<dyn futures_util::Stream<Item = Result<Msg, Status>> + Send>>;
    type Future =
        Pin<Box<dyn Future<Output = Result<Response<Self::ResponseStream>, Status>> + Send>>;

    fn call(&mut self, request: Request<Streaming<Msg>>) -> Self::Future {
        Box::pin(async move {
            let inbound = request.into_inner();
            let outbound = inbound.map(|item| item.map(|m| msg(&format!("echo {}", m.text))));
            Ok(Response::new(Box::pin(outbound) as Self::ResponseStream))
        })
    }
}

impl Service<http::Request<tonic::body::Body>> for Echo {
    type Response = http::Response<tonic::body::Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<tonic::body::Body>) -> Self::Future {
        self.seen.lock().unwrap().push((
            request.uri().path().to_owned(),
            request
                .headers()
                .get("authorization")
                .map(|v| v.to_str().unwrap().to_owned()),
        ));
        let path = request.uri().path().to_owned();
        Box::pin(async move {
            let codec = ProstCodec::<Msg, Msg>::default();
            let mut grpc = Grpc::new(codec);
            Ok(match path.as_str() {
                "/t.Echo/Unary" => grpc.unary(UnaryEcho, request).await,
                "/t.Echo/Bidi" => grpc.streaming(BidiEcho, request).await,
                _ => Status::unimplemented("no such method").into_http(),
            })
        })
    }
}

async fn server(pki: &Pki) -> (H2Server, Seen) {
    let seen: Seen = Arc::default();
    let echo = Echo {
        seen: Arc::clone(&seen),
    };
    let handler: Handler = Arc::new(move |request, _| {
        let mut echo = echo.clone();
        Box::pin(async move {
            let (parts, body) = request.into_parts();
            let request = http::Request::from_parts(parts, tonic::body::Body::new(body));
            let response = echo.call(request).await.unwrap();
            let (parts, body) = response.into_parts();
            http::Response::from_parts(
                parts,
                body.map_err(|status| -> terminate_support::h2_rig::BoxError { Box::new(status) })
                    .boxed_unsync(),
            )
        })
    });
    (H2Server::streaming(pki, "bound.test", handler).await, seen)
}

/// A tonic channel over the guest's HTTP/2 connection through the proxy.
#[derive(Clone)]
struct Channel {
    sender: hyper::client::conn::http2::SendRequest<terminate_support::h2_rig::ReqBody>,
}

impl Service<http::Request<tonic::body::Body>> for Channel {
    type Response = http::Response<hyper::body::Incoming>;
    type Error = hyper::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, hyper::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), hyper::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<tonic::body::Body>) -> Self::Future {
        let (mut parts, body) = request.into_parts();
        parts.uri = format!("https://bound.test{}", parts.uri.path())
            .parse()
            .unwrap();
        let request = http::Request::from_parts(
            parts,
            body.map_err(|status| -> terminate_support::h2_rig::BoxError { Box::new(status) })
                .boxed_unsync(),
        );
        let mut sender = self.sender.clone();
        Box::pin(async move { sender.send_request(request).await })
    }
}

async fn connect(
    rig: &terminate_support::Rig,
) -> (
    terminate_support::Guest,
    H2Guest,
    tonic::client::Grpc<Channel>,
) {
    let mut guest = rig.guest().await;
    let client = guest.h2("bound.test:443", &[b"h2"]).await;
    let channel = Channel {
        sender: client.sender.clone(),
    };
    (guest, client, tonic::client::Grpc::new(channel))
}

fn path(p: &'static str) -> http::uri::PathAndQuery {
    http::uri::PathAndQuery::from_static(p)
}

#[tokio::test]
async fn unary_calls_carry_trailers_and_the_credential_and_errors_arrive_as_statuses() {
    let pki = Pki::new();
    let (server, seen) = server(&pki).await;
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .build();
    let (_guest, _client, mut grpc) = connect(&rig).await;
    grpc.ready().await.unwrap();
    let reply = grpc
        .unary(
            Request::new(msg("hello")),
            path("/t.Echo/Unary"),
            ProstCodec::<Msg, Msg>::default(),
        )
        .await
        .unwrap();
    assert_eq!(reply.into_inner().text, "HELLO");
    let status = grpc
        .unary(
            Request::new(msg("fail")),
            path("/t.Echo/Unary"),
            ProstCodec::<Msg, Msg>::default(),
        )
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::NotFound);
    assert_eq!(status.message(), "no such thing");
    let status = grpc
        .unary(
            Request::new(msg("x")),
            path("/t.Echo/Missing"),
            ProstCodec::<Msg, Msg>::default(),
        )
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unimplemented);
    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 3);
    assert!(
        seen.iter()
            .all(|(_, auth)| auth.as_deref() == Some(&format!("Basic {CANARY}")))
    );
}

#[tokio::test]
async fn a_large_message_crosses_in_both_directions() {
    let pki = Pki::new();
    let (server, _) = server(&pki).await;
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .build();
    let (_guest, _client, mut grpc) = connect(&rig).await;
    grpc.ready().await.unwrap();
    let mut big = msg("big");
    big.blob = vec![0xab; 3 * 1024 * 1024];
    let reply = grpc
        .unary(
            Request::new(big),
            path("/t.Echo/Unary"),
            ProstCodec::<Msg, Msg>::default(),
        )
        .await
        .unwrap()
        .into_inner();
    assert_eq!(reply.blob.len(), 3 * 1024 * 1024);
    assert!(reply.blob.iter().all(|b| *b == 0xab));
}

#[tokio::test]
async fn bidirectional_streaming_is_not_buffered() {
    let pki = Pki::new();
    let (server, _) = server(&pki).await;
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .build();
    let (_guest, _client, mut grpc) = connect(&rig).await;
    grpc.ready().await.unwrap();
    let (tx, rx) = tokio::sync::mpsc::channel::<Msg>(1);
    let outbound = tokio_stream_from(rx);
    let response = grpc
        .streaming(
            Request::new(outbound),
            path("/t.Echo/Bidi"),
            ProstCodec::<Msg, Msg>::default(),
        )
        .await
        .unwrap();
    let mut inbound = response.into_inner();
    // Ping-pong: each answer must arrive before the next message is sent, so nothing may sit in
    // a buffer waiting for the request body to end.
    for i in 0..5 {
        tx.send(msg(&format!("m{i}"))).await.unwrap();
        let answer = tokio::time::timeout(Duration::from_secs(5), inbound.message())
            .await
            .expect("the answer arrives while the request is still open")
            .unwrap()
            .unwrap();
        assert_eq!(answer.text, format!("echo m{i}"));
    }
    drop(tx);
    assert!(inbound.message().await.unwrap().is_none());
    assert!(inbound.trailers().await.unwrap().is_some());
}

fn tokio_stream_from(
    mut rx: tokio::sync::mpsc::Receiver<Msg>,
) -> impl futures_util::Stream<Item = Msg> + Send + 'static {
    futures_util::stream::poll_fn(move |cx| rx.poll_recv(cx))
}
