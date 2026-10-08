// SPDX-License-Identifier: GPL-3.0-or-later
//! What the injector tests share: the crate's own `World` and a few checks on a decision.
#![expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "helpers outside #[test] functions fail the test by panicking"
)]
#![allow(dead_code, reason = "each test binary uses a different subset")]

use puddle_inject::testing::World;
use puddle_proxy::{InjectContext, InjectDecision, Injector as _, RequestView};
use puddle_types::Host;

/// The injector's decision for `method target` on `host` with `headers` (`name: value`), and the
/// body the injector asked for.
pub(crate) trait Ask {
    async fn decide(
        &self,
        host: &str,
        method: &str,
        target: &str,
        headers: &[&str],
    ) -> InjectDecision;

    async fn decide_with(
        &self,
        host: &str,
        method: &str,
        target: &str,
        headers: &[&str],
        body: Option<&[u8]>,
    ) -> InjectDecision;

    fn body_wanted(&self, host: &str, method: &str, target: &str) -> Option<usize>;
}

impl Ask for World {
    async fn decide(
        &self,
        host: &str,
        method: &str,
        target: &str,
        headers: &[&str],
    ) -> InjectDecision {
        self.decide_with(host, method, target, headers, None).await
    }

    async fn decide_with(
        &self,
        host: &str,
        method: &str,
        target: &str,
        headers: &[&str],
        body: Option<&[u8]>,
    ) -> InjectDecision {
        let host = Host::parse_normalised(host).unwrap();
        let context = InjectContext {
            workspace: &self.workspace,
            host: &host,
        };
        let mut lines = vec![format!("host: {host}")];
        lines.extend(headers.iter().map(|h| (*h).to_owned()));
        let mut view = RequestView::new(method, target, &lines);
        if let Some(body) = body {
            view = view.with_body(body);
        }
        self.injector.decide(&context, &view).await
    }

    fn body_wanted(&self, host: &str, method: &str, target: &str) -> Option<usize> {
        let host = Host::parse_normalised(host).unwrap();
        let context = InjectContext {
            workspace: &self.workspace,
            host: &host,
        };
        let view = RequestView::new(method, target, &[]);
        self.injector.body_wanted(&context, &view)
    }
}

/// Whether `decision` injects exactly one `authorization` header with the value `expected`.
pub(crate) fn injected(decision: &InjectDecision, expected: &str) -> bool {
    match decision {
        InjectDecision::Inject(injection) => {
            injection.headers().len() == 1
                && injection
                    .headers()
                    .iter()
                    .all(|h| h.name().as_str() == "authorization" && h.value_is(expected))
        }
        _ => false,
    }
}

pub(crate) fn refusal(decision: &InjectDecision) -> (u16, &'static str, String) {
    match decision {
        InjectDecision::Refuse(r) => (r.status(), r.code(), r.message().to_owned()),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

pub(crate) fn basic(user: &str, token: &str) -> String {
    use base64::Engine as _;
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{user}:{token}"))
    )
}
