// SPDX-License-Identifier: GPL-3.0-or-later
//! Reading a Git host's answer: ok, the host's rate limit (and for how long to leave it alone),
//! a rejected token, a refusal. Pure functions over an [`ApiReply`], so every rule has a test on
//! the answers the hosts document.
//!
//! GitHub (REST rate limits, "Handle rate limit errors appropriately"): on `403` or `429`, wait
//! `retry-after` seconds when it is there; else, when `x-ratelimit-remaining` is `0`, until
//! `x-ratelimit-reset`; else (a secondary limit with no header) at least a minute, longer on each
//! repeat. Azure DevOps answers `429` with `Retry-After`.

use serde::Deserialize;

use crate::api::ApiReply;

/// The wait when a host limits us and says nothing about how long: one minute, doubling on each
/// repeat up to an hour.
const MIN_WAIT_MS: u64 = 60_000;
const MAX_WAIT_MS: u64 = 60 * 60_000;
/// How much of a host's own message is kept.
const MESSAGE_CHARS: usize = 200;

/// What an answer means for the request that got it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// A usable answer.
    Ok,
    /// The host does not know the token (expired, revoked, wrong), or answered with its sign-in
    /// page.
    Rejected,
    /// The host limits requests; nothing is asked before `until_ms`.
    Limited {
        /// Epoch milliseconds.
        until_ms: u64,
        /// Whether it is the primary limit (the hour's budget) rather than a secondary one.
        primary: bool,
    },
    /// The host knows the token and refuses this, with its own words.
    Forbidden(Option<String>),
    /// There is nothing at that address (an organisation the sign-in cannot see).
    NotFound,
    /// A status this version has no rule for.
    Other(u16),
}

/// The wait after the `strikes`-th limit in a row (1 for the first).
pub(crate) fn backoff_ms(strikes: u32) -> u64 {
    let doublings = strikes.saturating_sub(1).min(8);
    (MIN_WAIT_MS << doublings).min(MAX_WAIT_MS)
}

fn number(reply: &ApiReply, name: &str) -> Option<u64> {
    reply.header(name)?.trim().parse().ok()
}

/// The host's own `message`, cleaned of control characters and cut short.
pub(crate) fn message_of(reply: &ApiReply) -> Option<String> {
    #[derive(Deserialize)]
    struct Body {
        message: Option<String>,
    }
    let body: Body = serde_json::from_slice(&reply.body).ok()?;
    let text: String = body
        .message?
        .chars()
        .filter(|c| !c.is_control())
        .take(MESSAGE_CHARS)
        .collect();
    let text = text.trim().to_owned();
    (!text.is_empty()).then_some(text)
}

/// A successful GitHub answer that used up the hour's budget: nothing more is asked until it
/// resets.
pub(crate) fn github_spent(reply: &ApiReply) -> Option<u64> {
    if number(reply, "x-ratelimit-remaining")? != 0 {
        return None;
    }
    Some(number(reply, "x-ratelimit-reset")?.saturating_mul(1000))
}

/// GitHub's answer to one request. `strikes` counts limits in a row, this one included.
pub(crate) fn github(reply: &ApiReply, now_ms: u64, strikes: u32) -> Verdict {
    match reply.status {
        200..=299 => Verdict::Ok,
        401 => Verdict::Rejected,
        404 => Verdict::NotFound,
        403 | 429 => {
            let message = message_of(reply);
            if let Some(seconds) = number(reply, "retry-after") {
                let wait = seconds.saturating_mul(1000).max(backoff_ms(strikes) / 2);
                return limited(now_ms, wait, false);
            }
            if let Some(until) = github_spent(reply) {
                return Verdict::Limited {
                    until_ms: until.max(now_ms.saturating_add(1000)),
                    primary: true,
                };
            }
            let said_limit = message
                .as_deref()
                .is_some_and(|m| m.to_ascii_lowercase().contains("rate limit"));
            if said_limit || reply.status == 429 {
                return limited(now_ms, backoff_ms(strikes), false);
            }
            Verdict::Forbidden(message)
        }
        other => Verdict::Other(other),
    }
}

fn limited(now_ms: u64, wait_ms: u64, primary: bool) -> Verdict {
    Verdict::Limited {
        until_ms: now_ms.saturating_add(wait_ms.min(MAX_WAIT_MS)),
        primary,
    }
}

/// Azure DevOps' answer to one request. It answers a bad or expired token with its sign-in page
/// (`203`, or a redirect, or a `200` of HTML) rather than `401`, so those count as rejected.
pub(crate) fn azure(reply: &ApiReply, now_ms: u64, strikes: u32) -> Verdict {
    if let Some(seconds) = number(reply, "retry-after")
        && reply.status >= 400
    {
        return limited(now_ms, seconds.saturating_mul(1000), false);
    }
    match reply.status {
        200 if is_json(reply) => Verdict::Ok,
        200 | 203 | 301 | 302 | 303 | 307 | 308 | 401 => Verdict::Rejected,
        403 => Verdict::Forbidden(message_of(reply)),
        404 => Verdict::NotFound,
        429 => limited(now_ms, backoff_ms(strikes), false),
        other => Verdict::Other(other),
    }
}

fn is_json(reply: &ApiReply) -> bool {
    reply
        .header("content-type")
        .is_some_and(|t| t.to_ascii_lowercase().contains("json"))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    const NOW: u64 = 1_700_000_000_000;

    fn reply(status: u16, headers: &[(&str, &str)], body: &str) -> ApiReply {
        ApiReply {
            status,
            headers: headers
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect::<BTreeMap<_, _>>(),
            body: body.as_bytes().to_vec(),
        }
    }

    const SECONDARY: &str = r#"{"message":"You have exceeded a secondary rate limit. Please wait a few minutes before you try again.","documentation_url":"https://docs.github.com/rest/overview/rate-limits-for-the-rest-api#about-secondary-rate-limits"}"#;
    const PRIMARY: &str = r#"{"message":"API rate limit exceeded for user ID 1.","documentation_url":"https://docs.github.com/rest/overview/resources-in-the-rest-api#rate-limiting"}"#;

    #[test]
    fn the_wait_doubles_from_a_minute_up_to_an_hour() {
        let waits: Vec<u64> = (1..=9).map(|n| backoff_ms(n) / 1000).collect();
        assert_eq!(waits, [60, 120, 240, 480, 960, 1920, 3600, 3600, 3600]);
        assert_eq!(backoff_ms(0), 60_000);
    }

    #[test]
    fn github_success_and_plain_errors() {
        assert_eq!(github(&reply(200, &[], "[]"), NOW, 1), Verdict::Ok);
        assert_eq!(github(&reply(401, &[], "{}"), NOW, 1), Verdict::Rejected);
        assert_eq!(github(&reply(404, &[], "{}"), NOW, 1), Verdict::NotFound);
        assert_eq!(github(&reply(500, &[], "{}"), NOW, 1), Verdict::Other(500));
    }

    #[test]
    fn a_github_secondary_limit_with_retry_after_waits_that_long() {
        let r = reply(403, &[("retry-after", "90")], SECONDARY);
        assert_eq!(
            github(&r, NOW, 1),
            Verdict::Limited {
                until_ms: NOW + 90_000,
                primary: false
            }
        );
    }

    #[test]
    fn a_retry_after_shorter_than_the_back_off_after_repeats_is_not_trusted_alone() {
        // Third limit in a row: the back-off is 240 s, so half of it (120 s) is the floor.
        let r = reply(429, &[("retry-after", "5")], SECONDARY);
        assert_eq!(
            github(&r, NOW, 3),
            Verdict::Limited {
                until_ms: NOW + 120_000,
                primary: false
            }
        );
    }

    #[test]
    fn a_github_primary_limit_waits_for_the_reset() {
        let r = reply(
            403,
            &[
                ("x-ratelimit-remaining", "0"),
                ("x-ratelimit-reset", "1700000600"),
            ],
            PRIMARY,
        );
        assert_eq!(
            github(&r, NOW, 1),
            Verdict::Limited {
                until_ms: 1_700_000_600_000,
                primary: true
            }
        );
        // A reset already in the past still waits a second.
        let past = reply(
            429,
            &[
                ("x-ratelimit-remaining", "0"),
                ("x-ratelimit-reset", "1600000000"),
            ],
            "",
        );
        assert_eq!(
            github(&past, NOW, 1),
            Verdict::Limited {
                until_ms: NOW + 1000,
                primary: true
            }
        );
    }

    #[test]
    fn a_secondary_limit_without_headers_waits_the_back_off() {
        let r = reply(403, &[], SECONDARY);
        assert_eq!(
            github(&r, NOW, 1),
            Verdict::Limited {
                until_ms: NOW + 60_000,
                primary: false
            }
        );
        assert_eq!(
            github(&r, NOW, 2),
            Verdict::Limited {
                until_ms: NOW + 120_000,
                primary: false
            }
        );
        // A bare 429 is a limit too, whatever it says.
        assert_eq!(
            github(&reply(429, &[], "<html>"), NOW, 1),
            Verdict::Limited {
                until_ms: NOW + 60_000,
                primary: false
            }
        );
    }

    #[test]
    fn a_github_403_that_is_not_a_limit_is_a_refusal_with_the_hosts_words() {
        let r = reply(
            403,
            &[("x-ratelimit-remaining", "4000")],
            r#"{"message":"Resource protected by organization SAML enforcement.\u0007"}"#,
        );
        assert_eq!(
            github(&r, NOW, 1),
            Verdict::Forbidden(Some(
                "Resource protected by organization SAML enforcement.".to_owned()
            ))
        );
        assert_eq!(
            github(&reply(403, &[], "not json"), NOW, 1),
            Verdict::Forbidden(None)
        );
        assert_eq!(
            github(&reply(403, &[], r#"{"message":"  "}"#), NOW, 1),
            Verdict::Forbidden(None)
        );
    }

    #[test]
    fn a_hosts_message_is_cut_short() {
        let long = format!(r#"{{"message":"{}"}}"#, "x".repeat(500));
        assert_eq!(
            message_of(&reply(403, &[], &long)).unwrap().len(),
            MESSAGE_CHARS
        );
    }

    #[test]
    fn a_success_that_spent_the_budget_blocks_until_the_reset() {
        let spent = reply(
            200,
            &[
                ("x-ratelimit-remaining", "0"),
                ("x-ratelimit-reset", "1700003600"),
            ],
            "[]",
        );
        assert_eq!(github_spent(&spent), Some(1_700_003_600_000));
        let some = reply(200, &[("x-ratelimit-remaining", "12")], "[]");
        assert_eq!(github_spent(&some), None);
        assert_eq!(github_spent(&reply(200, &[], "[]")), None);
        let no_reset = reply(200, &[("x-ratelimit-remaining", "0")], "[]");
        assert_eq!(github_spent(&no_reset), None);
    }

    #[test]
    fn azure_devops_takes_its_sign_in_page_for_a_rejected_token() {
        let json = [("content-type", "application/json; charset=utf-8")];
        assert_eq!(azure(&reply(200, &json, "{}"), NOW, 1), Verdict::Ok);
        let html = [("content-type", "text/html; charset=utf-8")];
        assert_eq!(
            azure(&reply(200, &html, "<html>"), NOW, 1),
            Verdict::Rejected
        );
        assert_eq!(
            azure(&reply(203, &html, "<html>"), NOW, 1),
            Verdict::Rejected
        );
        assert_eq!(azure(&reply(302, &[], ""), NOW, 1), Verdict::Rejected);
        assert_eq!(azure(&reply(401, &[], ""), NOW, 1), Verdict::Rejected);
        assert_eq!(azure(&reply(200, &[], "{}"), NOW, 1), Verdict::Rejected);
    }

    #[test]
    fn azure_devops_refusals_and_limits() {
        assert_eq!(
            azure(&reply(403, &[], r#"{"message":"TF401444: no"}"#), NOW, 1),
            Verdict::Forbidden(Some("TF401444: no".to_owned()))
        );
        assert_eq!(azure(&reply(404, &[], ""), NOW, 1), Verdict::NotFound);
        assert_eq!(azure(&reply(500, &[], ""), NOW, 1), Verdict::Other(500));
        assert_eq!(
            azure(&reply(429, &[("retry-after", "30")], ""), NOW, 1),
            Verdict::Limited {
                until_ms: NOW + 30_000,
                primary: false
            }
        );
        assert_eq!(
            azure(&reply(429, &[], ""), NOW, 2),
            Verdict::Limited {
                until_ms: NOW + 120_000,
                primary: false
            }
        );
        // A Retry-After on a success is the host being polite, not a limit.
        let json = [("content-type", "application/json"), ("retry-after", "30")];
        assert_eq!(azure(&reply(200, &json, "{}"), NOW, 1), Verdict::Ok);
    }
}
