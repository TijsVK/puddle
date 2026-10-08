// SPDX-License-Identifier: GPL-3.0-or-later
//! The event hub: puddle's components emit [`Event`]s into it ([`EventSink`]), and every SSE
//! subscriber gets a copy.

use std::convert::Infallible;

use axum::response::sse;
use futures_util::{Stream, StreamExt};
use puddle_types::{Event, EventSink, WorkspaceName};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, watch};
use utoipa::ToSchema;

/// Events buffered per subscriber before the slowest one starts missing some.
pub const DEFAULT_EVENT_BUFFER: usize = 1024;

/// Fans events out to SSE subscribers. Emitting never blocks: with no subscriber the event is
/// dropped, and a subscriber that falls more than the buffer behind gets a [`Lagged`] notice
/// instead of the events it missed.
#[derive(Debug)]
pub struct EventHub {
    tx: broadcast::Sender<Event>,
}

impl EventHub {
    /// A hub buffering `capacity` events per subscriber (at least 1).
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity.max(1));
        Self { tx }
    }

    /// How many SSE streams are open.
    #[must_use]
    pub fn subscribers(&self) -> usize {
        self.tx.receiver_count()
    }

    pub(crate) fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.tx.subscribe()
    }
}

impl Default for EventHub {
    fn default() -> Self {
        Self::new(DEFAULT_EVENT_BUFFER)
    }
}

impl EventSink for EventHub {
    fn emit(&self, event: Event) {
        // `send` fails only when nobody subscribes; then there is nobody to tell.
        let _ = self.tx.send(event);
    }
}

/// Sent on the event stream as `event: lagged` when a subscriber fell behind and events were
/// dropped for it. The client should refetch the state it shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Lagged {
    /// How many events were dropped.
    pub missed: u64,
}

/// Whether a subscriber filtering on `filter` gets `event`. Global events (no workspace) go to
/// every subscriber.
pub(crate) fn wanted(event: &Event, filter: Option<&WorkspaceName>) -> bool {
    wanted_for(event.workspace(), filter)
}

fn wanted_for(workspace: Option<&WorkspaceName>, filter: Option<&WorkspaceName>) -> bool {
    match (filter, workspace) {
        (None, _) | (_, None) => true,
        (Some(want), Some(got)) => want == got,
    }
}

fn to_sse(event: &Event) -> sse::Event {
    sse::Event::default()
        .json_data(event)
        .unwrap_or_else(|err| {
            // An `Event` always serialises; if that ever breaks, say so on the stream rather than
            // ending it.
            tracing::error!(error = %err, "event did not serialise");
            sse::Event::default()
                .event("error")
                .data("event did not serialise")
        })
}

fn lagged(missed: u64) -> sse::Event {
    sse::Event::default()
        .event("lagged")
        .json_data(Lagged { missed })
        .unwrap_or_else(|_| sse::Event::default().event("lagged").data("{}"))
}

/// The SSE stream for one subscriber. It ends when the hub is dropped or the server shuts down.
pub(crate) fn stream(
    rx: broadcast::Receiver<Event>,
    filter: Option<WorkspaceName>,
    mut shutdown: watch::Receiver<bool>,
) -> impl Stream<Item = Result<sse::Event, Infallible>> {
    let events = futures_util::stream::unfold(rx, move |mut rx| {
        let filter = filter.clone();
        async move {
            loop {
                match rx.recv().await {
                    Ok(event) if wanted(&event, filter.as_ref()) => {
                        return Some((Ok(to_sse(&event)), rx));
                    }
                    Ok(_) => {}
                    Err(broadcast::error::RecvError::Lagged(missed)) => {
                        return Some((Ok(lagged(missed)), rx));
                    }
                    Err(broadcast::error::RecvError::Closed) => return None,
                }
            }
        }
    });
    events.take_until(async move {
        // A dropped sender also means "shut down".
        let _ = shutdown.wait_for(|stop| *stop).await;
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use puddle_types::WorkspaceStatus;

    use super::*;

    fn name(s: &str) -> WorkspaceName {
        WorkspaceName::new(s).unwrap()
    }

    fn oom(s: &str) -> Event {
        Event::oom_kill(name(s), 1, "x")
    }

    #[test]
    fn filter_keeps_its_workspace_and_global_events() {
        let a = name("a");
        assert!(wanted(&oom("a"), Some(&a)));
        assert!(!wanted(&oom("b"), Some(&a)));
        assert!(wanted(&oom("b"), None));
        // Global events (`Event::workspace()` is `None`) reach filtered subscribers too. No real
        // global variant exists yet, so the rule is checked on the workspace alone.
        assert!(wanted_for(None, Some(&a)));
        assert!(wanted_for(None, None));
    }

    #[test]
    fn emitting_without_subscribers_is_fine() {
        let hub = EventHub::new(0);
        hub.emit(oom("a"));
        assert_eq!(hub.subscribers(), 0);
        let _rx = hub.subscribe();
        assert_eq!(hub.subscribers(), 1);
    }

    #[tokio::test]
    async fn stream_filters_reports_lag_and_ends_on_shutdown() {
        let hub = EventHub::new(2);
        let (stop, shutdown) = watch::channel(false);
        let mut s = Box::pin(stream(hub.subscribe(), Some(name("a")), shutdown));
        hub.emit(oom("b"));
        hub.emit(Event::StatusChanged {
            workspace: name("a"),
            status: WorkspaceStatus::Running,
        });
        assert!(s.next().await.is_some(), "the status event for a");
        for _ in 0..5 {
            hub.emit(oom("a"));
        }
        // Five events into a buffer of two: the subscriber learns it missed three.
        let next = s.next().await.unwrap().unwrap();
        assert!(format!("{next:?}").contains("lagged"), "{next:?}");
        stop.send(true).unwrap();
        let end = tokio::time::timeout(Duration::from_secs(5), async {
            while s.next().await.is_some() {}
        })
        .await;
        assert!(end.is_ok(), "stream ended on shutdown");
    }

    #[tokio::test]
    async fn stream_ends_when_the_hub_goes() {
        let hub = EventHub::default();
        let (_stop, shutdown) = watch::channel(false);
        let mut s = Box::pin(stream(hub.subscribe(), None, shutdown));
        drop(hub);
        assert!(s.next().await.is_none());
    }
}
