// SPDX-License-Identifier: GPL-3.0-or-later
//! The control server: a second loopback listener next to the API, so a test or a developer can
//! change what the page sees while it is open. It exists only in the fixture; the product has
//! nothing like it. It takes the same bearer token as the API.
//!
//! | Request | Does |
//! |---|---|
//! | `GET /control/state` | `{scenario, now_ms, pending, scripts}` |
//! | `POST /control/emit` (an event, `{"type": ...}`) | puts it on the SSE stream |
//! | `POST /control/advance {"ms": n}` | moves the clock, sweeps what expired |
//! | `POST /control/step` (a [`Step`]) | does one step |
//! | `POST /control/script/{name}` | runs a script of the scenario (404 if it has none) |
//! | `POST /control/restart` | ends open event streams and serves again, same data |
//! | `POST /control/reset` (optional `{"scenario": "<built-in name>"}`) | starts over |

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use puddle_types::{Event, EventSink};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use super::{Fixture, Step, load_scenario};

/// `GET /control/state`.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControlState {
    /// The running scenario's name.
    pub scenario: String,
    /// The fixture clock (epoch ms).
    pub now_ms: u64,
    /// Requests waiting for a decision.
    pub pending: usize,
    /// Scripts the scenario has.
    pub scripts: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Advance {
    ms: u64,
}

#[derive(Debug, Default, Deserialize)]
struct Reset {
    #[serde(default)]
    scenario: Option<String>,
}

/// Starts the control server on `127.0.0.1:<port>` (0 picks one).
///
/// # Errors
///
/// A readable message if the port can't be bound.
pub async fn serve(
    fixture: Arc<Fixture>,
    port: u16,
) -> Result<(SocketAddr, JoinHandle<()>), String> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port))
        .await
        .map_err(|err| format!("cannot listen on 127.0.0.1:{port}: {err}"))?;
    let addr = listener.local_addr().map_err(|err| err.to_string())?;
    let app = Router::new()
        .route("/control/state", get(state))
        .route("/control/emit", post(emit))
        .route("/control/advance", post(advance))
        .route("/control/step", post(step))
        .route("/control/script/{name}", post(script))
        .route("/control/restart", post(restart))
        .route("/control/reset", post(reset))
        .layer(middleware::from_fn_with_state(fixture.clone(), authorised))
        .with_state(fixture);
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok((addr, task))
}

async fn authorised(
    State(fixture): State<Arc<Fixture>>,
    headers: HeaderMap,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    let presented = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    match presented {
        Some(token) if fixture.token().matches(token.as_bytes()) => next.run(request).await,
        _ => (StatusCode::UNAUTHORIZED, "token required").into_response(),
    }
}

fn failed(message: String) -> Response {
    (StatusCode::UNPROCESSABLE_ENTITY, message).into_response()
}

fn done(result: Result<(), String>) -> Response {
    result.map_or_else(failed, |()| StatusCode::NO_CONTENT.into_response())
}

async fn state(State(fixture): State<Arc<Fixture>>) -> Json<ControlState> {
    Json(ControlState {
        scenario: fixture.scenario_name().await,
        now_ms: fixture.now_ms().await,
        pending: fixture.pending_count().await,
        scripts: fixture.script_names().await,
    })
}

async fn emit(State(fixture): State<Arc<Fixture>>, Json(event): Json<Event>) -> Response {
    fixture.event_sink().await.emit(event);
    StatusCode::NO_CONTENT.into_response()
}

async fn advance(State(fixture): State<Arc<Fixture>>, Json(body): Json<Advance>) -> Response {
    done(fixture.apply(&Step::Advance { ms: body.ms }).await)
}

async fn step(State(fixture): State<Arc<Fixture>>, Json(step): Json<Step>) -> Response {
    done(fixture.apply(&step).await)
}

async fn script(State(fixture): State<Arc<Fixture>>, Path(name): Path<String>) -> Response {
    match fixture.run_script(&name).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, format!("no script {name:?}")).into_response(),
        Err(err) => failed(err),
    }
}

async fn restart(State(fixture): State<Arc<Fixture>>) -> Response {
    done(fixture.restart().await)
}

async fn reset(State(fixture): State<Arc<Fixture>>, body: Bytes) -> Response {
    // No body means "the running scenario again".
    let body: Reset = if body.is_empty() {
        Reset::default()
    } else {
        match serde_json::from_slice(&body) {
            Ok(body) => body,
            Err(err) => return failed(err.to_string()),
        }
    };
    let scenario = match body.scenario {
        Some(name) => match load_scenario(&name) {
            Ok(scenario) => Some(scenario),
            Err(err) => return failed(err),
        },
        None => None,
    };
    done(fixture.reset(scenario).await)
}
