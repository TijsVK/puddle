// SPDX-License-Identifier: GPL-3.0-or-later
//! The API registers its address in the netpolicy endpoint registry while it is bound.

use std::sync::Arc;

use puddle_api::{
    ApiConfig, ApiServer, ApiToken, EventHub, MemorySettings, Services, SettingsRepo,
};
use puddle_netpolicy::{EndpointKind, OwnAddresses, PuddleEndpoints};
use puddle_store::{Limits, ManualClock, Store};

use crate::common::START_MS;

fn services(endpoints: &PuddleEndpoints) -> Services {
    let clock = Arc::new(ManualClock::new(START_MS));
    let store = Arc::new(Store::open_in_memory(clock.clone(), Limits::default()).unwrap());
    Services::new(
        store,
        Arc::new(MemorySettings::default()) as Arc<dyn SettingsRepo>,
        Arc::new(EventHub::default()),
        clock,
    )
    .with_endpoints(endpoints.clone())
}

#[tokio::test]
async fn the_api_is_registered_from_bind_until_it_stops() {
    let endpoints = PuddleEndpoints::new();
    let server = ApiServer::bind(
        ApiConfig::default(),
        ApiToken::generate().unwrap(),
        services(&endpoints),
    )
    .await
    .unwrap();
    let addr = server.local_addr();
    // Bound, not yet serving: already registered.
    assert_eq!(endpoints.list(), [(addr, EndpointKind::Api)]);
    let running = server.spawn();
    assert_eq!(endpoints.find(addr, &OwnAddresses), Some(EndpointKind::Api));
    running.shutdown().await;
    assert_eq!(endpoints.find(addr, &OwnAddresses), None);
}

#[tokio::test]
async fn a_server_that_is_dropped_before_serving_unregisters_too() {
    let endpoints = PuddleEndpoints::new();
    let server = ApiServer::bind(
        ApiConfig::default(),
        ApiToken::generate().unwrap(),
        services(&endpoints),
    )
    .await
    .unwrap();
    assert_eq!(endpoints.list().len(), 1);
    drop(server);
    assert_eq!(endpoints.list().len(), 0);
}
