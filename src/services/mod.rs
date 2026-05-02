use std::time::Duration;

use http_body_util::BodyExt;
use hyper::StatusCode;
use tower::{ServiceBuilder, ServiceExt};
use tower_http::{timeout::TimeoutLayer, trace::TraceLayer};
use tracing::info;

use crate::{
    config::PortoConfig,
    services::cache::ResponseCacheLayer,
    utils::{HyperService, PeerTable},
};

mod cache;
mod health;
mod proxy;
mod upstream;
mod upstream2;

fn setup_service(config: &PortoConfig) -> HyperService {
    let table = PeerTable::init(config);
    info!("initialized domains {table}");

    let service = ServiceBuilder::new()
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(20),
        ));

    service
        .service(upstream::UpstreamService::new(table))
        .map_response(|resp| resp.map(|body| body.boxed()))
        .boxed_clone()
}

pub fn setup_service2(config: &PortoConfig) -> HyperService {
    let table = PeerTable::init(config);
    info!("initialized domains {table}");

    let middleware = ServiceBuilder::new()
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(20),
        ))
        .layer(ResponseCacheLayer::new());

    let proxy = proxy::setup_proxy_service(table);

    middleware
        .service(proxy)
        .map_response(|resp| resp.map(|body| body.boxed()))
        .boxed_clone()
}
