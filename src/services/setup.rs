use std::time::Duration;

use http_body_util::BodyExt;
use hyper::StatusCode;
use tower::{ServiceBuilder, ServiceExt};
use tower_http::{compression::CompressionLayer, timeout::TimeoutLayer, trace::TraceLayer};
use tracing::{debug, info};

use crate::{
    config::PortoConfig,
    services::{
        addr::AddrServiceLayer,
        cache::ResponseCacheLayer,
        upstream::{
            connection_table::{ConnectionService, PoolConfig},
            hyper_client,
        },
    },
    utils::{HyperService, PeerTable},
};

pub fn setup_service(config: &PortoConfig) -> HyperService {
    let table = PeerTable::init(config);
    info!("initialized domains {table}");

    let service = ServiceBuilder::new()
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(20),
        ))
        .layer(CompressionLayer::new().gzip(true))
        .layer(AddrServiceLayer::new(table))
        .layer(ResponseCacheLayer::new(1024));

    service
        .service(hyper_client::UpstreamService::new())
        .map_response(|resp| resp.map(|body| body.boxed()))
        .map_err(anyhow::Error::from_boxed)
        .boxed_clone()
}

pub fn setup_service4(config: &PortoConfig) -> HyperService {
    let table = PeerTable::init(config);
    debug!("initialized domains {table}");

    // building THE tower (tm)
    let tower = ServiceBuilder::new()
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(20),
        ))
        .layer(CompressionLayer::new().gzip(true))
        .layer(AddrServiceLayer::new(table))
        .layer(ResponseCacheLayer::new(1024))
        .service(ConnectionService::new(PoolConfig::default()));

    // erasing types
    tower
        .map_response(|resp| {
            let resp = resp.map(|body| body.boxed());
            info!("sending {resp:?}");
            resp
        })
        .map_err(anyhow::Error::from_boxed)
        .boxed_clone()
}
