use std::time::{Duration, Instant};

use anyhow::anyhow;
use http_body_util::BodyExt;
use hyper::StatusCode;
use tower::{ServiceBuilder, ServiceExt};
use tower_http::{compression::CompressionLayer, timeout::TimeoutLayer, trace::TraceLayer};
use tracing::info;

use crate::{
    config::PortoConfig,
    services::{addr::AddrServiceLayer, cache::ResponseCacheLayer},
    utils::{HyperService, PeerTable},
};
use proxy::*;

mod addr;
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
        .map_err(|e| (*Box::new(e)).into())
        .boxed_clone()
}

pub fn setup_service2(config: &PortoConfig) -> HyperService {
    let table = PeerTable::init(config);
    info!("initialized domains {table}");

    let connector = ServiceBuilder::new()
        .concurrency_limit(10) // limits the amount of in-flight handshakes
        .service(PeerConnector::new(32));

    let cache = hyper_util::client::pool::cache::builder()
        .executor(hyper_util::rt::TokioExecutor::new())
        .build(connector);

    let mut worker_clone = cache.clone();

    // background worker to time out idle connections
    tokio::spawn(async move {
        let mut timeout_check = tokio::time::interval(Duration::from_secs(30));
        let idle_dur = Duration::from_secs(20);

        loop {
            timeout_check.tick().await;
            let now = Instant::now();
            worker_clone.retain(|sender| {
                if sender.sender.is_closed() {
                    return false;
                }
                now < sender.last_used + idle_dur
            });
        }
    });

    let tower = ServiceBuilder::new()
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(20),
        ))
        .layer(CompressionLayer::new())
        .layer(AddrServiceLayer::new(table))
        .layer(ResponseCacheLayer::new())
        .service(ConnectorPool::new(cache));

    tower
        .map_response(|resp| resp.map(|body| body.boxed()))
        .map_err(|e| anyhow::Error::from_boxed(e))
        .boxed_clone()
}
