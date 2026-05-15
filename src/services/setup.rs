use std::time::Duration;

use http_body_util::BodyExt;
use hyper::StatusCode;
use tower::{ServiceBuilder, ServiceExt, layer::layer_fn, util::option_layer};
use tower_http::{
    catch_panic::CatchPanicLayer,
    compression::{Compression, CompressionLayer},
    limit::{RequestBodyLimit, RequestBodyLimitLayer},
    timeout::TimeoutLayer,
    trace::TraceLayer,
};

use crate::{
    config::PortoConfig,
    services::{
        HealthServiceConfig,
        addr::AddrServiceLayer,
        cache::ResponseCacheLayer,
        ratelimit::{RateLimitLayer, RateLimiter},
        req_validation::ReqValidationLayer,
        setup_health_service,
        upstream::{
            connection_table::{ConnectionConfig, ConnectionService},
            hyper_client,
        },
    },
    utils::{HyperService, PeerTable, handle_panic},
};

pub fn setup_service(config: &PortoConfig) -> HyperService {
    let table = PeerTable::init(config);

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
        .map_response(|resp| resp.map(|body| body.boxed_unsync()))
        .map_err(anyhow::Error::from_boxed) // boxerror doesnt work and i cant figure out why
        .boxed_clone()
}

pub fn setup_service4(config: &PortoConfig) -> HyperService {
    let peers = PeerTable::init(config);

    if config.service.health {
        setup_health_service(HealthServiceConfig::default(), peers.clone());
    } else {
        // TODO: account for missing health service in peer table
    }

    ServiceBuilder::new()
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(20),
        ))
        .layer(CatchPanicLayer::custom(handle_panic))
        .layer(RateLimitLayer::new())
        .layer(ReqValidationLayer::new())
        .layer(RequestBodyLimitLayer::new(4096))
        .layer_fn(|svc| Compression::new(svc).gzip(true))
        .layer(AddrServiceLayer::new(peers))
        .layer(option_layer(
            config.service.cache.then(|| ResponseCacheLayer::new(1024)),
        ))
        .service(ConnectionService::new(ConnectionConfig::default()))
        // using a BoxError breaks the whole thing and i cant figure out why
        .map_err(anyhow::Error::from_boxed)
        .map_response(|resp: http::Response<_>| resp.map(|body| body.boxed_unsync()))
        .boxed_clone()
}
