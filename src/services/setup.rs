use std::time::Duration;

use http_body_util::BodyExt;
use hyper::StatusCode;
use tower::{ServiceBuilder, ServiceExt};
use tower_http::{
    catch_panic::CatchPanicLayer, limit::RequestBodyLimitLayer, normalize_path::NormalizePathLayer,
    timeout::TimeoutLayer, trace::TraceLayer,
};

use crate::{
    config::PortoConfig,
    services::{
        HealthEndpoint, HealthServiceConfig,
        addr::AddrServiceLayer,
        comp::setup_response_compresson,
        ratelimit::RateLimitLayer,
        req_validation::RequestValidationLayer,
        setup_health_service,
        upstream::{connection_table::{ConnectionConfig, ConnectionService}, hyper_client},
    },
    utils::{HyperService, RouteTable, handle_panic},
};

// legacy hyper client implementation
// pub fn setup_service(config: &PortoConfig) -> HyperService {
//     let table = RouteTable::init(config);
//
//     let service = ServiceBuilder::new()
//         .layer(TraceLayer::new_for_http())
//         .layer(TimeoutLayer::with_status_code(
//             StatusCode::REQUEST_TIMEOUT,
//             Duration::from_secs(20),
//         ))
//         .layer(CompressionLayer::new().gzip(true))
//         .layer(AddrServiceLayer::new(table))
//         .layer(ResponseCacheLayer::new(1024));
//
//     service
//         .service(hyper_client::UpstreamService::new())
//         .map_response(|resp| resp.map(|body| body.boxed_unsync()))
//         .map_err(anyhow::Error::from_boxed) // boxerror doesnt work and i cant figure out why
//         .boxed_clone()
// }

pub fn setup_service4(config: &PortoConfig) -> HyperService {
    let peers = RouteTable::init(config);

    setup_health_service(HealthServiceConfig::default(), peers.clone());

    ServiceBuilder::new()
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(20),
        ))
        .layer(CatchPanicLayer::custom(handle_panic))
        .layer_fn(HealthEndpoint::new)
        .layer(RateLimitLayer::new(config.global.limit))
        .layer(RequestValidationLayer::new())
        .layer(RequestBodyLimitLayer::new(4096))
        .layer_fn(setup_response_compresson)
        .layer(NormalizePathLayer::trim_trailing_slash())
        .layer(AddrServiceLayer::new(peers))
        .service(hyper_client::UpstreamService::new())
        // .service(ConnectionService::new(ConnectionConfig::default()))
        // using a BoxError breaks the whole thing and i cant figure out why
        .map_err(anyhow::Error::from_boxed)
        .map_response(|resp: http::Response<_>| resp.map(|body| body.boxed_unsync()))
        .boxed_clone()
}
