use std::{any::Any, time::Duration};

use http::Response;
use http_body_util::BodyExt;
use hyper::StatusCode;
use tower::{ServiceBuilder, ServiceExt};
use tower_http::{
    catch_panic::CatchPanicLayer, compression::CompressionLayer, timeout::TimeoutLayer,
    trace::TraceLayer,
};
use tracing::{debug, info};

use crate::{
    config::PortoConfig,
    services::{
        addr::AddrServiceLayer,
        cache::ResponseCacheLayer,
        upstream::{
            connection_table::{ConnectionConfig, ConnectionService},
            hyper_client,
        },
    },
    utils::{Body, HyperService, PeerTable, empty, internal_error},
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

pub fn setup_service4(config: &PortoConfig, peers: PeerTable) -> HyperService {
    // building THE tower (tm)
    let tower = ServiceBuilder::new()
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(20),
        ))
        .layer(CatchPanicLayer::custom(handle_panic))
        .layer(CompressionLayer::new().gzip(true))
        .layer(AddrServiceLayer::new(peers))
        .layer(ResponseCacheLayer::new(1024))
        .service(ConnectionService::new(ConnectionConfig::default()));

    // erasing types
    tower
        .map_response(|resp| {
            let resp = resp.map(|body| body.boxed_unsync());
            info!("sending {resp:?}");
            resp
        })
        .map_err(anyhow::Error::from_boxed) // boxerror doesnt work and i cant figure out why
        .boxed_clone()
}

fn handle_panic(err: Box<dyn Any + Send + 'static>) -> Response<Body> {
    let details = if let Some(s) = err.downcast_ref::<String>() {
        s.clone()
    } else if let Some(s) = err.downcast_ref::<&str>() {
        s.to_string()
    } else {
        "Unknown panic message".to_string()
    };
    tracing::error!(details);

    internal_error()
}
