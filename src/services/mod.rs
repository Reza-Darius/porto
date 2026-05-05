use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use anyhow::anyhow;
use http::{Request, Response};
use http_body_util::BodyExt;
use hyper::{
    StatusCode,
    body::Incoming,
    client::conn::http1::{SendRequest as SendRequest1, handshake as handshake1},
    client::conn::http2::{SendRequest as SendRequest2, handshake as handshake2},
};
use hyper_util::{
    client::pool::{map::Map, negotiate::builder, singleton::Singleton},
    rt::{TokioExecutor, TokioIo},
};
use tokio::net::{TcpStream, UnixStream};
use tower::{BoxError, Layer, Service, ServiceBuilder, ServiceExt, layer::layer_fn, service_fn};
use tower_http::{compression::CompressionLayer, timeout::TimeoutLayer, trace::TraceLayer};
use tracing::{debug, info};

use crate::{
    config::PortoConfig,
    services::{
        addr::AddrServiceLayer, cache::ResponseCacheLayer, connection_table::ConnectionService,
    },
    utils::{Body, HyperService, PeerAddr, PeerTable, response},
};
use connector::*;
use proxy::*;

mod addr;
mod cache;
mod connection_table;
mod connector;
mod health;
mod proxy;
mod upstream;
mod upstream2;

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
        .layer(ResponseCacheLayer::new());

    service
        .service(upstream::UpstreamService::new())
        .map_response(|resp| resp.map(|body| body.boxed()))
        .map_err(anyhow::Error::from_boxed)
        .boxed_clone()
}

// pub fn setup_service2(config: &PortoConfig) -> HyperService {
//     let table = PeerTable::init(config);
//     info!("initialized domains {table}");

//     let http1con = ServiceBuilder::new()
//         .concurrency_limit(10) // limits the amount of in-flight handshakes
//         .service(Http1Connector::new(32));

//     let http1_cache = hyper_util::client::pool::cache::builder()
//         .executor(hyper_util::rt::TokioExecutor::new())
//         .build(http1con);

//     let mut worker_clone = http1_cache.clone();

//     // background worker to time out idle connections
//     tokio::spawn(async move {
//         let mut timeout_check = tokio::time::interval(Duration::from_secs(30));
//         let idle_dur = Duration::from_secs(20);

//         loop {
//             timeout_check.tick().await;
//             let now = Instant::now();
//             worker_clone.retain(|sender| {
//                 if sender.sender.is_closed() {
//                     return false;
//                 }
//                 now < sender.last_used + idle_dur
//             });
//         }
//     });

//     // wrapper service to call the connection pool
//     let http1con = service_fn(move |req: Request<_>| {
//         let mut http1_cache = http1_cache.clone();
//         async move {
//             let peer_addr = req
//                 .extensions()
//                 .get()
//                 .cloned()
//                 .ok_or_else(|| anyhow!("PeerAddr extension not found, req: {req:?}"))?;

//             // implement a hashmap with connections here
//             let Ok(mut sender) = http1_cache
//                 .ready() // important to call ready here, otherwise the worker panics
//                 .await?
//                 .call(peer_addr) // call pool
//                 .await
//                 .inspect_err(|e| tracing::error!(%e, "couldnt get sender"))
//             else {
//                 return Ok::<Response<Body>, BoxError>(response(StatusCode::INTERNAL_SERVER_ERROR));
//             };

//             sender.ready().await?.call(req).await.or_else(|e| {
//                 tracing::error!(%e, "sending failed");
//                 Ok(response(StatusCode::INTERNAL_SERVER_ERROR))
//             })
//         }
//     });

//     // building THE tower (tm)
//     let tower = ServiceBuilder::new()
//         .layer(TraceLayer::new_for_http())
//         .layer(TimeoutLayer::with_status_code(
//             StatusCode::REQUEST_TIMEOUT,
//             Duration::from_secs(20),
//         ))
//         .layer(CompressionLayer::new().gzip(true))
//         .layer(AddrServiceLayer::new(table))
//         .layer(ResponseCacheLayer::new())
//         .service(http1con);

//     // erasing types
//     tower
//         .map_response(|resp| resp.map(|body| body.boxed()))
//         .map_response(|resp| {
//             info!("response {resp:?}");
//             resp
//         })
//         .map_err(anyhow::Error::from_boxed)
//         .boxed_clone()
// }

// pub fn setup_service3(config: &PortoConfig) -> HyperService {
//     let table = PeerTable::init(config);
//     info!("initialized domains {table}");

//     let con = service_fn(|addr: PeerAddr| async move {
//         match &*addr.clone() {
//             crate::utils::PeerAddrInner::Ipv4(socket_addr) => {
//                 let stream = TcpStream::connect(socket_addr)
//                     .await
//                     .map_err(Into::<BoxError>::into)?;
//                 Ok::<Upstream, BoxError>(Upstream::Tcp { s: stream })
//             }
//             crate::utils::PeerAddrInner::Uds(path_buf) => {
//                 let stream = UnixStream::connect(path_buf)
//                     .await
//                     .map_err(Into::<BoxError>::into)?;
//                 Ok::<Upstream, BoxError>(Upstream::Uds { s: stream })
//             }
//         }
//     });

//     let http1 = service_fn(|con: Upstream| async move {
//         let io = TokioIo::new(con);
//         let (sender, conn) = handshake1(io).await.map_err(Into::<BoxError>::into)?;
//         tokio::spawn(async move {
//             if let Err(err) = conn.await {
//                 tracing::error!("TCP Connection failed: {err:#}");
//             }
//             tracing::debug!("shutting down TCP connection");
//         });
//         Ok::<SendRequest1<Incoming>, BoxError>(sender)
//     });

//     let http2 = service_fn(|con: Upstream| async move {
//         let io = TokioIo::new(con);
//         let (sender, conn) = handshake2(TokioExecutor::new(), io)
//             .await
//             .map_err(Into::<BoxError>::into)?;
//         tokio::spawn(async move {
//             if let Err(err) = conn.await {
//                 tracing::error!("TCP Connection failed: {err:#}");
//             }
//             tracing::debug!("shutting down TCP connection");
//         });
//         Ok::<SendRequest2<Incoming>, BoxError>(sender)
//     });

//     // let http1con = ServiceBuilder::new()
//     //     .concurrency_limit(10) // limits the amount of in-flight handshakes
//     //     // .service(http1);
//     //     .service(service_fn(move |addr: PeerAddr| async move {
//     //         let upstream = con.clone().call(addr).await.unwrap();
//     //         let sender = http1.clone().call(upstream).await.unwrap();
//     //         Ok::<SendRequest1<Incoming>, BoxError>(sender)
//     //     }));

//     let http1con = ServiceBuilder::new()
//         .concurrency_limit(10) // limits the amount of in-flight handshakes
//         .service(http1);

//     let http1con = hyper_util::client::pool::cache::builder()
//         .executor(hyper_util::rt::TokioExecutor::new())
//         .build(http1con);

//     let http2con = Singleton::new(http2);

//     // let http2con = Singleton::new(service_fn(move |addr: PeerAddr| async move {
//     //     let upstream = con.clone().call(addr).await.unwrap();
//     //     let sender = http2.clone().call(upstream).await.unwrap();
//     //     Ok::<SendRequest2<Incoming>, BoxError>(sender)
//     // }));

//     let pool_layer = layer_fn(|svc| {
//         hyper_util::client::pool::negotiate::builder()
//             .connect(svc)
//             .fallback(http1con.clone())
//             .upgrade(http2con.clone())
//             .inspect(|con| true)
//             .build()
//     });

//     let pool_map = hyper_util::client::pool::map::Map::builder()
//         .keys(|dst: &Request<Incoming>| dst.extensions().get::<PeerAddr>().cloned().unwrap())
//         .values(move |_dst| pool_layer.layer(con.clone()))
//         .build();

//     // // background worker to time out idle connections
//     // tokio::spawn(async move {
//     //     let mut timeout_check = tokio::time::interval(Duration::from_secs(30));
//     //     let idle_dur = Duration::from_secs(20);

//     //     loop {
//     //         timeout_check.tick().await;
//     //         let now = Instant::now();
//     //         worker_clone.retain(|sender| {
//     //             if sender.sender.is_closed() {
//     //                 return false;
//     //             }
//     //             now < sender.last_used + idle_dur
//     //         });
//     //     }
//     // });

//     // // building THE tower (tm)
//     // let tower = ServiceBuilder::new()
//     //     .layer(TraceLayer::new_for_http())
//     //     .layer(TimeoutLayer::with_status_code(
//     //         StatusCode::REQUEST_TIMEOUT,
//     //         Duration::from_secs(20),
//     //     ))
//     //     .layer(CompressionLayer::new().gzip(true))
//     //     .layer(AddrServiceLayer::new(table))
//     //     .layer(ResponseCacheLayer::new())
//     //     .service(con);

//     // // erasing types
//     // tower
//     //     .map_response(|resp| resp.map(|body| body.boxed()))
//     //     .map_response(|resp| {
//     //         info!("response {resp:?}");
//     //         resp
//     //     })
//     //     .map_err(anyhow::Error::from_boxed)
//     //     .boxed_clone()
//     todo!()
// }

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
        .layer(ResponseCacheLayer::new())
        .service(ConnectionService::new());

    // erasing types
    tower
        .map_response(|resp| resp.map(|body| body.boxed()))
        .map_response(|resp| {
            info!("sending {resp:?}");
            resp
        })
        .map_err(anyhow::Error::from_boxed)
        .boxed_clone()
}
