use std::{
    collections::HashMap,
    sync::Arc,
    task::Poll,
    time::{Duration, Instant},
};

use anyhow::anyhow;
use http::{Request, Response, StatusCode};
use http_body_util::Limited;
use hyper::body::Incoming;
use hyper_util::{
    client::pool::{cache, map::Map, singleton::Singleton},
    rt::TokioExecutor,
};
use parking_lot::Mutex;
use tower::{
    BoxError, Service, ServiceBuilder, ServiceExt, layer::layer_fn, service_fn,
    util::BoxCloneService,
};
use tracing::{debug, error};

use super::{
    connector::UpstreamConnector,
    http::{Http1Connect, Http2Connect},
};
use crate::utils::{Body, BoxFut, Peer, PeerAddr, PeerProto, boxfut_err, response};

pub struct ConnectionService<B> {
    table: Arc<Mutex<HashMap<PeerAddr, HttpClient<B>>>>,
    config: Arc<ConnectionConfig>,
}

pub struct ConnectionConfig {
    /// max number of concurrent handshakes
    pub max_http1_in_flight: u16,
    /// max number of connections per client
    pub max_http1_con: u16,

    /// when to drop idle connections
    pub idle_timeout: Duration,
    /// timeout check interval
    pub to_check_int: Duration,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        ConnectionConfig {
            max_http1_in_flight: 10,
            max_http1_con: 32,
            idle_timeout: Duration::from_secs(30),
            to_check_int: Duration::from_secs(30),
        }
    }
}

impl<B> Clone for ConnectionService<B> {
    fn clone(&self) -> Self {
        Self {
            table: self.table.clone(),
            config: self.config.clone(),
        }
    }
}

// TODO: take configuration
impl<B> ConnectionService<B> {
    pub fn new(config: ConnectionConfig) -> Self {
        let table = Arc::new(Mutex::new(HashMap::new()));
        ConnectionService {
            table,
            config: Arc::new(config),
        }
    }
}

impl<B> Service<Request<B>> for ConnectionService<B>
where
    B: hyper::body::Body + Send + 'static + Unpin,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    type Response = Response<Body>;
    type Error = BoxError;
    type Future = BoxFut<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _: &mut std::task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let Some(peer) = req.extensions().get::<Peer>().cloned() else {
            return boxfut_err("no peer address found on request");
        };
        let prot = peer.prot;
        let mut svc = match self.table.lock().entry(peer.addr) {
            std::collections::hash_map::Entry::Occupied(occupied_entry) => {
                debug!(addr = %occupied_entry.key(), "getting client from table");
                occupied_entry.get().clone()
            }
            // initialize a fresh client
            std::collections::hash_map::Entry::Vacant(vacant_entry) => {
                let addr = vacant_entry.key().clone();

                debug!(%addr, "initializing fresh client");

                match prot {
                    crate::utils::PeerProto::Http1 => {
                        vacant_entry.insert(new_http1_client(addr, self)).clone()
                    }
                    crate::utils::PeerProto::Http2 => {
                        vacant_entry.insert(new_http2_client(addr, self)).clone()
                    }
                }
            }
        };
        Box::pin(async move { svc.call(req).await.inspect_err(|e| error!(%e)) })
    }
}

/// calling this service sends a request over HTTP
type HttpClient<B> = BoxCloneService<Request<B>, Response<Body>, BoxError>;

/// register a new HTTP1 client
fn new_http1_client<B>(addr: PeerAddr, pool: &ConnectionService<B>) -> HttpClient<B>
where
    B: hyper::body::Body + Send + 'static + Unpin,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    let handle = pool.table.clone();
    let to_interval = pool.config.to_check_int;
    let to_dur = pool.config.idle_timeout;

    // we use a cache to dynamically open new connections in a pool
    let http1 = ServiceBuilder::new()
        .layer_fn(|svc| {
            hyper_util::client::pool::cache::builder()
                .executor(hyper_util::rt::TokioExecutor::new())
                .build(svc)
        })
        .concurrency_limit(pool.config.max_http1_in_flight as usize) // limits the amount of in-flight handshakes
        .layer_fn(|con| Http1Connect::new(pool.config.max_http1_con as usize, con))
        .service(UpstreamConnector::new());

    let mut worker_clone = http1.clone();

    // background worker to time out idle connections
    tokio::spawn(async move {
        let mut timeout_check = tokio::time::interval(to_interval);

        // the first tick completes instantly
        timeout_check.tick().await;
        loop {
            timeout_check.tick().await;
            if worker_clone.is_empty() {
                debug!(%addr, "removing HTTP1 client");
                handle.lock().remove(&addr);
                return;
            }
            let now = Instant::now();
            worker_clone.retain(|sender| {
                if sender.sender.is_closed() {
                    return false;
                }
                now < sender.last_used + to_dur
            });
        }
    });

    // wrapper service to avoide double service calls and because "Cache" isnt nameable
    let http1 = service_fn(move |req: Request<_>| {
        let mut http1_svc = http1.clone();
        async move {
            debug!("calling connector");
            let peer = req
                .extensions()
                .get::<Peer>()
                .cloned()
                .ok_or_else(|| anyhow!("PeerAddr extension not found"))?;

            let Ok(mut sender) = http1_svc
                .ready() // important to call ready here, otherwise the worker panics
                .await?
                .call(peer.addr) // call pool
                .await
                .inspect_err(|e| tracing::error!(%e, "couldnt get sender"))
            else {
                return Ok::<Response<Body>, BoxError>(response(StatusCode::INTERNAL_SERVER_ERROR));
            };

            debug!("sending request");
            sender.ready().await?.call(req).await.or_else(|e| {
                tracing::error!(%e, "sending failed");
                Ok(response(StatusCode::INTERNAL_SERVER_ERROR))
            })
        }
    });
    http1.boxed_clone()
}

/// register a new HTTP2 client
fn new_http2_client<B>(addr: PeerAddr, pool: &ConnectionService<B>) -> HttpClient<B>
where
    B: hyper::body::Body + Send + 'static + Unpin,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    let handle = pool.table.clone();
    let to_interval = pool.config.to_check_int;
    let to_dur = pool.config.idle_timeout;

    // we use a singleton to multiplex HTTP2 over a single connection
    let http2 = ServiceBuilder::new()
        .layer_fn(Singleton::new)
        .layer_fn(Http2Connect::new)
        .service(UpstreamConnector::new());

    let mut worker_clone = http2.clone();

    // background worker to time out idle connections
    tokio::spawn(async move {
        let mut timeout_check = tokio::time::interval(to_interval);

        // the first tick completes instantly
        timeout_check.tick().await;
        loop {
            timeout_check.tick().await;
            if worker_clone.is_empty() {
                debug!(%addr, "removing HTTP2 client");
                handle.lock().remove(&addr);
                return;
            }
            let now = Instant::now();
            worker_clone.retain(|sender| {
                if sender.sender.is_closed() {
                    return false;
                }
                now < sender.last_used + to_dur
            });
        }
    });

    // wrapper service to avoide double service calls and because "Singleton" isnt nameable
    let http2 = service_fn(move |req: Request<_>| {
        let mut http2_svc = http2.clone();
        async move {
            debug!("calling connector");
            let peer = req
                .extensions()
                .get::<Peer>()
                .cloned()
                .ok_or_else(|| anyhow!("PeerAddr extension not found"))?;

            let Ok(mut sender) = http2_svc
                .ready() // important to call ready here, otherwise the worker panics
                .await?
                .call(peer.addr) // call pool
                .await
                .inspect_err(|e| tracing::error!(%e, "couldnt get sender"))
            else {
                return Ok::<Response<Body>, BoxError>(response(StatusCode::INTERNAL_SERVER_ERROR));
            };

            debug!("sending request");
            sender.ready().await?.call(req).await.or_else(|e| {
                tracing::error!(%e, "sending failed");
                Ok(response(StatusCode::INTERNAL_SERVER_ERROR))
            })
        }
    });
    http2.boxed_clone()
}

// WIP
// fn new_client(config: &ConnectionConfig) -> HttpClient {
//     let http1 = ServiceBuilder::new()
//         .layer(layer_fn(|inner| {
//             cache::builder().executor(TokioExecutor::new()).build(inner)
//         }))
//         .layer_fn(|inner| Http1Connect::new(32, inner))
//         .service(UpstreamConnector::new());

//     let http2 = ServiceBuilder::new()
//         .layer(layer_fn(Singleton::new))
//         .layer_fn(Http2Connect::new)
//         .service(UpstreamConnector::new());

//     let neg_layer = service_fn(move |req: Request<_>| {
//         let mut http1 = http1.clone();
//         let mut http2 = http2.clone();

//         async move {
//             debug!("calling connector");
//             let peer = req
//                 .extensions()
//                 .get::<Peer>()
//                 .cloned()
//                 .ok_or_else(|| anyhow!("PeerAddr extension not found, req: {req:?}"))?;

//             match peer.prot {
//                 PeerProto::Http1 => http1.ready().await?.call(peer.addr).await?.call(req).await,
//                 PeerProto::Http2 => http2.ready().await?.call(peer.addr).await?.call(req).await,
//             }
//         }
//     });

//     let map = Map::builder::<Peer>()
//         .keys(|peer| peer.addr.clone())
//         .values(move |_peer| neg_layer.clone())
//         .build();

//     let map = Arc::new(Mutex::new(map));
//     let worker_clone = map.clone();

//     let to_interval = config.to_check_int;
//     let to_dur = config.idle_timeout;

//     // background worker to time out idle connections
//     tokio::spawn(async move {
//         let mut timeout_check = tokio::time::interval(to_interval);

//         // the first tick completes instantly
//         timeout_check.tick().await;
//         loop {
//             timeout_check.tick().await;
//             let now = Instant::now();
//             worker_clone.lock().retain(|peer, svc| {
//                 // if peer.sender.is_closed() {
//                 //     return false;
//                 // }
//                 // now < peer.last_used + to_dur
//                 true
//             });
//         }
//     });

//     let svc = service_fn(move |req: Request<_>| {
//         let map = map.clone();

//         async move {
//             debug!("calling map");
//             let peer = req
//                 .extensions()
//                 .get::<Peer>()
//                 .ok_or_else(|| anyhow!("PeerAddr extension not found, req: {req:?}"))?;

//             let mut svc = { map.lock().service(peer).clone() };

//             svc.call(req).await
//         }
//     });

//     svc.boxed_clone()
// }
