use std::{
    collections::HashMap,
    sync::Arc,
    task::Poll,
    time::{Duration, Instant},
};

use anyhow::anyhow;
use http::{Request, Response, StatusCode};
use hyper::body::Incoming;
use hyper_util::client::pool::singleton::Singleton;
use parking_lot::Mutex;
use tower::{BoxError, Service, ServiceBuilder, ServiceExt, service_fn, util::BoxCloneService};
use tracing::{debug, error, trace};

use crate::{
    services::{
        connector::UpstreamConnector,
        proxy::{Http1Connector, Http2Connector},
    },
    utils::{Body, BoxFut, Peer, PeerAddr, response},
};

#[derive(Debug, Clone)]
pub struct ConnectionService {
    table: Arc<Mutex<HashMap<PeerAddr, HttpClient>>>,
}

struct PoolConfig {
    max_in_flight: u16,
    max_http1_con: u16,
    max_http2_con: u16,
}

// TODO: take configuration
impl ConnectionService {
    pub fn new() -> Self {
        let table = Arc::new(Mutex::new(HashMap::new()));
        ConnectionService { table }
    }
}

impl Service<Request<Incoming>> for ConnectionService {
    type Response = Response<Body>;
    type Error = BoxError;
    type Future = BoxFut<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _: &mut std::task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Incoming>) -> Self::Future {
        let Some(peer) = req.extensions().get::<Peer>().cloned() else {
            return Box::pin(async {
                Err(anyhow!("Connection Service Error: no PeerAddr found on request").into())
            });
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
                let handle = self.table.clone();

                debug!(%addr, "initializing fresh client");

                match prot {
                    crate::utils::PeerProto::Http1 => {
                        vacant_entry.insert(new_http1_client(addr, handle)).clone()
                    }
                    crate::utils::PeerProto::Http2 => {
                        vacant_entry.insert(new_http2_client(addr, handle)).clone()
                    }
                }
            }
        };
        Box::pin(async move { svc.call(req).await.inspect_err(|e| error!(%e)) })
    }
}

type HttpClient = BoxCloneService<Request<Incoming>, Response<Body>, BoxError>;

fn new_http1_client(
    addr: PeerAddr,
    handle: Arc<Mutex<HashMap<PeerAddr, HttpClient>>>,
) -> HttpClient {
    let http1con = ServiceBuilder::new()
        .concurrency_limit(10) // limits the amount of in-flight handshakes
        .layer_fn(|con| Http1Connector::new(32, con))
        .service(UpstreamConnector::new());

    let http1 = hyper_util::client::pool::cache::builder()
        .executor(hyper_util::rt::TokioExecutor::new())
        .build(http1con);

    let mut worker_clone = http1.clone();

    // background worker to time out idle connections
    tokio::spawn(async move {
        let mut timeout_check = tokio::time::interval(Duration::from_secs(30));
        let idle_dur = Duration::from_secs(20);

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
                now < sender.last_used + idle_dur
            });
        }
    });

    // wrapper service to avoide double service calls and because "Cache" isnt nameable
    let http1con = service_fn(move |req: Request<_>| {
        let mut http1_svc = http1.clone();
        async move {
            debug!("calling connector");
            let peer = req
                .extensions()
                .get::<Peer>()
                .cloned()
                .ok_or_else(|| anyhow!("PeerAddr extension not found, req: {req:?}"))?;

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
    http1con.boxed_clone()
}

fn new_http2_client(
    addr: PeerAddr,
    handle: Arc<Mutex<HashMap<PeerAddr, HttpClient>>>,
) -> HttpClient {
    let http2 = ServiceBuilder::new()
        .layer_fn(Http2Connector::new)
        .service(UpstreamConnector::new());
    let http2 = Singleton::new(http2);

    let mut worker_clone = http2.clone();

    // background worker to time out idle connections
    tokio::spawn(async move {
        let mut timeout_check = tokio::time::interval(Duration::from_secs(30));
        let idle_dur = Duration::from_secs(20);

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
                now < sender.last_used + idle_dur
            });
        }
    });

    // wrapper service to avoide double service calls and because "Singleton" isnt nameable
    let http2con = service_fn(move |req: Request<_>| {
        let mut http2_svc = http2.clone();
        async move {
            debug!("calling connector");
            let peer = req
                .extensions()
                .get::<Peer>()
                .cloned()
                .ok_or_else(|| anyhow!("PeerAddr extension not found, req: {req:?}"))?;

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
    http2con.boxed_clone()
}
