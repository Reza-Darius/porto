use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::task::Poll;
use std::time::Instant;

use anyhow::anyhow;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::client::conn::http1::SendRequest;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use pin_project_lite::pin_project;
use tokio::net::{TcpStream, UnixStream};
use tokio::time::Duration;
use tower::{Service, ServiceBuilder, ServiceExt};
use tracing::{debug, error};

use crate::utils::*;

// pure mental illness following:

// TODO: add some configuration, maybe a bulider

pub fn setup_proxy_service(peers: PeerTable) -> HyperService {
    let connector = ServiceBuilder::new()
        .concurrency_limit(10) // limits the amount of in-flight handshakes
        .service(PeerConnector::new());

    let cache = hyper_util::client::pool::cache::builder()
        .executor(TokioExecutor::new())
        .build(connector);

    let worker_clone = cache.clone();

    // background worker to time out idle connections
    tokio::spawn(async move {
        let mut pool = worker_clone;

        let mut timeout_check = tokio::time::interval(Duration::from_secs(30));
        let idle_dur = Duration::from_secs(20);

        loop {
            timeout_check.tick().await;
            let now = Instant::now();
            pool.retain(|sender| {
                if sender.sender.is_closed() {
                    return false;
                }
                now < sender.last_used + idle_dur
            });
        }
    });
    ServiceBuilder::new()
        .layer_fn(|inner| AddrService::new(peers.clone(), inner))
        .service(PoolService::new(cache))
        .boxed_clone()
}

/// wrapper around a connection pool
#[derive(Clone)]
pub struct PoolService<Cache> {
    pub pool: Cache,
}

impl<Cache> PoolService<Cache> {
    pub fn new(pool: Cache) -> Self {
        PoolService { pool }
    }
}

impl<Cache, Sender> Service<Request<Incoming>> for PoolService<Cache>
where
    // the cache is a service which returns another impl service
    Cache: Service<PeerAddr, Response = Sender> + Send + 'static + Clone,
    Cache::Future: Send + 'static,
    Cache::Error: Into<anyhow::Error>,
    // this is the sender the cache spits out, which itself is another server
    Sender: Service<Request<Incoming>, Response = Response<Body>> + Send + 'static,
    Sender::Future: Send + 'static,
    Sender::Error: Into<anyhow::Error>,
{
    type Response = Response<Body>;
    type Error = anyhow::Error;
    type Future = BoxFut<Self::Response, Self::Error>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
        self.pool.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, req: Request<Incoming>) -> Self::Future {
        let mut pool = self.pool.clone();

        Box::pin(async move {
            let peer_addr = req
                .extensions()
                .get()
                .cloned()
                .ok_or_else(|| anyhow!("PeerAddr extension not found"))?;

            let Ok(mut sender) = pool
                .ready() // important to call ready here, otherwise the worker panics
                .await
                .map_err(Into::into)?
                .call(peer_addr) // call pool
                .await
                .map_err(Into::into)
                .inspect_err(|e| error!(%e, "couldnt get sender"))
            else {
                return Ok(response(StatusCode::INTERNAL_SERVER_ERROR));
            };

            sender.call(req).await.map_err(Into::into).or_else(|e| {
                error!(%e, "sending failed");
                Ok(response(StatusCode::INTERNAL_SERVER_ERROR))
            })
        })
    }
}

/// rewrites the request and attaches PeerAddr for the connector
#[derive(Clone)]
pub struct AddrService<S> {
    peers: PeerTable,
    inner: S,
}

impl<S> AddrService<S> {
    pub fn new(peers: PeerTable, inner: S) -> Self {
        AddrService { peers, inner }
    }
}

impl<S, B> Service<Request<B>> for AddrService<S>
where
    S: Service<Request<B>, Response = Response<Body>>,
    B: hyper::body::Body,
    S::Error: Into<anyhow::Error>,
{
    type Response = S::Response;
    type Error = anyhow::Error;
    type Future = AddrFuture<S::Future>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        // get host name
        let Ok(req_host) = get_target_host(&req) else {
            debug!("no host header found on request");
            return AddrFuture::Error {
                code: StatusCode::BAD_REQUEST,
            };
        };

        // get associated socket name
        let Some(peer_addr) = self.peers.get_peer_addr(req_host) else {
            debug!(requested_host = %req_host, "coulndnt retrieve socket name");
            return AddrFuture::Error {
                code: StatusCode::NOT_FOUND,
            };
        };

        let uri = req.uri().clone();
        let mut req = rewrite_request(req, uri);
        req.extensions_mut().insert(peer_addr);

        AddrFuture::Service {
            fut: self.inner.call(req),
        }
    }
}

pin_project! {
    #[project = EnumProj]
    pub enum AddrFuture<F> {
        Service {#[pin] fut: F},
        Error{code: StatusCode},
    }
}

impl<F, E> Future for AddrFuture<F>
where
    F: Future<Output = Result<Response<Body>, E>>,
    E: Into<anyhow::Error>,
{
    type Output = Result<Response<Body>, anyhow::Error>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.project();
        match this {
            EnumProj::Service { fut } => fut.poll(cx).map_err(Into::into),
            EnumProj::Error { code } => Poll::Ready(Ok(response(*code))),
        }
    }
}

/// thin service wrapper over a sender
pub struct UpstreamSender {
    pub last_used: Instant,
    pub sender: SendRequest<Incoming>,
}

pin_project! {
    struct SenderFuture<F> {
        #[pin]
        inner: F,
    }
}

impl<F> Future for SenderFuture<F>
where
    F: Future<Output = Result<Response<Incoming>, hyper::Error>>,
{
    type Output = Result<Response<Body>, hyper::Error>;

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        this.inner
            .poll(cx)
            .map(|res| res.map(|resp| resp.map(|b| b.boxed())))
    }
}

impl Service<Request<Incoming>> for UpstreamSender {
    type Response = Response<Body>;
    type Error = anyhow::Error;
    type Future = BoxFut<Self::Response, Self::Error>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
        self.sender.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, req: Request<Incoming>) -> Self::Future {
        self.last_used = Instant::now();
        let f = self.sender.send_request(req);
        Box::pin(async move {
            let resp = f.await?;

            Ok(resp.map(|b| b.boxed()))
        })
    }
}

/// a service to establish a connection to a backend via UDS or TCP
#[derive(Clone, Default, Debug)]
pub struct PeerConnector {
    /// number of active connections
    n_connections: Arc<AtomicU16>,
}

impl PeerConnector {
    pub fn new() -> Self {
        PeerConnector {
            n_connections: Arc::new(0.into()),
        }
    }
}

impl Service<PeerAddr> for PeerConnector {
    type Response = UpstreamSender;
    type Error = anyhow::Error;
    type Future = BoxFut<Self::Response, Self::Error>;

    fn poll_ready(
        &mut self,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: PeerAddr) -> Self::Future {
        let n_connections = self.n_connections.clone();
        Box::pin(async move {
            debug!(%req, "dialing new upstream connection");

            let sender = match &*req {
                PeerAddrInner::Ipv4(sock_addr) => {
                    let t = Instant::now();

                    let stream = TokioIo::new(TcpStream::connect(sock_addr).await?);
                    let (sender, conn) = hyper::client::conn::http1::handshake(stream).await?;
                    let n = n_connections.fetch_add(1, Ordering::Relaxed) + 1;

                    debug!(
                        n_con = n,
                        elapsed_ms = t.elapsed().as_millis(),
                        "TCP connection established"
                    );

                    tokio::spawn(async move {
                        if let Err(err) = conn.await {
                            error!("TCP Connection failed: {err:#}");
                        }
                        let n = n_connections.fetch_sub(1, Ordering::Relaxed) - 1;
                        debug!(n_con = n, "shutting down TCP connection");
                    });
                    sender
                }
                PeerAddrInner::Uds(sock_addr) => {
                    let t = Instant::now();

                    let stream = TokioIo::new(UnixStream::connect(sock_addr).await?);
                    let (sender, conn) = hyper::client::conn::http1::handshake(stream).await?;
                    let n = n_connections.fetch_add(1, Ordering::Relaxed) + 1;

                    debug!(
                        n_con = n,
                        elapsed_ms = t.elapsed().as_millis(),
                        "UDS connection established"
                    );

                    tokio::spawn(async move {
                        if let Err(err) = conn.await {
                            error!("UDS Connection failed: {err:#}");
                        }
                        let n = n_connections.fetch_sub(1, Ordering::Relaxed) - 1;
                        debug!(n_con = n, "shutting down UDS connection");
                    });
                    sender
                }
            };
            Ok(UpstreamSender {
                last_used: Instant::now(),
                sender,
            })
        })
    }
}
