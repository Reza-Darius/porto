use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::task::Poll;
use std::time::Instant;

use anyhow::anyhow;
use http::{Uri, Version};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::client::conn::http1::SendRequest;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use pin_project_lite::pin_project;
use tokio::net::{TcpStream, UnixStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Duration;
use tokio_util::sync::PollSemaphore;
use tower::{Service, ServiceBuilder, ServiceExt};
use tracing::{debug, error};

use crate::utils::*;

// pure mental illness following:

// TODO: add some configuration, maybe a bulider

pub fn setup_proxy_service(peers: PeerTable) -> HyperService {
    let connector = ServiceBuilder::new()
        // .concurrency_limit(10) // limits the amount of in-flight handshakes
        .service(PeerConnector::new(5));

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

// i apologize that you have to see this, i couldnt make this any other way because Cache from hyper is
// not a namable type
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

            sender
                .ready()
                .await
                .map_err(Into::into)?
                .call(req)
                .await
                .map_err(Into::into)
                .or_else(|e| {
                    error!(%e, "sending failed");
                    Ok(response(StatusCode::INTERNAL_SERVER_ERROR))
                })
        })
    }
}

/// rewrites the request and attaches PeerAddr for the connector
///
/// if this service fails, it will respond with Ok(http_response)
///
/// however, if the underlying service fails, it will propagate that error
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
    S: Service<Request<B>, Response = Response<Body>> + Send + 'static + Clone,
    B: hyper::body::Body,
    S::Error: Into<anyhow::Error>,
    S::Future: Send + 'static,
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
        let (mut parts, body) = req.into_parts();
        let Some(path_and_query) = parts.uri.path_and_query() else {
            debug!("no path found on request");
            return AddrFuture::Error {
                code: StatusCode::BAD_REQUEST,
            };
        };

        // get host name
        let Some(req_host) = get_host(&parts) else {
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

        // rewriting request

        parts.headers.insert(
            hyper::header::HOST,
            hyper::header::HeaderValue::from_str(req_host).unwrap(),
        );

        if parts.version == Version::HTTP_2 {
            parts.version = Version::HTTP_11;
        }

        parts.uri = Uri::builder()
            .path_and_query(path_and_query.to_owned())
            .build()
            .unwrap();

        debug!(?parts, "rewritten to response");

        let mut req = Request::from_parts(parts, body);

        adjust_header(&mut req);
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
pub struct UpstreamSender<B> {
    pub last_used: Instant,
    pub sender: SendRequest<B>,
    _permit: OwnedSemaphorePermit,
    con_id: u16,
}

impl<B> Drop for UpstreamSender<B> {
    fn drop(&mut self) {
        debug!(id = self.con_id, "dropping sender");
    }
}

impl Service<Request<Incoming>> for UpstreamSender<Incoming> {
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
#[derive(Debug)]
pub struct PeerConnector {
    /// number of active connections
    n_connections: Arc<AtomicU16>,
    semaphore: PollSemaphore,
    permit: Option<OwnedSemaphorePermit>,
}

#[allow(clippy::new_without_default)]
impl PeerConnector {
    pub fn new(max_connections: usize) -> Self {
        PeerConnector {
            n_connections: Arc::new(0.into()),
            semaphore: PollSemaphore::new(Arc::new(Semaphore::new(max_connections))),
            permit: None,
        }
    }
}

// clone the connector without an acquired permit
impl Clone for PeerConnector {
    fn clone(&self) -> Self {
        Self {
            n_connections: self.n_connections.clone(),
            semaphore: self.semaphore.clone(),
            permit: None,
        }
    }
}

impl Service<PeerAddr> for PeerConnector {
    type Response = UpstreamSender<Incoming>;
    type Error = anyhow::Error;
    type Future = BoxFut<Self::Response, Self::Error>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
        // If we haven't already acquired a permit from the semaphore, try to
        // acquire one first.
        if self.permit.is_none() {
            self.permit = std::task::ready!(self.semaphore.poll_acquire(cx));
            debug_assert!(self.permit.is_some(), "semaphore is never closed",);
        }
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: PeerAddr) -> Self::Future {
        // we take a permit and pack it into the sender
        let permit = self
            .permit
            .take()
            .expect("dont call this without calling poll ready first");

        let n_connections = self.n_connections.clone();
        Box::pin(async move {
            debug!(%req, "dialing new upstream connection");

            let t = Instant::now();
            match &*req {
                PeerAddrInner::Ipv4(sock_addr) => {
                    let stream = TokioIo::new(TcpStream::connect(sock_addr).await?);
                    let (sender, conn) = hyper::client::conn::http1::handshake(stream).await?;
                    let id = n_connections.fetch_add(1, Ordering::Relaxed) + 1;

                    tokio::spawn(async move {
                        if let Err(err) = conn.await {
                            error!("TCP Connection failed: {err:#}");
                        }
                        let n = n_connections.fetch_sub(1, Ordering::Relaxed) - 1;
                        debug!(n_con = n, "shutting down TCP connection");
                    });

                    debug!(
                        id = id,
                        elapsed_ms = t.elapsed().as_millis(),
                        "TCP connection established"
                    );

                    Ok(UpstreamSender {
                        last_used: Instant::now(),
                        sender,
                        _permit: permit,
                        con_id: id,
                    })
                }
                PeerAddrInner::Uds(sock_addr) => {
                    let stream = TokioIo::new(UnixStream::connect(sock_addr).await?);
                    let (sender, conn) = hyper::client::conn::http1::handshake(stream).await?;
                    let id = n_connections.fetch_add(1, Ordering::Relaxed) + 1;

                    tokio::spawn(async move {
                        if let Err(err) = conn.await {
                            error!("UDS Connection failed: {err:#}");
                        }
                        let n = n_connections.fetch_sub(1, Ordering::Relaxed) - 1;
                        debug!(n_con = n, "shutting down UDS connection");
                    });

                    debug!(
                        id = id,
                        elapsed_ms = t.elapsed().as_millis(),
                        "UDS connection established"
                    );

                    Ok(UpstreamSender {
                        last_used: Instant::now(),
                        sender,
                        _permit: permit,
                        con_id: id,
                    })
                }
            }
        })
    }
}
