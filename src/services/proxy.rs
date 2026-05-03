use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::task::Poll;
use std::time::Instant;

use anyhow::anyhow;
use futures::FutureExt;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::client::conn::http1::SendRequest;
use hyper::client::conn::http2::SendRequest as SendRequest2;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use parking_lot::Mutex;
use tokio::net::{TcpStream, UnixStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Duration;
use tokio_util::sync::PollSemaphore;
use tower::{BoxError, Service, ServiceBuilder, ServiceExt};
use tracing::{debug, error};

use crate::utils::*;

/// wrapper around a connection pool
#[derive(Clone)]
pub struct ProxyService<Cache> {
    pub pool: Cache,
}

impl<Cache> ProxyService<Cache> {
    pub fn new(pool: Cache) -> Self {
        ProxyService { pool }
    }
}

// i apologize that you have to see this, i was unable to make this work any other way because hyper Cache
// is not a namable type
impl<Cache, Sender> Service<Request<Incoming>> for ProxyService<Cache>
where
    // the cache is a service which returns another impl service
    Cache: Service<PeerAddr, Response = Sender> + Send + 'static + Clone,
    Cache::Future: Send + 'static,
    Cache::Error: Into<BoxError>,
    // this is the sender the cache spits out, which itself is another server
    Sender: Service<Request<Incoming>, Response = Response<Body>> + Send + 'static,
    Sender::Future: Send + 'static,
    Sender::Error: Into<BoxError>,
{
    type Response = Response<Body>;
    type Error = BoxError;
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
                .ok_or_else(|| anyhow!("PeerAddr extension not found, req: {req:?}"))?;

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

/// thin service wrapper over a sender
///
/// this is whats being cached
pub struct Http1Sender<B> {
    pub last_used: Instant,
    pub sender: SendRequest<B>,
    _permit: OwnedSemaphorePermit,
    con_id: u16,
}

impl<B> Drop for Http1Sender<B> {
    fn drop(&mut self) {
        debug!(id = self.con_id, "dropping sender");
    }
}

impl Service<Request<Incoming>> for Http1Sender<Incoming> {
    type Response = Response<Body>;
    type Error = BoxError;
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
            debug!(?resp, "response from backend");
            Ok(resp.map(|r| r.map_err(Into::into).boxed()))
        })
    }
}

/// a service to establish a connection to a backend via UDS or TCP
#[derive(Debug)]
pub struct Http1Connector {
    /// number of active connections
    n_connections: Arc<AtomicU16>,
    semaphore: PollSemaphore,
    permit: Option<OwnedSemaphorePermit>,
}

#[allow(clippy::new_without_default)]
impl Http1Connector {
    pub fn new(max_connections: usize) -> Self {
        Http1Connector {
            n_connections: Arc::new(0.into()),
            semaphore: PollSemaphore::new(Arc::new(Semaphore::new(max_connections))),
            permit: None,
        }
    }
}

// clone the connector without an acquired permit
impl Clone for Http1Connector {
    fn clone(&self) -> Self {
        Self {
            n_connections: self.n_connections.clone(),
            semaphore: self.semaphore.clone(),
            permit: None,
        }
    }
}

impl Service<PeerAddr> for Http1Connector {
    type Response = Http1Sender<Incoming>;
    type Error = BoxError;
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

                    Ok(Http1Sender {
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

                    Ok(Http1Sender {
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

/// thin service wrapper over a sender
///
/// this is whats being cached
pub struct Http2Sender<B> {
    pub last_used: Instant,
    pub sender: SendRequest2<B>,
    con_id: u16,
}

impl<B> Clone for Http2Sender<B> {
    fn clone(&self) -> Self {
        Self {
            last_used: self.last_used,
            sender: self.sender.clone(),
            con_id: self.con_id,
        }
    }
}

impl<B> Drop for Http2Sender<B> {
    fn drop(&mut self) {
        debug!(id = self.con_id, "dropping sender");
    }
}

impl Service<Request<Incoming>> for Http2Sender<Incoming> {
    type Response = Response<Body>;
    type Error = BoxError;
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
            debug!(?resp, "response from backend");
            Ok(resp.map(|r| r.map_err(Into::into).boxed()))
        })
    }
}

/// a service to establish a connection to a backend via UDS or TCP
#[derive(Debug)]
pub struct Http2Connector {
    /// number of active connections
    n_connections: Arc<AtomicU16>,
}

#[allow(clippy::new_without_default)]
impl Http2Connector {
    pub fn new(max_connections: usize) -> Self {
        Http2Connector {
            n_connections: Arc::new(0.into()),
        }
    }
}

// clone the connector without an acquired permit
impl Clone for Http2Connector {
    fn clone(&self) -> Self {
        Self {
            n_connections: self.n_connections.clone(),
        }
    }
}

impl Service<PeerAddr> for Http2Connector {
    type Response = Http2Sender<Incoming>;
    type Error = BoxError;
    type Future = BoxFut<Self::Response, Self::Error>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: PeerAddr) -> Self::Future {
        let n_connections = self.n_connections.clone();
        Box::pin(async move {
            debug!(%req, "dialing new upstream connection");

            let t = Instant::now();
            match &*req {
                PeerAddrInner::Ipv4(sock_addr) => {
                    let stream = TokioIo::new(TcpStream::connect(sock_addr).await?);
                    let (sender, conn) =
                        hyper::client::conn::http2::handshake(TokioExecutor::new(), stream).await?;
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

                    Ok(Http2Sender {
                        last_used: Instant::now(),
                        sender,
                        con_id: id,
                    })
                }
                PeerAddrInner::Uds(sock_addr) => {
                    let stream = TokioIo::new(UnixStream::connect(sock_addr).await?);
                    let (sender, conn) =
                        hyper::client::conn::http2::handshake(TokioExecutor::new(), stream).await?;
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

                    Ok(Http2Sender {
                        last_used: Instant::now(),
                        sender,
                        con_id: id,
                    })
                }
            }
        })
    }
}
