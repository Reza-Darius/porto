use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Instant;

use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::client::conn::http1::SendRequest;
use hyper::client::conn::http2::SendRequest as SendRequest2;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::PollSemaphore;
use tower::{BoxError, Service};
use tracing::{debug, error};

use super::connector::Upstream;
use crate::utils::*;

// this could be a larger int but eh, i dont care that much
static CON_ID: AtomicU16 = AtomicU16::new(0);

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

impl<B> Service<Request<B>> for Http1Sender<B>
where
    B: hyper::body::Body + Send + 'static,
{
    type Response = Response<Body>;
    type Error = BoxError;
    type Future = BoxFut<Self::Response, Self::Error>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
        self.sender.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        self.last_used = Instant::now();
        let f = self.sender.send_request(req);
        Box::pin(async move {
            let resp = f.await?;
            debug!(?resp, "response from backend");
            Ok(resp.map(|r| r.map_err(Into::into).boxed_unsync()))
        })
    }
}

/// a service to establish a connection to a backend via UDS or TCP
#[derive(Debug)]
pub struct Http1Connect<S> {
    /// number of active connections
    n_connections: Arc<AtomicU16>,
    semaphore: PollSemaphore,
    permit: Option<OwnedSemaphorePermit>,
    inner: S,
}

#[allow(clippy::new_without_default)]
impl<S> Http1Connect<S> {
    pub fn new(max_connections: usize, inner: S) -> Self {
        Http1Connect {
            n_connections: Arc::new(0.into()),
            semaphore: PollSemaphore::new(Arc::new(Semaphore::new(max_connections))),
            permit: None,
            inner,
        }
    }
}

// clone the connector without an acquired permit
impl<S: Clone> Clone for Http1Connect<S> {
    fn clone(&self) -> Self {
        Self {
            n_connections: self.n_connections.clone(),
            semaphore: self.semaphore.clone(),
            permit: None,
            inner: self.inner.clone(),
        }
    }
}

impl<S> Service<PeerAddr> for Http1Connect<S>
where
    S: Service<PeerAddr, Response = Upstream> + Clone + Send + 'static,
    S::Error: Into<BoxError>,
    S::Future: Send + 'static,
{
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
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, addr: PeerAddr) -> Self::Future {
        // we take a permit and pack it into the sender
        let permit = self
            .permit
            .take()
            .expect("dont call this without calling poll ready first");
        let n_connections = self.n_connections.clone();
        let mut svc = svc_clone(&mut self.inner);

        Box::pin(async move {
            debug!(%addr, "dialing new upstream connection");

            let t = Instant::now();
            let stream = svc.call(addr).await.map_err(Into::into)?;
            let (sender, conn) =
                hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
            n_connections.fetch_add(1, Ordering::Relaxed);

            tokio::spawn(async move {
                if let Err(err) = conn.await {
                    error!("Connection failed: {err:#}");
                }
                let n = n_connections.fetch_sub(1, Ordering::Relaxed) - 1;
                debug!(active_connections = n, "shutting down connection");
            });

            let id = CON_ID.fetch_add(1, Ordering::Relaxed);

            debug!(
                id = id,
                elapsed_ms = t.elapsed().as_millis(),
                "HTTP1 connection established"
            );

            Ok(Http1Sender {
                last_used: Instant::now(),
                sender,
                _permit: permit,
                con_id: id,
            })
        })
    }
}

/// thin service wrapper over a sender
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

impl<B> Service<Request<B>> for Http2Sender<B>
where
    B: hyper::body::Body + Send + 'static,
{
    type Response = Response<Body>;
    type Error = BoxError;
    type Future = BoxFut<Self::Response, Self::Error>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
        self.sender.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        self.last_used = Instant::now();
        let f = self.sender.send_request(req);
        Box::pin(async move {
            let resp = f.await?;
            debug!(?resp, "response from backend");
            Ok(resp.map(|r| r.map_err(Into::into).boxed_unsync()))
        })
    }
}

/// a service to establish a connection to a backend via UDS or TCP
#[derive(Debug, Clone)]
pub struct Http2Connect<S> {
    /// number of active connections
    n_connections: Arc<AtomicU16>,
    inner: S,
}

#[allow(clippy::new_without_default)]
impl<S> Http2Connect<S> {
    pub fn new(inner: S) -> Self {
        Http2Connect {
            n_connections: Arc::new(0.into()),
            inner,
        }
    }
}

impl<S> Service<PeerAddr> for Http2Connect<S>
where
    S: Service<PeerAddr, Response = Upstream> + Clone + Send + 'static,
    S::Error: Into<BoxError>,
    S::Future: Send + 'static,
{
    type Response = Http2Sender<Incoming>;
    type Error = BoxError;
    type Future = BoxFut<Self::Response, Self::Error>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, addr: PeerAddr) -> Self::Future {
        let n_connections = self.n_connections.clone();
        let mut svc = svc_clone(&mut self.inner);

        Box::pin(async move {
            debug!(%addr, "dialing new upstream connection");

            let t = Instant::now();
            let stream = svc.call(addr).await.map_err(Into::into)?;
            let (sender, conn) =
                hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
                    .await?;
            n_connections.fetch_add(1, Ordering::Relaxed);

            tokio::spawn(async move {
                if let Err(err) = conn.await {
                    error!("Connection failed: {err:#}");
                }
                let n = n_connections.fetch_sub(1, Ordering::Relaxed) - 1;
                debug!(active_connections = n, "shutting down connection");
            });

            let id = CON_ID.fetch_add(1, Ordering::Relaxed);

            debug!(
                id = id,
                elapsed_ms = t.elapsed().as_millis(),
                "HTTP2 connection established"
            );

            Ok(Http2Sender {
                last_used: Instant::now(),
                sender,
                con_id: id,
            })
        })
    }
}
