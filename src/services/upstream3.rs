use std::error::Error;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Instant;

use anyhow::anyhow;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::client::conn::http1::SendRequest;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use parking_lot::Mutex;
use tokio::net::{TcpStream, UnixStream};
use tokio::sync::mpsc::Sender;
use tokio::sync::oneshot::{Receiver, channel};
use tokio::time::Duration;
use tower::util::BoxCloneService;
use tower::{Service, ServiceBuilder, ServiceExt};
use tracing::{debug, error};

use crate::utils::*;

// pure mental illness following:

// TODO: add some configuration, maybe a bulider

pub fn setup_upstream_service(domains: UpstreamMap) -> impl Service<Request<Incoming>> {
    let layer = ServiceBuilder::new()
        // limit the amount of in-flight handshakes
        // .concurrency_limit(100)
        .service(ConnectorService::new());

    let cache = hyper_util::client::pool::cache::builder()
        .executor(TokioExecutor::new())
        .build(layer);

    let svc = UpstreamService {
        peers: domains,
        pool: Arc::new(Mutex::new(cache)),
    };
    let worker_clone = svc.pool.clone();

    tokio::spawn(async move {
        let cache = worker_clone;

        let mut timeout_check = tokio::time::interval(Duration::from_secs(30));
        let idle_dur = Duration::from_secs(20);

        loop {
            timeout_check.tick().await;
            let now = Instant::now();
            cache.lock().retain(|sender| {
                if sender.sender.is_closed() {
                    return false;
                }
                now < sender.last_used + idle_dur
            });
        }
    });
    svc
}

#[derive(Clone)]
pub struct UpstreamService<S> {
    pub peers: UpstreamMap,
    pub pool: Arc<Mutex<S>>,
}

impl<S, M> Service<Request<Incoming>> for UpstreamService<S>
where
    S: Service<PeerAddr, Response = M> + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<anyhow::Error> + Send + 'static,
    M: Service<Request<Incoming>, Response = Response<Body>> + Send + 'static,
    M::Future: Send + 'static,
    M::Error: Into<anyhow::Error> + Send + 'static,
{
    type Response = Response<Body>;
    type Error = anyhow::Error;
    type Future = BoxFut<Self::Response, Self::Error>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
        self.pool.lock().poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, req: Request<Incoming>) -> Self::Future {
        let pool = self.pool.clone();
        let table = self.peers.clone();

        Box::pin(async move {
            // get host name
            let Ok(req_host) = get_target_host(&req) else {
                debug!("no host header found on request");
                return Ok(response(StatusCode::BAD_REQUEST));
            };

            // get associated socket name
            let Some(peer_addr) = table.get_peer_addr(req_host).cloned() else {
                debug!(requested_host = %req_host, "coulndnt retrieve socket name");
                return Ok(response(StatusCode::NOT_FOUND));
            };

            let req = match &peer_addr {
                PeerAddr::Uds(socket_addr) => {
                    let upstream_uri = hyperlocal::Uri::new(socket_addr, req.uri().path()).into();
                    rewrite_request(req, upstream_uri)
                }
                PeerAddr::Ipv4(_) => {
                    let mut parts = req.uri().clone().into_parts();
                    debug!(?parts, "request parts");
                    parts.scheme = Some("http".parse().expect("its hardcoded"));
                    parts.authority = parts
                        .authority
                        .map(|auth| strip_port(auth.as_str()).parse().unwrap())
                        .or_else(|| Some(req_host.parse().unwrap()));

                    let upstream_uri = hyper::Uri::from_parts(parts).unwrap();

                    rewrite_request(req, upstream_uri)
                }
            };
            let fut = pool.lock().call(peer_addr);

            let Ok(mut sender) = fut.await.map_err(Into::into) else {
                error!("couldnt get sender");
                return Ok(response(StatusCode::INTERNAL_SERVER_ERROR));
            };

            sender.call(req).await.map_err(Into::into)
        })
    }
}

// pub struct AddrService<S> {
//     peers: UpstreamMap,
//     inner: S,
// }

// impl<S> Service<Request<Incoming>> for AddrService<S>
// where
//     S: Service<PeerAddr>,
// {
//     type Response = Response<B>;
//     type Error;
//     type Future;

//     fn poll_ready(
//         &mut self,
//         cx: &mut std::task::Context<'_>,
//     ) -> std::task::Poll<Result<(), Self::Error>> {
//         todo!()
//     }

//     fn call(&mut self, req: Request<Incoming>) -> Self::Future {
//         todo!()
//     }
// }

pub struct UpstreamSender {
    pub last_used: Instant,
    pub sender: SendRequest<Incoming>,
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

#[derive(Clone, Default, Debug)]
pub struct ConnectorService {
    count: Arc<AtomicU16>,
}

impl ConnectorService {
    pub fn new() -> Self {
        ConnectorService {
            count: Arc::new(0.into()),
        }
    }
}

impl Service<PeerAddr> for ConnectorService {
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
        let count = self.count.clone();
        Box::pin(async move {
            debug!(%req, "dialing new upstream connection");

            let sender = match req {
                PeerAddr::Ipv4(sock_addr) => {
                    let t = Instant::now();

                    let stream = TokioIo::new(TcpStream::connect(sock_addr).await?);
                    let (sender, conn) = hyper::client::conn::http1::handshake(stream).await?;
                    let n = count.fetch_add(1, Ordering::Relaxed) + 1;

                    debug!(
                        n_con = n,
                        elapsed_ms = t.elapsed().as_millis(),
                        "TCP connection established"
                    );

                    tokio::spawn(async move {
                        if let Err(err) = conn.await {
                            error!("TCP Connection failed: {err:#}");
                        }
                        let n = count.fetch_sub(1, Ordering::Relaxed) - 1;
                        debug!(n_con = n, "shutting down TCP connection");
                    });
                    sender
                }
                PeerAddr::Uds(sock_addr) => {
                    let t = Instant::now();

                    let stream = TokioIo::new(UnixStream::connect(sock_addr).await?);
                    let (sender, conn) = hyper::client::conn::http1::handshake(stream).await?;
                    let n = count.fetch_add(1, Ordering::Relaxed) + 1;

                    debug!(
                        n_con = n,
                        elapsed_ms = t.elapsed().as_millis(),
                        "UDS connection established"
                    );

                    tokio::spawn(async move {
                        if let Err(err) = conn.await {
                            error!("UDS Connection failed: {err:#}");
                        }
                        let n = count.fetch_sub(1, Ordering::Relaxed) - 1;
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
