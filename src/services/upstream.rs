use std::future::{Ready, ready};
use std::net::SocketAddr;
use std::task::ready;

use addr::domain;
use anyhow::{Result, anyhow};
use http_body_util::BodyExt;
use hyper::StatusCode;
use hyper::body::Incoming;
use hyper::{Request, Response, Uri};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::connect::dns::Name;
use hyper_util::client::legacy::{Client, ResponseFuture};
use hyper_util::rt::TokioTimer;
use hyperlocal::UnixConnector;
use hyperlocal::Uri as UdsUri;
use pin_project_lite::pin_project;
use tokio::net::{TcpStream, UnixStream};
use tokio::time::Instant;
use tower::{BoxError, Service};
use tracing::{debug, error};

use crate::services::connector::UpstreamConnector;
use crate::utils::*;

/*
 * this upstream service uses hyper's client to talk to peers
 */

pub fn setup_uds_client() -> Client<UnixConnector, Incoming> {
    Client::builder(hyper_util::rt::TokioExecutor::new())
        .pool_idle_timeout(std::time::Duration::from_secs(30))
        .pool_timer(TokioTimer::new())
        .pool_max_idle_per_host(40)
        .build(UnixConnector)
}

pub fn setup_tcp_client(domains: PeerTable) -> Client<HttpConnector<UpstreamResolver>, Incoming> {
    let mut connector = HttpConnector::new_with_resolver(UpstreamResolver::new(domains));
    connector.set_nodelay(true);

    Client::builder(hyper_util::rt::TokioExecutor::new())
        .pool_idle_timeout(std::time::Duration::from_secs(30))
        .pool_timer(TokioTimer::new())
        .pool_max_idle_per_host(40)
        .build(connector)
}

pub fn setup_client() -> Client<UpstreamConnector, Incoming> {
    Client::builder(hyper_util::rt::TokioExecutor::new())
        .pool_idle_timeout(std::time::Duration::from_secs(30))
        .pool_timer(TokioTimer::new())
        .pool_max_idle_per_host(40)
        .build(UpstreamConnector::new())
}

#[derive(Debug, Clone)]
pub struct UpstreamService {
    client: Client<UpstreamConnector, Incoming>,
}

impl UpstreamService {
    pub fn new() -> Self {
        debug!("new upstream service");
        Self {
            client: setup_client(),
        }
    }
}

impl Service<Request<Incoming>> for UpstreamService {
    type Response = Response<Body>;
    type Error = BoxError;
    type Future = UpstreamResponseFuture;

    fn poll_ready(
        &mut self,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Incoming>) -> Self::Future {
        let client = self.client.clone();

        UpstreamResponseFuture {
            f: client.request(req),
        }
    }
}

pin_project! {
    pub struct UpstreamResponseFuture {
        #[pin]
        f: ResponseFuture
    }
}

impl Future for UpstreamResponseFuture {
    type Output = Result<Response<Body>, BoxError>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.project();

        let t = Instant::now();
        let r = match ready!(this.f.poll(cx)) {
            Ok(resp) => {
                debug!(
                    elapsed_ms = t.elapsed().as_millis(),
                    "forwarded message time"
                );
                Ok(resp.map(|r| r.map_err(Into::into).boxed()))
            }
            Err(e) => {
                error!(?e, "couldnt send request");
                Ok(response(StatusCode::INTERNAL_SERVER_ERROR))
            }
        };
        std::task::Poll::Ready(r)
    }
}

pin_project! {
    struct UpstreamFuture {
        #[pin]
        fut: ResponseFuture,
        now: Instant,
    }
}

impl Future for UpstreamFuture {
    type Output = core::result::Result<Response<Incoming>, hyper_util::client::legacy::Error>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.project();

        match this.fut.poll(cx) {
            std::task::Poll::Ready(r) => match r {
                Ok(resp) => {
                    debug!(
                        elapsed_ms = this.now.elapsed().as_millis(),
                        "forwarded message time"
                    );
                    std::task::Poll::Ready(Ok(resp))
                }
                Err(e) => {
                    error!(%e, "couldnt send request");
                    std::task::Poll::Ready(Err(e))
                }
            },
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

#[derive(Clone)]
pub struct UpstreamResolver {
    peers: PeerTable,
}

impl UpstreamResolver {
    fn new(domains: PeerTable) -> Self {
        UpstreamResolver { peers: domains }
    }
}

impl Service<Name> for UpstreamResolver {
    type Response = std::iter::Once<SocketAddr>;
    type Error = anyhow::Error;
    type Future = Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(
        &mut self,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Name) -> Self::Future {
        let Some(addr) = self.peers.get_peer_addr(req.as_str()) else {
            error!(name = req.as_str(), "couldnt find addr");
            return ready(Err(anyhow!("couldnt find addr")));
        };
        let resp = match &*addr {
            PeerAddrInner::Ipv4(socket_addr) => {
                debug!(req = req.as_str(), %socket_addr, "resolved address");
                Ok(std::iter::once(*socket_addr))
            }
            PeerAddrInner::Uds(uds_addrs) => {
                error!(addr = %uds_addrs.display(), "UDS address found in resolver");
                Err(anyhow!("found UDS address"))
            }
        };
        ready(resp)
    }
}
