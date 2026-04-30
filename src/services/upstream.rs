use std::future::{Ready, ready};
use std::net::SocketAddr;

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
use tokio::time::Instant;
use tower::Service;
use tracing::{debug, error};

use crate::utils::*;

/*
 * this upstream service uses hyper's client to talk to peers
 */

pub fn setup_uds_client() -> Client<UnixConnector, Incoming> {
    Client::builder(hyper_util::rt::TokioExecutor::new())
        .pool_idle_timeout(std::time::Duration::from_secs(30))
        .pool_timer(TokioTimer::new())
        .pool_max_idle_per_host(32) // Tune based on your backend
        .build(UnixConnector)
}

pub fn setup_tcp_client(domains: UpstreamMap) -> Client<HttpConnector<UpstreamResolver>, Incoming> {
    let resolver = UpstreamResolver { peers: domains };
    let connector = HttpConnector::new_with_resolver(resolver);

    Client::builder(hyper_util::rt::TokioExecutor::new())
        .pool_idle_timeout(std::time::Duration::from_secs(30))
        .pool_timer(TokioTimer::new())
        .pool_max_idle_per_host(32) // Tune based on your backend
        .build(connector)
}

#[derive(Debug, Clone)]
pub struct UpstreamService {
    uds_client: Client<UnixConnector, Incoming>,
    tcp_client: Client<HttpConnector<UpstreamResolver>, Incoming>,
    table: UpstreamMap,
}

impl UpstreamService {
    pub fn new(domains: UpstreamMap) -> Self {
        debug!("new upstream service");
        Self {
            table: domains.clone(),
            uds_client: setup_uds_client(),
            tcp_client: setup_tcp_client(domains),
        }
    }
}

impl Service<Request<Incoming>> for UpstreamService {
    type Response = Response<Body>;
    type Error = hyper::Error;
    type Future = BoxFut<Self::Response, Self::Error>;

    fn poll_ready(
        &mut self,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Incoming>) -> Self::Future {
        let table = self.table.clone();
        let uds_client = self.uds_client.clone();
        let tcp_client = self.tcp_client.clone();

        Box::pin(async move {
            // get host name
            let Ok(req_host) = get_target_host(&req) else {
                debug!("no host header found on request");
                return Ok(response(StatusCode::BAD_REQUEST));
            };

            // get associated socket name
            let Some(peer_addr) = table.get_peer_addr(req_host) else {
                debug!(requested_host = %req_host, "coulndnt retrieve socket name");
                return Ok(response(StatusCode::NOT_FOUND));
            };

            match peer_addr {
                PeerAddr::Uds(socket_addr) => {
                    let upstream_uri = UdsUri::new(socket_addr, req.uri().path()).into();
                    let req = rewrite_request(req, upstream_uri);

                    let t = Instant::now();
                    match uds_client.request(req).await {
                        Ok(resp) => {
                            debug!(
                                elapsed_ms = t.elapsed().as_millis(),
                                "forwarded message time"
                            );
                            Ok(resp.map(|b| b.boxed()))
                        }
                        Err(e) => {
                            error!(?e, "couldnt send request");
                            Ok(response(StatusCode::INTERNAL_SERVER_ERROR))
                        }
                    }
                }
                PeerAddr::Ipv4(_) => {
                    let mut parts = req.uri().clone().into_parts();
                    parts.scheme = Some("http".parse().expect("its hardcoded"));
                    parts.authority = parts
                        .authority
                        .map(|auth| strip_port(auth.as_str()).parse().unwrap());
                    let upstream_uri = Uri::from_parts(parts).unwrap();

                    let req = rewrite_request(req, upstream_uri);

                    let t = Instant::now();
                    match tcp_client.request(req).await {
                        Ok(resp) => {
                            debug!(
                                elapsed_ms = t.elapsed().as_millis(),
                                "forwarded message time"
                            );
                            Ok(resp.map(|b| b.boxed()))
                        }
                        Err(e) => {
                            error!(?e, "couldnt send request");
                            Ok(response(StatusCode::INTERNAL_SERVER_ERROR))
                        }
                    }
                }
            }
        })
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
    peers: UpstreamMap,
}

impl UpstreamResolver {
    fn new(domains: UpstreamMap) -> Self {
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
        let resp = match addr {
            PeerAddr::Ipv4(socket_addr) => {
                debug!(req = req.as_str(), %socket_addr, "resolved address");
                Ok(std::iter::once(*socket_addr))
            }
            PeerAddr::Uds(uds_addrs) => {
                error!(addr = %uds_addrs.display(), "UDS address found in resolver");
                Err(anyhow!("found UDS address"))
            }
        };
        ready(resp)
    }
}
