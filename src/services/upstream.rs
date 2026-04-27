use anyhow::Result;
use http_body_util::BodyExt;
use hyper::Version;
use hyper::body::Incoming;
use hyper::{Request, Response};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioTimer;
use hyperlocal::{UnixConnector, Uri};
use tokio::time::Instant;
use tower::Service;
use tracing::{debug, error, warn};

use crate::utils::*;

pub fn setup_client() -> Client<UnixConnector, Incoming> {
    Client::builder(hyper_util::rt::TokioExecutor::new())
        .pool_idle_timeout(std::time::Duration::from_secs(30))
        .pool_timer(TokioTimer::new())
        .pool_max_idle_per_host(32) // Tune based on your backend
        .build(UnixConnector)
}

#[derive(Debug, Clone)]
pub struct UpstreamService {
    upstream_client: Client<UnixConnector, Incoming>,
    domains: UpstreamMap,
}

impl UpstreamService {
    pub fn new(domains: UpstreamMap, client: Client<UnixConnector, Incoming>) -> Self {
        debug!("new upstream service");
        Self {
            domains,
            upstream_client: client,
        }
    }
}

impl Service<Request<Incoming>> for UpstreamService {
    type Response = Response<Body>;
    type Error = std::convert::Infallible;
    type Future = BoxFut<Self::Response, Self::Error>;

    fn poll_ready(
        &mut self,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, mut req: Request<Incoming>) -> Self::Future {
        let domain_handle = self.domains.clone();
        let client = self.upstream_client.clone();

        Box::pin(async move {
            // get host name
            let req_host = if let Ok(host) = get_host(&req) {
                host
            } else {
                warn!("no host header found on request");
                return Ok(bad_request());
            };

            // get associated socket name
            let Some(peer_addr) = domain_handle.get_peer_addr(req_host) else {
                warn!("coulndnt retrieve socket name");
                return Ok(internal_error());
            };

            let sock_path = match peer_addr {
                PeerAddr::Ipv4(_) => unimplemented!("IP upstream is not supported yet"),
                PeerAddr::Uds(socket_addr) => socket_addr
                    .as_pathname()
                    .expect("unnamed sockets arent supported"),
            };

            strip_header(req.headers_mut());

            if req.version() == Version::HTTP_2 {
                let (mut parts, body) = req.into_parts();

                parts.version = hyper::Version::HTTP_11;
                parts.uri = Uri::new(sock_path, parts.uri.path()).into();
                parts
                    .headers
                    .entry("host")
                    .or_insert("localhost".parse().unwrap());

                req = Request::from_parts(parts, body);
            } else {
                *req.uri_mut() = Uri::new(sock_path, req.uri().path()).into();
            }

            let t = Instant::now();
            match client.request(req).await {
                Ok(resp) => {
                    debug!(
                        elapsed_ms = t.elapsed().as_millis(),
                        "forwarded message time"
                    );
                    Ok(resp.map(|b| b.boxed()))
                }
                Err(e) => {
                    error!(?e, "couldnt send request");
                    Ok(internal_error())
                }
            }
        })
    }
}
