use anyhow::Result;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::{Request, Response};
use hyper::{StatusCode, Version};
use hyper_util::client::legacy::{Client, ResponseFuture};
use hyper_util::rt::TokioTimer;
use hyperlocal::UnixConnector;
use hyperlocal::Uri as UdsUri;
use pin_project_lite::pin_project;
use tokio::time::Instant;
use tower::Service;
use tracing::{debug, error, warn};

use crate::utils::*;

/*
 * this upstream service uses hyper's client to talk to peers
 */

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
    type Error = hyper::Error;
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
                debug!("no host header found on request");
                return Ok(response(StatusCode::BAD_REQUEST));
            };

            // get associated socket name
            let Some(peer_addr) = domain_handle.get_peer_addr(req_host) else {
                debug!(requested_host = %req_host, "coulndnt retrieve socket name");
                return Ok(response(StatusCode::NOT_FOUND));
            };

            let sock_path = match peer_addr {
                PeerAddr::Ipv4(_) => {
                    error!("ipv4 upstream are not supported yet");
                    return Ok(response(StatusCode::INTERNAL_SERVER_ERROR));
                }
                PeerAddr::Uds(socket_addr) => socket_addr,
            };

            adjust_header(&mut req);

            if req.version() == Version::HTTP_2 {
                let (mut parts, body) = req.into_parts();

                parts.version = hyper::Version::HTTP_11;
                parts.uri = UdsUri::new(sock_path, parts.uri.path()).into();
                parts
                    .headers
                    .entry("host")
                    .or_insert("localhost".parse().unwrap());

                req = Request::from_parts(parts, body);
            } else {
                *req.uri_mut() = UdsUri::new(sock_path, req.uri().path()).into();
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
                    Ok(response(StatusCode::INTERNAL_SERVER_ERROR))
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
