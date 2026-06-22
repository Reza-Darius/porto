use std::task::{Poll, ready};

use http::Version;
use hyper::{Request, Response, StatusCode};
use pin_project_lite::pin_project;
use tower::{BoxError, Service};
use tracing::{debug, error};

use crate::utils::*;

/// rewrites the request and attaches PeerAddr for the connector
///
/// if this service fails, it will respond with Ok(http_response)
///
/// however, if the underlying service fails, it will propagate that error
#[derive(Clone)]
pub struct AddrService<S> {
    table: RouteTable,
    inner: S,
}

#[derive(Debug, Clone)]
pub struct AddrServiceLayer {
    table: RouteTable,
}

impl AddrServiceLayer {
    pub fn new(table: RouteTable) -> Self {
        AddrServiceLayer { table }
    }
}

impl<S> tower::Layer<S> for AddrServiceLayer {
    type Service = AddrService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AddrService {
            inner,
            table: self.table.clone(),
        }
    }
}

impl<S, ReqB> Service<Request<ReqB>> for AddrService<S>
where
    S: Service<Request<ReqB>, Response = Response<Body>>,
    S::Error: Into<BoxError>,
{
    type Response = S::Response;
    type Error = BoxError;
    type Future = AddrFuture<S::Future>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, req: Request<ReqB>) -> Self::Future {
        let (mut parts, body) = req.into_parts();
        debug!(?parts, "rewriting request");

        let Some(req_host) = get_host_from_parts(&parts) else {
            debug!("no host header found on request");

            return AddrFuture::Error {
                code: StatusCode::BAD_REQUEST,
            };
        };

        let Some(peer) = self.table.get_peer(req_host) else {
            // peer might be missing or unreachable
            debug!(requested_host = %req_host, "no peer found");

            return AddrFuture::Error {
                code: StatusCode::NOT_FOUND,
            };
        };

        // overwrite host header in case the upstream expects http1
        if parts.version == Version::HTTP_2 && *peer.prot() == Version::HTTP_11 {
            parts.headers.insert(
                hyper::header::HOST,
                hyper::header::HeaderValue::from_str(req_host).unwrap(),
            );
        }

        // rewrite URI
        // TODO: use origin form when not using hyper client
        parts.uri = match uri_absolute(&parts, peer.addr()) {
            Ok(uri) => uri,
            Err(e) => {
                error!(%e, "couldnt create absolute uri");

                return AddrFuture::Error {
                    code: StatusCode::BAD_REQUEST,
                };
            }
        };

        debug!(peer_addr= %peer.addr(), ?parts, "rewritten to response");

        let mut req = Request::from_parts(parts, body);

        adjust_header(&mut req);

        // we embed the peer in the request for subsequent services
        let client_expect = req.version();
        req.extensions_mut().insert(peer);

        AddrFuture::Service {
            fut: self.inner.call(req),
            client_expect,
        }
    }
}

pin_project! {
    #[project = EnumProj]
    pub enum AddrFuture<F> {
        // the response future and the protocol we need to map it to
        Service {#[pin] fut: F, client_expect: Version},
        Error{code: StatusCode},
    }
}

impl<F, E> Future for AddrFuture<F>
where
    F: Future<Output = Result<Response<Body>, E>>,
    E: Into<BoxError>,
{
    type Output = Result<Response<Body>, BoxError>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.project();
        match this {
            EnumProj::Service { fut, client_expect } => {
                let mut resp = ready!(fut.poll(cx).map_err(Into::into))?;

                // when the client expects HTTP2 but our backend responded with HTTP1
                if resp.version() == Version::HTTP_11 && *client_expect == Version::HTTP_2 {
                    strip_illegal_http2_header(resp.headers_mut());
                }

                Poll::Ready(Ok(resp))
            }
            EnumProj::Error { code } => Poll::Ready(Ok(response(*code))),
        }
    }
}

