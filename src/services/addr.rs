use std::task::Poll;

use http::{Uri, Version};
use hyper::{Request, Response, StatusCode};
use pin_project_lite::pin_project;
use tower::Service;
use tracing::debug;

use crate::utils::*;

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

    #[tracing::instrument(skip_all)]
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
