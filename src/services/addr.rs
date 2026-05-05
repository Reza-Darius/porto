use std::{str::FromStr, task::Poll};

use anyhow::anyhow;
use http::{Uri, Version, uri::Authority};
use hyper::{Request, Response, StatusCode};
use hyperlocal::Uri as UdsUri;
use pin_project_lite::pin_project;
use tower::{BoxError, Service};
use tracing::debug;

use crate::utils::*;

/// rewrites the request and attaches PeerAddr for the connector
///
/// if this service fails, it will respond with Ok(http_response)
///
/// however, if the underlying service fails, it will propagate that error
#[derive(Clone)]
pub struct AddrService<S> {
    table: PeerTable,
    inner: S,
}

impl<S> AddrService<S> {
    pub fn new(peers: PeerTable, inner: S) -> Self {
        AddrService {
            table: peers,
            inner,
        }
    }
}

impl<S, B> Service<Request<B>> for AddrService<S>
where
    S: Service<Request<B>, Response = Response<Body>>,
    B: hyper::body::Body,
    S::Future: Send + 'static,
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

    #[tracing::instrument(skip_all)]
    fn call(&mut self, req: Request<B>) -> Self::Future {
        let (mut parts, body) = req.into_parts();

        let Some(req_host) = get_host(&parts) else {
            debug!("no host header found on request");
            return AddrFuture::Error {
                code: StatusCode::BAD_REQUEST,
            };
        };

        let Some(peer_addr) = self.table.get_peer_addr(req_host) else {
            debug!(requested_host = %req_host, "coulndnt retrieve socket name");
            return AddrFuture::Error {
                code: StatusCode::NOT_FOUND,
            };
        };

        // rewriting request
        if parts.version == Version::HTTP_2 {
            parts.headers.insert(
                hyper::header::HOST,
                hyper::header::HeaderValue::from_str(req_host).unwrap(),
            );
            parts.version = Version::HTTP_11;
        }

        // rewrite URI
        parts.uri = match uri_absolute(&parts, &peer_addr) {
            Ok(uri) => uri,
            Err(e) => {
                tracing::error!(%e, "couldnt create absolute uri");
                return AddrFuture::Error {
                    code: StatusCode::BAD_REQUEST,
                };
            }
        };

        debug!(peer_addr= %peer_addr, ?parts, "rewritten to response");

        let mut req = Request::from_parts(parts, body);

        insert_forward_header(&mut req);
        req.extensions_mut().insert(peer_addr);

        AddrFuture::Service {
            fut: self.inner.call(req),
        }
    }
}

// this is not ideal but compatible with the hyper legacy client
fn uri_absolute(parts: &http::request::Parts, peer_addr: &PeerAddr) -> anyhow::Result<Uri> {
    let path = parts
        .uri
        .path_and_query()
        .cloned()
        .ok_or_else(|| anyhow!("no path found on request"))?;

    let uri = match &**peer_addr {
        PeerAddrInner::Uds(socket_addr) => UdsUri::new(socket_addr, path.as_str()).into(),
        PeerAddrInner::Ipv4(addr) => {
            let authority: Authority = Authority::from_str(&addr.to_string()).unwrap();
            Uri::builder()
                .scheme("http")
                .authority(authority)
                .path_and_query(path)
                .build()
                .unwrap()
        }
    };
    Ok(uri)
}

fn uri_origin(parts: &http::request::Parts) -> anyhow::Result<Uri> {
    let path = parts
        .uri
        .path_and_query()
        .cloned()
        .ok_or_else(|| anyhow!("no path found on request"))?;

    Uri::builder()
        .path_and_query(path)
        .build()
        .map_err(Into::into)
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
    E: Into<BoxError>,
{
    type Output = Result<Response<Body>, BoxError>;

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

#[derive(Debug, Clone)]
pub struct AddrServiceLayer {
    table: PeerTable,
}

impl AddrServiceLayer {
    pub fn new(table: PeerTable) -> Self {
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
