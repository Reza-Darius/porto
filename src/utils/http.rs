use std::net::SocketAddr as IpSockAddr;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Result, anyhow};
use http_body_util::Empty;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::header::HOST;
use hyper::header::HeaderValue;
use hyper::{HeaderMap, Request, Response, StatusCode, Uri, Version};
use tap::Pipe;
use tokio::net::unix::{SocketAddr, UCred};
use tracing::debug;
use tracing::trace;

use crate::utils::Body;

// We create some utility functions to make Empty and Full bodies
// fit our broadened Response body type.
pub fn empty() -> Body {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

pub fn full<T: Into<Bytes>>(chunk: T) -> Body {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
struct UdsConnectInfo {
    peer_addr: Arc<tokio::net::unix::SocketAddr>,
    peer_cred: UCred,
}

pub fn setup_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_target(false)
        .init();
}

pub async fn shutdown_signal() {
    // Wait for the CTRL+C signal
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install CTRL+C signal handler");
}

pub fn response(status: StatusCode) -> Response<Body> {
    Response::builder().status(status).body(empty()).unwrap()
}

pub fn bad_request() -> Response<Body> {
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(empty())
        .unwrap()
}

pub fn not_found() -> Response<Body> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(empty())
        .unwrap()
}

pub fn internal_error() -> Response<Body> {
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .body(empty())
        .unwrap()
}

/// retrieves the targeted host from the request
pub fn get_target_host<B>(req: &Request<B>) -> Result<&str> {
    match req.version() {
        Version::HTTP_2 => req
            .uri()
            .authority()
            .map(|au| au.host())
            .inspect(|host| debug!("found host in request: {host}"))
            .ok_or_else(|| anyhow!("no authority or host header found on http2 request")),
        _ => {
            // this works only for origin form
            let host = req
                .headers()
                .get(HOST)
                .ok_or_else(|| anyhow!("no host header on http1 request"))?
                .to_str()?
                .pipe(strip_port);

            debug!("found host in request: {host}");
            Ok(host)
        }
    }
}

/// this only works with ipv4!
pub fn strip_port(input: &str) -> &str {
    input.split(':').next().unwrap_or(input)
}

pub fn adjust_header<B>(req: &mut Request<B>) {
    strip_header(req.headers_mut());

    if let Some(client_addr) = req.extensions().get::<IpSockAddr>().cloned() {
        debug!("adjusting header with {client_addr}");

        if let Ok(addr) = HeaderValue::from_str(&client_addr.to_string()) {
            req.headers_mut().insert("X-Forwarded-For", addr);
        } else {
            tracing::error!("couldnt create header value from sock addr");
        };
    };
}

pub fn strip_header(headers: &mut HeaderMap) {
    use hyper::header;
    trace!("stripping header");

    headers.remove(header::CONNECTION);
    headers.remove(header::TRANSFER_ENCODING);
    headers.remove(header::TE);
    headers.remove(header::TRAILER);
    headers.remove(header::UPGRADE);
    headers.remove("keep-alive");
    headers.remove("proxy-authenticate");
    headers.remove("proxy-authorization");
}

pub fn rewrite_request<B>(mut req: Request<B>, upstream_uri: Uri) -> Request<B> {
    let t = Instant::now();
    adjust_header(&mut req);

    let (mut parts, body) = req.into_parts();

    if parts.version == Version::HTTP_2 {
        parts.version = Version::HTTP_11;
    }

    parts.uri = upstream_uri;

    let host = parts
        .uri
        .authority()
        .map(|a| a.host())
        .unwrap_or("localhost");

    parts.headers.insert(
        hyper::header::HOST,
        hyper::header::HeaderValue::from_str(host).unwrap(),
    );

    debug!(
        elapsed = t.elapsed().as_millis(),
        ?parts,
        "rewritten to response"
    );

    Request::from_parts(parts, body)
}

pub fn extract_remote_add<B>(req: &Request<B>) -> &SocketAddr {
    req.extensions()
        .get()
        .expect("we attach it to every message")
}
