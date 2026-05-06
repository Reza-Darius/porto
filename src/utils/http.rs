use std::net::SocketAddr as IpSockAddr;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Result, anyhow};
use http::header;
use http::request::Parts;
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
pub fn get_target_host<B>(req: &Request<B>) -> Option<&str> {
    match req.version() {
        Version::HTTP_2 => req
            .uri()
            .authority()
            .map(|au| au.host())
            .inspect(|host| debug!("found host in request: {host}")),
        _ => {
            // this works only for origin form
            req.headers()
                .get(HOST)
                .and_then(|host| host.to_str().ok())
                .map(strip_port)
                .inspect(|host| debug!("found host in request: {host}"))
        }
    }
}

/// retrieves the targeted host from the request
pub fn get_host_from_parts(parts: &Parts) -> Option<&str> {
    match parts.version {
        Version::HTTP_2 => parts
            .uri
            .authority()
            .map(|au| au.host())
            .inspect(|host| debug!("found host in request: {host}")),
        _ => {
            // this works only for origin form
            parts
                .headers
                .get(HOST)
                .and_then(|host| host.to_str().ok())
                .map(strip_port)
                .inspect(|host| debug!("found host in request: {host}"))
        }
    }
}

/// this only works with ipv4!
pub fn strip_port(input: &str) -> &str {
    input.split(':').next().unwrap_or(input)
}

/// strips and adds header
pub fn adjust_header<B>(req: &mut Request<B>) {
    strip_header(req.headers_mut());
    add_forward_header(req);
}

pub fn strip_illegal_http2_header(headers: &mut HeaderMap) {
    headers.remove(header::UPGRADE);
    headers.remove(header::TRANSFER_ENCODING);
    headers.remove(header::CONNECTION);
    headers.remove("keep-alive");
    headers.remove("proxy-connection");
}

pub fn strip_header(headers: &mut HeaderMap) {
    headers.remove(header::CONNECTION);
    headers.remove(header::TRANSFER_ENCODING);
    headers.remove(header::TE);
    headers.remove(header::TRAILER);
    headers.remove(header::UPGRADE);
    headers.remove("keep-alive");
    headers.remove("proxy-authenticate");
    headers.remove("proxy-authorization");
}

fn add_forward_header<B>(req: &mut Request<B>) {
    if let Some(client_addr) = req.extensions().get::<IpSockAddr>().cloned() {
        debug!("inserted forward header: {client_addr}");

        if let Ok(addr) = HeaderValue::from_str(&client_addr.to_string()) {
            req.headers_mut().insert("X-Forwarded-For", addr);
        } else {
            tracing::error!("couldnt create header value from sock addr");
        };
    };
}
