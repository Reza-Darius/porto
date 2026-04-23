use anyhow::{Result, anyhow};
use derive_more::{AsRef, Display};
use http_body_util::{BodyExt, Full};
use hyper::header::HOST;
use hyper::{HeaderMap, Request, Response, StatusCode, Version};
use std::ops::Deref;
use std::pin::Pin;
use tokio::net::TcpStream;
use tracing::debug;

use http_body_util::{Empty, combinators::BoxBody};
use hyper::body::Bytes;
use std::sync::Arc;
use tokio::net::unix::UCred;

pub type BoxFut<R, E> = Pin<Box<dyn Future<Output = std::result::Result<R, E>> + Send>>;
pub type Body = BoxBody<Bytes, hyper::Error>;

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

pub fn get_host<B>(req: &Request<B>) -> Result<&str> {
    let header = req.headers();
    match req.version() {
        Version::HTTP_2 => {
            if let Some(host) = header.get(HOST) {
                let host = host
                    .to_str()
                    .ok()
                    .map(|str| {
                        if str.contains(':') {
                            str.split(':').next().unwrap()
                        } else {
                            str
                        }
                    })
                    .unwrap();
                debug!("host header {host}");
                return Ok(host);
            };

            let host = if let Some(host) = req.uri().authority().map(|au| au.as_str()) {
                host
            } else {
                return Err(anyhow!(
                    "no authority or host header found on http2 request"
                ));
            };
            debug!("found host: {host}");
            Ok(host)
        }
        _ => {
            let host = if let Some(host) = header.get(HOST) {
                host.to_str()
                    .ok()
                    .map(|str| {
                        if str.contains(':') {
                            str.split(':').next().unwrap()
                        } else {
                            str
                        }
                    })
                    .unwrap()
            } else {
                return Err(anyhow!("no host field on http1 request"));
            };

            debug!("found host: {host}");
            Ok(host)
        }
    }
}

pub fn strip_header(headers: &mut HeaderMap) {
    use hyper::header;
    headers.remove(header::CONNECTION);
    headers.remove(header::TRANSFER_ENCODING);
    headers.remove(header::TE);
    headers.remove(header::TRAILER);
    headers.remove(header::UPGRADE);
    headers.remove("keep-alive");
    headers.remove("proxy-authenticate");
    headers.remove("proxy-authorization");
}

async fn is_tls(stream: &TcpStream) -> bool {
    let mut peek_buf = [0u8; 1];
    match stream.peek(&mut peek_buf).await {
        Ok(1) => peek_buf[0] == 0x16,
        _ => false,
    }
}

pub struct Domain(String);

impl Deref for Domain {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone, AsRef, Display, Hash)]
pub struct CertPem(String);

impl Deref for CertPem {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone, AsRef, Display, Hash)]
pub struct KeyPem(String);

impl Deref for KeyPem {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone, AsRef, Display, Hash)]
pub struct AcmeToken(String);

impl Deref for AcmeToken {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
