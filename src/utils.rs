use anyhow::{Result, anyhow};
use derive_more::{AsRef, Display, Eq, From};
use http_body_util::{BodyExt, Full};
use hyper::header::HOST;
use hyper::{HeaderMap, Request, Response, StatusCode, Version};
use std::borrow::Borrow;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::pin::Pin;
use tokio::net::TcpStream;
use tracing::debug;

use http_body_util::{Empty, combinators::BoxBody};
use hyper::body::Bytes;
use std::os::unix::net::SocketAddr;
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
        // a https "client hello" starts with 0x16
        Ok(1) => peek_buf[0] == 0x16,
        _ => false,
    }
}

/// maps domains to upstream addresses as either UDS or TCP connection
#[derive(Debug, Clone)]
pub struct PeerMap {
    inner: Arc<DomainMapInner>,
}

impl PeerMap {
    pub fn new(domains: &[(impl AsRef<str>, PeerAddr)]) -> Self {
        PeerMap {
            inner: Arc::new(DomainMapInner {
                map: domains
                    .iter()
                    .map(|(domain, addr)| (domain.as_ref().into(), addr.clone()))
                    .collect(),
            }),
        }
    }

    pub fn get_peer_addr(&self, domain: impl AsRef<str>) -> Option<&PeerAddr> {
        self.inner.map.get(domain.as_ref())
    }

    pub fn get_domains(&self) -> impl Iterator<Item = &Domain> {
        self.inner.map.keys()
    }
}

#[derive(Debug)]
struct DomainMapInner {
    map: HashMap<Domain, PeerAddr>,
}

#[derive(Debug, Clone)]
pub enum PeerAddr {
    Ipv4(Ipv4Addr),
    Uds(SocketAddr),
}

#[derive(Debug, Clone, AsRef, Display, Hash, Eq, PartialEq, PartialOrd, Ord, From)]
pub struct Domain(Arc<str>);

impl From<&str> for Domain {
    fn from(value: &str) -> Self {
        Domain(value.into())
    }
}

impl From<String> for Domain {
    fn from(value: String) -> Self {
        Domain(Arc::from(value))
    }
}

impl Borrow<str> for Domain {
    fn borrow(&self) -> &str {
        self.0.borrow()
    }
}

impl Borrow<str> for &Domain {
    fn borrow(&self) -> &str {
        self.0.borrow()
    }
}

#[derive(Debug, Clone, AsRef, Display, Hash, Eq, PartialEq, PartialOrd, Ord, From)]
pub struct CertChainPem(Arc<str>);

impl Borrow<str> for CertChainPem {
    fn borrow(&self) -> &str {
        self.0.borrow()
    }
}

impl From<&str> for CertChainPem {
    fn from(value: &str) -> Self {
        CertChainPem(value.into())
    }
}
impl From<String> for CertChainPem {
    fn from(value: String) -> Self {
        CertChainPem(Arc::from(value))
    }
}

#[derive(Debug, Clone, AsRef, Display, Hash, Eq, PartialEq, PartialOrd, Ord, From)]
pub struct KeyPem(Arc<str>);

impl Borrow<str> for KeyPem {
    fn borrow(&self) -> &str {
        self.0.borrow()
    }
}

impl From<&str> for KeyPem {
    fn from(value: &str) -> Self {
        KeyPem(value.into())
    }
}

impl From<String> for KeyPem {
    fn from(value: String) -> Self {
        KeyPem(Arc::from(value))
    }
}

#[derive(Debug, Clone, AsRef, Display, Hash, Eq, PartialEq, PartialOrd, Ord, From)]
pub struct AcmeToken(Arc<str>);

impl Borrow<str> for AcmeToken {
    fn borrow(&self) -> &str {
        self.0.borrow()
    }
}

impl From<&str> for AcmeToken {
    fn from(value: &str) -> Self {
        AcmeToken(value.into())
    }
}

impl From<String> for AcmeToken {
    fn from(value: String) -> Self {
        AcmeToken(Arc::from(value))
    }
}
