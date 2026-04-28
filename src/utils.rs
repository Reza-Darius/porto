use std::borrow::Borrow;
use std::collections::HashMap;
use std::fmt::Display;
use std::net::Ipv4Addr;
use std::net::SocketAddr as IpSockAddr;
use std::os::unix::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use addr::parse_domain_name;
use anyhow::{Result, anyhow};
use derive_more::{AsRef, Display, Eq, From};
use http_body_util::{BodyExt, Full};
use http_body_util::{Empty, combinators::BoxBody};
use hyper::body::{Bytes, Incoming};
use hyper::header::HOST;
use hyper::header::HeaderValue;
use hyper::{HeaderMap, Request, Response, StatusCode, Version};
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio::net::unix::UCred;
use tower::util::BoxCloneService;
use tracing::debug;
use tracing::trace;

pub type BoxFut<R, E> = Pin<Box<dyn Future<Output = std::result::Result<R, E>> + Send>>;
pub type Body = BoxBody<Bytes, hyper::Error>;
pub type HyperService = BoxCloneService<Request<Incoming>, Response<Body>, hyper::Error>;

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
    // which dumbass wrote this?
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

pub async fn is_tls(stream: &TcpStream) -> bool {
    let mut peek_buf = [0u8; 1];
    match stream.peek(&mut peek_buf).await {
        // a https "client hello" starts with 0x16
        Ok(1) => peek_buf[0] == 0x16,
        _ => false,
    }
}

/// maps domains to upstream addresses as either UDS or TCP connection
#[derive(Debug, Clone)]
pub struct UpstreamMap {
    inner: Arc<UpstreamMapInner>,
}

impl UpstreamMap {
    pub fn new(domains: &[(Domain, PeerAddr)]) -> Self {
        UpstreamMap {
            inner: Arc::new(UpstreamMapInner {
                map: domains.iter().cloned().collect(),
            }),
        }
    }

    pub fn get_peer_addr(&self, domain: &str) -> Option<&PeerAddr> {
        self.inner.map.get(domain)
    }

    pub fn get_domains(&self) -> impl Iterator<Item = &Domain> {
        self.inner.map.keys()
    }
}

impl<const N: usize> TryFrom<&[(&str, &str); N]> for UpstreamMap {
    type Error = anyhow::Error;

    fn try_from(value: &[(&str, &str); N]) -> std::result::Result<Self, Self::Error> {
        let map = value
            .iter()
            .map(|(domain, addr)| {
                Ok::<_, anyhow::Error>((
                    Domain::parse(domain)?,
                    PeerAddr::Uds(SocketAddr::from_pathname(addr)?),
                ))
            })
            .collect::<Result<_, _>>()?;

        Ok(UpstreamMap {
            inner: Arc::new(UpstreamMapInner { map }),
        })
    }
}

impl Display for UpstreamMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (domain, peer) in self.inner.map.iter() {
            write!(f, "Domain: {domain}, peer: {peer:?}")?;
        }
        std::fmt::Result::Ok(())
    }
}

#[derive(Debug)]
struct UpstreamMapInner {
    map: HashMap<Domain, PeerAddr>,
}

#[derive(Debug, Clone)]
pub enum PeerAddr {
    Ipv4(Ipv4Addr),
    Uds(SocketAddr),
}

#[derive(Debug, Clone, Display, Hash, Eq, PartialEq, PartialOrd, Ord)]
pub struct Domain(Arc<str>);

impl Domain {
    pub fn parse(domain: impl AsRef<str>) -> Result<Self> {
        parse_domain_name(domain.as_ref())
            .map_err(|e| anyhow!("{e}"))?
            .root()
            .ok_or_else(|| anyhow!("couldnt extract root from domain name"))
            .map(|dm| Domain(Arc::from(dm)))

        // Url::parse(url.as_ref())?
        //     .host_str()
        //     .ok_or_else(|| anyhow!("couldnt extract host identifier from {}", url.as_ref()))
        //     .map(Arc::from)
        //     .map(Domain)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Borrow<str> for Domain {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

#[derive(Debug, Clone, Display, Hash, Eq, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CertChainPem(String);

impl CertChainPem {
    pub fn from_str(str: impl Into<String>) -> Self {
        CertChainPem(str.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Display, Hash, Eq, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KeyPem(String);

impl KeyPem {
    pub fn from_str(str: impl Into<String>) -> Self {
        KeyPem(str.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, AsRef, Display, Hash, Eq, PartialEq, PartialOrd, Ord, From)]
pub struct AcmeToken(String);

impl AcmeToken {
    pub fn from_str(str: impl Into<String>) -> Self {
        AcmeToken(str.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Borrow<str> for AcmeToken {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}
