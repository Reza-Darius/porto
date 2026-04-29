use std::borrow::Borrow;
use std::collections::HashMap;
use std::fmt::Display;
use std::path::PathBuf;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;

use addr::parse_domain_name;
use anyhow::{Result, anyhow};
use derive_more::{AsRef, Display, Eq, From};
use http_body_util::combinators::BoxBody;
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response};
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tower::util::BoxCloneService;
use tracing::debug;

use crate::config::PortoConfig;

pub type BoxFut<R, E> = Pin<Box<dyn Future<Output = std::result::Result<R, E>> + Send>>;
pub type Body = BoxBody<Bytes, hyper::Error>;
pub type HyperService = BoxCloneService<Request<Incoming>, Response<Body>, hyper::Error>;

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
    pub fn get_peer_addr_from_req<B>(&self, req: &Request<B>) -> Option<PeerAddr> {
        let host = super::get_target_host(req).ok()?;
        self.get_peer_addr(host).cloned().or_else(|| {
            debug!(requested_host = %host, "coulndnt retrieve socket name");
            None
        })
    }
}

#[derive(Debug)]
struct UpstreamMapInner {
    map: HashMap<Domain, PeerAddr>,
}

impl UpstreamMap {
    pub fn new(config: &PortoConfig) -> Self {
        let map = config
            .get_proxies()
            .map(|(d, a)| (d.clone(), a.clone()))
            .collect();
        UpstreamMap {
            inner: Arc::new(UpstreamMapInner { map }),
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
                    PeerAddr::Uds(PathBuf::from_str(addr)?),
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

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum PeerAddr {
    Ipv4(std::net::SocketAddr),
    Uds(PathBuf), // must be second so serde evaluates in the right order
}

impl TryFrom<&str> for PeerAddr {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        value
            .parse::<std::net::SocketAddr>()
            .map(PeerAddr::Ipv4)
            .or_else(|_| Ok(PeerAddr::Uds(PathBuf::from_str(value)?)))
    }
}

impl Display for PeerAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerAddr::Ipv4(socket_addr) => write!(f, "{}", socket_addr),
            PeerAddr::Uds(path_buf) => write!(f, "{}", path_buf.display()),
        }
    }
}

#[derive(Debug, Clone, Display, Hash, Eq, PartialEq, PartialOrd, Ord, Deserialize)]
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

impl AsRef<str> for Domain {
    fn as_ref(&self) -> &str {
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
