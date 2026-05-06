#![allow(clippy::new_without_default)]
use std::borrow::Borrow;
use std::collections::HashMap;
use std::fmt::Display;
use std::ops::Deref;
use std::path::PathBuf;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use addr::parse_domain_name;
use anyhow::{Context, Result, anyhow};
use derive_more::{AsRef, Display, Eq, From};
use http::Version;
use http_body_util::combinators::BoxBody;
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tower::BoxError;
use tower::util::BoxCloneService;

use crate::config::{PortoConfig, ProxyConfig};

pub type BoxFut<R, E> = Pin<Box<dyn Future<Output = std::result::Result<R, E>> + Send>>;
pub type Body = BoxBody<Bytes, BoxError>;
pub type HyperService = BoxCloneService<Request<Incoming>, Response<Body>, anyhow::Error>;

/// monotonic counter for peer ids
static ID_COUNTER: AtomicU64 = AtomicU64::new(0);

/// maps domains to upstream addresses as either UDS or TCP connection
#[derive(Debug, Clone, Default)]
pub struct PeerTable {
    inner: Arc<PeerTableInner>,
}

#[derive(Debug, Default)]
struct PeerTableInner {
    domain_table: Mutex<HashMap<Domain, PeerId>>,
    alive_peers: Mutex<HashMap<PeerId, Peer>>,
}

// TODO: prevent duplicate addresses

impl PeerTable {
    fn new() -> Self {
        PeerTable {
            inner: Arc::new(PeerTableInner {
                ..Default::default()
            }),
        }
    }
    pub fn init(config: &PortoConfig) -> Self {
        let table = PeerTable {
            inner: Arc::new(PeerTableInner {
                domain_table: Mutex::new(HashMap::new()),
                alive_peers: Mutex::new(HashMap::new()),
            }),
        };
        // TODO: intializing backnds needs to move somewhere else
        for proxy in config.get_proxies() {
            table.register_peer(proxy);
        }
        table
    }

    pub fn register_peer(&self, proxy: ProxyConfig) {
        let id = PeerId::new();
        let peer = Peer::new(
            proxy.upstream,
            match proxy.http2 {
                true => PeerProto::Http2,
                false => PeerProto::Http1,
            },
        );
        self.inner.alive_peers.lock().insert(id, peer);
        self.inner.domain_table.lock().insert(proxy.domain, id);
    }

    pub fn get_peer(&self, host: &str) -> Option<Peer> {
        self.inner
            .domain_table
            .lock()
            .get(host)
            .and_then(|id| self.get_peer_by_id(id))
    }

    pub fn get_peer_by_id(&self, id: &PeerId) -> Option<Peer> {
        self.inner.alive_peers.lock().get(id).cloned()
    }

    pub fn get_domains(&self) -> Vec<Domain> {
        self.inner.domain_table.lock().keys().cloned().collect()
    }
}

#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct PeerId(u64);

impl PeerId {
    pub fn new() -> Self {
        PeerId(ID_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
    }
}

/// a backend peer to upstream requests to
#[derive(Debug, Clone)]
pub struct Peer {
    pub addr: PeerAddr,
    pub prot: PeerProto,
}

impl Peer {
    fn new(addr: PeerAddr, prot: PeerProto) -> Self {
        Peer { addr, prot }
    }
}

impl<const N: usize> TryFrom<&[(&str, &str); N]> for PeerTable {
    type Error = anyhow::Error;

    fn try_from(value: &[(&str, &str); N]) -> std::result::Result<Self, Self::Error> {
        let table = PeerTable::new();

        for (domain, addr) in value.iter() {
            let domain = Domain::parse(domain)?;
            let upstream = PeerAddr::try_from(*addr)?;
            let p = ProxyConfig {
                domain,
                upstream,
                http2: false,
            };
            table.register_peer(p);
        }

        Ok(table)
    }
}

impl Display for PeerTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (domain, peer) in self.inner.domain_table.lock().iter() {
            write!(f, "Domain: {domain}, peer: {peer:?}")?;
        }
        std::fmt::Result::Ok(())
    }
}
// TODO: refactor this into a wrapper type

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct PeerAddr {
    inner: Arc<PeerAddrInner>,
}

/// the HTTP protocol supported by the backend
#[derive(Debug, Clone, Copy, Deserialize, Hash, PartialEq, Eq, PartialOrd, Ord, Default)]
#[serde(untagged)]
pub enum PeerProto {
    #[default]
    Http1,
    Http2,
}

impl PeerProto {
    pub fn to_ver(&self) -> http::Version {
        match self {
            PeerProto::Http1 => Version::HTTP_11,
            PeerProto::Http2 => Version::HTTP_2,
        }
    }
}

impl<'de> Deserialize<'de> for PeerAddr {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let inner = PeerAddrInner::deserialize(deserializer)?;
        Ok(PeerAddr {
            inner: Arc::new(inner),
        })
    }
}

impl TryFrom<http::Uri> for PeerAddr {
    type Error = anyhow::Error;

    fn try_from(value: http::Uri) -> std::result::Result<Self, Self::Error> {
        value
            .authority()
            .ok_or_else(|| anyhow!("no authority found"))
            .and_then(|host| PeerAddr::try_from(host.as_str()))
            .with_context(|| anyhow!("couldnt convert URI to peeraddr {value:?}"))
    }
}

impl Borrow<PeerAddrInner> for PeerAddr {
    fn borrow(&self) -> &PeerAddrInner {
        &self.inner
    }
}

impl Deref for PeerAddr {
    type Target = PeerAddrInner;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[derive(Debug, Clone, Deserialize, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[serde(untagged)]
pub enum PeerAddrInner {
    Ipv4(std::net::SocketAddr),
    Uds(PathBuf), // must be second so serde evaluates in the right order
}

impl TryFrom<&str> for PeerAddr {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        let inner = value
            .parse::<std::net::SocketAddr>()
            .map(PeerAddrInner::Ipv4)
            .or_else(|_| Ok::<_, anyhow::Error>(PeerAddrInner::Uds(PathBuf::from_str(value)?)))?;

        Ok(PeerAddr {
            inner: Arc::new(inner),
        })
    }
}

impl Display for PeerAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self.inner {
            PeerAddrInner::Ipv4(ref socket_addr) => write!(f, "{}", socket_addr),
            PeerAddrInner::Uds(ref path_buf) => write!(f, "{}", path_buf.display()),
        }
    }
}

#[derive(Debug, Clone, Display, Hash, Eq, PartialEq, PartialOrd, Ord, Deserialize)]
pub struct Domain(Arc<str>);

impl Domain {
    pub fn parse(domain: impl AsRef<str>) -> Result<Self> {
        let domain = domain.as_ref();
        parse_domain_name(domain)
            .map_err(|e| anyhow!("{e}"))?
            .root()
            .ok_or_else(|| anyhow!("couldnt extract root from domain {domain}"))
            .map(|domain| Domain(Arc::from(domain)))
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
