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
use anyhow::{Result, anyhow};
use derive_more::{AsRef, Display, Eq, From};
use http_body_util::combinators::BoxBody;
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tower::util::BoxCloneService;

use crate::config::PortoConfig;

pub type BoxFut<R, E> = Pin<Box<dyn Future<Output = std::result::Result<R, E>> + Send>>;
pub type Body = BoxBody<Bytes, hyper::Error>;
pub type HyperService = BoxCloneService<Request<Incoming>, Response<Body>, anyhow::Error>;

/// monotonic counter for peer ids
static ID_COUNTER: AtomicU64 = AtomicU64::new(0);

pub async fn is_tls(stream: &TcpStream) -> bool {
    let mut peek_buf = [0u8; 1];
    match stream.peek(&mut peek_buf).await {
        // a https "client hello" starts with 0x16
        Ok(1) => peek_buf[0] == 0x16,
        _ => false,
    }
}

/// maps domains to upstream addresses as either UDS or TCP connection
#[derive(Debug, Clone, Default)]
pub struct PeerTable {
    inner: Arc<PeerTableInner>,
}

impl PeerTable {}

#[derive(Debug, Default)]
struct PeerTableInner {
    domain_table: Mutex<HashMap<Domain, PeerId>>,
    peer_table: Mutex<HashMap<PeerId, Peer>>,
}

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
                peer_table: Mutex::new(HashMap::new()),
            }),
        };

        for (domain, peer) in config.get_proxies() {
            table.register_peer(domain.clone(), peer.clone());
        }
        table
    }

    pub fn register_peer(&self, domain: Domain, addr: PeerAddr) {
        let id = PeerId::new();
        let peer = Peer::new(addr);
        self.inner.peer_table.lock().insert(id, peer);
        self.inner.domain_table.lock().insert(domain, id);
    }

    pub fn get_peer_addr(&self, domain: &str) -> Option<PeerAddr> {
        self.inner.domain_table.lock().get(domain).and_then(|id| {
            self.inner
                .peer_table
                .lock()
                .get(id)
                .map(|peer| peer.addr.clone())
        })
    }

    pub fn get_domains(&self) -> Vec<Domain> {
        self.inner.domain_table.lock().keys().cloned().collect()
    }
}

#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
struct PeerId(u64);

impl PeerId {
    pub fn new() -> Self {
        PeerId(ID_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
    }
}

#[derive(Debug)]
struct Peer {
    addr: PeerAddr,
    alive: bool,
}

impl Peer {
    fn new(addr: PeerAddr) -> Self {
        Peer { addr, alive: false }
    }
}

impl<const N: usize> TryFrom<&[(&str, &str); N]> for PeerTable {
    type Error = anyhow::Error;

    fn try_from(value: &[(&str, &str); N]) -> std::result::Result<Self, Self::Error> {
        let table = PeerTable::new();

        for (domain, addr) in value.iter() {
            let d = Domain::parse(domain)?;
            let p = PeerAddr::try_from(*addr)?;
            table.register_peer(d, p);
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

#[derive(Debug, Clone, Deserialize)]
pub struct PeerAddr {
    inner: Arc<PeerAddrInner>,
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

#[derive(Debug, Clone, Deserialize)]
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
        parse_domain_name(domain.as_ref())
            .map_err(|e| anyhow!("{e}"))?
            .root()
            .ok_or_else(|| anyhow!("couldnt extract root from domain name"))
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
