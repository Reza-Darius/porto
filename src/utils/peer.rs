#![allow(clippy::new_without_default)]
use std::borrow::Borrow;
use std::collections::{HashMap};
use std::fmt::Display;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use addr::parse_domain_name;
use anyhow::{Context, Result, anyhow};
use derive_more::{Display, Eq};
use http::uri::{Authority, PathAndQuery};
use http::{Uri, Version};
use hyperlocal::Uri as UdsUri;
use parking_lot::{Mutex, RwLock};
use serde::Deserialize;
use tracing::{debug, info};

use crate::config::{PortoConfig, ServiceConfig};

/// monotonic counter for peer ids
static ID_COUNTER: AtomicU64 = AtomicU64::new(0);

/// maps domains to backends
///
/// shared across the application
#[derive(Debug, Clone, Default)]
pub struct RouteTable {
    inner: Arc<RouteTableInner>,
}

#[derive(Debug, Default)]
struct RouteTableInner {
    domains: RwLock<HashMap<Domain, PeerId>>,

    /// reachable peers
    alive: RwLock<HashMap<PeerId, Peer>>,

    /// list of peers for initialization
    peers: Mutex<Vec<Peer>>,
}

impl RouteTable {
    fn new() -> Self {
        RouteTable {
            inner: Arc::new(RouteTableInner {
                ..Default::default()
            }),
        }
    }
    pub fn init(config: &PortoConfig) -> Self {
        let table = RouteTable {
            inner: Arc::new(RouteTableInner {
                peers: Mutex::new(config.get_proxies().collect()),
                ..Default::default()
            }),
        };

        info!("initialized domains {table}");
        table
    }

    // initializes a proxy table under the assumption they are reachable
    pub fn init_debug<const N: usize>(value: &[(&str, &str); N]) -> Result<Self> {
        let table = RouteTable::new();

        for (domain, addr) in value.iter() {
            let domain = Domain::parse(domain)?;
            let upstream = PeerAddr::try_from(*addr)?;
            let p = Peer::new(domain, upstream, Version::HTTP_11, ServiceConfig::default());
            table.register_peer(p);
        }
        Ok(table)
    }

    /// the caller has to ensure the peer is reachable
    pub fn register_peer(&self, peer: Peer) {
        debug!(id = %peer.id(), domatin = %peer.name(), addr = %peer.addr(), "registering peer");

        self.inner
            .domains
            .write()
            .insert(peer.name().clone(), peer.id());
        self.inner.alive.write().insert(peer.id(), peer);
    }

    pub fn evict_peer(&self, id: PeerId) -> Option<Peer> {
        debug!(%id, "evicting peer");

        let peer = self.inner.alive.write().remove(&id)?;
        self.inner.domains.write().remove(peer.name());
        Some(peer)
    }

    /// fetches a reachable Peer
    pub fn get_peer(&self, host: &str) -> Option<Peer> {
        self.inner
            .domains
            .read()
            .get(host)
            .and_then(|id| self.get_peer_by_id(*id))
    }

    pub fn get_peer_by_id(&self, id: PeerId) -> Option<Peer> {
        self.inner.alive.read().get(&id).cloned()
    }

    pub fn get_domains(&self) -> Vec<Domain> {
        self.inner.domains.read().keys().cloned().collect()
    }

    pub fn get_reg_peers(&self) -> impl Iterator<Item = Peer> {
        let mut guard = self.inner.peers.lock();
        std::mem::take(&mut *guard).into_iter()
    }
}

impl Display for RouteTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (domain, peer) in self.inner.domains.read().iter() {
            write!(f, "Domain: {domain}, peer: {peer:?}")?;
        }
        std::fmt::Result::Ok(())
    }
}

#[derive(Display, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct PeerId(u64);

impl PeerId {
    pub fn new() -> Self {
        PeerId(ID_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
    }
}

/// a backend peer to upstream requests to
#[derive(Debug, Clone)]
pub struct Peer {
    inner: Arc<PeerInner>,
}

#[derive(Debug)]
pub struct PeerInner {
    pub id: PeerId,
    pub name: Domain,
    pub addr: PeerAddr,
    pub prot: Version,
    pub config: ServiceConfig,
}

impl Peer {
    pub fn new(name: Domain, addr: PeerAddr, prot: Version, config: ServiceConfig) -> Self {
        Peer {
            inner: Arc::new(PeerInner {
                id: PeerId::new(),
                name,
                addr,
                prot,
                config,
            }),
        }
    }

    pub fn id(&self) -> PeerId {
        self.inner.id
    }

    pub fn name(&self) -> &Domain {
        &self.inner.name
    }

    pub fn addr(&self) -> &PeerAddr {
        &self.inner.addr
    }

    pub fn prot(&self) -> &Version {
        &self.inner.prot
    }

    pub fn config(&self) -> &ServiceConfig {
        &self.inner.config
    }
}

#[derive(Debug, Clone, Deserialize, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[serde(untagged)]
pub enum PeerAddr {
    Ipv4(std::net::SocketAddr),
    Uds(PathBuf), // must be second so serde evaluates in the right order
}

impl PeerAddr {
    /// converts the peeraddr to an URI with the peer addr as the authority/host
    pub fn to_uri<P>(&self, path: P) -> Result<Uri, P::Error>
    where
        P: TryInto<PathAndQuery>,
    {
        let uri = match self {
            PeerAddr::Uds(socket_addr) => {
                UdsUri::new(socket_addr, path.try_into()?.as_str()).into()
            }
            PeerAddr::Ipv4(addr) => {
                let authority: Authority = Authority::from_str(&addr.to_string()).unwrap();
                Uri::builder()
                    .scheme("http")
                    .authority(authority)
                    .path_and_query(path.try_into()?)
                    .build()
                    .unwrap()
            }
        };
        Ok(uri)
    }

    pub fn parse(addr: impl AsRef<str>) -> Result<Self> {
        addr.as_ref().try_into()
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

impl TryFrom<&str> for PeerAddr {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        let addr = value
            .parse::<std::net::SocketAddr>()
            .map(PeerAddr::Ipv4)
            .or_else(|_| Ok::<_, anyhow::Error>(PeerAddr::Uds(PathBuf::from_str(value)?)))?;

        Ok(addr)
    }
}

impl Display for PeerAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            PeerAddr::Ipv4(ref socket_addr) => write!(f, "{}", socket_addr),
            PeerAddr::Uds(ref path_buf) => write!(f, "{}", path_buf.display()),
        }
    }
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

#[derive(Debug, Clone, Display, Hash, Eq, PartialEq, PartialOrd, Ord)]
pub struct Domain(Arc<str>);

// normalizing deserialization to lowercase
impl<'de> Deserialize<'de> for Domain {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de> {
        let s = String::deserialize(deserializer)?;
        Ok(Domain(Arc::from(s.to_ascii_lowercase())))
    }
}

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
        &self.0
    }
}
