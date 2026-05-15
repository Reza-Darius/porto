#![allow(clippy::new_without_default)]
use std::borrow::Borrow;
use std::collections::HashMap;
use std::fmt::Display;
use std::ops::Deref;
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
use tracing::debug;

use crate::config::PortoConfig;

/// monotonic counter for peer ids
static ID_COUNTER: AtomicU64 = AtomicU64::new(0);

/// maps domains to backends
///
/// shared across the application
#[derive(Debug, Clone, Default)]
pub struct PeerTable {
    inner: Arc<PeerTableInner>,
}

#[derive(Debug, Default)]
struct PeerTableInner {
    /// routing table mapping domains to peers
    route: RwLock<HashMap<Domain, PeerId>>,

    /// reachable peers
    alive: RwLock<HashMap<PeerId, Peer>>,

    /// list of peers for initialization
    peers: Mutex<Vec<Peer>>,
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
                peers: Mutex::new(config.get_proxies().collect()),
                ..Default::default()
            }),
        };

        debug!("initialized domains {table}");
        table
    }

    // initializes a proxy table under the assumption they are reachable
    pub fn init_debug<const N: usize>(value: &[(&str, &str); N]) -> Result<Self> {
        let table = PeerTable::new();

        for (domain, addr) in value.iter() {
            let domain = Domain::parse(domain)?;
            let upstream = PeerAddr::try_from(*addr)?;
            let p = Peer::new(domain, upstream, PeerProto::Http1);
            table.register_peer(p);
        }
        Ok(table)
    }

    /// the caller has to ensure the peer is reachable
    pub fn register_peer(&self, peer: Peer) {
        debug!(id = %peer.id, addr = %peer.addr, "registering peer");

        self.inner.route.write().insert(peer.name.clone(), peer.id);
        self.inner.alive.write().insert(peer.id, peer);
    }

    pub fn evict_peer(&self, id: PeerId) -> Option<Peer> {
        let peer = self.inner.alive.write().remove(&id)?;
        self.inner.route.write().remove(&peer.name);
        Some(peer)
    }

    /// fetches a reachable Peer
    pub fn get_peer(&self, host: &str) -> Option<Peer> {
        self.inner
            .route
            .read()
            .get(host)
            .and_then(|id| self.get_peer_by_id(*id))
    }

    pub fn get_peer_by_id(&self, id: PeerId) -> Option<Peer> {
        self.inner.alive.read().get(&id).cloned()
    }

    pub fn get_domains(&self) -> Vec<Domain> {
        self.inner.route.read().keys().cloned().collect()
    }

    pub fn get_reg_peers(&self) -> impl Iterator<Item = Peer> {
        let mut guard = self.inner.peers.lock();
        std::mem::take(&mut *guard).into_iter()
    }
}

impl Display for PeerTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (domain, peer) in self.inner.route.read().iter() {
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
///
/// cheap-ish to clone
#[derive(Debug, Clone)]
pub struct Peer {
    pub id: PeerId,
    pub name: Domain,
    pub addr: PeerAddr,
    /// supported HTTP protocol
    pub prot: PeerProto,
}

impl Peer {
    pub fn new(name: Domain, addr: PeerAddr, prot: PeerProto) -> Self {
        Peer {
            id: PeerId::new(),
            name,
            addr,
            prot,
        }
    }
}

// TODO: refactor this into a wrapper type

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct PeerAddr {
    inner: Arc<PeerAddrInner>,
}

impl PeerAddr {
    /// converts the peeraddr to an URI with the peer addr as the authority/host
    pub fn to_uri<P>(&self, path: P) -> Result<Uri, P::Error>
    where
        P: TryInto<PathAndQuery>,
    {
        let uri = match &**self {
            PeerAddrInner::Uds(socket_addr) => {
                UdsUri::new(socket_addr, path.try_into()?.as_str()).into()
            }
            PeerAddrInner::Ipv4(addr) => {
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
        &self.0
    }
}

fn foo() {
    let mut map: HashMap<String, String> = HashMap::new();
    map.insert(String::from("hello"), String::from("world"));
    let domain = Domain(Arc::from("hello"));
    let r = map.get(domain.as_str());
}
