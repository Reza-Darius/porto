#![allow(dead_code, unused_variables)]
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use http::{Method, Request};
use tap::Pipe;
use tower::Service;
use tracing::warn;

use crate::{services::upstream::hyper_client::UpstreamService, utils::*};

// this is a singleton running in the background
struct HealthService {
    /// client to send requests with to backends
    client: UpstreamService<Body>,
    config: HealthServiceConfig,

    /// this queue corresponds with the alive_backend table
    alive_q: Queue<QEntry>,
    alive_t: PeerTable, // the alive peers live in the peertable
    /// this is a unique queue only the health worker cares about
    dead_q: Queue<QEntry>,
    dead_t: HashMap<PeerId, Peer>,
}

#[derive(Clone, Copy)]
struct QEntry {
    id: PeerId,
    added: Instant,
}

impl QEntry {
    pub fn new(id: PeerId) -> Self {
        QEntry {
            id,
            added: Instant::now(),
        }
    }

    fn is_expired(&self, ttl: Duration) -> bool {
        self.added.elapsed() > ttl
    }

    fn reset(&mut self) {
        self.added = Instant::now()
    }
}

impl From<PeerId> for QEntry {
    fn from(value: PeerId) -> Self {
        QEntry::new(value)
    }
}

pub struct HealthServiceConfig {
    /// how often to check the queue
    alive_check_interval: Duration,
    dead_check_interval: Duration,

    /// minimum elapsed time before a backend gets checked again
    alive_ttl: Duration,
    dead_ttl: Duration,

    /// capacity of each queue
    q_cap: u16,
}

impl Default for HealthServiceConfig {
    fn default() -> Self {
        HealthServiceConfig {
            alive_check_interval: Duration::from_secs(30),
            dead_check_interval: Duration::from_secs(30),
            alive_ttl: Duration::from_secs(30),
            dead_ttl: Duration::from_secs(60),
            q_cap: 50,
        }
    }
}

impl HealthService {
    fn new(config: HealthServiceConfig, peers: PeerTable) -> Self {
        HealthService {
            client: UpstreamService::new(),
            alive_q: Queue::new(config.q_cap as usize),
            alive_t: peers,
            dead_q: Queue::new(config.q_cap as usize),
            dead_t: HashMap::new(),
            config,
        }
    }

    async fn check_aliveq(&mut self) {
        let Some(mut entry) = self.alive_q.pop() else {
            return;
        };

        entry.reset();

        if !entry.is_expired(self.config.alive_ttl) {
            self.alive_q.push(entry);
            return;
        }

        self.check_entry(entry).await;
    }

    async fn check_deadq(&mut self) {
        let Some(mut entry) = self.dead_q.pop() else {
            return;
        };

        entry.reset();

        if !entry.is_expired(self.config.dead_ttl) {
            self.dead_q.push(entry);
            return;
        }

        self.check_entry(entry).await;
    }

    async fn check_entry(&mut self, entry: QEntry) {
        // we need to call the peer
        let peer = self
            .alive_t
            .get_peer_by_id(entry.id)
            .expect("if its in the alive queue, it has to be in the table");

        if self.check_peer_alive(&peer).await {
            self.alive_q.push(entry);
            self.alive_t.register_peer(peer);
            self.dead_t.remove(&entry.id);
        } else {
            self.dead_q.push(entry);
            self.alive_t.evict_peer(entry.id);
            self.dead_t.insert(entry.id, peer);
        }
    }

    async fn check_peer_alive(&mut self, peer: &Peer) -> bool {
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("/health")
            .body(empty())
            .expect("the values are hard coded");

        req.extensions_mut().insert(peer.addr.clone());

        match self.client.call(req).await {
            Ok(resp) => resp.status().is_success(),
            Err(e) => {
                warn!(%e);
                false
            }
        }
    }
}

pub fn setup_health_service(config: HealthServiceConfig, peers: PeerTable) {
    let mut hw = HealthService::new(config, peers);
    tokio::spawn(async move {
        // we call each peer on startup
    });
}
