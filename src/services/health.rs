#![allow(dead_code, unused_variables)]
use std::{
    collections::HashMap,
    task::Poll,
    time::{Duration, Instant},
};

use http::{Method, Request, Response, StatusCode};
use pin_project_lite::pin_project;
use rand::RngExt;
use tower::Service;
use tracing::{debug, info, warn};

use crate::{errors::TraceErr, services::upstream::hyper_client::UpstreamService, utils::*};

// this is a singleton running in the background
struct HealthService {
    /// client to send requests with to backends
    client: UpstreamService<Body>,
    config: HealthServiceConfig,

    /// this queue corresponds with the alive_backend table
    alive_q: Queue<QEntry>,
    alive_t: RouteTable, // the alive peers live in the peertable

    /// this is a unique queue only the health worker cares about
    dead_q: Queue<QEntry>,
    dead_t: HashMap<PeerId, Peer>,
}

#[derive(Clone, Copy)]
struct QEntry {
    id: PeerId,
    timestamp: Instant,
}

impl QEntry {
    pub fn new(id: PeerId) -> Self {
        QEntry {
            id,
            timestamp: Instant::now(),
        }
    }

    fn is_expired(&self, ttl: Duration) -> bool {
        self.timestamp.elapsed() >= ttl
    }

    fn reset(&mut self) {
        self.timestamp = Instant::now();
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

    /// timeout threshhold after which the backend is considered unreachable
    req_to: Duration,
    /// capacity of each queue
    q_cap: u16,
}

impl Default for HealthServiceConfig {
    fn default() -> Self {
        HealthServiceConfig {
            alive_check_interval: Duration::from_secs(10),
            dead_check_interval: Duration::from_secs(20),
            alive_ttl: Duration::from_secs(10),
            dead_ttl: Duration::from_secs(20),
            req_to: Duration::from_secs(2),
            q_cap: 50,
        }
    }
}

impl HealthService {
    fn new(config: HealthServiceConfig, peers: RouteTable) -> Self {
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
        debug!("checking reachable backends...");

        while let Some(entry) = self.alive_q.pop() {
            // we stop as soon as we see a non-expired entry, because all the ones following arent expired either
            if !entry.is_expired(self.config.alive_ttl) {
                debug!(%entry.id, "entry not expired");
                self.alive_q
                    .push(entry)
                    .expect("we dont handle full queue yet");
                return;
            }

            debug!(%entry.id, "entry expired");

            let peer = self
                .alive_t
                .get_peer_by_id(entry.id)
                .expect("if its in the alive queue, it has to be in the table");
            self.check_entry(entry, peer).await;
        }
    }

    async fn check_deadq(&mut self) {
        debug!("checking unreachable backends...");

        while let Some(entry) = self.dead_q.pop() {
            if !entry.is_expired(self.config.dead_ttl) {
                debug!(%entry.id, "entry not expired");
                self.dead_q
                    .push(entry)
                    .expect("we dont handle full queue yet");
                return;
            }

            debug!(%entry.id, "entry expired");

            let peer = self
                .dead_t
                .get(&entry.id)
                .cloned()
                .expect("if its in the alive queue, it has to be in the table");
            self.check_entry(entry, peer).await;
        }
    }

    async fn check_entry(&mut self, mut entry: QEntry, peer: Peer) {
        entry.reset();

        if self.check_peer_alive(&peer).await {
            debug!(peer = %peer.name(), "peer OK");

            self.alive_q
                .push(entry)
                .expect("we dont handle full queue yet");
            self.alive_t.register_peer(peer);
            self.dead_t.remove(&entry.id);
        } else {
            warn!(peer = %peer.name(), "peer unreachable");

            self.dead_q
                .push(entry)
                .expect("we dont handle full queue yet");
            self.alive_t.evict_peer(entry.id);
            self.dead_t.insert(entry.id, peer);
        }
    }

    async fn check_peer_alive(&mut self, peer: &Peer) -> bool {
        let uri = peer.addr().to_uri("/health").trace_err().unwrap();

        let mut req = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(empty())
            .expect("the values are hard coded");

        req.extensions_mut().insert(peer.clone());

        tokio::select! {
            res = self.client.call(req) => {
                match res {
                    Ok(resp) => resp.status().is_success(),
                    Err(e) => {
                        warn!(%e);
                        false
                    }
                }
            }
            _ = tokio::time::sleep(self.config.req_to) => {
                false
            }
        }
    }

    async fn register_new_peer(&mut self, peer: Peer) {
        let entry = QEntry::new(peer.id());

        if self.check_peer_alive(&peer).await {
            debug!(peer = %peer.name(), "peer OK");

            self.alive_q
                .push(entry)
                .expect("we dont handle full queue yet");
            self.alive_t.register_peer(peer);
        } else {
            warn!(peer = %peer.name(), "peer unreachable");

            self.dead_q
                .push(entry)
                .expect("we dont handle full queue yet");
            self.dead_t.insert(entry.id, peer);
        }
    }
}

pub fn setup_health_service(config: HealthServiceConfig, peers: RouteTable) {
    tokio::spawn(async move {
        info!("setting up health service");

        let new_peers = peers.get_reg_peers();
        let mut hw = HealthService::new(config, peers.clone());

        debug!("initializing peers");

        let mut count = 0;
        for peer in new_peers {
            hw.register_new_peer(peer).await;
            count += 1;
        }
        debug_assert_eq!(count, hw.alive_q.len() + hw.dead_q.len());

        let mut alive_int = tokio::time::interval(hw.config.alive_check_interval);
        let mut dead_int = tokio::time::interval(hw.config.dead_check_interval);

        loop {
            tokio::select! {
                _ = alive_int.tick() => {
                    hw.check_aliveq().await;
                    debug!("currently reachable backends: {}", hw.alive_q.len());
                }
                _ = dead_int.tick() => {
                    hw.check_deadq().await;
                    debug!("currently unreachable backends: {}", hw.dead_q.len());
                }
            }
        }
    });
}

fn jittered(base: Duration, percent: f64) -> Duration {
    let mut rng = rand::rng();

    let factor = rng.random_range((1.0 - percent)..=(1.0 + percent));

    base.mul_f64(factor)
}

#[derive(Clone)]
pub struct HealthEndpoint<S> {
    inner: S,
}

impl<S> HealthEndpoint<S> {
    pub fn new(inner: S) -> Self {
        HealthEndpoint { inner }
    }
}

impl<S, ReqB, RespB> Service<Request<ReqB>> for HealthEndpoint<S>
where
    S: Service<Request<ReqB>, Response = Response<RespB>>,
    S::Future: Send + 'static,
{
    type Response = Response<ResponseBody<RespB>>;
    type Error = S::Error;
    type Future = HealthEndpointFuture<S::Future>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqB>) -> Self::Future {
        if let Some(path) = req.uri().path_and_query()
            && path.path() == "/health"
        {
            HealthEndpointFuture::Ok
        } else {
            HealthEndpointFuture::Inner {
                fut: self.inner.call(req),
            }
        }
    }
}

pin_project! {
    #[project = EnumProj]
    pub enum HealthEndpointFuture<F> {
        Inner { #[pin] fut: F },
        Ok,
    }
}

impl<F, E, RespB> Future for HealthEndpointFuture<F>
where
    F: Future<Output = Result<Response<RespB>, E>>,
{
    type Output = Result<Response<ResponseBody<RespB>>, E>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        match self.project() {
            EnumProj::Inner { fut } => fut
                .poll(cx)
                .map(|res| res.map(|resp| resp.map(ResponseBody::wrap))),
            EnumProj::Ok => Poll::Ready(Ok(Response::builder()
                .status(StatusCode::OK)
                .body(ResponseBody::empty())
                .expect("the values are hard coded"))),
        }
    }
}
