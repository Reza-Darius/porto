#![allow(dead_code)]
use std::{
    collections::{HashMap, hash_map::Entry},
    net::{IpAddr, SocketAddr},
    sync::Arc,
    task::Poll,
    time::{Duration, Instant},
};

use http::{Request, Response, StatusCode};
use parking_lot::Mutex;
use pin_project_lite::pin_project;
use tower::{BoxError, Layer, Service};
use tracing::{debug, warn};

use crate::utils::{Body, response};

const BUCKET_SIZE: u16 = 10;
const REFILL_INTERVAL: Duration = Duration::from_mins(1);
const REFILL_TOKENS: u16 = 2;

const CLEANUP_INTERVAL: Duration = Duration::from_mins(10);
const BUCKET_TIMEOUT: Duration = Duration::from_mins(5);

/// an IP based rate limiter using token buckets
#[derive(Clone)]
pub struct RateLimitLayer {
    inner: Arc<RateLimiterInner>,
}

impl<S> Layer<S> for RateLimitLayer {
    type Service = RateLimiter<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RateLimiter {
            rl: self.inner.clone(),
            svc: inner,
        }
    }
}

impl RateLimitLayer {
    pub fn new() -> Self {
        let rl = Arc::new(RateLimiterInner {
            map: Mutex::new(HashMap::new()),
        });

        let rl_clone = rl.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        rl_clone.cleanup();
                    }
                }
            }
        });

        RateLimitLayer { inner: rl }
    }
}

#[derive(Clone)]
pub struct RateLimiter<S> {
    rl: Arc<RateLimiterInner>,
    svc: S,
}

impl<S> RateLimiter<S> {
    pub fn has_token(&self, addr: SocketAddr) -> bool {
        let addr = addr.ip();
        match self.rl.map.lock().entry(addr) {
            Entry::Occupied(mut occupied_entry) => {
                let bucket = occupied_entry.get_mut();

                bucket.fill();

                if bucket.tokens > 0 {
                    bucket.tokens -= 1;
                    debug!(tokens = bucket.tokens, "tokens remaining");
                    true
                } else {
                    warn!(%addr, "too many requests");
                    false
                }
            }
            Entry::Vacant(vacant_entry) => {
                debug!(%addr, "new bucket");
                vacant_entry.insert(Bucket::new(BUCKET_SIZE - 1));
                true
            }
        }
    }
}

struct RateLimiterInner {
    map: Mutex<HashMap<IpAddr, Bucket>>,
}

impl RateLimiterInner {
    fn cleanup(&self) {
        self.map
            .lock()
            .retain(|_, bucket| bucket.last_update.elapsed() < BUCKET_TIMEOUT);
        debug!(len = %self.map.lock().len(), "bucket list after cleanup");
    }
}

struct Bucket {
    tokens: u16,
    last_update: Instant,
}

impl Bucket {
    fn new(tokens: u16) -> Self {
        Bucket {
            tokens,
            last_update: Instant::now(),
        }
    }

    // we check how many refills could have been done in the elapsed time
    fn fill(&mut self) {
        let elapsed = self.last_update.elapsed().as_secs();
        let n_updates = elapsed / REFILL_INTERVAL.as_secs();

        if n_updates == 0 {
            return;
        }

        for _ in 0..n_updates {
            self.tokens += REFILL_TOKENS;

            if self.tokens > BUCKET_SIZE {
                self.tokens = BUCKET_SIZE;
                self.last_update = Instant::now();
                return;
            }
        }

        self.last_update += REFILL_INTERVAL * (n_updates as u32);
    }
}

impl<S, ReqB> Service<Request<ReqB>> for RateLimiter<S>
where
    S: Service<Request<ReqB>, Response = Response<Body>>,
    S::Error: Into<BoxError>,
{
    type Response = Response<Body>;
    type Error = BoxError;
    type Future = RateLimitFuture<S::Future>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.svc.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, req: Request<ReqB>) -> Self::Future {
        let addr = req
            .extensions()
            .get::<SocketAddr>()
            .expect("we require every request to have it");

        if self.has_token(*addr) {
            RateLimitFuture::Service {
                fut: self.svc.call(req),
            }
        } else {
            RateLimitFuture::RateLimited
        }
    }
}

pin_project! {
    #[project = EnumProj]
    pub enum RateLimitFuture<F> {
        Service {#[pin] fut: F},
        RateLimited,
    }
}

impl<F, E> Future for RateLimitFuture<F>
where
    F: Future<Output = Result<Response<Body>, E>>,
    E: Into<BoxError>,
{
    type Output = Result<Response<Body>, BoxError>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.project();
        match this {
            EnumProj::Service { fut } => fut.poll(cx).map_err(Into::into),
            EnumProj::RateLimited => Poll::Ready(Ok(response(StatusCode::TOO_MANY_REQUESTS))),
        }
    }
}
