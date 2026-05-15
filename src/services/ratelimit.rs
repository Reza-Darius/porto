#![allow(dead_code)]
use std::{
    collections::{HashMap, hash_map::Entry},
    net::{IpAddr, SocketAddr},
    sync::Arc,
    task::Poll,
    time::{Duration, Instant},
};

use anyhow::anyhow;
use http::{Request, Response, StatusCode};
use parking_lot::Mutex;
use pin_project_lite::pin_project;
use tower::{BoxError, Layer, Service};
use tracing::{debug, warn};

use crate::utils::ResponseBody;

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
            token: None,
            inner,
        }
    }
}

impl RateLimitLayer {
    pub fn new() -> Self {
        RateLimitLayer {
            inner: RateLimiterInner::new(),
        }
    }
}

// a simple marker type
#[derive(Clone, Copy)]
struct Token;

#[derive(Clone)]
pub struct RateLimiter<S> {
    rl: Arc<RateLimiterInner>,
    token: Option<Token>,
    inner: S,
}

impl<S> RateLimiter<S> {
    pub fn new(inner: S) -> Self {
        RateLimiter {
            rl: RateLimiterInner::new(),
            token: None,
            inner,
        }
    }
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
    fn new() -> Arc<Self> {
        let rl = Arc::new(RateLimiterInner {
            map: Mutex::new(HashMap::new()),
        });

        let rl_clone = rl.clone();

        // background worker to clean up stale buckets
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
            loop {
                interval.tick().await;
                rl_clone.cleanup();
            }
        });
        rl
    }
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

impl<S, ReqB, ResB> Service<Request<ReqB>> for RateLimiter<S>
where
    S: Service<Request<ReqB>, Response = Response<ResB>>,
    S::Error: Into<BoxError>,
{
    type Response = Response<ResponseBody<ResB>>;
    type Error = BoxError;
    type Future = RateLimitFuture<S::Future>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, req: Request<ReqB>) -> Self::Future {
        let Some(addr) = req.extensions().get::<SocketAddr>() else {
            return RateLimitFuture::NoAddrFoun;
        };

        if self.has_token(*addr) {
            RateLimitFuture::Ok {
                fut: self.inner.call(req),
            }
        } else {
            warn!(%addr, "rate limited");
            RateLimitFuture::RateLimited
        }
    }
}

pin_project! {
    #[project = EnumProj]
    pub enum RateLimitFuture<F> {
        Ok {#[pin] fut: F},
        RateLimited,
        NoAddrFoun,
    }
}

impl<F, E, ResB> Future for RateLimitFuture<F>
where
    F: Future<Output = Result<Response<ResB>, E>>,
    E: Into<BoxError>,
{
    type Output = Result<Response<ResponseBody<ResB>>, BoxError>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.project();
        match this {
            EnumProj::Ok { fut } => fut
                .poll(cx)
                .map_err(Into::into)
                .map(|f| f.map(|resp| resp.map(ResponseBody::wrap))),
            EnumProj::RateLimited => Poll::Ready(Ok(Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .body(ResponseBody::with_msg("too many requests"))
                .expect("the values are hard coded"))),
            EnumProj::NoAddrFoun => Poll::Ready(Err("no addr found on request".into())),
        }
    }
}
