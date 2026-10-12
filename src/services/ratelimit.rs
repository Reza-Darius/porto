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
use thiserror::Error;
use tower::{BoxError, Layer, Service};
use tracing::{trace, trace_span};

use crate::utils::ResponseBody;

const BUCKET_SIZE: u16 = 10;
const REFILL_INTERVAL: Duration = Duration::from_mins(1);
const REFILL_TOKENS: u16 = 2;

const CLEANUP_INTERVAL: Duration = Duration::from_mins(10);
const BUCKET_TIMEOUT: Duration = Duration::from_mins(5);

/// an IP based rate limiter using token buckets
#[derive(Clone)]
pub struct RateLimitLayer {
    inner: Option<Arc<RateLimiterInner>>,
}

impl RateLimitLayer {
    pub fn new(enabled: bool) -> Self {
        RateLimitLayer {
            inner: enabled.then_some(RateLimiterInner::new()),
        }
    }
}

impl<S> Layer<S> for RateLimitLayer {
    type Service = RateLimiter<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RateLimiter {
            rl: self.inner.clone(),
            inner,
        }
    }
}

#[derive(Clone)]
pub struct RateLimiter<S> {
    rl: Option<Arc<RateLimiterInner>>,
    inner: S,
}

impl<S> RateLimiter<S> {
    pub fn new(inner: S, enabled: bool) -> Self {
        RateLimiter {
            rl: enabled.then_some(RateLimiterInner::new()),
            inner,
        }
    }
}

impl<S> RateLimiter<S> {
    pub fn has_token(&self, addr: SocketAddr) -> bool {
        let addr = addr.ip();
        match self
            .rl
            .as_ref()
            .expect("this cant be called when disabled")
            .map
            .lock()
            .entry(addr)
        {
            Entry::Occupied(mut occupied_entry) => {
                let bucket = occupied_entry.get_mut();

                bucket.fill();

                if bucket.tokens > 0 {
                    bucket.tokens -= 1;
                    trace!(tokens = bucket.tokens, "tokens remaining");
                    true
                } else {
                    false
                }
            }
            Entry::Vacant(vacant_entry) => {
                trace!("new bucket");
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
        let mut guard = self.map.lock();
        guard.retain(|_, bucket| bucket.last_update.elapsed() < BUCKET_TIMEOUT);
        trace!(len = %guard.len(), "bucket list after cleanup");
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
        if self.rl.is_none() {
            return RateLimitFuture::Ok {
                fut: self.inner.call(req),
            };
        };

        let Some(addr) = req.extensions().get::<SocketAddr>() else {
            return RateLimitFuture::NoAddrFoun;
        };

        let _span = trace_span!("rate_limiter", client_addr = %addr.ip()).entered();

        if self.has_token(*addr) {
            RateLimitFuture::Ok {
                fut: self.inner.call(req),
            }
        } else {
            trace!("rate limited");
            RateLimitFuture::RateLimited
        }
    }
}

#[derive(Error, Debug)]
pub enum RateLimitError {
    #[error("no address found on request")]
    NoAddrFound,
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
            EnumProj::NoAddrFoun => Poll::Ready(Err(RateLimitError::NoAddrFound.into())),
        }
    }
}
