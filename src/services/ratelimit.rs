#![allow(dead_code)]
use std::{
    collections::{HashMap, hash_map::Entry},
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use axum::body::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::{Frame, SizeHint};
use parking_lot::Mutex;
use pin_project_lite::pin_project;
use tower::{BoxError, Layer, Service};
use tracing::{debug, warn};

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
            inner,
        }
    }
}

impl RateLimitLayer {
    pub fn new() -> Self {
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

        RateLimitLayer { inner: rl }
    }
}

#[derive(Clone)]
pub struct RateLimiter<S> {
    rl: Arc<RateLimiterInner>,
    inner: S,
}

struct RateLimiterInner {
    map: Mutex<HashMap<IpAddr, Bucket>>,
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

impl<S, ReqB, ResB> Service<Request<ReqB>> for RateLimiter<S>
where
    S: Service<Request<ReqB>, Response = Response<ResB>>,
    S::Error: Into<BoxError>,
    ResB: hyper::body::Body,
{
    type Response = Response<RLBody<ResB>>;
    type Error = BoxError;
    type Future = RateLimitFuture<S::Future>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, req: Request<ReqB>) -> Self::Future {
        let addr = req
            .extensions()
            .get::<SocketAddr>()
            .expect("we require every request to have it");

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
    }
}

impl<F, E, ResB> Future for RateLimitFuture<F>
where
    F: Future<Output = Result<Response<ResB>, E>>,
    E: Into<BoxError>,
    ResB: hyper::body::Body,
{
    type Output = Result<Response<RLBody<ResB>>, BoxError>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.project();
        match this {
            EnumProj::Ok { fut } => fut
                .poll(cx)
                .map_err(Into::into)
                .map(|f| f.map(|resp| resp.map(RLBody::new))),
            EnumProj::RateLimited => Poll::Ready(Ok(Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .body(RLBody::with_msg("too many requests"))
                .unwrap())),
        }
    }
}

pin_project! {
    pub struct RLBody<B> {
        #[pin]
        inner: RLBodyInner<B>
    }
}

impl<B> RLBody<B> {
    fn with_msg(str: &str) -> Self {
        Self {
            inner: RLBodyInner::Custom {
                body: Full::from(str.to_string()),
            },
        }
    }
    pub(crate) fn new(body: B) -> Self {
        Self {
            inner: RLBodyInner::Body { body },
        }
    }
}

pin_project! {
    #[project = BodyProj]
    enum RLBodyInner<B> {
        Custom {
            #[pin]
            body: Full<Bytes>,
        },
        Body {
            #[pin]
            body: B
        }
    }
}

impl<B> hyper::body::Body for RLBody<B>
where
    B: hyper::body::Body<Data = Bytes>,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.project().inner.project() {
            BodyProj::Custom { body } => body.poll_frame(cx).map_err(|err| match err {}),
            BodyProj::Body { body } => body.poll_frame(cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        match &self.inner {
            RLBodyInner::Custom { body } => body.is_end_stream(),
            RLBodyInner::Body { body } => body.is_end_stream(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match &self.inner {
            RLBodyInner::Custom { body } => body.size_hint(),
            RLBodyInner::Body { body } => body.size_hint(),
        }
    }
}
