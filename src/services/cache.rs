#![allow(dead_code, clippy::new_without_default)]

use std::{borrow::Borrow, collections::HashMap, sync::Arc};

use anyhow::{Result, anyhow};
use derive_more::Display;
use http_body_util::BodyExt;
use hyper::{
    Request, Response, StatusCode,
    body::{Bytes, Incoming},
    header::HOST,
};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tower::{Layer, Service};
use tracing::{debug, error, trace};

use crate::utils::*;

trait CacheStore
where
    Self: Clone,
{
    fn get(&self, req: &CacheKey) -> Option<Response<Body>>;
    fn insert(
        &self,
        key: CacheKey,
        value: Response<Body>,
    ) -> impl Future<Output = Result<Response<Body>>> + Send;
}

#[derive(Debug, Clone, Display, Hash, Eq, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
struct CacheKey(String);

impl Borrow<str> for CacheKey {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl CacheKey {
    fn from_req<B: hyper::body::Body>(req: &Request<B>) -> Result<Self> {
        let header = req.headers();
        let mut key: String = String::new();

        // key = method + ":" + host + path + "?" + query
        key.push_str(req.method().as_str());
        key.push(':');
        key.push_str(
            header
                .get(HOST)
                .ok_or_else(|| anyhow!("no host header found"))?
                .to_str()?,
        );
        key.push_str(req.uri().path());
        key.push('?');

        if let Some(query) = req.uri().query() {
            key.push_str(query);
        }

        debug!("new cache key: {key}");
        Ok(CacheKey(key))
    }
}

#[derive(Debug, Clone)]
struct Store {
    inner: Arc<StoreInner>,
}

impl Store {
    pub fn new() -> Self {
        Store {
            inner: Arc::new(StoreInner {
                store: Mutex::new(HashMap::new()),
            }),
        }
    }
}

impl CacheStore for Store {
    fn get(&self, key: &CacheKey) -> Option<Response<Body>> {
        trace!("trying to retrieve response with {key}");

        self.inner
            .store
            .lock()
            .get(key)
            .cloned()
            .map(|r| r.map(full))
    }

    async fn insert(&self, key: CacheKey, value: Response<Body>) -> Result<Response<Body>> {
        trace!("trying to insert response with {key}");

        let (parts, body) = value.into_parts();
        let body = body.collect().await?.to_bytes();
        let resp = Response::from_parts(parts, body);

        self.inner.store.lock().insert(key, resp.clone());
        Ok(resp.map(full))
    }
}

#[derive(Debug)]
struct StoreInner {
    store: Mutex<HashMap<CacheKey, Response<Bytes>>>,
}

#[derive(Debug, Clone)]
pub struct ResponseCacheLayer<C> {
    cache: C,
}

impl ResponseCacheLayer<Store> {
    pub fn new() -> Self {
        ResponseCacheLayer {
            cache: Store::new(),
        }
    }
}

impl<S, C: CacheStore> Layer<S> for ResponseCacheLayer<C> {
    type Service = ResponseCache<S, C>;

    fn layer(&self, inner: S) -> Self::Service {
        ResponseCache {
            cache: self.cache.clone(),
            inner,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ResponseCache<S, C> {
    inner: S,
    cache: C,
}

impl<S, C> Service<Request<Incoming>> for ResponseCache<S, C>
where
    S: Service<
            Request<Incoming>,
            Response = Response<Body>,
            Error = hyper::Error,
            Future = BoxFut<Response<Body>, hyper::Error>,
        > + Send
        + 'static,
    C: CacheStore + Send + 'static,
{
    type Response = Response<Body>;
    type Error = hyper::Error;
    type Future = BoxFut<Self::Response, Self::Error>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Incoming>) -> Self::Future {
        let Ok(key) = CacheKey::from_req(&req) else {
            error!("couldnt create key from request for cache");
            return self.inner.call(req);
        };

        if let Some(resp) = self.cache.get(&key) {
            debug!("retrieved response from cache");
            return Box::pin(async move { Ok(resp) });
        };

        let handle = self.cache.clone();
        let resp = self.inner.call(req);

        let f = async move {
            let Ok(resp) = resp.await else {
                return Ok(internal_error());
            };
            let Ok(resp) = handle.insert(key, resp).await else {
                error!("couldnt insert response into cache");
                return Ok(internal_error());
            };
            Ok(resp)
        };
        Box::pin(f)
    }
}
