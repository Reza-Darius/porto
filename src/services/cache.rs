#![allow(dead_code)]

use std::{borrow::Borrow, collections::HashMap, sync::Arc};

use anyhow::{Result, anyhow};
use derive_more::Display;
use hyper::{Request, Response, StatusCode, body::Incoming, header::HOST};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tap::Tap;
use tower::{Layer, Service};
use tracing::debug;

use crate::utils::*;

trait CacheStore
where
    Self: Clone,
{
    fn get(&self, req: Request<Incoming>) -> Option<Response<Body>>;
    fn insert(&self, key: CacheKey, value: Response<Body>) -> Result<()>;
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

#[derive(Debug)]
struct StoreInner {
    store: Mutex<HashMap<CacheKey, Response<Body>>>,
}

#[derive(Debug, Clone)]
pub struct ResponseCacheLayer<C> {
    cache: C,
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
    cache: C,
    inner: S,
}

impl<S, C> Service<Request<Incoming>> for ResponseCache<S, C>
where
    S: Service<Request<Incoming>, Response = Response<Body>, Error = hyper::Error>,
    S::Future: Send + 'static,
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
        todo!()
    }
}
