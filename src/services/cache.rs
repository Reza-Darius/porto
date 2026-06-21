#![allow(dead_code, clippy::new_without_default)]

use std::{borrow::Borrow, sync::Arc, time::SystemTime};

use derive_more::Display;
use foyer::{Cache, CacheBuilder, EvictionConfig, S3FifoConfig};
use futures::{FutureExt, TryFutureExt};
use http_body_util::BodyExt;
use http_cache_semantics::{AfterResponse, CachePolicy};
use hyper::{Request, Response, body::Bytes};
use tower::{BoxError, Layer, Service};
use tracing::{debug, error};

use crate::utils::*;

#[derive(Debug, Clone)]
pub struct ResponseCache<S> {
    store: Store,
    inner: S,
}

impl<S, B> Service<Request<B>> for ResponseCache<S>
where
    S: Service<Request<B>, Response = Response<Body>> + Send + 'static + Clone,
    S::Error: Into<BoxError>,
    S::Future: Send + 'static,
    B: hyper::body::Body + Send + Sync + 'static,
{
    type Response = S::Response;
    type Error = BoxError;
    type Future = SvcBoxFut<Self::Response, Self::Error>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    #[allow(clippy::needless_return)]
    fn call(&mut self, req: Request<B>) -> Self::Future {
        let store = self.store.clone();
        let mut svc = svc_clone(&mut self.inner);

        let Some(peer) = req.extensions().get::<Peer>() else {
            return boxfut_err("No Peer Info found on request");
        };

        if !peer.config().cache {
            return svc.call(req).map_err(Into::into).boxed();
        }

        Box::pin(async move {
            let Ok(key) = CacheKey::from_req(&req) else {
                let e = Box::new(CacheError::CantCreateKey);
                return Err(e.into());
            };

            let (req_parts, req_body) = req.into_parts();
            let e = store.inner.store.get(&key);

            if let Some(entry) = e {
                match entry.policy.before_request(&req_parts, SystemTime::now()) {
                    http_cache_semantics::BeforeRequest::Fresh(parts) => {
                        debug!("cache hit!");
                        let body = full(entry.body.clone());
                        return Ok(Response::from_parts(parts, body));
                    }
                    http_cache_semantics::BeforeRequest::Stale { mut request, .. } => {
                        debug!(?request, "cache calling service");

                        // we have to carry over the Peer extension
                        request.extensions.insert(
                            req_parts
                                .extensions
                                .get::<Peer>()
                                .cloned()
                                .ok_or_else(|| BoxError::from("No Peer info found on request".to_string()))?
                        );

                        let new_req = Request::from_parts(request.clone(), req_body);

                        let Ok(mut resp) = svc
                            .call(new_req)
                            .await
                            .map_err(Into::into)
                            .inspect_err(|e| error!(%e))
                        else {
                            return Ok(internal_error());
                        };
                        let after_resp =
                            entry
                                .policy
                                .after_response(&request, &resp, SystemTime::now());

                        let (not_modified, new_policy, new_resp) = match after_resp {
                            AfterResponse::NotModified(p, r) => (true, p, r),
                            AfterResponse::Modified(p, r) => (false, p, r),
                        };
                        if new_policy.is_storable() {
                            if not_modified {
                                // and reconstruct the response from our cached bits
                                store.inner.store.insert(
                                    key,
                                    StoreEntry {
                                        policy: new_policy,
                                        body: entry.body.clone(),
                                    },
                                );

                                resp = Response::from_parts(new_resp, full(entry.body.clone()));
                            } else {
                                let (parts, body) = resp.into_parts();
                                debug!(?parts, "updating full cache entry");
                                let body = body.collect().await?.to_bytes();
                                store.inner.store.insert(
                                    key,
                                    StoreEntry {
                                        policy: new_policy,
                                        body: body.clone(),
                                    },
                                );

                                let body = full(body.clone());
                                resp = Response::from_parts(parts, body);
                            }
                        } else {
                            debug!("response is deemed not storable");
                        }
                        return Ok(resp);
                    }
                };
            // no cache entry
            } else {
                let Ok(mut resp) = svc
                    .call(Request::from_parts(req_parts.clone(), req_body))
                    .await
                else {
                    return Ok(internal_error());
                };

                let new_policy = CachePolicy::new(&req_parts, &resp);
                if new_policy.is_storable() {
                    debug!("inserting new cache entry");

                    let (resp_parts, resp_body) = resp.into_parts();
                    let body = resp_body.collect().await?.to_bytes();
                    store.inner.store.insert(
                        key,
                        StoreEntry {
                            policy: new_policy,
                            body: body.clone(),
                        },
                    );

                    resp = Response::from_parts(resp_parts, full(body));
                } else {
                    debug!("entry was not considered storable");
                }
                return Ok(resp);
            };
        })
    }
}

#[derive(Debug, Clone)]
pub struct ResponseCacheLayer {
    cache: Store,
}

impl ResponseCacheLayer {
    pub fn new(cap: usize) -> Self {
        ResponseCacheLayer {
            cache: Store::new(cap),
        }
    }
}

impl<S> Layer<S> for ResponseCacheLayer {
    type Service = ResponseCache<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ResponseCache {
            store: self.cache.clone(),
            inner,
        }
    }
}

#[derive(Debug, Clone)]
struct Store {
    inner: Arc<StoreInner>,
}

impl Store {
    pub fn new(cap: usize) -> Self {
        let cache = CacheBuilder::new(cap)
            .with_eviction_config(EvictionConfig::S3Fifo(S3FifoConfig::default()))
            .build();
        Store {
            inner: Arc::new(StoreInner { store: cache }),
        }
    }
}

#[derive(Debug, Clone)]
struct StoreEntry {
    policy: CachePolicy,
    body: Bytes,
}

#[derive(Debug)]
struct StoreInner {
    store: Cache<CacheKey, StoreEntry>,
}

#[derive(Debug, Clone, Display, Hash, Eq, PartialEq, PartialOrd, Ord)]
struct CacheKey(String);

impl Borrow<str> for CacheKey {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl CacheKey {
    fn from_req<B>(req: &Request<B>) -> Result<Self, CacheError> {
        // key = method + ":" + host + path + "?" + query
        let mut key: String = String::new();

        key.push_str(req.method().as_str());
        key.push(':');

        // alternatively get PeerAddr from extension
        key.push_str(get_target_host(req).ok_or(CacheError::CantCreateKey)?);
        key.push_str(req.uri().path());

        if let Some(query) = req.uri().query() {
            key.push('?');
            key.push_str(query);
        }

        debug!("new cache key: {key}");
        Ok(CacheKey(key))
    }
}

#[derive(thiserror::Error, Debug)]
pub enum CacheError {
    #[error("couldnt create key")]
    CantCreateKey,
}
