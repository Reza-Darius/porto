#![allow(dead_code, clippy::new_without_default)]

use std::{borrow::Borrow, collections::HashMap, sync::Arc, task::Poll};

use anyhow::{Result, anyhow};
use derive_more::Display;
use http_body_util::BodyExt;
use hyper::{
    Request, Response,
    body::{Bytes, Incoming},
    header::HOST,
};
use parking_lot::Mutex;
use pin_project_lite::pin_project;
use tower::{Layer, Service};
use tracing::{debug, error};

use crate::utils::*;

trait CacheStore
where
    Self: Clone + Send + 'static,
{
    fn get(&self, req: &CacheKey) -> Option<Response<Body>>;
    fn insert(&self, key: CacheKey, value: Response<Body>)
    -> BoxFut<Response<Body>, anyhow::Error>;
}

#[derive(Debug, Clone, Display, Hash, Eq, PartialEq, PartialOrd, Ord)]
struct CacheKey(String);

impl Borrow<str> for CacheKey {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl CacheKey {
    fn from_req<B>(req: &Request<B>) -> Result<Self> {
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
pub struct Store {
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
        debug!("trying to retrieve response with {key}");

        self.inner
            .store
            .lock()
            .get(key)
            .cloned()
            .map(|r| r.map(full))
    }

    fn insert(
        &self,
        key: CacheKey,
        value: Response<Body>,
    ) -> BoxFut<Response<Body>, anyhow::Error> {
        let handle = self.inner.clone();
        Box::pin(async move {
            debug!("trying to insert response with {key}");

            let (parts, body) = value.into_parts();
            let body = body.collect().await?.to_bytes();
            let resp = Response::from_parts(parts, body);

            handle.store.lock().insert(key, resp.clone());
            Ok(resp.map(full))
        })
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

impl<S, C, B> Service<Request<B>> for ResponseCache<S, C>
where
    S: Service<Request<B>, Response = Response<Body>> + Send + 'static,
    S::Error: Into<anyhow::Error>,
    S::Future: Send + 'static,
    C: CacheStore,
{
    type Response = S::Response;
    type Error = anyhow::Error;
    type Future = CacheResponseFuture<S::Future, C>;
    // type Future = BoxFut<Self::Response, Self::Error>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }
    fn call(&mut self, req: Request<B>) -> Self::Future {
        let Ok(key) = CacheKey::from_req(&req)
            .inspect_err(|e| error!(%e, "couldnt create key from request for cache"))
        else {
            return CacheResponseFuture::CacheMiss {
                svc_fut: self.inner.call(req),
                cache_handle: None,
                svc_resp: None,
                collect_fut: None,
            };
        };

        if let Some(resp) = self.cache.get(&key) {
            debug!("cache hit!");
            return CacheResponseFuture::CacheHit { resp: Some(resp) };
        };

        CacheResponseFuture::CacheMiss {
            svc_fut: self.inner.call(req),
            cache_handle: Some((self.cache.clone(), key)),
            svc_resp: None,
            collect_fut: None,
        }
    }

    // fn call(&mut self, req: Request<Incoming>) -> Self::Future {
    //     let Ok(key) = CacheKey::from_req(&req) else {
    //         error!("couldnt create key from request for cache");
    //         let fut = self.inner.call(req);
    //         return Box::pin(async { fut.await.map_err(Into::into) });
    //     };

    //     if let Some(resp) = self.cache.get(&key) {
    //         debug!("retrieved response from cache");
    //         return Box::pin(async move { Ok(resp) });
    //     };

    //     let cache = self.cache.clone();
    //     let fut = self.inner.call(req);

    //     Box::pin(async move {
    //         let Ok(resp) = fut.await else {
    //             return Ok(internal_error());
    //         };
    //         let Ok(resp) = cache.insert(key, resp).await else {
    //             error!("couldnt insert response into cache");
    //             return Ok(internal_error());
    //         };
    //         Ok(resp)
    //     })
    // }
}

pin_project! {
    #[project = EnumProj]
    pub enum CacheResponseFuture<F, C> {
        /// in case of a cache miss, we call the inner service
        /// if there is no handle provided, we have to assume we cannot cache the response
        CacheMiss{
            #[pin] svc_fut: F,
            cache_handle: Option<(C, CacheKey)>,
            svc_resp: Option<Response<Body>>,
            collect_fut: Option<BoxFut<Response<Body>, anyhow::Error>>
        },
        /// we got something to return immediately!
        /// the option type is only for calling .take()
        CacheHit{ resp: Option<Response<Body>>}
    }
}

impl<F, E, C> Future for CacheResponseFuture<F, C>
where
    F: Future<Output = Result<Response<Body>, E>> + Send + 'static,
    E: Into<anyhow::Error>,
    C: CacheStore,
{
    type Output = Result<Response<Body>, anyhow::Error>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.project();

        match this {
            EnumProj::CacheHit { resp } => {
                Poll::Ready(Ok(resp.take().expect("we are done and wont poll it again")))
            }
            EnumProj::CacheMiss {
                mut svc_fut,
                cache_handle,
                svc_resp,
                collect_fut,
            } => {
                loop {
                    // we inserted into the cache, poll it until we get a response
                    if let Some(fut) = collect_fut.as_mut() {
                        match fut.as_mut().poll(cx) {
                            Poll::Pending => return Poll::Pending,
                            Poll::Ready(Ok(resp)) => return Poll::Ready(Ok(resp)),
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        }
                    }

                    // did we call the service?
                    match svc_resp.take() {
                        // we called the service and we have a handle and key to cache the response
                        Some(resp) if let Some((cache, key)) = cache_handle.take() => {
                            let fut = cache.insert(key.clone(), resp);
                            *collect_fut = Some(fut);
                            return Poll::Pending;
                        }
                        // return without caching
                        Some(resp) => return Poll::Ready(Ok(resp)),
                        // call the service
                        None => match svc_fut.as_mut().poll(cx) {
                            Poll::Pending => return Poll::Pending,
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                            Poll::Ready(Ok(resp)) => {
                                *svc_resp = Some(resp);
                                continue; // we could alternatively return poll pending here
                            }
                        },
                    };
                }

                // if let Some(resp) = svc_resp.take() {
                //     if let Some((cache, key)) = handle.take() {
                //         let fut = cache.insert(key.clone(), resp);
                //         *collect_fut = Some(fut);
                //         return Poll::Pending;
                //     } else {
                //         // we dont cache and return immediately
                //         return Poll::Ready(Ok(resp));
                //     }
                // }

                // // poll the inner service
                // match svc_fut.poll(cx) {
                //     Poll::Pending => Poll::Pending,
                //     Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
                //     Poll::Ready(Ok(resp)) => {
                //         *svc_resp = Some(resp);
                //         Poll::Pending // next poll will handle it
                //     }
                // }
            }
        }
    }
}
