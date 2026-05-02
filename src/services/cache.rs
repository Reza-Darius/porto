#![allow(dead_code, clippy::new_without_default)]

use std::{
    borrow::Borrow,
    collections::HashMap,
    sync::Arc,
    task::Poll,
    time::{Duration, SystemTime},
};

use anyhow::{Result, anyhow};
use derive_more::Display;
use http::request::Parts;
use http_body_util::{BodyExt, combinators::BoxBody};
use http_cache_semantics::{AfterResponse, CachePolicy};
use hyper::{Request, Response, body::Bytes};
use parking_lot::Mutex;
use pin_project_lite::pin_project;
use tower::{Layer, Service, ServiceExt};
use tracing::{debug, error};

use crate::utils::*;

const START: SystemTime = SystemTime::UNIX_EPOCH;
static CURRENT_TIME: Mutex<SystemTime> = Mutex::new(START);

pub fn current_time() -> SystemTime {
    *CURRENT_TIME.lock()
}

pub fn current_duration() -> Duration {
    current_time().duration_since(START).unwrap()
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
        let mut key: String = String::new();

        // key = method + ":" + host + path + "?" + query
        key.push_str(req.method().as_str());
        key.push(':');
        // alternatively get PeerAddr from extension
        key.push_str(get_target_host(req).ok_or_else(|| anyhow!("no host header found for key"))?);
        key.push_str(req.uri().path());

        if let Some(query) = req.uri().query() {
            key.push('?');
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

#[derive(Debug, Clone)]
struct StoreEntry {
    policy: CachePolicy,
    body: Bytes,
}

#[derive(Debug)]
struct StoreInner {
    store: Mutex<HashMap<CacheKey, StoreEntry>>,
}

#[derive(Debug, Clone)]
pub struct ResponseCacheLayer {
    cache: Store,
}

impl ResponseCacheLayer {
    pub fn new() -> Self {
        ResponseCacheLayer {
            cache: Store::new(),
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
pub struct ResponseCache<S> {
    store: Store,
    inner: S,
}

impl<S, B> Service<Request<B>> for ResponseCache<S>
where
    S: Service<Request<B>, Response = Response<Body>> + Send + 'static + Clone,
    S::Error: Into<anyhow::Error>,
    S::Future: Send + 'static,
    B: hyper::body::Body + Send + Sync + 'static,
{
    type Response = S::Response;
    type Error = anyhow::Error;
    // type Future = CacheResponseFuture<S::Future, C>;
    type Future = BoxFut<Self::Response, Self::Error>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }
    #[allow(clippy::needless_return)]
    fn call(&mut self, req: Request<B>) -> Self::Future {
        let store = self.store.clone();

        /*
         * Services are permitted to panic if call is invoked without obtaining Poll::Ready(Ok(())) from poll_ready.
         * You should therefore be careful when cloning services for example to move them into boxed futures.
         * Even though the original service is ready, the clone might not be.
         */
        let clone = self.inner.clone();
        // take the service that was ready
        let mut inner = std::mem::replace(&mut self.inner, clone);

        Box::pin(async move {
            let Ok(key) = CacheKey::from_req(&req) else {
                return Err(anyhow!("couldnt create cache key"));
            };

            let (req_parts, req_body) = req.into_parts();
            let e = store.inner.store.lock().get(&key).cloned();

            if let Some(entry) = e {
                match entry.policy.before_request(&req_parts, SystemTime::now()) {
                    http_cache_semantics::BeforeRequest::Fresh(parts) => {
                        debug!("cache hit!");
                        let body = full(entry.body.clone());
                        return Ok(Response::from_parts(parts, body));
                    }
                    http_cache_semantics::BeforeRequest::Stale { mut request, .. } => {
                        debug!(?request, "cache calling service");

                        // we have to carry over the PeerAddr extension
                        request.extensions.insert(
                            req_parts
                                .extensions
                                .get::<PeerAddr>()
                                .cloned()
                                .expect("this cant fail, unless the addr layer isnt called"),
                        );

                        let new_req = Request::from_parts(request.clone(), req_body);

                        let Ok(mut resp) = inner
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
                                let body = full(entry.body.clone());
                                resp = Response::from_parts(new_resp, body);

                                store.inner.store.lock().insert(
                                    key,
                                    StoreEntry {
                                        policy: new_policy,
                                        body: entry.body,
                                    },
                                );
                            } else {
                                let (parts, body) = resp.into_parts();
                                debug!(?parts, "updating full cache entry");
                                let body = body.collect().await.unwrap().to_bytes();
                                store.inner.store.lock().insert(
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
                            debug!("not storable");
                        }
                        return Ok(resp);
                    }
                };
            } else {
                let Ok(mut resp) = inner
                    .call(Request::from_parts(req_parts.clone(), req_body))
                    .await
                else {
                    return Ok(internal_error());
                };

                let new_policy = CachePolicy::new(&req_parts, &resp);
                if new_policy.is_storable() {
                    debug!("inserting new cache entry");
                    let (resp_parts, resp_body) = resp.into_parts();
                    let body = resp_body.collect().await.unwrap().to_bytes();
                    store.inner.store.lock().insert(
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

// enum CacheControl {
//     NoCache,
// }

// pin_project! {
//     #[project = EnumProj]
//     pub enum CacheResponseFuture<F, C> {
//         /// in case of a cache miss, we call the inner service
//         /// if there is no handle provided, we have to assume we cannot cache the response
//         CacheMiss{
//             #[pin] svc_fut: F,
//             cache_handle: Option<(C, CacheKey)>,
//             svc_resp: Option<Response<Body>>,
//             collect_fut: Option<BoxFut<Response<Body>, anyhow::Error>>
//         },
//         /// we got something to return immediately!
//         /// the option type is only for calling .take()
//         CacheHit{ resp: Option<Response<Body>>}
//     }
// }

// impl<F, E, C> Future for CacheResponseFuture<F, C>
// where
//     F: Future<Output = Result<Response<Body>, E>> + Send + 'static,
//     E: Into<anyhow::Error>,
//     C: CacheStore,
// {
//     type Output = Result<Response<Body>, anyhow::Error>;

//     fn poll(
//         self: std::pin::Pin<&mut Self>,
//         cx: &mut std::task::Context<'_>,
//     ) -> std::task::Poll<Self::Output> {
//         let this = self.project();

//         match this {
//             EnumProj::CacheHit { resp } => {
//                 Poll::Ready(Ok(resp.take().expect("we are done and wont poll it again")))
//             }
//             EnumProj::CacheMiss {
//                 mut svc_fut,
//                 cache_handle,
//                 svc_resp,
//                 collect_fut,
//             } => {
//                 loop {
//                     // we inserted into the cache, poll it until we get a response
//                     if let Some(fut) = collect_fut.as_mut() {
//                         match fut.as_mut().poll(cx) {
//                             Poll::Pending => return Poll::Pending,
//                             Poll::Ready(Ok(resp)) => return Poll::Ready(Ok(resp)),
//                             Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
//                         }
//                     }

//                     // did we call the service?
//                     match svc_resp.take() {
//                         // we called the service and we have a handle and key to cache the response
//                         Some(resp) if let Some((cache, key)) = cache_handle.take() => {
//                             let fut = cache.insert(key.clone(), resp);
//                             *collect_fut = Some(fut);
//                             continue;
//                         }
//                         // return without caching
//                         Some(resp) => return Poll::Ready(Ok(resp)),
//                         // call the service
//                         None => {
//                             match svc_fut.as_mut().poll(cx) {
//                                 Poll::Pending => return Poll::Pending,
//                                 Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
//                                 Poll::Ready(Ok(resp)) => {
//                                     *svc_resp = Some(resp);
//                                     continue; // we could alternatively return poll pending here
//                                 }
//                             }
//                         }
//                     };
//                 }
//             }
//         }
//     }
// }
