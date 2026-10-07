use std::{
    collections::HashMap, convert::Infallible, future::Ready, net::SocketAddr, sync::Arc,
    task::Poll,
};

use anyhow::Result;
use hyper::{Request, Response, StatusCode, server::conn::http1};
use hyper_util::{rt::TokioIo, service::TowerToHyperService};
use instant_acme::KeyAuthorization;
use parking_lot::{MappedMutexGuard, Mutex, MutexGuard};
use pin_project_lite::pin_project;
use tokio::net::TcpListener;
use tower::{BoxError, Service};
use tracing::{debug, error, info, warn};

use crate::{tls::cert_types::AcmeToken, utils::*};

/// cheap clonable handle to a store for ACME challenges
#[derive(Clone)]
pub struct ChallStore {
    inner: Arc<ChallStoreInner>,
}

struct ChallStoreInner {
    /// tokens for ACME challenges
    map: Mutex<HashMap<AcmeToken, KeyAuthorization>>,
}

impl ChallStore {
    pub fn new() -> Self {
        ChallStore {
            inner: Arc::new(ChallStoreInner {
                map: Mutex::new(HashMap::new()),
            }),
        }
    }

    pub fn register_challenge(&self, token: AcmeToken, key: KeyAuthorization) {
        self.inner.map.lock().insert(token, key);
    }

    pub fn check_request<ReqB, RespB>(
        &self,
        req: &Request<ReqB>,
    ) -> Option<Response<ResponseBody<RespB>>> {
        // http://<YOUR_DOMAIN>/.well-known/acme-challenge/<TOKEN>
        let uri_token = req
            .uri()
            .path()
            .strip_prefix("/.well-known/acme-challenge/")?;

        debug!(uri_token, "got ACME http challenge");

        self.inner
            .map
            .lock()
            .get(uri_token)
            .map(|key| Response::new(ResponseBody::full(key.as_str().to_string())))
    }

    pub fn get_chall_token(&self, token: &str) -> Option<MappedMutexGuard<'_, KeyAuthorization>> {
        let guard = self.inner.map.lock();
        MutexGuard::try_map(guard, |map| map.get_mut(token)).ok()
    }

    // pub fn remove_challenge(&self, token: &AcmeToken) {
    //     self.inner.map.lock().remove(token);
    // }

    pub fn clear(&self) {
        self.inner.map.lock().clear();
    }
}

// OPTIMIZE: setup and tear this down as needed
pub fn setup_chall_server(addr: SocketAddr, store: ChallStore) {
    tokio::spawn(async move {
        let listener = TcpListener::bind(addr).await.inspect_err(|e| error!(%e))?;
        let svc = Http1ChallSvc::new(store);

        info!("acme server listening on {addr}");

        while let Ok(con) = listener.accept().await {
            let svc = TowerToHyperService::new(svc.clone());
            http1::Builder::new()
                .serve_connection(TokioIo::new(con.0), svc)
                .await
                .inspect_err(|e| error!(%e))?;
        }
        Ok::<(), anyhow::Error>(())
    });
}

#[derive(Clone)]
pub struct Http1ChallSvc {
    store: ChallStore,
}

impl Http1ChallSvc {
    pub fn new(store: ChallStore) -> Self {
        Http1ChallSvc { store }
    }
}

impl<ReqB> Service<Request<ReqB>> for Http1ChallSvc {
    type Response = Response<Body>;
    type Error = Infallible;

    type Future = Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(
        &mut self,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<ReqB>) -> Self::Future {
        // http://<YOUR_DOMAIN>/.well-known/acme-challenge/<TOKEN>
        let Some(uri_token) = req
            .uri()
            .path()
            .strip_prefix("/.well-known/acme-challenge/")
        else {
            warn!(uri = req.uri().path(), "unknown URI");
            return std::future::ready(Ok(bad_request()));
        };

        debug!(uri_token, "got ACME token");

        let resp = match self.store.get_chall_token(uri_token) {
            Some(key) => Response::new(full(key.as_str().to_string())),
            None => {
                warn!("no key authorization found for token!");
                response(StatusCode::NOT_FOUND)
            }
        };
        std::future::ready(Ok(resp))
    }
}

#[derive(Clone)]
pub struct Http1ChallMiddleware<S> {
    store: ChallStore,
    inner: S,
}

impl<S> Http1ChallMiddleware<S> {
    pub fn new(store: ChallStore, inner: S) -> Self {
        Http1ChallMiddleware { store, inner }
    }
}

impl<S, ReqB, RespB> Service<Request<ReqB>> for Http1ChallMiddleware<S>
where
    S: Service<Request<ReqB>, Response = Response<RespB>>,
{
    type Response = Response<ResponseBody<RespB>>;
    type Error = S::Error;
    type Future = Http1ChallFut<S::Future, RespB>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqB>) -> Self::Future {
        self.store
            .check_request(&req)
            .map(|resp| Http1ChallFut::ChallResp { resp: Some(resp) })
            .unwrap_or_else(|| Http1ChallFut::Inner {
                fut: self.inner.call(req),
            })
    }
}

pin_project! {
    #[project = EnumProj]
    pub enum Http1ChallFut<F, ResB> {
        Inner{#[pin] fut: F},
        ChallResp{resp: Option<Response<ResponseBody<ResB>>>},
    }
}

impl<F, E, ResB> Future for Http1ChallFut<F, ResB>
where
    F: Future<Output = Result<Response<ResB>, E>>,
{
    type Output = Result<Response<ResponseBody<ResB>>, E>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.project();
        match this {
            EnumProj::Inner { fut } => fut
                .poll(cx)
                .map(|f| f.map(|resp| resp.map(ResponseBody::wrap))),
            EnumProj::ChallResp { resp } => Poll::Ready(Ok(resp.take().unwrap())),
        }
    }
}
