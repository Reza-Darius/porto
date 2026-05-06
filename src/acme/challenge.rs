use std::future::Ready;

use anyhow::Result;
use hyper::{Request, Response, StatusCode, body::Incoming};
use tower::Service;
use tracing::{info, warn};

use crate::{
    acme::{AcmeWorkerMode, PortoTLS, acme_worker},
    utils::*,
};

#[derive(Clone)]
pub struct Http1ChallSvc {
    store: PortoTLS,
}

impl Http1ChallSvc {
    pub fn init(store: PortoTLS, mode: AcmeWorkerMode) -> Self {
        tokio::spawn(acme_worker(store.clone(), mode));
        Http1ChallSvc { store }
    }
}

impl Service<Request<Incoming>> for Http1ChallSvc {
    type Response = Response<Body>;
    type Error = anyhow::Error;

    type Future = Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(
        &mut self,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Incoming>) -> Self::Future {
        // http://<YOUR_DOMAIN>/.well-known/acme-challenge/<TOKEN>
        let Some(uri_token) = req
            .uri()
            .path()
            .strip_prefix("/.well-known/acme-challenge/")
        else {
            warn!(uri = req.uri().path(), "unknown URI");
            return std::future::ready(Ok(bad_request()));
        };

        info!(uri_token, "got ACME token");

        let resp = match self.store.inner.pending_challenges.lock().get(uri_token) {
            Some(key) => Response::new(full(key.as_str().to_string())),
            None => {
                warn!("no key authorization found for token!");
                response(StatusCode::NOT_FOUND)
            }
        };
        std::future::ready(Ok(resp))
    }
}
