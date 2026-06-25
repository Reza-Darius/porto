use std::{future::Ready, net::SocketAddr};

use anyhow::Result;
use hyper::{Request, Response, StatusCode, body::Incoming, server::conn::http1};
use hyper_util::{rt::TokioIo, service::TowerToHyperService};
use tokio::net::TcpListener;
use tower::Service;
use tracing::{error, info, warn};

use crate::{acme::PortoTLS, utils::*};

// OPTIMIZE: setup and tear this down as needed
pub fn setup_chall_server(addr: SocketAddr, store: PortoTLS) {
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
    store: PortoTLS,
}

impl Http1ChallSvc {
    pub fn new(store: PortoTLS) -> Self {
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
