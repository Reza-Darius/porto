use std::{ops::Deref, os::unix::net::UnixListener};

use anyhow::Result;
use axum::{
    Router,
    body::Body,
    extract::Request,
    handler::HandlerWithoutStateExt,
    response::{IntoResponse, Response},
    routing::get,
};
use http::StatusCode;
use http::header::CACHE_CONTROL;
use hyper::{server::conn::http1, service::service_fn};
use hyper_util::{rt::TokioIo, service::TowerToHyperService};
use porto::utils::{PeerAddr, PeerAddrInner, setup_tracing};
use tokio::{fs, task::JoinSet};
use tracing::{error, info};

#[tokio::main]
async fn main() -> Result<()> {
    setup_tracing();
    let listen_addr = ["127.0.0.2:8000", "127.0.0.3:8000", "/tmp/test_peer.sock"];
    let listen_addr: Vec<_> = listen_addr
        .iter()
        .map(|addr| PeerAddr::try_from(*addr).unwrap())
        .collect();

    let mut set: JoinSet<Result<(), anyhow::Error>> = JoinSet::new();
    for addr in listen_addr.into_iter() {
        set.spawn(async move {
            let route = Router::new()
                .route("/", get(echo))
                .route("/cache", get(cache));

            match addr.deref() {
                PeerAddrInner::Ipv4(sock_addr) => {
                    let listener = tokio::net::TcpListener::bind(sock_addr)
                        .await
                        .inspect_err(|e| error!(%e))?;
                    info!("listening on TCP {sock_addr}");

                    while let Ok((stream, _)) = listener.accept().await {
                        info!("connection on {sock_addr}");

                        let svc = TowerToHyperService::new(route.clone());
                        tokio::task::spawn(async move {
                            if let Err(err) = http1::Builder::new()
                                .serve_connection(TokioIo::new(stream), svc)
                                .await
                            {
                                error!("Error serving connection: {:?}", err);
                            }
                        });
                    }
                }
                PeerAddrInner::Uds(sock_path) => {
                    tokio::fs::remove_file(sock_path)
                        .await
                        .inspect_err(|e| error!(%e))?;
                    info!("listening on UDS {}", sock_path.display());

                    let addr = std::os::unix::net::SocketAddr::from_pathname(sock_path)?;
                    axum_server::bind(addr)
                        .serve(route.into_make_service())
                        .await
                        .inspect_err(|e| error!(%e))?;
                }
            };
            Ok(())
        });
    }
    set.join_all().await;

    Ok(())
}

async fn hyper(req: hyper::Request<hyper::body::Incoming>) -> http::Response<porto::utils::Body> {
    todo!()
}

async fn echo(req: Request) -> impl IntoResponse {
    info!("received request: {req:?}");

    let resp = Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty());

    info!("replying with: {:?}", resp);
    resp.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

async fn cache(req: Request) -> impl IntoResponse {
    info!("received request: {req:?}");

    let resp = Response::builder()
        .status(StatusCode::OK)
        .header(CACHE_CONTROL, "max-age=60")
        .body(Body::empty());

    info!("replying with: {:?}", resp);
    resp.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}
