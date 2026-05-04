use std::ops::Deref;

use anyhow::Result;
use axum::{
    Router,
    body::Body,
    extract::Request,
    response::{IntoResponse, Response},
    routing::get,
};
use http::StatusCode;
use http::header::CACHE_CONTROL;
use hyper::server::conn::http1;
use hyper_util::{rt::TokioIo, service::TowerToHyperService};
use porto::utils::{PeerAddr, PeerAddrInner, setup_tracing};
use tokio::task::JoinSet;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    setup_tracing();
    let addr = ["127.0.0.2:8000", "127.0.0.3:8000", "/tmp/test_peer.sock"];
    let addr: Vec<_> = addr
        .iter()
        .map(|addr| PeerAddr::try_from(*addr).unwrap())
        .collect();

    let mut set: JoinSet<Result<(), anyhow::Error>> = JoinSet::new();
    for addr in addr.into_iter() {
        set.spawn(async move {
            let route = Router::new()
                .route("/", get(echo))
                .route("/cache", get(cache));

            match addr.deref() {
                PeerAddrInner::Ipv4(sock_addr) => {
                    let listener = tokio::net::TcpListener::bind(sock_addr).await?;
                    info!("listening on TCP {sock_addr}");

                    while let Ok((stream, _)) = listener.accept().await {
                        info!("connection on {sock_addr}");
                        let svc = TowerToHyperService::new(route.clone());
                        tokio::task::spawn(async move {
                            if let Err(err) = http1::Builder::new()
                                .serve_connection(TokioIo::new(stream), svc)
                                .await
                            {
                                println!("Error serving connection: {:?}", err);
                            }
                        });
                    }
                }
                PeerAddrInner::Uds(sock_path) => {
                    info!("listening on UDS {}", sock_path.display());
                    let addr = std::os::unix::net::SocketAddr::from_pathname(sock_path)?;
                    axum_server::bind(addr)
                        .serve(route.into_make_service())
                        .await?;
                }
            };
            Ok(())
        });
    }
    set.join_all().await;

    Ok(())
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
