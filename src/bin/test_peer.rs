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
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    setup_tracing();
    let args: Vec<String> = std::env::args().collect();
    let addr = PeerAddr::try_from(args[1].as_str())?;

    let route = Router::new()
        .route("/", get(echo))
        .route("/cache", get(cache));

    match addr.deref() {
        PeerAddrInner::Ipv4(sock_addr) => {
            let listener = tokio::net::TcpListener::bind(sock_addr).await?;
            info!("listening on TCP {}", sock_addr);

            while let Ok((stream, _)) = listener.accept().await {
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
