use std::{sync::Arc, time::Duration};

use anyhow::Result;
use axum::{
    Router,
    body::Body,
    extract::Request,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use http::StatusCode;
use http::header::CACHE_CONTROL;
use hyper::server::conn::http1;
use hyper_util::{rt::TokioIo, service::TowerToHyperService};
use porto::{config::PortoConfig, utils::PeerAddr};
use tokio::task::JoinSet;
use tower::Service;
use tracing::{error, info};

pub async fn run_backends(config: Arc<PortoConfig>) {
    let route = Router::new()
        .route("/", get(echo))
        .route("/cache", get(cache))
        .route("/health", get(health))
        .route("/comp", get(comp))
        .route("/timeout", get(timeout))
        .layer(middleware::from_fn(log_handle));

    let mut set: JoinSet<Result<(), anyhow::Error>> = JoinSet::new();
    for peer in config.get_proxies() {
        let route = route.clone();
        set.spawn(async move {
            match peer.addr() {
                PeerAddr::Ipv4(sock_addr) => {
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
                PeerAddr::Uds(sock_path) => {
                    if sock_path.exists() {
                        tokio::fs::remove_file(sock_path)
                            .await
                            .inspect_err(|e| error!(%e))?;
                    }
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
}

async fn log_handle(req: Request, mut next: Next) -> impl IntoResponse {
    info!("received request: {req:?}");
    let resp = next.call(req).await;
    info!("replying with: {:?}", resp);
    resp
}

async fn _hyper(_: hyper::Request<hyper::body::Incoming>) -> http::Response<porto::utils::Body> {
    todo!()
}

async fn health() -> StatusCode {
    StatusCode::OK
}

async fn comp() -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .body(Body::from("this is a response body".repeat(10)))
        .expect("the values are hard coded")
}

async fn echo(req: Request) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .body(req.into_body())
        .expect("the values are hard coded")
}

async fn cache() -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(CACHE_CONTROL, "max-age=60")
        .body(Body::empty())
        .expect("the value are hard coded")
}

async fn timeout() -> Response {
    tokio::time::sleep(Duration::from_secs(10)).await;
    Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .expect("the value are hard coded")
}
