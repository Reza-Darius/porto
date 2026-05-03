use std::ops::Deref;

use anyhow::Result;
use http::StatusCode;
use http::header::CACHE_CONTROL;
use http_body_util::BodyExt;
use hyper::service::service_fn;
use hyper::{Request, Response, body::Incoming, server::conn::http1};
use hyper_util::rt::TokioIo;
use porto::utils::{Body, PeerAddr, PeerAddrInner, setup_tracing};
use tokio::net::{TcpListener, UnixListener};
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    setup_tracing();
    let args: Vec<String> = std::env::args().collect();
    let addr = PeerAddr::try_from(args[1].as_str())?;

    match addr.deref() {
        PeerAddrInner::Ipv4(sock_addr) => {
            let listener = TcpListener::bind(sock_addr).await?;
            info!("listening on TCP {}", sock_addr);

            while let Ok((stream, _)) = listener.accept().await {
                tokio::task::spawn(async move {
                    if let Err(err) = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service_fn(echo))
                        .await
                    {
                        println!("Error serving connection: {:?}", err);
                    }
                });
            }
        }
        PeerAddrInner::Uds(sock_path) => {
            let listener = UnixListener::bind(sock_path.clone())?;
            info!("listening on UDS {}", sock_path.display());

            while let Ok((stream, _)) = listener.accept().await {
                tokio::task::spawn(async move {
                    if let Err(err) = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service_fn(echo))
                        .await
                    {
                        println!("Error serving connection: {:?}", err);
                    }
                });
            }
        }
    };

    Ok(())
}

async fn echo(req: Request<Incoming>) -> Result<Response<Body>, anyhow::Error> {
    info!("received request: {req:?}");
    let resp = match req.uri().path() {
        uri if uri.contains("cache") => Response::builder()
            .status(StatusCode::OK)
            .header(CACHE_CONTROL, "max-age=60")
            .body(req.into_body().map_err(Into::into).boxed())
            .map_err(Into::into),

        _ => Response::builder()
            .status(StatusCode::OK)
            .body(req.into_body().map_err(Into::into).boxed())
            .map_err(Into::into),
    };
    info!("replying with: {:?}", resp);
    resp
}
