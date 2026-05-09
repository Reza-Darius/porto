use std::io::ErrorKind;
use std::net::SocketAddr;

use anyhow::Result;
use hyper::Request;
use hyper_util::rt::TokioExecutor;
use hyper_util::server::conn::auto::Builder;
use hyper_util::server::graceful::Watcher;
use hyper_util::{rt::TokioIo, service::TowerToHyperService};
use porto::services::{HealthServiceConfig, setup_health_service};
use std::time::Instant;
use tap::Pipe;
use tikv_jemallocator::Jemalloc;
use tokio::net::TcpStream;
use tokio::select;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;
use tracing::{debug, error, info};

use porto::config::*;
use porto::services::*;
use porto::setup::*;
use porto::utils::*;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[tokio::main]
async fn main() -> Result<()> {
    setup_tracing();

    let config = setup_config()?;
    let listener = setup_listener(&config);
    let tls_acceptor = setup_tls_from_file(&config)?;
    let peers = PeerTable::init(&config);

    let service = setup_service4(&config, peers.clone());
    setup_health_service(HealthServiceConfig::default(), peers);

    let graceful = hyper_util::server::graceful::GracefulShutdown::new();
    let mut signal = std::pin::pin!(shutdown_signal());

    info!("listening on {}", config.get_addr());

    loop {
        let tls_acceptor = tls_acceptor.clone();
        let watcher = graceful.watcher();
        let service = service.clone();

        select! {
            Ok((tcp_stream, remote_addr)) = listener.accept() => {
                tokio::spawn(async move {
                    if is_tls(&tcp_stream).await {
                        handle_https(tcp_stream, remote_addr, tls_acceptor, service, watcher).await;
                    } else {
                        handle_http(tcp_stream, remote_addr, service, watcher).await;
                    }
                });
            }
            _ = &mut signal => {
                drop(listener);
                info!("shutting down server");
                break;
            }
        }
    }

    select! {
        _ = graceful.shutdown() => {
            info!("all connections closed");
        },
        _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {
            info!("timed out wait for all connections to close");
        }
    }
    Ok(())
}

async fn handle_https(
    stream: TcpStream,
    addr: SocketAddr,
    tls: TlsAcceptor,
    service: HyperService,
    watcher: Watcher,
) {
    // TLS handshake
    let t = Instant::now();
    let tls_stream = match tls.accept(stream).await {
        Ok(tls_stream) => TokioIo::new(tls_stream),
        Err(e) => {
            error!(?e, "failed to perform tls handshake");
            return;
        }
    };
    debug!(duration_ms = t.elapsed().as_millis(), "TLS handshake time");

    // attaching infos for rate limiting
    let service = service
        .map_request(move |mut req: Request<_>| {
            req.extensions_mut().insert(addr);
            req
        })
        .pipe(TowerToHyperService::new);

    let builder = Builder::new(TokioExecutor::new());
    let conn = builder
        .serve_connection(tls_stream, service)
        .pipe(|c| watcher.watch(c));

    if let Err(e) = conn.await {
        // ignoring rustls EOF errors
        if let Some(e) = e.downcast_ref::<std::io::Error>() {
            if e.kind() != ErrorKind::UnexpectedEof {
                error!("got MyError: {:?}", e);
            }
        } else {
            error!("error when serving connection {e:#}");
        }
    };

    debug!("stream closed");
}

async fn handle_http(stream: TcpStream, addr: SocketAddr, service: HyperService, watcher: Watcher) {
    // attaching infos for rate limiting
    let service = service
        .map_request(move |mut req: Request<_>| {
            req.extensions_mut().insert(addr);
            req
        })
        .pipe(TowerToHyperService::new);

    if let Err(e) = Builder::new(TokioExecutor::new())
        .serve_connection(TokioIo::new(stream), service)
        .pipe(|c| watcher.watch(c))
        .await
    {
        error!("error when serving connection {e:#}");
    };
    debug!("stream closed");
}
