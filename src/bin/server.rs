use std::io::ErrorKind;
use std::time::Duration;

use anyhow::Result;
use http_body_util::BodyExt;
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioExecutor;
use hyper_util::server::conn::auto::Builder;
use hyper_util::{rt::TokioIo, service::TowerToHyperService};
use proxy::config::{PortoConfig, setup_config};
use tap::Pipe;
use tikv_jemallocator::Jemalloc;
use tokio::select;
use tokio::time::Instant;
use tower::{ServiceBuilder, ServiceExt};
use tower_http::{timeout::TimeoutLayer, trace::TraceLayer};
use tracing::{debug, error, info};

use proxy::services::upstream::*;
use proxy::setup::*;
use proxy::utils::*;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[tokio::main]
async fn main() -> Result<()> {
    setup_tracing();

    let config = setup_config()?;

    let listener = setup_listener(&config);
    let tls_acceptor = setup_tls_from_file(&config)?;
    let service = setup_service(&config);

    let graceful = hyper_util::server::graceful::GracefulShutdown::new();
    let mut signal = std::pin::pin!(shutdown_signal());

    info!("listening on {}", config.bind);

    loop {
        let tls_acceptor = tls_acceptor.clone();
        let watcher = graceful.watcher();
        let service = service.clone();

        select! {
            Ok((tcp_stream, addr)) = listener.accept() => {
                tokio::spawn(async move {
                    // TLS handshake
                    let t = Instant::now();
                    let tls_stream = match tls_acceptor.accept(tcp_stream).await {
                        Ok(tls_stream) => TokioIo::new(tls_stream),
                        Err(e) => {
                            error!(?e, "failed to perform tls handshake");
                            return;
                        }
                    };
                    debug!(duration_ms = t.elapsed().as_millis(), "TLS handshake time");

                    // attaching infos for rate limiting
                    let service = service
                        .clone()
                        .map_request(move |mut req: Request<_>| {
                            req.extensions_mut().insert(addr);
                            req
                        }).pipe(TowerToHyperService::new);


                    let builder = Builder::new(TokioExecutor::new());
                    let conn = builder.serve_connection(tls_stream, service).pipe(|c| watcher.watch(c));

                    if let Err(e) = conn.await {
                        // ignoring rustls EOF errors
                        if let Some(e) = e.downcast_ref::<std::io::Error>() {
                            if e.kind() == ErrorKind::UnexpectedEof {} else {
                                error!("got MyError: {:?}", e);
                            }
                        } else {
                            error!(e, "error when serving connection");
                        }
                    };
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

fn setup_service(config: &PortoConfig) -> HyperService {
    let domains = UpstreamMap::new(config);
    let client = setup_client();

    let service = ServiceBuilder::new()
        // .layer(ConcurrencyLimitLayer::new(100))
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(20),
        ));

    service
        .service(UpstreamService::new(domains, client))
        .map_response(|resp| resp.map(|body| body.boxed()))
        .boxed_clone()
}
