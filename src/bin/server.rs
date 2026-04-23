use std::io::ErrorKind;
use std::{collections::HashMap, env, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Result;
use hyper::StatusCode;
use hyper_util::rt::TokioExecutor;
use hyper_util::server::conn::auto::Builder;
use hyper_util::{rt::TokioIo, service::TowerToHyperService};
use tikv_jemallocator::Jemalloc;
use tokio::select;
use tokio::time::Instant;
use tower::ServiceBuilder;
use tower_http::{timeout::TimeoutLayer, trace::TraceLayer};
use tracing::{debug, error};
use tracing_subscriber::EnvFilter;

use proxy::services::upstream::*;
use proxy::setup::*;
use proxy::utils::*;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

const SERVER_CERT_PATH: &str = "credentials/example_cert.pem";
const SERVER_KEY_PATH: &str = "credentials/example_key.pem";

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let addr = args
        .get(1)
        .map(|s| s.as_str())
        .unwrap_or_else(|| "127.0.0.1:3000")
        .parse::<SocketAddr>()?;

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .or_else(|_| EnvFilter::try_new("proxy=error,tower_http=warn"))?,
        )
        .init();

    let domains = Arc::new(HashMap::from([
        ("darius.dev", "/tmp/darius_dev.sock"),
        ("RezaDarius.de", "/tmp/darius_art.sock"),
    ]));

    let client = setup_client();
    let listener = setup_listener(addr);
    let tls_acceptor = setup_tls_from_file(SERVER_CERT_PATH, SERVER_KEY_PATH)?;

    let service = ServiceBuilder::new()
        // .layer(ConcurrencyLimitLayer::new(100))
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(20),
        ))
        .service(UpstreamService::new(domains, client));

    let service = TowerToHyperService::new(service);

    let graceful = hyper_util::server::graceful::GracefulShutdown::new();
    let mut signal = std::pin::pin!(shutdown_signal());

    println!("listening on {addr}");

    loop {
        // move clones
        let tls_acceptor = tls_acceptor.clone();
        let watcher = graceful.watcher();
        let service = service.clone();

        select! {
            Ok((tcp_stream, _)) = listener.accept() => {
                tokio::spawn(async move {
                    // TLS handshake
                    let t = Instant::now();
                    let tls_stream = match tls_acceptor.accept(tcp_stream).await {
                        Ok(tls_stream) => tls_stream,
                        Err(e) => {
                            error!(?e, "failed to perform tls handshake");
                            return;
                        }
                    };
                    debug!(duration_ms = t.elapsed().as_millis(), "TLS handshake time");

                    // compatiblity conversions
                    let stream = TokioIo::new(tls_stream);

                    let builder = Builder::new(TokioExecutor::new());
                    let conn = builder.serve_connection(stream, service);
                    let conn = watcher.watch(conn);

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
                eprintln!("shutting down server");
                break;
            }
        }
    }

    select! {
        _ = graceful.shutdown() => {
            eprintln!("all connections closed");
        },
        _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {
            eprintln!("timed out wait for all connections to close");
        }
    }
    Ok(())
}
