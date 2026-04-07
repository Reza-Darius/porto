use std::{env, net::SocketAddr, time::Duration};

use anyhow::Result;
use hyper::StatusCode;
use hyper_util::rt::TokioExecutor;
use hyper_util::server::conn::auto::Builder;
use hyper_util::{rt::TokioIo, service::TowerToHyperService};
use proxy::pool::new_backend_client;
use proxy::services::upstream_backend::UpstreamBackend;
use tokio::net::TcpStream;
use tokio::select;
use tokio::time::Instant;
use tower::ServiceBuilder;
use tower_http::{timeout::TimeoutLayer, trace::TraceLayer};
use tracing::{debug, error};
use tracing_subscriber::EnvFilter;

use proxy::setup::*;
use proxy::tls::setup_tls;
use proxy::utils::*;

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

    let domains = vec![
        ("darius.dev", "/tmp/darius_dev.sock"),
        ("RezaDarius.de", "/tmp/darius_art.sock"),
    ];

    let client = new_backend_client(&domains).await;

    // Create a TCP listener via tokio.
    let listener = setup_listener(addr);
    let tls_acceptor = setup_tls(SERVER_CERT_PATH, SERVER_KEY_PATH).await?;

    let service = ServiceBuilder::new()
        // .layer(ConcurrencyLimitLayer::new(100))
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(20),
        ))
        .service(UpstreamBackend::new(client));

    let service = TowerToHyperService::new(service);

    let graceful = hyper_util::server::graceful::GracefulShutdown::new();
    // when this signal completes, start shutdown
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
                    // TLS handhsake
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
                    let fut = watcher.watch(conn);

                    if let Err(e) = fut.await {
                        if let Some(io_err) = e.downcast_ref::<std::io::Error>() {
                            error!("got MyError: {:?}", io_err);
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
            eprintln!("all connections gracefully closed");
        },
        _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {
            eprintln!("timed out wait for all connections to close");
        }
    }
    Ok(())
}

// // get host name
// let req_host = if let Ok(host) = get_host(&req) {
//     host
// } else {
//     warn!("no host header found on request");
//     return Ok(bad_request());
// };

// let mut sender = sender_handle.lock().await;

// if sender.is_some() {
//     debug!("reusing upstream connection");
// } else {
//     debug!("establishing new upstream connection...")
// }

// // initilaize UDS connection
// if sender.is_none() {
//     let Some(send_host) = domain_handle.get(req_host) else {
//         warn!("requsted domain not found");
//         return Ok(not_found());
//     };

//     if let Ok(con) = uds_connect(send_host).await {
//         *sender = Some((req_host.to_string(), con));
//     } else {
//         warn!("failed to connect to UDS upstream");
//         return Ok(internal_error());
//     }
// }

// // send the data
// let (send_host, send_ref) = &mut sender.as_mut().expect("we know its there");

// if send_host != req_host {
//     warn!(req=?req, send_host=?send_host,"bad request: requested host doesnt match destination");
//     return Ok(bad_request());
// }

// strip_header(req.headers_mut());

// let t = Instant::now();
// match send_ref.send_request(req).await {
//     Ok(resp) => {
//         debug!(
//             elapsed_ms = t.elapsed().as_millis(),
//             "forwarded message time"
//         );
//         Ok(resp.map(|r| r.boxed()))
//     }
//     Err(e) => {
//         error!(?e, "failed to send upstream request");
//         Ok(internal_error())
//     }
// }
//

// let test = true;
// if test {
//     return Ok(Response::builder()
//         .status(StatusCode::OK)
//         .body(empty())
//         .unwrap());
// }

// // get host name
// let t = Instant::now();
// let req_host = if let Ok(host) = get_host(&req) {
//     host
// } else {
//     warn!("no host header found on request");
//     return Ok(bad_request());
// };
// debug!(elapsed_ms = t.elapsed().as_millis(), "get host time");

// let t = Instant::now();
// let Some(pool) = pool_handle.get(&req_host) else {
//     error!("couldnt retrieve pool");
//     return Ok(internal_error());
// };
// debug!(elapsed_ms = t.elapsed().as_millis(), "pool get time");

// let t = Instant::now();
// match pool.get().await {
//     Ok(mut sender) => {
//         debug!(elapsed_ms = t.elapsed().as_millis(), "pool wait time");
//         let t = Instant::now();
//         strip_header(req.headers_mut());
//         debug!(elapsed_ms = t.elapsed().as_millis(), "strip header time");

//         let t = Instant::now();
//         match sender.send_request(req).await {
//             Ok(resp) => {
//                 debug!(elapsed_ms = t.elapsed().as_millis(), "send request time");
//                 Ok(resp.map(|r| r.boxed()))
//             }
//             Err(e) => {
//                 error!(?e, "failed to send upstream request");
//                 Ok(internal_error())
//             }
//         }
//     }
//     Err(e) => {
//         debug!(elapsed_ms = t.elapsed().as_millis(), "pool wait time err");
//         error!(?e, "couldnt retrieve sender from pools");
//         Ok(internal_error())
//     }
// }

// // get host name
// let req_host = if let Ok(host) = get_host(&req) {
//     host
// } else {
//     warn!("no host header found on request");
//     return Ok(bad_request());
// };
