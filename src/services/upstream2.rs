use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Result, anyhow};
use deadpool::managed::{Manager, Pool, RecycleError, RecycleResult};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::client::conn::http1::SendRequest;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;
use tokio::time::Instant;
use tower::Service;
use tracing::{debug, error, instrument, warn};

use crate::utils::*;

/*
 * this upstream service uses a custom connection pool
 */

const MAX_POOL_SIZE: usize = 100;

pub fn setup_client(domains: &[(&'static str, &str)]) -> UpstreamClient {
    let mut pool = HashMap::new();

    for (domain, sock) in domains.iter() {
        let uds_pool = Pool::builder(UdsConPool::new(sock))
            .max_size(MAX_POOL_SIZE)
            .runtime(deadpool::Runtime::Tokio1)
            // .wait_timeout(Some(Duration::from_secs(5)))
            // .recycle_timeout(Some(Duration::from_secs(10)))
            .build()
            .unwrap();
        pool.insert(*domain, uds_pool);
    }
    UpstreamClient {
        pool: Arc::new(pool),
    }
}

#[derive(Debug, Clone)]
pub struct UpstreamClient {
    pool: Arc<HashMap<&'static str, Pool<UdsConPool>>>,
}

impl UpstreamClient {
    #[instrument(err)]
    pub async fn request(&self, req: Request<Incoming>) -> Result<Response<Body>> {
        // get host name
        let peer = if let Ok(host) = get_host(&req) {
            host
        } else {
            warn!("no host header found on request");
            return Ok(bad_request());
        };

        let t = Instant::now();
        let Some(pool) = self.pool.get(peer) else {
            return Err(anyhow!("couldnt retrieve from pool peer: {peer}"));
        };
        debug!(elapsed_ms = t.elapsed().as_millis(), "pool get time");

        let t = Instant::now();
        match pool.get().await {
            Ok(mut sender) => {
                debug!(elapsed_ms = t.elapsed().as_millis(), "pool wait time");

                let t = Instant::now();
                match sender.send_request(req).await {
                    Ok(resp) => {
                        debug!(elapsed_ms = t.elapsed().as_millis(), "send request time");
                        Ok(resp.map(|r| r.boxed()))
                    }
                    Err(e) => Err(anyhow!("failed to send upstream request: {e:?}")),
                }
            }
            Err(e) => {
                debug!(elapsed_ms = t.elapsed().as_millis(), "pool wait time err");
                Err(anyhow!("couldnt retrieve sender from pools: {e:?}"))
            }
        }
    }
}

#[derive(Debug)]
pub struct UdsConPool {
    path: PathBuf,
}

impl UdsConPool {
    fn new(sock_path: &str) -> Self {
        Self {
            path: PathBuf::from(sock_path),
        }
    }
}

impl Manager for UdsConPool {
    type Type = SendRequest<Incoming>;

    type Error = anyhow::Error;

    async fn create(&self) -> std::result::Result<Self::Type, Self::Error> {
        debug!("creating new upstream connection");

        let t = Instant::now();
        let stream = TokioIo::new(UnixStream::connect(&self.path).await?);
        let (sender, conn) = hyper::client::conn::http1::handshake(stream).await?;
        debug!(elapsed_ms = t.elapsed().as_millis(), "uds connect time");

        tokio::spawn(async move {
            if let Err(err) = conn.await {
                error!("UDS Connection failed: {err}");
            }
            debug!("shutting down UDS connection");
        });
        Ok(sender)
    }

    fn recycle(
        &self,
        obj: &mut Self::Type,
        metrics: &deadpool::managed::Metrics,
    ) -> impl Future<Output = RecycleResult<Self::Error>> + Send {
        debug!(metrics.recycle_count, "pool:");

        let reusable = !obj.is_closed();

        async move {
            if reusable {
                debug!("pool: recycling connection");
                Ok(())
            } else {
                debug!("pool: connection closed or not ready");
                Err(RecycleError::message("connection closed"))
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct UpstreamService {
    client: UpstreamClient,
}

impl UpstreamService {
    pub fn new(client: UpstreamClient) -> Self {
        debug!("new upstream service");
        Self { client }
    }
}

impl Service<Request<Incoming>> for UpstreamService {
    type Response = Response<Body>;
    type Error = std::convert::Infallible;
    type Future = BoxFut<Self::Response, Self::Error>;

    fn poll_ready(
        &mut self,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, mut req: Request<Incoming>) -> Self::Future {
        let client = self.client.clone();

        Box::pin(async move {
            strip_header(req.headers_mut());

            let t = Instant::now();
            match client.request(req).await {
                Ok(resp) => {
                    debug!(
                        elapsed_ms = t.elapsed().as_millis(),
                        "forwarded message time"
                    );
                    Ok(resp)
                }
                Err(e) => {
                    error!(?e, "couldnt send request");
                    Ok(internal_error())
                }
            }
        })
    }
}
