use anyhow::{Result, anyhow};
use deadpool::managed::{Manager, Pool, RecycleError, RecycleResult};
use http_body_util::BodyExt;
use hyper::{Request, Response, body::Incoming, client::conn::http1::SendRequest};
use hyper_util::rt::TokioIo;
use std::{collections::HashMap, path::PathBuf, sync::Arc};
use tokio::{net::UnixStream, time::Instant};
use tracing::{debug, error, warn};

use super::utils::*;

const MAX_POOL_SIZE: usize = 100;

pub async fn new_backend_client(domains: &[(&'static str, &str)]) -> BackendClient {
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
    BackendClient {
        pool: Arc::new(pool),
    }
}

#[derive(Debug, Clone)]
pub struct BackendClient {
    pool: Arc<HashMap<&'static str, Pool<UdsConPool>>>,
}

impl BackendClient {
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
            error!(peer, "pool: couldnt retrieve pool");
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
                    Err(e) => {
                        error!(?e, "failed to send upstream request");
                        Err(anyhow!("failed to send upstream request"))
                    }
                }
            }
            Err(e) => {
                debug!(elapsed_ms = t.elapsed().as_millis(), "pool wait time err");
                error!(?e, "couldnt retrieve sender from pools");
                Err(anyhow!("couldnt retrieve sender from pools"))
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

        tokio::task::spawn(async move {
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
        let ready = obj.is_ready() && !obj.is_closed();
        debug!(metrics.recycle_count, "pool:");
        async move {
            if ready {
                debug!("pool: recycling connection");
                Ok(())
            } else {
                debug!("pool: connection closed or not ready");
                Err(RecycleError::message("connection closed"))
            }
        }
    }
}
