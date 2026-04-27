use std::str::FromStr;

use anyhow::{Result, anyhow};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::client::conn::http1::SendRequest;
use hyper::{Request, Response, Uri};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::UnixStream;
use tokio::time::Instant;
use tower::Service;
use tracing::{debug, error};

use crate::utils::*;
// pure mental illness following:

async fn dial_peer(uri: &str) -> Result<SendRequest<Incoming>> {
    let t = Instant::now();
    let stream = TokioIo::new(UnixStream::connect(uri).await?);
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

async fn test() {
    let svc = ConnectorService::new();
    let mut cache = hyper_util::client::pool::cache::builder()
        .executor(TokioExecutor::new())
        .build(svc);

    let mut r = cache
        .call(Uri::from_str("example.com").unwrap())
        .await
        .unwrap();
    // r.call(Request::new(full("hello world"))).await;
}

#[derive(Clone)]
pub struct ConnectorService;

impl ConnectorService {
    pub fn new() -> Self {
        ConnectorService
    }
}

impl Service<Uri> for ConnectorService {
    type Response = UpstreamServiceTwo;
    type Error = anyhow::Error;
    type Future = BoxFut<Self::Response, Self::Error>;

    fn poll_ready(
        &mut self,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Uri) -> Self::Future {
        Box::pin(async move {
            let host = req
                .host()
                .ok_or_else(|| anyhow!("couldnt get host from URI"))?;

            Ok(UpstreamServiceTwo {
                sender: dial_peer(host).await?,
            })
        })
    }
}

pub struct UpstreamServiceTwo {
    sender: SendRequest<Incoming>,
}

impl Service<Request<Incoming>> for UpstreamServiceTwo {
    type Response = Response<Body>;

    type Error = hyper::Error;

    type Future = BoxFut<Self::Response, Self::Error>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
        self.sender.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Incoming>) -> Self::Future {
        let f = self.sender.send_request(req);
        Box::pin(async move {
            let resp = f.await?;
            Ok(resp.map(|b| b.boxed()))
        })
    }
}
