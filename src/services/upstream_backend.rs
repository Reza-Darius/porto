use anyhow::Result;
use hyper::body::Incoming;
use hyper::{Request, Response};
use tokio::time::Instant;
use tower::Service;
use tracing::{debug, error};

use crate::pool::BackendClient;
use crate::utils::*;

#[derive(Debug, Clone)]
pub struct UpstreamBackend {
    client: BackendClient,
}

impl UpstreamBackend {
    pub fn new(client: BackendClient) -> Self {
        debug!("new upstream service");
        Self { client }
    }
}

impl Service<Request<Incoming>> for UpstreamBackend {
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
