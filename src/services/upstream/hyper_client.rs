use anyhow::Result;
use http_body_util::BodyExt;
use hyper::StatusCode;
use hyper::{Request, Response};
use hyper_util::client::legacy::{Client, ResponseFuture};
use hyper_util::rt::TokioTimer;
use pin_project_lite::pin_project;
use tokio::time::Instant;
use tower::{BoxError, Service};
use tracing::{debug, error};

use super::connector::UpstreamConnector;
use crate::utils::*;

/*
 * this upstream service uses hyper's client to talk to peers
 */

#[derive(Debug)]
pub struct UpstreamService<B> {
    client: Client<UpstreamConnector, B>,
}

impl<B> Clone for UpstreamService<B> {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
        }
    }
}

impl<B> UpstreamService<B>
where
    B: hyper::body::Body + Send,
    B::Data: Send,
{
    pub fn new() -> Self {
        let client = Client::builder(hyper_util::rt::TokioExecutor::new())
            .pool_idle_timeout(std::time::Duration::from_secs(30))
            .pool_timer(TokioTimer::new())
            .pool_max_idle_per_host(40)
            .build(UpstreamConnector::new());
        Self { client }
    }
}

impl<B> Service<Request<B>> for UpstreamService<B>
where
    B: hyper::body::Body + Send + 'static + Unpin,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    type Response = Response<Body>;
    type Error = BoxError;
    type Future = UpstreamResponseFuture;

    fn poll_ready(
        &mut self,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let client = self.client.clone();

        UpstreamResponseFuture {
            f: client.request(req),
        }
    }
}

pin_project! {
    pub struct UpstreamResponseFuture {
        #[pin]
        f: ResponseFuture
    }
}

impl Future for UpstreamResponseFuture {
    type Output = Result<Response<Body>, BoxError>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.project();

        // let t = Instant::now();
        let r = match std::task::ready!(this.f.poll(cx)) {
            Ok(resp) => {
                // debug!(
                //     elapsed_ms = t.elapsed().as_millis(),
                //     "forwarded message time"
                // );
                Ok(resp.map(|r| r.map_err(Into::into).boxed_unsync()))
            }
            Err(e) => {
                // error!(?e, "couldnt send request");
                Ok(response(StatusCode::INTERNAL_SERVER_ERROR))
            }
        };
        std::task::Poll::Ready(r)
    }
}
