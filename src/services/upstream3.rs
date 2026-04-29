use std::convert::Infallible;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Instant;

use addr::domain;
use anyhow::{Result, anyhow};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::client::conn::http1::SendRequest;
use hyper::{Request, Response, StatusCode, Uri};
use hyper_util::rt::{TokioExecutor, TokioIo};
use parking_lot::Mutex;
use tokio::net::UnixStream;
use tokio::sync::mpsc::Sender;
use tokio::sync::oneshot::{Receiver, channel};
use tokio::time::Duration;
use tower::{Service, ServiceBuilder, ServiceExt};
use tracing::{debug, error};

use crate::utils::*;

// pure mental illness following:

// TODO: add some configuration, maybe a bulider

async fn setup_upstream_service(domains: UpstreamMap) -> UpstreamService {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Envelope>(1024);

    tokio::spawn(async move {
        let layer = ServiceBuilder::new()
            // limit the amount of in-flight handshakes
            .concurrency_limit(100)
            // .layer_fn(|svc| PeerAddrService {
            //     domains: domains.clone(),
            //     inner: svc,
            // })
            .service(ConnectorService::new());

        let mut cache = hyper_util::client::pool::cache::builder()
            .executor(TokioExecutor::new())
            .build(layer);

        let mut timeout_check = tokio::time::interval(Duration::from_secs(10));
        let idle_dur = Duration::from_secs(20);

        loop {
            tokio::select! {
                _ = timeout_check.tick() => {
                    debug!("checking for timed out sender...");

                    let now = Instant::now();
                    cache.retain(|sender| {
                        if sender.sender.is_closed() {
                            return false;
                        }
                        now < sender.last_used + idle_dur
                    });
                }
                Some(msg) = rx.recv() => {
                    // get socket address
                    let Some(peer_addr) = domains.get_peer_addr_from_req(&msg.req) else {
                        let _ = msg.talk_back.send(bad_request());
                        continue
                    };

                    // get sender from the cache service
                    let mut sender = match cache.call(peer_addr).await {
                        Ok(sender) => sender,
                        Err(e) => {
                         error!(%e, "error when calling cache service");
                         continue
                        }
                    };

                    match sender.call(msg.req).await {
                        Ok(resp) => {
                            let _ = msg.talk_back.send(resp);
                        }
                        Err(e) => {
                         error!(%e, "error when sending request to upstream sender");
                         continue
                        }
                    };
                }
            }
        }
    });
    UpstreamService { handle: tx }
}

struct Envelope {
    req: Request<Incoming>,
    talk_back: tokio::sync::oneshot::Sender<Response<Body>>,
}

impl Envelope {
    fn new(req: Request<Incoming>) -> (Self, Receiver<Response<Body>>) {
        let (tx, rx) = channel();
        (Envelope { req, talk_back: tx }, rx)
    }
}

#[derive(Clone)]
pub struct UpstreamService {
    handle: Sender<Envelope>,
}

impl Service<Request<Incoming>> for UpstreamService {
    type Response = Response<Body>;
    type Error = anyhow::Error;
    type Future = BoxFut<Self::Response, Self::Error>;

    fn poll_ready(
        &mut self,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
        if self.handle.is_closed() {
            std::task::Poll::Ready(Err(anyhow!("channel is closed")))
        } else {
            std::task::Poll::Ready(Ok(()))
        }
    }

    fn call(&mut self, req: Request<Incoming>) -> Self::Future {
        let (env, rx) = Envelope::new(req);
        let handle = self.handle.clone();

        Box::pin(async move {
            handle.send(env).await?;
            rx.await.or_else(|e| {
                error!(%e, "error when awating one shot receiver");
                Ok(internal_error())
            })
        })
    }
}

// pub struct PeerAddrService<S> {
//     domains: UpstreamMap,
//     inner: S,
// }

// impl<S> Service<&Request<Incoming>> for PeerAddrService<S>
// where
//     S: Service<PeerAddr> + Send + 'static,
//     S::Future: Send,
//     S::Error: Into<anyhow::Error>,
// {
//     type Response = S::Response;
//     type Error = anyhow::Error;
//     type Future = BoxFut<Self::Response, Self::Error>;

//     fn poll_ready(
//         &mut self,
//         cx: &mut std::task::Context<'_>,
//     ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
//         self.inner.poll_ready(cx).map_err(Into::into)
//     }

//     fn call(&mut self, req: &Request<Incoming>) -> Self::Future {
//         // get host name
//         let req_host = if let Ok(host) = get_host(&req) {
//             host
//         } else {
//             debug!("no host header found on request");
//             return Box::pin(async { Err(anyhow!("no host header found on request")) });
//         };

//         // get associated socket name
//         let Some(peer_addr) = self.domains.get_peer_addr(req_host).cloned() else {
//             debug!(requested_host = %req_host, "coulndnt retrieve socket name");
//             return Box::pin(async { Err(anyhow!("couldnt retrieve socket name")) });
//         };

//         let fut = self.inner.call(peer_addr);
//         Box::pin(async move { fut.await.map_err(Into::into) })
//     }
// }

#[derive(Clone)]
pub struct ConnectorService;

impl ConnectorService {
    pub fn new() -> Self {
        ConnectorService
    }
}

impl Service<PeerAddr> for ConnectorService {
    type Response = UpstreamSender;
    type Error = anyhow::Error;
    type Future = BoxFut<Self::Response, Self::Error>;

    fn poll_ready(
        &mut self,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: PeerAddr) -> Self::Future {
        Box::pin(async move {
            debug!(%req, "dialing new upstream connection");

            match req {
                PeerAddr::Ipv4(_) => todo!(),
                PeerAddr::Uds(sock_addr) => {
                    let t = Instant::now();

                    let stream = TokioIo::new(UnixStream::connect(sock_addr).await?);
                    let (sender, conn) = hyper::client::conn::http1::handshake(stream).await?;

                    debug!(elapsed_ms = t.elapsed().as_millis(), "uds connect time");

                    tokio::spawn(async move {
                        if let Err(err) = conn.await {
                            error!("UDS Connection failed: {err}");
                        }
                        debug!("shutting down UDS connection");
                    });

                    Ok(UpstreamSender {
                        last_used: Instant::now(),
                        sender,
                    })
                }
            }
        })
    }
}

pub struct UpstreamSender {
    last_used: Instant,
    sender: SendRequest<Incoming>,
}

impl Service<Request<Incoming>> for UpstreamSender {
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
        self.last_used = Instant::now();
        let f = self.sender.send_request(req);
        Box::pin(async move {
            let resp = f.await?;

            Ok(resp.map(|b| b.boxed()))
        })
    }
}
