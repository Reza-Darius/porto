use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Instant;

use anyhow::anyhow;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::client::conn::http1::SendRequest;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::{TcpStream, UnixStream};
use tokio::sync::mpsc::Sender;
use tokio::sync::oneshot::{Receiver, channel};
use tokio::time::Duration;
use tower::{Service, ServiceBuilder, ServiceExt};
use tracing::{debug, error};

use crate::utils::*;

// pure mental illness following:

// TODO: add some configuration, maybe a bulider

pub fn setup_upstream_service(domains: UpstreamMap) -> UpstreamService {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Envelope>(1024);

    tokio::spawn(async move {
        let layer = ServiceBuilder::new()
            // limit the amount of in-flight handshakes
            .concurrency_limit(100)
            .service(ConnectorService::new());

        let mut cache = hyper_util::client::pool::cache::builder()
            .executor(TokioExecutor::new())
            .build(layer);

        let mut timeout_check = tokio::time::interval(Duration::from_secs(30));
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
                    let mut sender = match cache.ready().await.unwrap().call(peer_addr).await {
                        Ok(sender) => sender,
                        Err(e) => {
                         error!(%e, "error when calling cache service");
                         continue
                        }
                    };

                    match sender.ready().await.unwrap().call(msg.req).await {
                        Ok(resp) => {
                            let _ = msg.talk_back.send(resp).inspect_err(|_| error!("failed to send through one-shot channel"));
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

#[derive(Clone, Default, Debug)]
pub struct ConnectorService {
    count: Arc<AtomicU16>,
}

impl ConnectorService {
    pub fn new() -> Self {
        ConnectorService {
            count: Arc::new(0.into()),
        }
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
        let count = self.count.clone();
        Box::pin(async move {
            debug!(%req, "dialing new upstream connection");

            let sender = match req {
                PeerAddr::Ipv4(sock_addr) => {
                    let t = Instant::now();

                    let stream = TokioIo::new(TcpStream::connect(sock_addr).await?);
                    let (sender, conn) = hyper::client::conn::http1::handshake(stream).await?;
                    let n = count.fetch_add(1, Ordering::Relaxed) + 1;

                    debug!(
                        n_con = n,
                        elapsed_ms = t.elapsed().as_millis(),
                        "TCP connection established"
                    );

                    tokio::spawn(async move {
                        if let Err(err) = conn.await {
                            error!("TCP Connection failed: {err:#}");
                        }
                        let n = count.fetch_sub(1, Ordering::Relaxed) - 1;
                        debug!(n_con = n, "shutting down TCP connection");
                    });
                    sender
                }
                PeerAddr::Uds(sock_addr) => {
                    let t = Instant::now();

                    let stream = TokioIo::new(UnixStream::connect(sock_addr).await?);
                    let (sender, conn) = hyper::client::conn::http1::handshake(stream).await?;
                    let n = count.fetch_add(1, Ordering::Relaxed) + 1;

                    debug!(
                        n_con = n,
                        elapsed_ms = t.elapsed().as_millis(),
                        "UDS connection established"
                    );

                    tokio::spawn(async move {
                        if let Err(err) = conn.await {
                            error!("UDS Connection failed: {err:#}");
                        }
                        let n = count.fetch_sub(1, Ordering::Relaxed) - 1;
                        debug!(n_con = n, "shutting down UDS connection");
                    });
                    sender
                }
            };
            Ok(UpstreamSender {
                last_used: Instant::now(),
                sender,
            })
        })
    }
}

pub struct UpstreamSender {
    last_used: Instant,
    sender: SendRequest<Incoming>,
}

impl Service<Request<Incoming>> for UpstreamSender {
    type Response = Response<Body>;
    type Error = anyhow::Error;
    type Future = BoxFut<Self::Response, Self::Error>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
        self.sender.poll_ready(cx).map_err(Into::into)
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
