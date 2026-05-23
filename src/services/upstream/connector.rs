use std::io;
use std::path::PathBuf;
use std::task;
use std::task::Poll;

use hex::FromHex;
use http::Uri;
use hyper_util::client::legacy::connect::Connection;
use hyper_util::rt::TokioIo;
use pin_project_lite::pin_project;
use tokio::net::TcpStream;
use tokio::net::UnixStream;
use tracing::debug;
use tracing::error;

use crate::utils::PeerAddr;

pin_project! {
    #[project = EnumProj]
    pub enum Upstream {
        Tcp{#[pin] s: TcpStream},
        Uds{#[pin] s: UnixStream}
    }
}

impl tokio::io::AsyncRead for Upstream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.project();
        match this {
            EnumProj::Tcp { s } => s.poll_read(cx, buf),
            EnumProj::Uds { s } => s.poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for Upstream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.project();
        match this {
            EnumProj::Tcp { s } => s.poll_write(cx, buf),
            EnumProj::Uds { s } => s.poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.project();
        match this {
            EnumProj::Tcp { s } => s.poll_flush(cx),
            EnumProj::Uds { s } => s.poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.project();
        match this {
            EnumProj::Tcp { s } => s.poll_shutdown(cx),
            EnumProj::Uds { s } => s.poll_shutdown(cx),
        }
    }
}

impl Connection for Upstream {
    fn connected(&self) -> hyper_util::client::legacy::connect::Connected {
        match self {
            Upstream::Tcp { s } => s.connected(),
            Upstream::Uds { s } => s.connected(),
        }
    }
}

#[derive(Clone)]
pub struct UpstreamConnector;

impl UpstreamConnector {
    pub fn new() -> Self {
        UpstreamConnector
    }
}

/// implementation to use with hyper's client
impl tower::Service<Uri> for UpstreamConnector {
    type Response = TokioIo<Upstream>;
    type Error = std::io::Error;
    // We can't "name" an `async` generated future.
    type Future =
        std::pin::Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        // This connector is always ready, but others might not be.
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        Box::pin(async move {
            debug!(%uri, "dialing connection");
            let addr = PeerAddr::try_from(uri.clone()).map_err(|e| {
                error!(%e, "connector error");
                std::io::Error::new(std::io::ErrorKind::InvalidInput, e)
            })?;

            match addr {
                crate::utils::PeerAddr::Ipv4(socket_addr) => {
                    let stream = TcpStream::connect(socket_addr)
                        .await
                        .inspect_err(|e| error!(%e, %addr, "tcp connect error"))?;
                    Ok(TokioIo::new(Upstream::Tcp { s: stream }))
                }
                crate::utils::PeerAddr::Uds(_) => {
                    let path = parse_socket_path(&uri)?;
                    debug!(path = %path.display(), "parsed UDS path");
                    let stream = UnixStream::connect(path)
                        .await
                        .inspect_err(|e| error!(%e, %addr, "uds connect error"))?;
                    Ok(TokioIo::new(Upstream::Uds { s: stream }))
                }
            }
        })
    }
}
fn parse_socket_path(uri: &Uri) -> Result<PathBuf, io::Error> {
    if uri.scheme_str() != Some("unix") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid URL, scheme must be unix",
        ));
    }

    if let Some(host) = uri.host() {
        let bytes = Vec::from_hex(host).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid URL, host must be a hex-encoded path",
            )
        })?;

        Ok(PathBuf::from(String::from_utf8_lossy(&bytes).into_owned()))
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid URL, host must be present",
        ))
    }
}

/// implementation for own client
impl tower::Service<PeerAddr> for UpstreamConnector {
    type Response = Upstream;
    type Error = std::io::Error;
    // We can't "name" an `async` generated future.
    type Future =
        std::pin::Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        // This connector is always ready, but others might not be.
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, addr: PeerAddr) -> Self::Future {
        Box::pin(async move {
            debug!(%addr, "dialing connection");
            match addr {
                crate::utils::PeerAddr::Ipv4(socket_addr) => {
                    let stream = TcpStream::connect(socket_addr)
                        .await
                        .inspect_err(|e| error!(%e, %addr, "tcp connect error"))?;
                    debug!(%addr, "TCP established");
                    Ok(Upstream::Tcp { s: stream })
                }
                crate::utils::PeerAddr::Uds(ref path_buf) => {
                    let stream = UnixStream::connect(path_buf)
                        .await
                        .inspect_err(|e| error!(%e, %addr, "uds connect error"))?;
                    debug!(%addr, "UDS established");
                    Ok(Upstream::Uds { s: stream })
                }
            }
        })
    }
}
