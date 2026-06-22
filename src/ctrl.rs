use std::{convert::Infallible, env::temp_dir, path::Path};

use anyhow::{Result, anyhow};
use http::Method;
use hyper::body::Incoming;
use reqwest::{Request, Response};
use tokio::net::{UnixDatagram, UnixListener};
use tracing::debug;
use url::Url;

use crate::utils::SvcBoxFut;

const NOTIFY_SOCKET: &str = "NOTIFY_SOCKET";
const CTRL_SOCK_PATH: &str = "/tmp/porto-ctrl.sock";

pub fn setup_ctrl_sock() -> Result<UnixListener> {
    let path = Path::new(CTRL_SOCK_PATH);
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    UnixListener::bind(Path::new(path)).map_err(Into::into)
}

pub async fn send_ctrl_msg(ctrl: CtrlMsg) -> Result<Response> {
    let client = reqwest::ClientBuilder::new()
        .unix_socket(CTRL_SOCK_PATH)
        .http1_only()
        .build()?;

    client.execute(ctrl.into_req()).await.map_err(Into::into)
}

#[derive(Debug, PartialEq)]
pub enum CtrlMsg {
    Status,
    Stop,
    Ready,
}

impl CtrlMsg {
    const BASE_URL: &str = "http://porto.ctrl";

    pub fn into_req(self) -> Request {
        match self {
            Self::Stop => {
                let url = format!("{}/stop", Self::BASE_URL);
                Request::new(
                    Method::POST,
                    Url::parse(&url).expect("the values are hard coded"),
                )
            }
            _ => unimplemented!(),
        }
    }

    pub fn from_resp(resp: &Response) -> Self {
        match resp.url().path() {
            "/stop" => Self::Stop,
            _ => unimplemented!(),
        }
    }

    pub fn ready() -> Self {
        Self::Ready
    }
}
/*
    READY=1\n                          # "I'm up and ready to serve"
    STOPPING=1\n                       # "I'm shutting down intentionally"
    WATCHDOG=1\n                       # "I'm still alive" (keepalive)
    STATUS=Reloading config...\n       # arbitrary human-readable status string
    RELOADING=1\nMONOTONIC_USEC=...\n # "I'm reloading" (systemd 253+)
*/

/// sends a notify to systemd
async fn send_notify(msg: CtrlMsg) -> Result<()> {
    let msg = match msg {
        CtrlMsg::Stop => "STOPPING=1",
        CtrlMsg::Status => todo!(),
        CtrlMsg::Ready => "READY=1",
    };

    let Some(socket_path) = std::env::var_os(NOTIFY_SOCKET) else {
        debug!("no notify socket variable found");
        return Ok(());
    };

    let tmp = temp_dir();

    let socket = UnixDatagram::bind(tmp.join("notify_sender"))?;
    let nbytes = socket.send_to(msg.as_bytes(), socket_path).await?;

    if nbytes != msg.len() {
        return Err(anyhow!("incomplete sd notify send"));
    }

    Ok(())
}

#[derive(Debug, Clone)]
pub struct CtrlService {
    sender: tokio::sync::mpsc::Sender<CtrlMsg>,
}

impl CtrlService {
    pub fn new(sender: tokio::sync::mpsc::Sender<CtrlMsg>) -> Self {
        CtrlService { sender }
    }
}

impl hyper::service::Service<http::Request<Incoming>> for CtrlService {
    type Response = axum::response::Response;
    type Error = Infallible;
    type Future = SvcBoxFut<Self::Response, Self::Error>;

    fn call(&self, req: http::Request<Incoming>) -> Self::Future {
        let sender = self.sender.clone();
        Box::pin(async move {
            let ctrl = match req.uri().path() {
                "/stop" => CtrlMsg::Stop,
                _ => unimplemented!(),
            };

            debug!("received ctrl message {ctrl:?}");

            sender.send(ctrl).await.expect("this cant fail");

            Ok(axum::response::Response::builder()
                .status(200)
                .body(axum::body::Body::empty())
                .unwrap())
        })
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use super::*;
    use hyper::body::Incoming;
    use hyper_util::rt::TokioIo;
    use test_log::test;
    use tokio::sync::Notify;
    use tracing::{debug, error};

    async fn handler(req: http::Request<Incoming>) -> Result<http::Response<String>> {
        debug!("got request {:?}", req.uri());
        Ok(http::Response::new("got ctrl message".to_string()))
    }

    #[test]
    fn url() {
        let msg = CtrlMsg::Stop;
        let req = msg.into_req();
        println!("{:?}", req);
    }

    #[test(tokio::test)]
    async fn ctrl_snd_rcv() {
        let srv_rdy = Arc::new(Notify::new());
        let srv_clone = srv_rdy.clone();

        tokio::spawn(async move {
            let listener = setup_ctrl_sock().unwrap();
            srv_clone.notify_one();

            let stream = listener.accept().await.unwrap();

            let conn = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream.0), hyper::service::service_fn(handler));

            if let Err(e) = conn.await {
                error!("server connection error: {}", e);
            }
        });

        srv_rdy.notified().await;

        let msg = CtrlMsg::Stop;
        let res = send_ctrl_msg(msg).await.unwrap();

        let ctr = CtrlMsg::from_resp(&res);
        assert_eq!(ctr, CtrlMsg::Stop);
    }
}
