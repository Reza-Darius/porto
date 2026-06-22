use std::{convert::Infallible, env::temp_dir, path::Path};

use anyhow::{Result, anyhow};
use http::Method;
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use reqwest::{Request, Response};
use tokio::{
    net::{UnixDatagram, UnixListener},
    sync::mpsc::Receiver,
};
use tracing::{debug, error};
use url::Url;

use crate::utils::SvcBoxFut;

const NOTIFY_SOCKET: &str = "NOTIFY_SOCKET";
const CTRL_SOCK_PATH: &str = "/tmp/porto-ctrl.sock";

/// sets up the ctrl socket for the server in the background
pub fn setup_ctrl_sock() -> Result<Receiver<CtrlMsg>> {
    let path = Path::new(CTRL_SOCK_PATH);
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    let socket = UnixListener::bind(Path::new(path))?;

    let (ctrl_tx, ctrl_rx) = tokio::sync::mpsc::channel::<CtrlMsg>(1024);

    tokio::spawn(async move {
        let svc = CtrlService::new(ctrl_tx);
        while let Ok((stream, _)) = socket.accept().await {
            let conn = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), svc.clone());

            if let Err(e) = conn.await {
                error!("server connection error: {}", e);
            }
        }
    });
    Ok(ctrl_rx)
}

/// sends a ctrl message to the ctrl socket, should be used from the CLI client
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
}

impl CtrlMsg {
    const BASE_URL: &str = "http://porto.ctrl";

    pub fn into_req(self) -> reqwest::Request {
        match self {
            Self::Stop => {
                let url = format!("{}/stop", Self::BASE_URL);
                Request::new(
                    Method::POST,
                    Url::parse(&url).expect("the values are hard coded"),
                )
            }
            CtrlMsg::Status => {
                let url = format!("{}/status", Self::BASE_URL);
                Request::new(
                    Method::POST,
                    Url::parse(&url).expect("the values are hard coded"),
                )
            }
        }
    }

    pub fn from_resp(resp: &reqwest::Response) -> Self {
        match resp.url().path() {
            "/stop" => Self::Stop,
            _ => unimplemented!(),
        }
    }
}

/*
    sends are atomic, we only need a new line delimter for multiple commands in one send

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
        CtrlMsg::Status => return Ok(()),
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
struct CtrlService {
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
                "/status" => CtrlMsg::Status,
                invalid => {
                    error!("unknown ctrl message received {invalid}");

                    return Ok(axum::response::Response::builder()
                        .status(200)
                        .body(axum::body::Body::empty())
                        .unwrap());
                }
            };

            debug!("received ctrl message: {ctrl:?}");

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
    use std::time::Duration;

    use super::*;
    use test_log::test;

    #[test]
    fn url() {
        let msg = CtrlMsg::Stop;
        let req = msg.into_req();
        println!("{:?}", req);
    }

    #[test(tokio::test)]
    async fn ctrl_snd_rcv() {
        let mut rx = setup_ctrl_sock().unwrap();

        tokio::time::sleep(Duration::from_secs(2)).await;

        let res = send_ctrl_msg(CtrlMsg::Stop).await.unwrap();
        let rx_resp = rx.recv().await.unwrap();
        assert_eq!(rx_resp, CtrlMsg::Stop);
        let ctr = CtrlMsg::from_resp(&res);
        assert_eq!(ctr, CtrlMsg::Stop);
    }
}
