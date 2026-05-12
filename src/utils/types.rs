use std::pin::Pin;

use axum::body::Bytes;
use http::{Request, Response};
use http_body_util::combinators::UnsyncBoxBody;
use hyper::body::Incoming;
use tower::{BoxError, util::BoxCloneService};

pub type BoxFut<R, E> = Pin<Box<dyn Future<Output = std::result::Result<R, E>> + Send>>;
pub type Body = UnsyncBoxBody<Bytes, BoxError>;
pub type HyperService = BoxCloneService<Request<Incoming>, Response<Body>, anyhow::Error>;

pub type HyperService2<ReqB, ResB> = BoxCloneService<Request<ReqB>, Response<ResB>, anyhow::Error>;
