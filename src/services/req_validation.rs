#![allow(dead_code)]
use std::task::Poll;

use http::{Request, Response, StatusCode};
use pin_project_lite::pin_project;
use thiserror::Error;
use tower::{Layer, Service};
use tracing::warn;

use crate::utils::ResponseBody;

const BODY_SIZE_LIMIT: u32 = 1 << 20; // 1 MB
const HEADER_SIZE_LIMIT: u32 = (1 << 10) * 8; // 8 Kb

/// an IP based rate limiter using token buckets
#[derive(Clone)]
pub struct ReqValidationLayer;

impl<S> Layer<S> for ReqValidationLayer {
    type Service = ReqValidation<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ReqValidation { inner }
    }
}

impl ReqValidationLayer {
    pub fn new() -> Self {
        ReqValidationLayer
    }
}

#[derive(Clone)]
pub struct ReqValidation<S> {
    inner: S,
}

impl<S, ReqB, ResB> Service<Request<ReqB>> for ReqValidation<S>
where
    S: Service<Request<ReqB>, Response = Response<ResB>>,
{
    type Response = Response<ResponseBody<ResB>>;
    type Error = S::Error;
    type Future = ReqValidationFuture<S::Future>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqB>) -> Self::Future {
        let header_len: u32 = req
            .headers()
            .iter()
            .map(|(header, value)| header.as_str().len() as u32 + value.as_bytes().len() as u32)
            .sum();

        if header_len > HEADER_SIZE_LIMIT {
            return ReqValidationFuture::Err {
                e: ReqValidationError::HeaderSizeExceeded,
            };
        }

        ReqValidationFuture::Ok {
            fut: self.inner.call(req),
        }
    }
}

pin_project! {
    #[project = EnumProj]
    pub enum ReqValidationFuture<F> {
        Ok {#[pin] fut: F},
        Err{e: ReqValidationError},
    }
}

#[derive(Error, Debug)]
enum ReqValidationError {
    #[error("Request header are too large")]
    HeaderSizeExceeded,
    #[error("No content-length header found")]
    NoContentField,
}

impl<F, E, ResB> Future for ReqValidationFuture<F>
where
    F: Future<Output = Result<Response<ResB>, E>>,
{
    type Output = Result<Response<ResponseBody<ResB>>, E>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.project();
        // todo!()
        match this {
            EnumProj::Ok { fut } => fut
                .poll(cx)
                .map(|f| f.map(|resp| resp.map(ResponseBody::wrap))),
            EnumProj::Err { e } => {
                let status = match e {
                    ReqValidationError::HeaderSizeExceeded => {
                        StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
                    }
                    ReqValidationError::NoContentField => StatusCode::BAD_REQUEST,
                };

                warn!(resp = %status, "invalid request");

                Poll::Ready(Ok(Response::builder()
                    .status(status)
                    .body(ResponseBody::with_msg("error"))
                    .unwrap()))
            }
        }
    }
}
