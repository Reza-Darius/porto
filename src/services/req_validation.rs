#![allow(dead_code)]
use std::{
    pin::Pin,
    task::{Context, Poll},
};

use axum::body::Bytes;
use http::{Request, Response, StatusCode, header::CONTENT_LENGTH};
use http_body_util::Full;
use hyper::body::{Frame, SizeHint};
use pin_project_lite::pin_project;
use thiserror::Error;
use tower::{BoxError, Layer, Service};
use tracing::warn;

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
    S::Error: Into<BoxError>,
    ResB: hyper::body::Body,
{
    type Response = Response<ResponseBody<ResB>>;
    type Error = BoxError;
    type Future = ReqValidationFuture<S::Future>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, req: Request<ReqB>) -> Self::Future {
        let Some(c_len) = req.headers().get(CONTENT_LENGTH) else {
            return ReqValidationFuture::Err {
                e: ReqValidationError::NoContentField,
            };
        };

        let req_len = c_len.to_str().unwrap().parse::<u32>().unwrap();
        if req_len > BODY_SIZE_LIMIT {
            return ReqValidationFuture::Err {
                e: ReqValidationError::BodySizeExceeded,
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
    #[error("Request body is too large")]
    BodySizeExceeded,
    #[error("No content-length header found")]
    NoContentField,
}

impl<F, E, ResB> Future for ReqValidationFuture<F>
where
    F: Future<Output = Result<Response<ResB>, E>>,
    E: Into<BoxError>,
    ResB: hyper::body::Body,
{
    type Output = Result<Response<ResponseBody<ResB>>, BoxError>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.project();
        // todo!()
        match this {
            EnumProj::Ok { fut } => fut
                .poll(cx)
                .map_err(Into::into)
                .map(|f| f.map(|resp| resp.map(ResponseBody::new))),
            EnumProj::Err { e } => {
                let status = match e {
                    ReqValidationError::HeaderSizeExceeded => {
                        StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
                    }
                    ReqValidationError::BodySizeExceeded => StatusCode::PAYLOAD_TOO_LARGE,
                    ReqValidationError::NoContentField => todo!(),
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

pin_project! {
    pub struct ResponseBody<B> {
        #[pin]
        inner: ResponseBodyInner<B>
    }
}

impl<B> ResponseBody<B> {
    fn with_msg(str: &str) -> Self {
        Self {
            inner: ResponseBodyInner::Custom {
                body: Full::from(str.to_string()),
            },
        }
    }
    pub(crate) fn new(body: B) -> Self {
        Self {
            inner: ResponseBodyInner::Body { body },
        }
    }
}

pin_project! {
    #[project = BodyProj]
    enum ResponseBodyInner<B> {
        Custom {
            #[pin]
            body: Full<Bytes>,
        },
        Body {
            #[pin]
            body: B
        }
    }
}

impl<B> hyper::body::Body for ResponseBody<B>
where
    B: hyper::body::Body<Data = Bytes>,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.project().inner.project() {
            BodyProj::Custom { body } => body.poll_frame(cx).map_err(|err| match err {}),
            BodyProj::Body { body } => body.poll_frame(cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        match &self.inner {
            ResponseBodyInner::Custom { body } => body.is_end_stream(),
            ResponseBodyInner::Body { body } => body.is_end_stream(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match &self.inner {
            ResponseBodyInner::Custom { body } => body.size_hint(),
            ResponseBodyInner::Body { body } => body.size_hint(),
        }
    }
}
