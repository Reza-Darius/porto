use std::{
    any::Any,
    pin::Pin,
    task::{Context, Poll},
};

use axum::body::Bytes;
use http::{Response, StatusCode};
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::{Frame, SizeHint};
use pin_project_lite::pin_project;
use tower::BoxError;

use http::Request;
use http_body_util::combinators::UnsyncBoxBody;
use hyper::body::Incoming;
use tower::util::BoxCloneService;

/// convenience type suitable for Futures returned by by Service impls
pub type SvcBoxFut<R, E> =
    Pin<Box<dyn Future<Output = std::result::Result<R, E>> + Send + 'static>>;
// OPTIMIZE: replace body with the wrapper body type
pub type Body = UnsyncBoxBody<Bytes, BoxError>;
pub type HyperService = BoxCloneService<Request<Incoming>, Response<Body>, anyhow::Error>;

/*
* Services are permitted to panic if call is invoked without obtaining Poll::Ready(Ok(())) from poll_ready.
* You should therefore be careful when cloning services for example to move them into boxed futures.
* Even though the original service is ready, the clone might not be.
*/
/// helper function to safely clone a service, see comment
pub fn svc_clone<S: Clone + Sized>(inner: &mut S) -> S {
    let clone = inner.clone();
    // take the service that was ready
    std::mem::replace(inner, clone)
}

pub fn boxfut_err<R>(e: impl std::fmt::Display) -> SvcBoxFut<R, BoxError> {
    let err: BoxError = e.to_string().into();
    Box::pin(async { Err(err) })
}

pub fn boxfut_res<E>(status: StatusCode) -> SvcBoxFut<Response<Body>, E> {
    let resp = response(status);
    Box::pin(async { Ok(resp) })
}

pub fn handle_panic(err: Box<dyn Any + Send + 'static>) -> Response<Body> {
    let details = if let Some(s) = err.downcast_ref::<String>() {
        s.clone()
    } else if let Some(s) = err.downcast_ref::<&str>() {
        s.to_string()
    } else {
        "Unknown panic message".to_string()
    };
    tracing::error!(details, "request caused a panic");

    response(StatusCode::INTERNAL_SERVER_ERROR)
}

/// helper function to build a response
pub fn response(status: StatusCode) -> Response<Body> {
    Response::builder()
        .status(status)
        .body(empty())
        .expect("the values are hard coded")
}

// We create some utility functions to make Empty and Full bodies
// fit our broadened Response body type.
pub fn empty() -> Body {
    Empty::<Bytes>::new()
        // .map_err(|never| match never {})
        .map_err(Into::into)
        .boxed_unsync()
}

pub fn full(chunk: impl Into<Bytes>) -> Body {
    Full::new(chunk.into()).map_err(Into::into).boxed_unsync()
}

pub trait ResponseExt<B> {
    /// maps a response's body to the ResponseBody wrapper type
    fn map_body(self) -> Response<ResponseBody<B>>;

    /// builds a response with a response body
    fn build(status: StatusCode, body: impl Into<Bytes>) -> Response<ResponseBody<B>>;

    /// builds a response with an empty response body
    fn empty(status: StatusCode) -> Response<ResponseBody<B>>;

    /// builds a response with an empty response body, and 200 status code
    fn ok() -> Response<ResponseBody<B>>;
}

impl<B> ResponseExt<B> for Response<B> {
    #[inline]
    fn map_body(self) -> Response<ResponseBody<B>> {
        self.map(ResponseBody::wrap)
    }

    #[inline]
    fn build(status: StatusCode, body: impl Into<Bytes>) -> Response<ResponseBody<B>> {
        Response::builder()
            .status(status)
            .body(ResponseBody::new(body))
            .unwrap()
    }

    #[inline]
    fn empty(status: StatusCode) -> Response<ResponseBody<B>> {
        Response::builder()
            .status(status)
            .body(ResponseBody::empty())
            .unwrap()
    }

    #[inline]
    fn ok() -> Response<ResponseBody<B>> {
        Response::empty(StatusCode::OK)
    }
}

/*
 * helper struct and function for service futures allowing to pass the nested
 * response body or return a HTTP message without a boxed future
 */
pin_project! {
    #[project = BodyProj]
    pub enum ResponseBody<B> {
        Full {
            #[pin]
            body: Full<Bytes>,
        },
        Empty,
        Wrapped {
            #[pin]
            body: B
        }
    }
}

impl<B> ResponseBody<B> {
    /// create a new body data
    pub(crate) fn new(data: impl Into<Bytes>) -> Self {
        ResponseBody::Full {
            body: Full::new(data.into()),
        }
    }

    /// create a empty body
    pub(crate) fn empty() -> Self {
        ResponseBody::Empty
    }

    /// wraps another body, use this if you want to pass a generic body unaltered
    pub(crate) fn wrap(body: B) -> Self {
        ResponseBody::Wrapped { body }
    }
}

impl<B> hyper::body::Body for ResponseBody<B>
where
    B: hyper::body::Body<Data = Bytes>,
{
    type Data = Bytes;
    type Error = B::Error;

    #[inline]
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.project() {
            BodyProj::Full { body } => body.poll_frame(cx).map_err(|e| match e {}),
            BodyProj::Wrapped { body } => body.poll_frame(cx),
            BodyProj::Empty => Poll::Ready(None),
        }
    }

    #[inline]
    fn is_end_stream(&self) -> bool {
        match &self {
            ResponseBody::Full { body } => body.is_end_stream(),
            ResponseBody::Wrapped { body } => body.is_end_stream(),
            ResponseBody::Empty => true,
        }
    }

    #[inline]
    fn size_hint(&self) -> SizeHint {
        match &self {
            ResponseBody::Full { body } => body.size_hint(),
            ResponseBody::Wrapped { body } => body.size_hint(),
            ResponseBody::Empty => SizeHint::with_exact(0),
        }
    }
}
