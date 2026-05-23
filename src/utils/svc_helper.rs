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

use crate::utils::{internal_error, response};

use http::Request;
use http_body_util::combinators::UnsyncBoxBody;
use hyper::body::Incoming;
use tower::util::BoxCloneService;

/// convenience type suitable for Futures returned by by Service impls
pub type SvcBoxFut<R, E> =
    Pin<Box<dyn Future<Output = std::result::Result<R, E>> + Send + 'static>>;
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

    internal_error()
}

// We create some utility functions to make Empty and Full bodies
// fit our broadened Response body type.
pub fn empty() -> Body {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed_unsync()
}

pub fn full<T: Into<Bytes>>(chunk: T) -> Body {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed_unsync()
}

/*
 * helper struct and function for service futures allowing to pass the nested
 * response body or return a HTTP message without a boxed future
 */
pin_project! {
    pub struct ResponseBody<B> {
        #[pin]
        inner: ResponseBodyInner<B>
    }
}

impl<B> ResponseBody<B> {
    /// create a new body with a message
    pub(crate) fn with_msg(str: &str) -> Self {
        Self {
            inner: ResponseBodyInner::Custom {
                body: Full::from(str.to_string()).map_err(Into::into).boxed_unsync(),
            },
        }
    }

    /// create a empty body
    pub(crate) fn empty() -> Self {
        Self {
            inner: ResponseBodyInner::Custom {
                body: Empty::new().map_err(Into::into).boxed_unsync(),
            },
        }
    }

    /// wraps the body, use this if you want to pass the body unaltered
    pub(crate) fn wrap(body: B) -> Self {
        Self {
            inner: ResponseBodyInner::Body { body },
        }
    }
}

pin_project! {
    #[project = BodyProj]
    pub enum ResponseBodyInner<B> {
        Custom {
            #[pin]
            body: UnsyncBoxBody<Bytes, BoxError>,
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
    B::Error: Into<BoxError>,
{
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.project().inner.project() {
            BodyProj::Custom { body } => body.poll_frame(cx),
            BodyProj::Body { body } => body.poll_frame(cx).map_err(Into::into),
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
