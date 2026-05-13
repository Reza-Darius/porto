use std::{
    any::Any,
    pin::Pin,
    task::{Context, Poll},
};

use axum::body::Bytes;
use http::{Response, StatusCode};
use http_body_util::{Empty, Full};
use hyper::body::{Frame, SizeHint};
use pin_project_lite::pin_project;
use tower::BoxError;

use crate::utils::{Body, BoxFut, internal_error, response};

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

pub fn boxfut_err<R>(e: impl ToString) -> BoxFut<R, BoxError> {
    let err: BoxError = e.to_string().into();
    Box::pin(async { Err(err) })
}

pub fn boxfut_res<E>(status: StatusCode) -> BoxFut<Response<Body>, E> {
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
    pub(crate) fn with_msg(str: &str) -> Self {
        Self {
            inner: ResponseBodyInner::Custom {
                body: Full::from(str.to_string()),
            },
        }
    }

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
