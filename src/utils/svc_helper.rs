use std::any::Any;

use http::{Response, StatusCode};
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
    tracing::error!(details);

    internal_error()
}
