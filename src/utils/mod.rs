mod http;
mod peer;
mod ringbuffer;
mod tls;

pub use http::*;
pub use peer::*;
pub use ringbuffer::*;
pub use tls::*;

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
