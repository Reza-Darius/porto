#![allow(dead_code)]

use tower_http::compression::{Compression, DefaultPredicate, Predicate, predicate::And};

use crate::utils::Peer;

pub fn setup_response_compresson<S>(
    inner: S,
) -> Compression<S, And<DefaultPredicate, PeerCompSettings>> {
    Compression::new(inner)
        .gzip(true)
        .compress_when(DefaultPredicate::new().and(PeerCompSettings))
}

/// determines compression based on settings per peer
#[derive(Clone)]
pub struct PeerCompSettings;

impl Predicate for PeerCompSettings {
    fn should_compress<B>(&self, response: &http::Response<B>) -> bool
    where
        B: hyper::body::Body,
    {
        if let Some(peer) = response.extensions().get::<Peer>() {
            peer.config().comp
        } else {
            false
        }
    }
}
