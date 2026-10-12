#![allow(dead_code)]

use tower_http::compression::Predicate;

use crate::utils::Peer;

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
            panic!("no peer info found on response")
        }
    }
}
