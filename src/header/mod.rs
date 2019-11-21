use crate::header::filler::Filler;
use crate::header::keys::PayloadKey;
use crate::header::routing::EncapsulatedRoutingInformation;
use crate::route::{Destination, Node};
use crate::utils::crypto;

pub mod delays;
pub mod filler;
pub mod keys;
pub mod mac;
pub mod routing;

pub struct SphinxHeader {
    pub shared_secret: crypto::SharedSecret,
    pub routing_info: EncapsulatedRoutingInformation,
}

// needs client's secret key, how should we inject this?
// needs to deal with SURBs too at some point
pub fn create(route: &[Node], destination: &Destination) -> (SphinxHeader, Vec<PayloadKey>) {
    let initial_secret = crypto::generate_secret();
    let key_material = keys::KeyMaterial::derive(route, initial_secret);
    let delays = delays::generate(route.len());
    let filler_string = Filler::new(&key_material.routing_keys);
    let routing_info = routing::EncapsulatedRoutingInformation::new(
        route,
        destination,
        &key_material.routing_keys,
        filler_string,
    );

    // encapsulate header.routing information, compute MACs
    (
        SphinxHeader {
            shared_secret: key_material.initial_shared_secret,
            routing_info,
        },
        key_material
            .routing_keys
            .iter()
            .map(|routing_key| routing_key.payload_key)
            .collect(),
    )
}
