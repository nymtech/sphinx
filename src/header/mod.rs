use crate::header::header::RouteElement;
use crate::header::keys::PayloadKey;
use crate::header::routing::RoutingInfo;
use crate::utils::crypto;

pub mod delays;
pub mod filler;
pub mod header;
pub mod keys;
pub mod routing;

pub struct SphinxHeader {
    pub shared_secret: crypto::SharedSecret,
    pub routing_info: RoutingInfo,
}

// needs client's secret key, how should we inject this?
// needs to deal with SURBs too at some point
pub fn create(route: &[RouteElement]) -> (SphinxHeader, Vec<PayloadKey>) {
    let initial_secret = crypto::generate_secret();
    let key_material = keys::KeyMaterial::derive(route, initial_secret);
    let delays = delays::generate(route.len() - 1); // we don't generate delay for the destination
    let filler_string = filler::generate_pseudorandom_filler(&key_material.routing_keys);
    let routing_info =
        routing::generate_all_routing_info(route, &key_material.routing_keys, filler_string);

    // encapsulate routing information, compute MACs
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
