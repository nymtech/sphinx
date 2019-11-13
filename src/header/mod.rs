use crate::header::header::RouteElement;
use crate::utils::crypto;

pub mod delays;
pub mod header;
pub mod keys;

pub struct SphinxHeader {}

// needs client's secret key, how should we inject this?
// needs to deal with SURBs too at some point
pub fn create(route: &[RouteElement]) -> (SphinxHeader, Vec<crypto::SharedKey>) {
    let initial_secret = crypto::generate_secret();
    let key_material = keys::derive(route, initial_secret);
    let delays = delays::generate(route.len() - 1); // we don't generate delay for the destination
    let filler_string = header::generate_pseudorandom_filler_bytes(&key_material.routing_keys);
    let routing_info =
        header::generate_all_routing_info(route, &key_material.routing_keys, filler_string);
    // encapsulate routing information, compute MACs
    (SphinxHeader {}, Vec::new())
}
